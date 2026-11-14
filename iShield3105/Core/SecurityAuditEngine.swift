//
//  SecurityAuditEngine.swift
//  iShield3105
//
//  System-level MDM/Supervision, MitM/Root CA, Runtime Dylib Injection & Loopback Port Auditor
//

import Foundation
import Security
import CFNetwork

@MainActor
final class SecurityAuditEngine: ObservableObject {
    @Published private(set) var lastReport: SecurityAuditReport?
    @Published private(set) var isScanning = false

    nonisolated private static let suspiciousDylibKeywords: [String] = [
        "frida", "fridagadget", "substrate", "mobilesubstrate", "cynject",
        "ellekit", "libhooker", "substitute", "shadow", "fishhook", "cycript",
        "reveal", "flex", "ssl-kill", "sslkillswitch", "objection", "dobby",
        "libblackjack", "dopamine", "palera1n", "tweak", "inject", "jailbreak",
        "bypass", "hooker", "antidebug"
    ]

    nonisolated private static let systemTrustedPrefixes: [String] = [
        "/System/Library/",
        "/usr/lib/",
        "/System/Cryptexes/",
        "/Developer/"
    ]

    nonisolated private static let knownMitMCAKeywords: [String] = [
        "charles", "mitmproxy", "fiddler", "portswigger", "burp",
        "proxyman", "surge", "quantumult", "shadowrocket", "reqable",
        "thor", "stream", "zscaler", "netskope", "fortinet", "palo alto",
        "bluecoat", "ssl inspection", "intercept", "debug ca"
    ]

    nonisolated private static let dangerousPortsCatalog: [(port: UInt16, service: String, desc: String, severity: RiskSeverity)] = [
        (22, "SSH / Dropbear", "Cổng truy cập shell từ xa (Remote Shell / SSH)", .critical),
        (27042, "Frida Server", "Cổng mặc định của công cụ hook/gián điệp runtime Frida", .critical),
        (27043, "Frida Secondary", "Cổng phụ của Frida Server", .critical),
        (4444, "Backdoor / Reverse Shell", "Cổng phổ biến cho payload điều khiển từ xa (Metasploit)", .critical),
        (23, "Telnet", "Giao thức điều khiển từ xa không mã hóa", .critical),
        (1337, "Debug / C2 Listener", "Cổng dịch vụ debug hoặc C2 nội bộ", .warning),
        (8888, "Local HTTP Proxy", "Cổng proxy cục bộ (Charles/mitmproxy/Proxy tool)", .warning),
        (62078, "lockdownd / usbmuxd", "Cổng đồng bộ USB/Wi-Fi Sync của thiết bị iOS", .info)
    ]

    func runFullAudit() async -> SecurityAuditReport {
        isScanning = true
        defer { isScanning = false }

        let report: SecurityAuditReport = await Task.detached(priority: .userInitiated) {
            async let mdmResult = Self.inspectMDMAndSupervision()
            async let proxyResult = Self.inspectGlobalProxySettings()
            async let trustStoreResult = Self.inspectTrustStoreAndKeychain()
            async let tlsResult = Self.auditLiveTLSChains()
            async let provisioningResult = Self.inspectEmbeddedProvisioningProfile()
            async let runtimeResult = Self.inspectLoadedDylibsAndDebugger()
            async let portsResult = Self.scanDangerousLoopbackPorts()

            let (mdmIndicators, isSupervised, isMDM) = await mdmResult
            let proxy = await proxyResult
            let trustFindings = await trustStoreResult
            let tlsAudits = await tlsResult
            let provisioning = await provisioningResult
            let (dylibs, suspiciousDylibs, debuggerAttached) = await runtimeResult
            let ports = await portsResult

            return SecurityAuditReport(
                auditedAt: Date(),
                mdmIndicators: mdmIndicators,
                isSupervisedDetected: isSupervised,
                isMDMDetected: isMDM,
                proxyReport: proxy,
                tlsChainAudits: tlsAudits,
                trustStoreFindings: trustFindings,
                provisioningInfo: provisioning,
                dylibs: dylibs,
                suspiciousDylibs: suspiciousDylibs,
                debuggerAttached: debuggerAttached,
                localPorts: ports
            )
        }.value

        lastReport = report
        return report
    }

    // MARK: - 1. MDM & Supervision Detector

    nonisolated private static func inspectMDMAndSupervision() async -> ([MDMProfileIndicator], Bool, Bool) {
        let bridge = ISContainerBridge.shared()
        let fm = FileManager.default
        var indicators: [MDMProfileIndicator] = []
        var supervisedDetected = false
        var mdmDetected = false

        let candidatePaths: [(name: String, path: String)] = [
            ("CloudConfigurationDetails (SystemGroup)", "/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/CloudConfigurationDetails.plist"),
            ("UserSettings (SystemGroup)", "/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/UserSettings.plist"),
            ("EffectiveUserSettings (SystemGroup)", "/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/EffectiveUserSettings.plist"),
            ("CloudConfigurationDetails (Mobile)", "/var/mobile/Library/ConfigurationProfiles/CloudConfigurationDetails.plist"),
            ("UserSettings (Mobile)", "/var/mobile/Library/ConfigurationProfiles/UserSettings.plist")
        ]

        for item in candidatePaths {
            let exists = fm.fileExists(atPath: item.path)
            if let data = try? Data(contentsOf: URL(fileURLWithPath: item.path)),
               let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] {
                let isSup = plist["IsSupervised"] as? Bool
                let orgName = plist["OrganizationName"] as? String
                let configURL = plist["ConfigurationURL"] as? String
                let wasApplied = plist["ConfigurationWasApplied"] as? Bool
                let mdmUnremovable = plist["IsMDMUnremovable"] as? Bool
                let hasMDM = (configURL?.isEmpty == false) || (orgName?.isEmpty == false) || (wasApplied == true) || (mdmUnremovable == true)

                if isSup == true { supervisedDetected = true }
                if hasMDM { mdmDetected = true }

                var detailMap: [String: String] = [:]
                for (k, v) in plist {
                    if let b = v as? Bool {
                        detailMap[k] = b ? "true" : "false"
                    } else if let s = v as? String {
                        detailMap[k] = s
                    } else if let n = v as? NSNumber {
                        detailMap[k] = n.stringValue
                    } else if let dict = v as? [String: Any] {
                        detailMap[k] = "{\(dict.count) keys}"
                    }
                }

                indicators.append(MDMProfileIndicator(
                    sourceName: item.name,
                    sourcePath: item.path,
                    accessStatus: "Đọc được trực tiếp",
                    isReadable: true,
                    isSupervised: isSup,
                    mdmEnrolled: hasMDM,
                    organizationName: orgName,
                    configurationURL: configURL,
                    details: detailMap
                ))
            } else {
                let status = exists
                    ? "Tồn tại nhưng bị iOS Sandbox chặn đọc trực tiếp (EPERM)"
                    : "Không tồn tại hoặc bị ẩn bởi Sandbox"
                indicators.append(MDMProfileIndicator(
                    sourceName: item.name,
                    sourcePath: item.path,
                    accessStatus: status,
                    isReadable: false,
                    isSupervised: nil,
                    mdmEnrolled: nil,
                    organizationName: nil,
                    configurationURL: nil,
                    details: [:]
                ))
            }
        }

        // Probe cfprefsd for configurationprofiles keys
        let cfSupervised = bridge.readCFPreferenceValue(forKey: "IsSupervised", applicationID: "com.apple.configurationprofiles") as? Bool
        let cfOrg = bridge.readCFPreferenceValue(forKey: "OrganizationName", applicationID: "com.apple.configurationprofiles") as? String
        let cfConfigURL = bridge.readCFPreferenceValue(forKey: "ConfigurationURL", applicationID: "com.apple.configurationprofiles") as? String
        if cfSupervised == true { supervisedDetected = true }
        if cfOrg != nil || cfConfigURL != nil { mdmDetected = true }

        var cfDetails: [String: String] = [:]
        if let cfSupervised { cfDetails["IsSupervised"] = cfSupervised ? "true" : "false" }
        if let cfOrg { cfDetails["OrganizationName"] = cfOrg }
        if let cfConfigURL { cfDetails["ConfigurationURL"] = cfConfigURL }

        indicators.append(MDMProfileIndicator(
            sourceName: "cfprefsd (com.apple.configurationprofiles)",
            sourcePath: "CFPreferencesCopyAppValue",
            accessStatus: cfDetails.isEmpty ? "Không có dữ liệu công khai qua cfprefsd" : "Đọc được từ cfprefsd",
            isReadable: !cfDetails.isEmpty,
            isSupervised: cfSupervised,
            mdmEnrolled: (cfOrg != nil || cfConfigURL != nil) ? true : nil,
            organizationName: cfOrg,
            configurationURL: cfConfigURL,
            details: cfDetails
        ))

        // Check Managed App Configuration (standard MDM deployment key)
        if let managedConfig = UserDefaults.standard.dictionary(forKey: "com.apple.configuration.managed"),
           !managedConfig.isEmpty {
            mdmDetected = true
            var strMap: [String: String] = [:]
            for (k, v) in managedConfig {
                strMap[k] = String(describing: v)
            }
            indicators.append(MDMProfileIndicator(
                sourceName: "Managed App Config (MDM)",
                sourcePath: "UserDefaults: com.apple.configuration.managed",
                accessStatus: "Phát hiện cấu hình MDM đẩy xuống ứng dụng",
                isReadable: true,
                isSupervised: nil,
                mdmEnrolled: true,
                organizationName: strMap["OrganizationName"] ?? strMap["organization"],
                configurationURL: strMap["ServerURL"],
                details: strMap
            ))
        }

        return (indicators, supervisedDetected, mdmDetected)
    }

    // MARK: - 2. Global Proxy & Root CA / MitM Check

    nonisolated private static func inspectGlobalProxySettings() async -> ProxyConfigurationReport {
        guard let raw = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return ProxyConfigurationReport(
                httpProxyEnabled: false,
                httpProxyHost: nil,
                httpProxyPort: nil,
                httpsProxyEnabled: false,
                httpsProxyHost: nil,
                httpsProxyPort: nil,
                socksProxyEnabled: false,
                socksProxyHost: nil,
                socksProxyPort: nil,
                pacEnabled: false,
                pacURL: nil,
                scopedInterfaceProxies: [:]
            )
        }

        let httpEnabled = (raw["HTTPEnable"] as? Int ?? 0) != 0
        let httpHost = raw["HTTPProxy"] as? String
        let httpPort = raw["HTTPPort"] as? Int

        let httpsEnabled = (raw["HTTPSEnable"] as? Int ?? 0) != 0
        let httpsHost = raw["HTTPSProxy"] as? String
        let httpsPort = raw["HTTPSPort"] as? Int

        let socksEnabled = (raw["SOCKSEnable"] as? Int ?? 0) != 0
        let socksHost = raw["SOCKSProxy"] as? String
        let socksPort = raw["SOCKSPort"] as? Int

        let pacEnabled = (raw["ProxyAutoConfigEnable"] as? Int ?? 0) != 0
        let pacURL = raw["ProxyAutoConfigURLString"] as? String

        var scopedMap: [String: String] = [:]
        if let scoped = raw["__SCOPED__"] as? [String: Any] {
            for (iface, value) in scoped {
                guard let dict = value as? [String: Any] else { continue }
                var parts: [String] = []
                if (dict["HTTPEnable"] as? Int ?? 0) != 0, let host = dict["HTTPProxy"] as? String {
                    let port = dict["HTTPPort"] as? Int ?? 0
                    parts.append("HTTP \(host):\(port)")
                }
                if (dict["HTTPSEnable"] as? Int ?? 0) != 0, let host = dict["HTTPSProxy"] as? String {
                    let port = dict["HTTPSPort"] as? Int ?? 0
                    parts.append("HTTPS \(host):\(port)")
                }
                if (dict["SOCKSEnable"] as? Int ?? 0) != 0, let host = dict["SOCKSProxy"] as? String {
                    let port = dict["SOCKSPort"] as? Int ?? 0
                    parts.append("SOCKS \(host):\(port)")
                }
                if (dict["ProxyAutoConfigEnable"] as? Int ?? 0) != 0, let pac = dict["ProxyAutoConfigURLString"] as? String {
                    parts.append("PAC \(pac)")
                }
                if !parts.isEmpty {
                    scopedMap[iface] = parts.joined(separator: " | ")
                }
            }
        }

        return ProxyConfigurationReport(
            httpProxyEnabled: httpEnabled,
            httpProxyHost: httpHost,
            httpProxyPort: httpPort,
            httpsProxyEnabled: httpsEnabled,
            httpsProxyHost: httpsHost,
            httpsProxyPort: httpsPort,
            socksProxyEnabled: socksEnabled,
            socksProxyHost: socksHost,
            socksProxyPort: socksPort,
            pacEnabled: pacEnabled,
            pacURL: pacURL,
            scopedInterfaceProxies: scopedMap
        )
    }

    nonisolated private static func inspectTrustStoreAndKeychain() async -> [String] {
        var findings: [String] = []
        let fm = FileManager.default

        let trustPaths = [
            "/private/var/protected/trustd/private/TrustStore.sqlite3",
            "/var/Keychains/TrustStore.sqlite3"
        ]
        for path in trustPaths where fm.isReadableFile(atPath: path) {
            if let attrs = try? fm.attributesOfItem(atPath: path),
               let size = attrs[.size] as? NSNumber,
               size.int64Value > 0 {
                findings.append("Đọc được TrustStore hệ thống tại \(path) (\(size.int64Value) bytes) — có chứng chỉ người dùng tùy chỉnh hoặc quyền đọc mở rộng.")
            }
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let certs = result as? [SecCertificate] {
            for cert in certs {
                let summary = (SecCertificateCopySubjectSummary(cert) as String?) ?? "Unknown Certificate"
                let lower = summary.lowercased()
                if knownMitMCAKeywords.contains(where: { lower.contains($0) }) {
                    findings.append("Phát hiện chứng chỉ CA nghi ngờ MitM trong Keychain: \(summary)")
                }
            }
        }

        return findings
    }

    nonisolated private static func auditLiveTLSChains() async -> [TLSChainAuditReport] {
        let targets = [
            URL(string: "https://1.1.1.1/cdn-cgi/trace")!,
            URL(string: "https://api.ipify.org?format=json")!
        ]

        var results: [TLSChainAuditReport] = []
        for url in targets {
            let audit = await auditSingleTLSChain(url: url)
            results.append(audit)
        }
        return results
    }

    nonisolated private static func auditSingleTLSChain(url: URL) async -> TLSChainAuditReport {
        let delegate = TLSAuditSessionDelegate(knownMitMKeywords: knownMitMCAKeywords)
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 6
        config.timeoutIntervalForResource = 8
        config.requestCachePolicy = .reloadIgnoringLocalCacheData

        let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        var request = URLRequest(url: url)
        request.httpMethod = "HEAD"

        do {
            _ = try await session.data(for: request)
        } catch {
            if delegate.capturedSubjects.isEmpty && delegate.capturedError == nil {
                delegate.recordNetworkError(error.localizedDescription)
            }
        }

        return TLSChainAuditReport(
            targetHost: url.host ?? url.absoluteString,
            trustEvaluatedValid: delegate.trustValid,
            evaluationError: delegate.capturedError,
            certificateSubjects: delegate.capturedSubjects,
            suspectedMitMAuthority: delegate.suspectedMitM,
            auditedAt: Date()
        )
    }

    nonisolated private static func inspectEmbeddedProvisioningProfile() async -> ProvisioningAuditInfo {
        guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
              let data = try? Data(contentsOf: url),
              let rawText = String(data: data, encoding: .isoLatin1),
              let startRange = rawText.range(of: "<?xml"),
              let endRange = rawText.range(of: "</plist>") else {
            return ProvisioningAuditInfo(
                hasEmbeddedProvision: false,
                teamName: nil,
                appIDName: nil,
                provisionsAllDevices: false,
                expirationDate: nil,
                parsedEntitlements: [:]
            )
        }

        let plistXML = String(rawText[startRange.lowerBound..<endRange.upperBound])
        guard let plistData = plistXML.data(using: .utf8),
              let dict = try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil) as? [String: Any] else {
            return ProvisioningAuditInfo(
                hasEmbeddedProvision: true,
                teamName: nil,
                appIDName: nil,
                provisionsAllDevices: false,
                expirationDate: nil,
                parsedEntitlements: [:]
            )
        }

        let teamName = dict["TeamName"] as? String
        let appIDName = dict["AppIDName"] as? String
        let provisionsAll = dict["ProvisionsAllDevices"] as? Bool ?? false
        let expiration = dict["ExpirationDate"] as? Date

        var entitlementsMap: [String: String] = [:]
        if let ents = dict["Entitlements"] as? [String: Any] {
            for (k, v) in ents {
                entitlementsMap[k] = String(describing: v)
            }
        }

        return ProvisioningAuditInfo(
            hasEmbeddedProvision: true,
            teamName: teamName,
            appIDName: appIDName,
            provisionsAllDevices: provisionsAll,
            expirationDate: expiration,
            parsedEntitlements: entitlementsMap
        )
    }

    // MARK: - 3. Runtime Dylib Injection & Debugger Detection

    nonisolated private static func inspectLoadedDylibsAndDebugger() async -> ([LoadedDylibReport], [LoadedDylibReport], Bool) {
        let bridge = ISContainerBridge.shared()
        let rawEntries = bridge.loadedDynamicLibraries()
        let bundlePath = Bundle.main.bundlePath
        let debuggerAttached = bridge.isDebuggerAttached()

        var allReports: [LoadedDylibReport] = []
        var suspiciousList: [LoadedDylibReport] = []

        for entry in rawEntries {
            let path = entry.imagePath
            let lowerPath = path.lowercased()
            let lowerName = entry.imageName.lowercased()

            let isSystem = systemTrustedPrefixes.contains(where: { path.hasPrefix($0) })
                || (path.hasPrefix("/private/preboot/") && (path.contains("/System/Library/") || path.contains("/usr/lib/")))
            let isBundleOwned = path.hasPrefix(bundlePath)
            let matchesHookSignature = suspiciousDylibKeywords.first(where: { lowerPath.contains($0) || lowerName.contains($0) })

            var isSuspicious = false
            var reason: String?

            if let signature = matchesHookSignature {
                isSuspicious = true
                reason = "Trùng chữ ký hook/gián điệp runtime '\(signature)'."
            } else if !isSystem && !isBundleOwned {
                isSuspicious = true
                reason = "Thư viện nạp từ ngoài phân vùng hệ thống (/System/Library, /usr/lib) và ngoài app bundle."
            } else if isBundleOwned && (lowerPath.contains("/documents/") || lowerPath.contains("/tmp/") || lowerPath.contains("/caches/")) {
                isSuspicious = true
                reason = "Thư viện động nạp từ thư mục ghi được (Documents/tmp/Caches)."
            }

            let report = LoadedDylibReport(
                index: entry.imageIndex,
                name: entry.imageName,
                path: path,
                architecture: entry.architecture ?? "arm64",
                isSystemTrusted: isSystem,
                isBundleOwned: isBundleOwned,
                isSuspicious: isSuspicious,
                riskReason: reason
            )
            allReports.append(report)
            if isSuspicious {
                suspiciousList.append(report)
            }
        }

        return (allReports, suspiciousList, debuggerAttached)
    }

    // MARK: - 4. Loopback Backdoor Port Scanner (127.0.0.1)

    nonisolated private static func scanDangerousLoopbackPorts() async -> [LocalPortProbeResult] {
        let bridge = ISContainerBridge.shared()
        var results: [LocalPortProbeResult] = []
        for item in dangerousPortsCatalog {
            let isOpen = bridge.isLocalhostPortOpen(item.port, timeoutMilliseconds: 220)
            results.append(LocalPortProbeResult(
                port: item.port,
                serviceName: item.service,
                description: item.desc,
                isOpen: isOpen,
                severityIfOpen: item.severity
            ))
        }
        return results
    }
}

// MARK: - URLSession TLS Chain Inspector Delegate

private final class TLSAuditSessionDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private let knownMitMKeywords: [String]

    private var _trustValid = true
    private var _capturedError: String?
    private var _capturedSubjects: [String] = []
    private var _suspectedMitM: String?

    init(knownMitMKeywords: [String]) {
        self.knownMitMKeywords = knownMitMKeywords
    }

    var trustValid: Bool {
        lock.lock(); defer { lock.unlock() }
        return _trustValid
    }

    var capturedError: String? {
        lock.lock(); defer { lock.unlock() }
        return _capturedError
    }

    var capturedSubjects: [String] {
        lock.lock(); defer { lock.unlock() }
        return _capturedSubjects
    }

    var suspectedMitM: String? {
        lock.lock(); defer { lock.unlock() }
        return _suspectedMitM
    }

    func recordNetworkError(_ message: String) {
        lock.lock(); defer { lock.unlock() }
        _capturedError = message
    }

    nonisolated func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        let chain = (SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate]) ?? []
        let subjects = chain.map { (SecCertificateCopySubjectSummary($0) as String?) ?? "Unknown Cert" }

        var cfError: CFError?
        let isValid = SecTrustEvaluateWithError(serverTrust, &cfError)
        let evalErr = cfError.map { CFErrorCopyDescription($0) as String }

        var mitmAuthority: String?
        for subject in subjects {
            let lower = subject.lowercased()
            if knownMitMKeywords.contains(where: { lower.contains($0) }) {
                mitmAuthority = subject
                break
            }
        }

        lock.lock()
        _trustValid = isValid
        _capturedError = evalErr
        _capturedSubjects = subjects
        _suspectedMitM = mitmAuthority
        lock.unlock()

        if isValid {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

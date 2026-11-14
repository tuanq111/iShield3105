//
//  SecurityModels.swift
//  iShield3105
//

import Foundation

enum RiskSeverity: Int, Comparable, Codable, CaseIterable {
    case safe = 0
    case info = 1
    case warning = 2
    case critical = 3

    static func < (lhs: RiskSeverity, rhs: RiskSeverity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var label: String {
        switch self {
        case .safe: return "AN TOÀN"
        case .info: return "THÔNG TIN"
        case .warning: return "CẢNH BÁO"
        case .critical: return "NGUY HIỂM"
        }
    }
}

enum AuditCategory: String, CaseIterable, Identifiable {
    case deviceControl = "MDM & Quyền Điều Khiển"
    case runtime = "Runtime & Dylib Injection"
    case network = "Mạng, VPN & Rò Rỉ DNS/IP"
    case container = "Container 3105 & Cache"

    var id: String { rawValue }
}

struct SecurityAlertBanner: Identifiable, Hashable {
    let id = UUID()
    let category: AuditCategory
    let severity: RiskSeverity
    let title: String
    let detail: String
    let targetTab: Int
}

// MARK: - Container Inspector Models (3105)

struct InstalledAppItem: Identifiable, Hashable {
    let id: String
    let bundleIdentifier: String
    let displayName: String
    let applicationType: String
    let shortVersion: String?
    let dataContainerURL: URL?
    let groupContainerURLs: [String: URL]
    let pluginIdentifiers: [String]
    let signerIdentity: String?

    init(
        bundleIdentifier: String,
        displayName: String,
        applicationType: String,
        shortVersion: String? = nil,
        dataContainerURL: URL? = nil,
        groupContainerURLs: [String: URL] = [:],
        pluginIdentifiers: [String] = [],
        signerIdentity: String? = nil
    ) {
        self.id = bundleIdentifier
        self.bundleIdentifier = bundleIdentifier
        self.displayName = displayName
        self.applicationType = applicationType
        self.shortVersion = shortVersion
        self.dataContainerURL = dataContainerURL
        self.groupContainerURLs = groupContainerURLs
        self.pluginIdentifiers = pluginIdentifiers
        self.signerIdentity = signerIdentity
    }
}

enum SuspiciousFileKind: String, CaseIterable {
    case foreignDylib = "Thư viện .dylib / Binary lạ"
    case proxyConfig = "Cấu hình Proxy / Tunnel"
    case trackingArtifact = "Tệp theo dõi / Fingerprint"
    case bloatedCache = "Dữ liệu đệm phình to bất thường"
}

struct SuspiciousContainerFile: Identifiable, Hashable {
    let id = UUID()
    let fileURL: URL
    let relativePath: String
    let directoryScope: String
    let sizeBytes: Int64
    let kind: SuspiciousFileKind
    let severity: RiskSeverity
    let reason: String
    let modifiedDate: Date?
}

struct PreferenceKeyEntry: Identifiable, Hashable {
    let id = UUID()
    let plistFileName: String
    let plistURL: URL
    let key: String
    let valuePreview: String
    let isSuspicious: Bool
    let suspicionReason: String?
}

struct PlistBackupRecord: Identifiable, Codable, Hashable {
    let id: UUID
    let bundleIdentifier: String
    let originalFileName: String
    let originalPath: String
    let backupPath: String
    let sha256: String
    let createdAt: Date
    let note: String
}

struct ContainerInspectionReport: Identifiable {
    let id = UUID()
    let bundleIdentifier: String
    let dataContainerURL: URL?
    let dataContainerExisted: Bool
    let dataContainerReadable: Bool
    let sandboxTokenConsumed: Bool
    let dataContainerError: String?
    let resolvedGroupContainers: [String: URL]
    let resolvedPluginContainers: [String: URL]
    let cachesSizeBytes: Int64
    let cachesFileCount: Int
    let tmpSizeBytes: Int64
    let tmpFileCount: Int
    let preferencesFileCount: Int
    let suspiciousFiles: [SuspiciousContainerFile]
    let preferenceEntries: [PreferenceKeyEntry]
    let quarantinedDylibs: [SuspiciousContainerFile]
    let inspectedAt: Date

    var totalCleanableBytes: Int64 {
        cachesSizeBytes + tmpSizeBytes
    }

    var totalCleanableFiles: Int {
        cachesFileCount + tmpFileCount
    }

    var highestSeverity: RiskSeverity {
        let fileMax = suspiciousFiles.map(\.severity).max() ?? .safe
        let prefMax: RiskSeverity = preferenceEntries.contains(where: \.isSuspicious) ? .warning : .safe
        return max(fileMax, prefMax)
    }
}

struct ContainerCleanupSummary: Identifiable {
    let id = UUID()
    let bundleIdentifier: String
    let removedItemsCount: Int
    let freedBytes: Int64
    let skippedItemsCount: Int
    let backedUpPlistCount: Int
    let sanitizedPlistKeysCount: Int
    let errors: [String]
    let completedAt: Date
}

// MARK: - Device Control, MDM, MitM & Runtime Security Models

struct MDMProfileIndicator: Identifiable, Hashable {
    let id = UUID()
    let sourceName: String
    let sourcePath: String
    let accessStatus: String
    let isReadable: Bool
    let isSupervised: Bool?
    let mdmEnrolled: Bool?
    let organizationName: String?
    let configurationURL: String?
    let details: [String: String]
}

struct ProxyConfigurationReport: Hashable {
    let httpProxyEnabled: Bool
    let httpProxyHost: String?
    let httpProxyPort: Int?
    let httpsProxyEnabled: Bool
    let httpsProxyHost: String?
    let httpsProxyPort: Int?
    let socksProxyEnabled: Bool
    let socksProxyHost: String?
    let socksProxyPort: Int?
    let pacEnabled: Bool
    let pacURL: String?
    let scopedInterfaceProxies: [String: String]

    var hasActiveProxy: Bool {
        httpProxyEnabled || httpsProxyEnabled || socksProxyEnabled || pacEnabled || !scopedInterfaceProxies.isEmpty
    }
}

struct TLSChainAuditReport: Identifiable, Hashable {
    let id = UUID()
    let targetHost: String
    let trustEvaluatedValid: Bool
    let evaluationError: String?
    let certificateSubjects: [String]
    let suspectedMitMAuthority: String?
    let auditedAt: Date
}

struct LoadedDylibReport: Identifiable, Hashable {
    let id = UUID()
    let index: UInt
    let name: String
    let path: String
    let architecture: String
    let isSystemTrusted: Bool
    let isBundleOwned: Bool
    let isSuspicious: Bool
    let riskReason: String?
}

struct LocalPortProbeResult: Identifiable, Hashable {
    let id = UUID()
    let port: UInt16
    let serviceName: String
    let description: String
    let isOpen: Bool
    let severityIfOpen: RiskSeverity
}

struct ProvisioningAuditInfo: Hashable {
    let hasEmbeddedProvision: Bool
    let teamName: String?
    let appIDName: String?
    let provisionsAllDevices: Bool
    let expirationDate: Date?
    let parsedEntitlements: [String: String]
}

struct SecurityAuditReport {
    let auditedAt: Date
    let mdmIndicators: [MDMProfileIndicator]
    let isSupervisedDetected: Bool
    let isMDMDetected: Bool
    let proxyReport: ProxyConfigurationReport
    let tlsChainAudits: [TLSChainAuditReport]
    let trustStoreFindings: [String]
    let provisioningInfo: ProvisioningAuditInfo
    let dylibs: [LoadedDylibReport]
    let suspiciousDylibs: [LoadedDylibReport]
    let debuggerAttached: Bool
    let localPorts: [LocalPortProbeResult]

    var openDangerousPorts: [LocalPortProbeResult] {
        localPorts.filter(\.isOpen)
    }

    var hasMitMRisk: Bool {
        proxyReport.hasActiveProxy
            || tlsChainAudits.contains(where: { !$0.trustEvaluatedValid || $0.suspectedMitMAuthority != nil })
            || !trustStoreFindings.isEmpty
    }
}

// MARK: - Network Privacy, VPN Tunnel & DNS/IP Models

enum NetworkInterfaceCategory: String, Hashable {
    case wifi = "Wi-Fi"
    case cellular = "Di động (Cellular)"
    case virtualTunnel = "Đường hầm ảo (VPN/Tunnel)"
    case loopback = "Loopback"
    case awdl = "Apple Wireless Direct"
    case other = "Khác"
}

struct NetworkInterfaceItem: Identifiable, Hashable {
    let id: String
    let name: String
    let category: NetworkInterfaceCategory
    let ipv4Addresses: [String]
    let ipv6Addresses: [String]
    let isUp: Bool
    let isRunning: Bool
    let isPointToPoint: Bool
    let hasRoutableIP: Bool
    let isSuspiciousHiddenTunnel: Bool
    let tunnelAssessment: String?
}

struct DNSServerAuditItem: Identifiable, Hashable {
    let id = UUID()
    let address: String
    let providerName: String
    let isTrustedKnownDNS: Bool
    let isPrivateLAN: Bool
    let riskLevel: RiskSeverity
    let note: String
}

struct PublicIPInfoReport: Hashable {
    let ip: String
    let hostname: String?
    let city: String?
    let region: String?
    let country: String?
    let org: String?
    let timezone: String?
    let isHostingOrVPN: Bool
    let leakedHeaders: [String: String]
    let observedResponseHeaders: [String: String]
    let sourceEndpoint: String
    let fetchedAt: Date
    let errorMessage: String?

    var isRealIPExposed: Bool {
        errorMessage == nil && !ip.isEmpty && !isHostingOrVPN
    }
}

struct NetworkPrivacyReport {
    let scannedAt: Date
    let interfaces: [NetworkInterfaceItem]
    let activeTunnels: [NetworkInterfaceItem]
    let suspiciousTunnels: [NetworkInterfaceItem]
    let dnsServers: [DNSServerAuditItem]
    let dnsSnapshotError: String?
    let dnsHijackSuspected: Bool
    let publicIP: PublicIPInfoReport?
    let nwPathUsesVPN: Bool
    let nwPathSummary: String
}

// MARK: - DoH Configuration Profile Provider

enum DoHProviderOption: String, CaseIterable, Identifiable {
    case cloudflareStandard = "Cloudflare 1.1.1.1"
    case cloudflareSecurity = "Cloudflare Malware Block (1.1.1.2)"
    case quad9Recommended = "Quad9 Malware Block (dns.quad9.net)"
    case adguardTracking = "AdGuard DNS Chặn Theo Dõi"

    var id: String { rawValue }

    var serverURL: String {
        switch self {
        case .cloudflareStandard:
            return "https://cloudflare-dns.com/dns-query"
        case .cloudflareSecurity:
            return "https://security.cloudflare-dns.com/dns-query"
        case .quad9Recommended:
            return "https://dns.quad9.net/dns-query"
        case .adguardTracking:
            return "https://dns.adguard-dns.com/dns-query"
        }
    }

    var serverAddresses: [String] {
        switch self {
        case .cloudflareStandard:
            return ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"]
        case .cloudflareSecurity:
            return ["1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002"]
        case .quad9Recommended:
            return ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"]
        case .adguardTracking:
            return ["94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"]
        }
    }

    var description: String {
        switch self {
        case .cloudflareStandard:
            return "DNS-over-HTTPS tốc độ cao, không lưu nhật ký IP nguồn."
        case .cloudflareSecurity:
            return "Tự động chặn tên miền độc hại, phishing và botnet."
        case .quad9Recommended:
            return "Chặn mã độc theo threat intelligence đa nguồn, không lưu log."
        case .adguardTracking:
            return "Chặn quảng cáo, telemetry và SDK theo dõi ở tầng DNS."
        }
    }
}

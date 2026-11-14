//
//  ContainerManager.swift
//  iShield3105
//
//  3105 Container Inspector, Deep Cleaner & Quarantine Engine
//

import Foundation
import CryptoKit

@MainActor
final class ContainerManager: ObservableObject {
    @Published private(set) var frameworkStatus: ISFrameworkLoadStatus?
    @Published private(set) var installedApps: [InstalledAppItem] = []
    @Published private(set) var backups: [PlistBackupRecord] = []
    @Published private(set) var lastInspection: ContainerInspectionReport?
    @Published private(set) var lastCleanup: ContainerCleanupSummary?
    @Published private(set) var isLoadingApps = false
    @Published private(set) var isInspecting = false
    @Published private(set) var statusMessage: String?

    private let bridge = ISContainerBridge.sharedBridge()
    private let fileManager = FileManager.default

    private static let bloatedSingleFileThresholdBytes: Int64 = 50 * 1024 * 1024 // 50 MB
    private static let suspiciousBinaryExtensions: Set<String> = [
        "dylib", "deb", "so", "framework", "bundle", "tweak"
    ]
    private static let proxyConfigNameKeywords: [String] = [
        "proxy", "mitm", "shadowsocks", "clash", "mihomo", "v2ray", "xray",
        "trojan", "surge", "quantumult", "sing-box", "singbox", "pac", "tunnel"
    ]
    private static let trackingKeyKeywords: [String] = [
        "proxy", "httpproxy", "httpsproxy", "socksproxy", "pacurl",
        "adjust", "appsflyer", "branch", "amplitude", "mixpanel", "sensorsdata",
        "umeng", "bugly", "bytedance", "pangle", "idfa", "advertisingid",
        "fingerprint", "device_fingerprint", "tracking", "telemetry", "keylog",
        "clipboard", "exfiltrate", "beacon", "spy", "hook", "c2", "frida"
    ]
    private static let trackingPlistNameKeywords: [String] = [
        "adjust", "appsflyer", "branch", "amplitude", "mixpanel", "sensors",
        "umeng", "bugly", "facebook", "fb_", "tiktok", "bytedance", "analytics",
        "tracking", "telemetry", "proxy"
    ]

    init() {
        frameworkStatus = bridge.loadPrivateFrameworks()
        loadBackupManifest()
    }

    // MARK: - App Enumeration

    func refreshInstalledApps() async {
        isLoadingApps = true
        defer { isLoadingApps = false }

        let status = bridge.loadPrivateFrameworks()
        frameworkStatus = status

        let loaded: [InstalledAppItem] = await Task.detached(priority: .userInitiated) {
            let rawApps = (try? ISContainerBridge.sharedBridge().installedApplications()) ?? []
            return rawApps.map { desc in
                InstalledAppItem(
                    bundleIdentifier: desc.bundleIdentifier,
                    displayName: desc.displayName,
                    applicationType: desc.applicationType,
                    shortVersion: desc.shortVersion,
                    dataContainerURL: desc.dataContainerURL,
                    groupContainerURLs: desc.groupContainerURLs,
                    pluginIdentifiers: desc.pluginIdentifiers,
                    signerIdentity: desc.signerIdentity
                )
            }
        }.value

        installedApps = loaded
        if loaded.isEmpty {
            statusMessage = "Không liệt kê được ứng dụng do sandbox iOS hạn chế — hãy nhập Bundle ID thủ công."
        } else {
            statusMessage = "Đã nạp \(loaded.count) ứng dụng từ hệ thống."
        }
    }

    // MARK: - 3105 Deep Container Inspection

    func inspectContainer(
        bundleIdentifier: String,
        explicitAppGroupIDs: [String] = []
    ) async -> ContainerInspectionReport {
        isInspecting = true
        defer { isInspecting = false }

        let trimmedID = bundleIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        let knownApp = installedApps.first(where: { $0.bundleIdentifier == trimmedID })

        let report: ContainerInspectionReport = await Task.detached(priority: .userInitiated) {
            let bridge = ISContainerBridge.sharedBridge()
            let fm = FileManager.default

            let dataDesc = bridge.resolveAppDataContainer(forBundleIdentifier: trimmedID)
            var resolvedDataURL = dataDesc.url
            var resolvedExisted = dataDesc.existed
            var resolvedReadable = dataDesc.isReadable
            let tokenConsumed = dataDesc.sandboxTokenConsumed
            var dataError = dataDesc.errorMessage

            // Fallback to known LSApplicationProxy URL or own NSHomeDirectory if inspecting self
            if resolvedDataURL == nil {
                if let knownURL = knownApp?.dataContainerURL {
                    resolvedDataURL = knownURL
                    resolvedExisted = fm.fileExists(atPath: knownURL.path)
                    resolvedReadable = fm.isReadableFile(atPath: knownURL.path)
                } else if trimmedID == (Bundle.main.bundleIdentifier ?? "com.apple.mobile.MobileHouseArrest") {
                    let selfURL = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
                    resolvedDataURL = selfURL
                    resolvedExisted = true
                    resolvedReadable = fm.isReadableFile(atPath: selfURL.path)
                    dataError = nil
                }
            }

            // Resolve App Group containers
            var groupURLs: [String: URL] = knownApp?.groupContainerURLs ?? [:]
            var candidateGroups = Set(explicitAppGroupIDs.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty })
            if !trimmedID.isEmpty {
                candidateGroups.insert("group.\(trimmedID)")
            }
            for groupID in candidateGroups where groupURLs[groupID] == nil {
                let grpDesc = bridge.resolveSharedGroupContainer(forIdentifier: groupID)
                if let url = grpDesc.url {
                    groupURLs[groupID] = url
                }
            }

            // Resolve PluginKit containers
            var pluginURLs: [String: URL] = [:]
            for pluginID in (knownApp?.pluginIdentifiers ?? []) {
                let plugDesc = bridge.resolvePluginKitContainer(forIdentifier: pluginID)
                if let url = plugDesc.url {
                    pluginURLs[pluginID] = url
                }
            }

            guard let rootURL = resolvedDataURL else {
                return ContainerInspectionReport(
                    bundleIdentifier: trimmedID,
                    dataContainerURL: nil,
                    dataContainerExisted: resolvedExisted,
                    dataContainerReadable: false,
                    sandboxTokenConsumed: tokenConsumed,
                    dataContainerError: dataError ?? "Không truy xuất được Data Container.",
                    resolvedGroupContainers: groupURLs,
                    resolvedPluginContainers: pluginURLs,
                    cachesSizeBytes: 0,
                    cachesFileCount: 0,
                    tmpSizeBytes: 0,
                    tmpFileCount: 0,
                    preferencesFileCount: 0,
                    suspiciousFiles: [],
                    preferenceEntries: [],
                    quarantinedDylibs: [],
                    inspectedAt: Date()
                )
            }

            let cachesURL = rootURL.appendingPathComponent("Library/Caches", isDirectory: true)
            let tmpURL = rootURL.appendingPathComponent("tmp", isDirectory: true)
            let prefsURL = rootURL.appendingPathComponent("Library/Preferences", isDirectory: true)

            let cachesScan = Self.scanDirectory(
                cachesURL,
                containerRoot: rootURL,
                scopeName: "Library/Caches"
            )
            let tmpScan = Self.scanDirectory(
                tmpURL,
                containerRoot: rootURL,
                scopeName: "tmp"
            )
            let prefsScan = Self.scanPreferencesDirectory(
                prefsURL,
                containerRoot: rootURL
            )

            // Also scan App Groups for hidden foreign dylibs or proxy configs
            var groupFindings: [SuspiciousContainerFile] = []
            for (groupID, groupURL) in groupURLs {
                let scan = Self.scanDirectory(
                    groupURL,
                    containerRoot: groupURL,
                    scopeName: "AppGroup(\(groupID))"
                )
                groupFindings.append(contentsOf: scan.suspiciousFiles)
            }

            let allSuspicious = (cachesScan.suspiciousFiles + tmpScan.suspiciousFiles + prefsScan.suspiciousFiles + groupFindings)
                .sorted {
                    if $0.severity != $1.severity {
                        return $0.severity > $1.severity
                    }
                    return $0.sizeBytes > $1.sizeBytes
                }

            let dylibFindings = allSuspicious.filter { $0.kind == .foreignDylib }

            return ContainerInspectionReport(
                bundleIdentifier: trimmedID,
                dataContainerURL: resolvedDataURL,
                dataContainerExisted: resolvedExisted,
                dataContainerReadable: resolvedReadable,
                sandboxTokenConsumed: tokenConsumed,
                dataContainerError: dataError,
                resolvedGroupContainers: groupURLs,
                resolvedPluginContainers: pluginURLs,
                cachesSizeBytes: cachesScan.totalBytes,
                cachesFileCount: cachesScan.fileCount,
                tmpSizeBytes: tmpScan.totalBytes,
                tmpFileCount: tmpScan.fileCount,
                preferencesFileCount: prefsScan.plistCount,
                suspiciousFiles: allSuspicious,
                preferenceEntries: prefsScan.preferenceEntries,
                quarantinedDylibs: dylibFindings,
                inspectedAt: Date()
            )
        }.value

        lastInspection = report
        return report
    }

    // MARK: - Safe Cleaning (Library/Caches & tmp) + Plist Backup/Restore

    func cleanTrackingCaches(
        for report: ContainerInspectionReport,
        sanitizeSuspiciousPreferences: Bool
    ) async -> ContainerCleanupSummary {
        let quarantineRoot = Self.quarantineRootURL()
        let bundleID = report.bundleIdentifier

        let result: (ContainerCleanupSummary, [PlistBackupRecord]) = await Task.detached(priority: .userInitiated) {
            let fm = FileManager.default
            var removedCount = 0
            var freedBytes: Int64 = 0
            var skippedCount = 0
            var backedUpCount = 0
            var sanitizedKeysCount = 0
            var errors: [String] = []
            var newBackups: [PlistBackupRecord] = []

            guard let dataRoot = report.dataContainerURL else {
                let summary = ContainerCleanupSummary(
                    bundleIdentifier: bundleID,
                    removedItemsCount: 0,
                    freedBytes: 0,
                    skippedItemsCount: 0,
                    backedUpPlistCount: 0,
                    sanitizedPlistKeysCount: 0,
                    errors: ["Không có đường dẫn Data Container hợp lệ."],
                    completedAt: Date()
                )
                return (summary, [])
            }

            let safeTargets = [
                dataRoot.appendingPathComponent("Library/Caches", isDirectory: true),
                dataRoot.appendingPathComponent("tmp", isDirectory: true)
            ]

            for targetDir in safeTargets {
                guard fm.fileExists(atPath: targetDir.path) else { continue }
                let standardizedPrefix = targetDir.standardizedFileURL.path + "/"
                let resolvedPrefix = targetDir.resolvingSymlinksInPath().standardizedFileURL.path + "/"

                do {
                    let children = try fm.contentsOfDirectory(
                        at: targetDir,
                        includingPropertiesForKeys: [.isSymbolicLinkKey, .fileSizeKey, .isDirectoryKey],
                        options: []
                    )

                    for child in children {
                        let resolvedChildPath = child.standardizedFileURL.path
                        // Strict path containment check: NEVER delete outside Library/Caches or tmp
                        guard resolvedChildPath.hasPrefix(standardizedPrefix) || resolvedChildPath.hasPrefix(resolvedPrefix) else {
                            skippedCount += 1
                            continue
                        }

                        // Skip symlinks pointing outside container
                        let values = try? child.resourceValues(forKeys: [.isSymbolicLinkKey])
                        if values?.isSymbolicLink == true {
                            let dest = child.resolvingSymlinksInPath().standardizedFileURL.path
                            if !dest.hasPrefix(resolvedPrefix) && !dest.hasPrefix(standardizedPrefix) {
                                skippedCount += 1
                                continue
                            }
                        }

                        let itemSize = Self.calculateDirectoryOrFileSize(at: child, fileManager: fm)
                        do {
                            try fm.removeItem(at: child)
                            removedCount += 1
                            freedBytes += itemSize
                        } catch {
                            skippedCount += 1
                            errors.append("\(child.lastPathComponent): \(error.localizedDescription)")
                        }
                    }
                } catch {
                    errors.append("Không thể duyệt \(targetDir.lastPathComponent): \(error.localizedDescription)")
                }
            }

            if sanitizeSuspiciousPreferences {
                let suspiciousEntries = report.preferenceEntries.filter(\.isSuspicious)
                let groupedByPlist = Dictionary(grouping: suspiciousEntries, by: \.plistURL)

                for (plistURL, entries) in groupedByPlist {
                    do {
                        // Step 1: Mandatory backup of original .plist before modifying
                        let backupRecord = try Self.createPlistBackup(
                            plistURL: plistURL,
                            bundleIdentifier: bundleID,
                            quarantineRoot: quarantineRoot,
                            note: "Auto-backup trước khi khử \(entries.count) khóa theo dõi"
                        )
                        newBackups.append(backupRecord)
                        backedUpCount += 1

                        // Step 2: Load & remove only suspicious tracking/proxy keys
                        let rawData = try Data(contentsOf: plistURL)
                        var format: PropertyListSerialization.PropertyListFormat = .binary
                        if var dict = try PropertyListSerialization.propertyList(
                            from: rawData,
                            options: .mutableContainersAndLeaves,
                            format: &format
                        ) as? [String: Any] {
                            var removedHere = 0
                            for entry in entries where dict[entry.key] != nil {
                                dict.removeValue(forKey: entry.key)
                                removedHere += 1
                            }
                            if removedHere > 0 {
                                let serialized = try PropertyListSerialization.data(
                                    fromPropertyList: dict,
                                    format: format,
                                    options: 0
                                )
                                try serialized.write(to: plistURL, options: .atomic)
                                sanitizedKeysCount += removedHere
                            }
                        }
                    } catch {
                        errors.append("Sao lưu/làm sạch \(plistURL.lastPathComponent): \(error.localizedDescription)")
                    }
                }
            }

            let summary = ContainerCleanupSummary(
                bundleIdentifier: bundleID,
                removedItemsCount: removedCount,
                freedBytes: freedBytes,
                skippedItemsCount: skippedCount,
                backedUpPlistCount: backedUpCount,
                sanitizedPlistKeysCount: sanitizedKeysCount,
                errors: errors,
                completedAt: Date()
            )
            return (summary, newBackups)
        }.value

        if !result.1.isEmpty {
            backups.insert(contentsOf: result.1, at: 0)
            saveBackupManifest()
        }
        lastCleanup = result.0
        _ = await inspectContainer(
            bundleIdentifier: bundleID,
            explicitAppGroupIDs: Array(report.resolvedGroupContainers.keys)
        )
        return result.0
    }

    func backupPlist(at plistURL: URL, bundleIdentifier: String, note: String = "Manual Backup") throws -> PlistBackupRecord {
        let record = try Self.createPlistBackup(
            plistURL: plistURL,
            bundleIdentifier: bundleIdentifier,
            quarantineRoot: Self.quarantineRootURL(),
            note: note
        )
        backups.insert(record, at: 0)
        saveBackupManifest()
        return record
    }

    func restorePlistBackup(_ record: PlistBackupRecord) throws {
        let backupURL = URL(fileURLWithPath: record.backupPath)
        let originalURL = URL(fileURLWithPath: record.originalPath)

        guard fileManager.fileExists(atPath: backupURL.path) else {
            throw NSError(domain: "iShield3105.Quarantine", code: 404, userInfo: [
                NSLocalizedDescriptionKey: "Không tìm thấy tệp sao lưu tại \(backupURL.path)."
            ])
        }

        let data = try Data(contentsOf: backupURL)
        let currentHash = Self.sha256Hex(of: data)
        guard currentHash == record.sha256 else {
            throw NSError(domain: "iShield3105.Quarantine", code: 422, userInfo: [
                NSLocalizedDescriptionKey: "Mã kiểm tra SHA-256 của bản sao lưu không khớp."
            ])
        }

        let parent = originalURL.deletingLastPathComponent()
        if !fileManager.fileExists(atPath: parent.path) {
            try fileManager.createDirectory(at: parent, withIntermediateDirectories: true)
        }
        try data.write(to: originalURL, options: .atomic)
        statusMessage = "Đã khôi phục \(record.originalFileName) cho \(record.bundleIdentifier)."
    }

    // MARK: - Private Directory Scanners & Helpers

    private struct DirectoryScanAccumulator {
        var totalBytes: Int64 = 0
        var fileCount: Int = 0
        var suspiciousFiles: [SuspiciousContainerFile] = []
    }

    private struct PreferenceScanAccumulator {
        var plistCount: Int = 0
        var suspiciousFiles: [SuspiciousContainerFile] = []
        var preferenceEntries: [PreferenceKeyEntry] = []
    }

    nonisolated private static func scanDirectory(
        _ directoryURL: URL,
        containerRoot: URL,
        scopeName: String
    ) -> DirectoryScanAccumulator {
        var acc = DirectoryScanAccumulator()
        let fm = FileManager.default
        guard fm.fileExists(atPath: directoryURL.path) else { return acc }

        let keys: [URLResourceKey] = [.isRegularFileKey, .isDirectoryKey, .isPackageKey, .fileSizeKey, .contentModificationDateKey, .isSymbolicLinkKey]
        guard let enumerator = fm.enumerator(
            at: directoryURL,
            includingPropertiesForKeys: keys,
            options: [.skipsPackageDescendants],
            errorHandler: { _, _ in true }
        ) else {
            return acc
        }

        let rootPrefix = containerRoot.standardizedFileURL.path + "/"

        for case let fileURL as URL in enumerator {
            let values = try? fileURL.resourceValues(forKeys: Set(keys))
            if values?.isSymbolicLink == true { continue }

            let stdPath = fileURL.standardizedFileURL.path
            let relPath = stdPath.hasPrefix(rootPrefix)
                ? String(stdPath.dropFirst(rootPrefix.count))
                : fileURL.lastPathComponent
            let ext = fileURL.pathExtension.lowercased()

            if (values?.isDirectory == true || values?.isPackage == true) {
                if suspiciousBinaryExtensions.contains(ext) {
                    let pkgSize = Self.calculateDirectoryOrFileSize(at: fileURL, fileManager: fm)
                    acc.totalBytes += pkgSize
                    acc.fileCount += 1
                    acc.suspiciousFiles.append(SuspiciousContainerFile(
                        fileURL: fileURL,
                        relativePath: relPath,
                        directoryScope: scopeName,
                        sizeBytes: pkgSize,
                        kind: .foreignDylib,
                        severity: .critical,
                        reason: "Phát hiện gói nhị phân/framework (.\(ext)) nằm trong \(scopeName).",
                        modifiedDate: values?.contentModificationDate
                    ))
                    enumerator.skipDescendants()
                }
                continue
            }

            guard values?.isRegularFile == true else { continue }

            let size = Int64(values?.fileSize ?? 0)
            acc.totalBytes += size
            acc.fileCount += 1

            let lowerName = fileURL.lastPathComponent.lowercased()

            if suspiciousBinaryExtensions.contains(ext) {
                acc.suspiciousFiles.append(SuspiciousContainerFile(
                    fileURL: fileURL,
                    relativePath: relPath,
                    directoryScope: scopeName,
                    sizeBytes: size,
                    kind: .foreignDylib,
                    severity: .critical,
                    reason: "Phát hiện nhị phân/thư viện động (.\(ext)) nằm trong \(scopeName).",
                    modifiedDate: values?.contentModificationDate
                ))
            } else if proxyConfigNameKeywords.contains(where: { lowerName.contains($0) }) {
                acc.suspiciousFiles.append(SuspiciousContainerFile(
                    fileURL: fileURL,
                    relativePath: relPath,
                    directoryScope: scopeName,
                    sizeBytes: size,
                    kind: .proxyConfig,
                    severity: .warning,
                    reason: "Tên tệp trùng mẫu cấu hình Proxy/Tunnel ẩn.",
                    modifiedDate: values?.contentModificationDate
                ))
            } else if trackingPlistNameKeywords.contains(where: { lowerName.contains($0) }) {
                acc.suspiciousFiles.append(SuspiciousContainerFile(
                    fileURL: fileURL,
                    relativePath: relPath,
                    directoryScope: scopeName,
                    sizeBytes: size,
                    kind: .trackingArtifact,
                    severity: .warning,
                    reason: "Tệp lưu dấu vết SDK theo dõi hoặc telemetry.",
                    modifiedDate: values?.contentModificationDate
                ))
            } else if size >= bloatedSingleFileThresholdBytes {
                acc.suspiciousFiles.append(SuspiciousContainerFile(
                    fileURL: fileURL,
                    relativePath: relPath,
                    directoryScope: scopeName,
                    sizeBytes: size,
                    kind: .bloatedCache,
                    severity: .warning,
                    reason: "Dung lượng đơn tệp vượt ngưỡng \(ByteCountFormatter.string(fromByteCount: bloatedSingleFileThresholdBytes, countStyle: .file)).",
                    modifiedDate: values?.contentModificationDate
                ))
            }
        }

        return acc
    }

    nonisolated private static func scanPreferencesDirectory(
        _ prefsURL: URL,
        containerRoot: URL
    ) -> PreferenceScanAccumulator {
        var acc = PreferenceScanAccumulator()
        let fm = FileManager.default
        guard fm.fileExists(atPath: prefsURL.path) else { return acc }

        guard let items = try? fm.contentsOfDirectory(
            at: prefsURL,
            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey, .contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ) else {
            return acc
        }

        let rootPrefix = containerRoot.standardizedFileURL.path + "/"

        for fileURL in items {
            let ext = fileURL.pathExtension.lowercased()
            let lowerName = fileURL.lastPathComponent.lowercased()
            let values = try? fileURL.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey, .contentModificationDateKey])
            let size = Int64(values?.fileSize ?? 0)
            let relPath = fileURL.standardizedFileURL.path.hasPrefix(rootPrefix)
                ? String(fileURL.standardizedFileURL.path.dropFirst(rootPrefix.count))
                : fileURL.lastPathComponent

            if suspiciousBinaryExtensions.contains(ext) {
                acc.suspiciousFiles.append(SuspiciousContainerFile(
                    fileURL: fileURL,
                    relativePath: relPath,
                    directoryScope: "Library/Preferences",
                    sizeBytes: size,
                    kind: .foreignDylib,
                    severity: .critical,
                    reason: "Nhị phân lạ xuất hiện trong Library/Preferences.",
                    modifiedDate: values?.contentModificationDate
                ))
                continue
            }

            guard ext == "plist" else { continue }
            acc.plistCount += 1

            if proxyConfigNameKeywords.contains(where: { lowerName.contains($0) }) {
                acc.suspiciousFiles.append(SuspiciousContainerFile(
                    fileURL: fileURL,
                    relativePath: relPath,
                    directoryScope: "Library/Preferences",
                    sizeBytes: size,
                    kind: .proxyConfig,
                    severity: .warning,
                    reason: "Tệp plist nghi ngờ chứa cấu hình Proxy/Tunnel.",
                    modifiedDate: values?.contentModificationDate
                ))
            } else if trackingPlistNameKeywords.contains(where: { lowerName.contains($0) }) {
                acc.suspiciousFiles.append(SuspiciousContainerFile(
                    fileURL: fileURL,
                    relativePath: relPath,
                    directoryScope: "Library/Preferences",
                    sizeBytes: size,
                    kind: .trackingArtifact,
                    severity: .info,
                    reason: "Tệp plist thuộc SDK phân tích/theo dõi.",
                    modifiedDate: values?.contentModificationDate
                ))
            }

            guard let data = try? Data(contentsOf: fileURL),
                  let rawPlist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
                  let dict = rawPlist as? [String: Any] else {
                continue
            }

            let sortedKeys = dict.keys.sorted()
            for key in sortedKeys {
                let value = dict[key]
                let preview = Self.summarizePlistValue(value)
                let lowerKey = key.lowercased()
                let lowerPreview = preview.lowercased()

                var suspicion: String?
                if let matchedKey = trackingKeyKeywords.first(where: { lowerKey.contains($0) }) {
                    suspicion = "Khóa trùng từ khóa nhạy cảm '\(matchedKey)'."
                } else if lowerPreview.contains("http://") || lowerPreview.contains("socks5://") || lowerPreview.contains("127.0.0.1:") {
                    suspicion = "Giá trị chứa địa chỉ Proxy/Tunnel nội bộ."
                }

                acc.preferenceEntries.append(PreferenceKeyEntry(
                    plistFileName: fileURL.lastPathComponent,
                    plistURL: fileURL,
                    key: key,
                    valuePreview: preview,
                    isSuspicious: suspicion != nil,
                    suspicionReason: suspicion
                ))
            }
        }

        acc.preferenceEntries.sort {
            if $0.isSuspicious != $1.isSuspicious {
                return $0.isSuspicious && !$1.isSuspicious
            }
            return $0.key.localizedCaseInsensitiveCompare($1.key) == .orderedAscending
        }

        return acc
    }

    nonisolated private static func summarizePlistValue(_ value: Any?) -> String {
        guard let value else { return "nil" }
        switch value {
        case let str as String:
            return str.count > 120 ? String(str.prefix(117)) + "..." : str
        case let num as NSNumber:
            if CFGetTypeID(num) == CFBooleanGetTypeID() {
                return num.boolValue ? "true" : "false"
            }
            return num.stringValue
        case let date as Date:
            return ISO8601DateFormatter().string(from: date)
        case let data as Data:
            return "<Data \(data.count) bytes>"
        case let arr as [Any]:
            return "<Array \(arr.count) items>"
        case let dict as [String: Any]:
            return "<Dict \(dict.count) keys>"
        default:
            return String(describing: value)
        }
    }

    nonisolated private static func calculateDirectoryOrFileSize(at url: URL, fileManager: FileManager) -> Int64 {
        let values = try? url.resourceValues(forKeys: [.isDirectoryKey, .fileSizeKey])
        if values?.isDirectory != true {
            return Int64(values?.fileSize ?? 0)
        }
        var total: Int64 = 0
        if let enumerator = fileManager.enumerator(
            at: url,
            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
            options: [],
            errorHandler: { _, _ in true }
        ) {
            for case let child as URL in enumerator {
                let childVals = try? child.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
                if childVals?.isRegularFile == true {
                    total += Int64(childVals?.fileSize ?? 0)
                }
            }
        }
        return total
    }

    nonisolated private static func quarantineRootURL() -> URL {
        let fm = FileManager.default
        let appSupport = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        return appSupport
            .appendingPathComponent("iShield3105", isDirectory: true)
            .appendingPathComponent("Quarantine", isDirectory: true)
    }

    nonisolated private static func createPlistBackup(
        plistURL: URL,
        bundleIdentifier: String,
        quarantineRoot: URL,
        note: String
    ) throws -> PlistBackupRecord {
        let fm = FileManager.default
        let rawData = try Data(contentsOf: plistURL)
        let hash = sha256Hex(of: rawData)

        let timestamp = Int(Date().timeIntervalSince1970)
        let safeBundle = bundleIdentifier.replacingOccurrences(of: "/", with: "_")
        let folder = quarantineRoot
            .appendingPathComponent(safeBundle, isDirectory: true)
            .appendingPathComponent("\(timestamp)-\(UUID().uuidString.prefix(6))", isDirectory: true)
        try fm.createDirectory(at: folder, withIntermediateDirectories: true)

        let destURL = folder.appendingPathComponent(plistURL.lastPathComponent)
        try rawData.write(to: destURL, options: .atomic)

        return PlistBackupRecord(
            id: UUID(),
            bundleIdentifier: bundleIdentifier,
            originalFileName: plistURL.lastPathComponent,
            originalPath: plistURL.path,
            backupPath: destURL.path,
            sha256: hash,
            createdAt: Date(),
            note: note
        )
    }

    nonisolated private static func sha256Hex(of data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func manifestURL() -> URL {
        Self.quarantineRootURL().appendingPathComponent("backups-manifest.json")
    }

    private func loadBackupManifest() {
        let url = manifestURL()
        guard let data = try? Data(contentsOf: url),
              let decoded = try? JSONDecoder().decode([PlistBackupRecord].self, from: data) else {
            backups = []
            return
        }
        backups = decoded.filter { fileManager.fileExists(atPath: $0.backupPath) }
    }

    private func saveBackupManifest() {
        let root = Self.quarantineRootURL()
        try? fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        if let data = try? JSONEncoder().encode(backups) {
            try? data.write(to: manifestURL(), options: .atomic)
        }
    }
}

//
//  SecurityModels.swift
//  iShieldPro
//
//  Domain Models for Threat Detection, Active Defense, Remediation & Prevention Policies
//

import Foundation

enum RiskSeverity: Int, Comparable, Codable, CaseIterable, Sendable {
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

enum AuditCategory: String, CaseIterable, Identifiable, Codable, Sendable {
    case deviceControl = "MDM & Quyền Điều Khiển"
    case runtime = "Runtime & Dylib Injection"
    case network = "Mạng, VPN & Rò Rỉ DNS/IP"
    case container = "Container & Dữ Liệu App"
    case antiSpying = "Chống Nghe Lén, Theo Dõi & Nền"

    var id: String { rawValue }
}

struct SecurityAlertBanner: Identifiable, Hashable, Sendable {
    let id = UUID()
    let category: AuditCategory
    let severity: RiskSeverity
    let title: String
    let detail: String
    let targetTab: Int
}

// MARK: - Active Remediation & Prevention Models

enum RemediationActionKind: String, Codable, Hashable, Sendable {
    case cleanContainer
    case quarantineSuspiciousFiles
    case wipeClipboard
    case stripClipboardTracking
    case installDoHProfile
    case enableAcousticJammer
    case enableMicLock
    case enableContinuousWatchdog
    case openAppSettings
    case guideDisableProxy
    case guideRemoveMDM
    case guideDisableBackgroundRefresh
    case guideRebootDevice
    case guideSetupPasscode
}

struct RemediationTask: Identifiable, Hashable, Sendable {
    let id: String
    let category: AuditCategory
    let severity: RiskSeverity
    let title: String
    let detail: String
    let isResolved: Bool
    let canAutoFix: Bool
    let actionLabel: String
    let actionKind: RemediationActionKind
    let targetTab: Int
}

struct SecurityEventEntry: Identifiable, Codable, Hashable, Sendable {
    let id: UUID
    let timestamp: Date
    let category: AuditCategory
    let severity: RiskSeverity
    let actionTaken: String
    let title: String
    let detail: String

    init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        category: AuditCategory,
        severity: RiskSeverity,
        actionTaken: String,
        title: String,
        detail: String
    ) {
        self.id = id
        self.timestamp = timestamp
        self.category = category
        self.severity = severity
        self.actionTaken = actionTaken
        self.title = title
        self.detail = detail
    }
}

struct ProtectionPolicySettings: Codable, Hashable, Sendable {
    var autoScanOnResume: Bool = true
    var continuousWatchdogEnabled: Bool = true
    var micSentinelEnabled: Bool = true
    var autoSanitizeClipboardOnScan: Bool = false
    var enforceOnDemandDoH: Bool = true
    var maxUptimeDaysBeforeWarning: Int = 7
}

// MARK: - Active Defense (Anti-Eavesdrop, Anti-Tracking & Anti-Background)

struct AudioRouteInputInfo: Identifiable, Hashable, Sendable {
    let id: String
    let portName: String
    let portType: String
    let isBluetooth: Bool
    let isExternalAccessory: Bool
}

struct AudioEavesdropAudit: Hashable, Sendable {
    let auditedAt: Date
    let isOtherAudioPlaying: Bool
    let secondaryAudioSilenced: Bool
    let activeCallDetected: Bool
    let activeCallsSummary: String
    let activeInputs: [AudioRouteInputInfo]
    let availableInputs: [AudioRouteInputInfo]
    let externalCaptureDevices: [String]
    let micPermissionLabel: String
    let bluetoothMicConnected: Bool
    let isAcousticJammerActive: Bool
    let isMicLockActive: Bool
    let audioRiskLevel: RiskSeverity
    let lastEventSummary: String
}

struct ClipboardScanResult: Hashable, Sendable {
    let scannedAt: Date
    let hasContent: Bool
    let detectedSensitivePatterns: [String]
    let detectedTrackingParams: [String]
    let originalPreview: String?
    let sanitizedText: String?
    let wasCleaned: Bool
    let statusNote: String
}

struct PhotoPrivacyStripResult: Identifiable, Hashable, Sendable {
    let id = UUID()
    let originalFileName: String
    let removedTags: [String]
    let originalBytes: Int
    let cleanedBytes: Int
    let cleanedFileURL: URL
    let strippedAt: Date
}

struct InterfaceTrafficRate: Identifiable, Hashable, Sendable {
    let id: String
    let interfaceName: String
    let category: NetworkInterfaceCategory
    let totalRxBytes: UInt64
    let totalTxBytes: UInt64
    let rxBytesPerSec: Double
    let txBytesPerSec: Double
    let isBackgroundSpikeSuspected: Bool
}

struct BackgroundGuardSnapshot: Hashable, Sendable {
    let sampledAt: Date
    let backgroundRefreshStatusLabel: String
    let backgroundRefreshEnabled: Bool
    let thermalStateLabel: String
    let thermalElevated: Bool
    let isLowPowerMode: Bool
    let uptimeHours: Double
    let needsRebootRecommended: Bool
    let residentMemoryBytes: UInt64
    let activeThreadCount: Int
    let passcodeOrBiometricEnabled: Bool
    let attStatusLabel: String
    let idfaExposed: Bool
    let trafficRates: [InterfaceTrafficRate]
    let backgroundSpikeAlert: String?
}

// MARK: - Container Inspector & Quarantine Models

struct InstalledAppItem: Identifiable, Hashable, Sendable {
    let id: String
    let bundleIdentifier: String
    let displayName: String
    let applicationType: String
    let shortVersion: String?
    let bundleURL: URL?
    let dataContainerURL: URL?
    let groupContainerURLs: [String: URL]
    let pluginIdentifiers: [String]
    let signerIdentity: String?

    init(
        bundleIdentifier: String,
        displayName: String,
        applicationType: String,
        shortVersion: String? = nil,
        bundleURL: URL? = nil,
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
        self.bundleURL = bundleURL
        self.dataContainerURL = dataContainerURL
        self.groupContainerURLs = groupContainerURLs
        self.pluginIdentifiers = pluginIdentifiers
        self.signerIdentity = signerIdentity
    }
}

enum SuspiciousFileKind: String, CaseIterable, Codable, Sendable {
    case foreignDylib = "Thư viện .dylib / Binary lạ"
    case proxyConfig = "Cấu hình Proxy / Tunnel"
    case trackingArtifact = "Tệp theo dõi / Fingerprint"
    case bloatedCache = "Dữ liệu đệm phình to bất thường"
}

struct SuspiciousContainerFile: Identifiable, Hashable, Sendable {
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

struct PreferenceKeyEntry: Identifiable, Hashable, Sendable {
    let id = UUID()
    let plistFileName: String
    let plistURL: URL
    let key: String
    let valuePreview: String
    let isSuspicious: Bool
    let suspicionReason: String?
}

struct PlistBackupRecord: Identifiable, Codable, Hashable, Sendable {
    let id: UUID
    let bundleIdentifier: String
    let originalFileName: String
    let originalPath: String
    let backupPath: String
    let sha256: String
    let createdAt: Date
    let note: String
}

struct QuarantinedArtifactRecord: Identifiable, Codable, Hashable, Sendable {
    let id: UUID
    let bundleIdentifier: String
    let fileName: String
    let originalPath: String
    let quarantinePath: String
    let sizeBytes: Int64
    let kind: SuspiciousFileKind
    let sha256: String
    let quarantinedAt: Date
    let reason: String
}

struct ContainerInspectionReport: Identifiable, Sendable {
    let id = UUID()
    let bundleIdentifier: String
    let dataContainerURL: URL?
    let dataContainerExisted: Bool
    let dataContainerReadable: Bool
    let sandboxTokenConsumed: Bool
    let dataContainerError: String?
    let resolvedGroupContainers: [String: URL]
    let resolvedPluginContainers: [String: URL]
    let backgroundModesDetected: [String]
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

struct ContainerCleanupSummary: Identifiable, Sendable {
    let id = UUID()
    let bundleIdentifier: String
    let removedItemsCount: Int
    let freedBytes: Int64
    let skippedItemsCount: Int
    let backedUpPlistCount: Int
    let sanitizedPlistKeysCount: Int
    let quarantinedFilesCount: Int
    let errors: [String]
    let completedAt: Date
}

struct BatchContainerRemediationSummary: Identifiable, Sendable {
    let id = UUID()
    let scannedAppsCount: Int
    let accessibleAppsCount: Int
    let cleanedAppsCount: Int
    let totalFreedBytes: Int64
    let totalQuarantinedFiles: Int
    let totalSanitizedPlistKeys: Int
    let completedAt: Date
}

// MARK: - Device Control, MDM, MitM & Runtime Security Models

struct MDMProfileIndicator: Identifiable, Hashable, Sendable {
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

struct ProxyConfigurationReport: Hashable, Sendable {
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

struct TLSChainAuditReport: Identifiable, Hashable, Sendable {
    let id = UUID()
    let targetHost: String
    let trustEvaluatedValid: Bool
    let evaluationError: String?
    let certificateSubjects: [String]
    let suspectedMitMAuthority: String?
    let auditedAt: Date
}

struct LoadedDylibReport: Identifiable, Hashable, Sendable {
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

struct LocalPortProbeResult: Identifiable, Hashable, Sendable {
    let id = UUID()
    let port: UInt16
    let serviceName: String
    let description: String
    let isOpen: Bool
    let severityIfOpen: RiskSeverity
}

struct ProvisioningAuditInfo: Hashable, Sendable {
    let hasEmbeddedProvision: Bool
    let teamName: String?
    let appIDName: String?
    let provisionsAllDevices: Bool
    let expirationDate: Date?
    let parsedEntitlements: [String: String]
}

struct SecurityAuditReport: Sendable {
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

enum NetworkInterfaceCategory: String, Hashable, Codable, Sendable {
    case wifi = "Wi-Fi"
    case cellular = "Di động (Cellular)"
    case virtualTunnel = "Đường hầm ảo (VPN/Tunnel)"
    case loopback = "Loopback"
    case awdl = "Apple Wireless Direct"
    case other = "Khác"
}

struct NetworkInterfaceItem: Identifiable, Hashable, Sendable {
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

struct DNSServerAuditItem: Identifiable, Hashable, Sendable {
    let id = UUID()
    let address: String
    let providerName: String
    let isTrustedKnownDNS: Bool
    let isPrivateLAN: Bool
    let riskLevel: RiskSeverity
    let note: String
}

struct PublicIPInfoReport: Hashable, Sendable {
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

struct NetworkPrivacyReport: Sendable {
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

enum DoHProviderOption: String, CaseIterable, Identifiable, Sendable {
    case adguardTracking = "AdGuard DNS Chặn Theo Dõi & Gián Điệp"
    case controlDPrivacy = "Control D Chặn Quảng Cáo + Telemetry + Mã Độc"
    case cloudflareSecurity = "Cloudflare Malware Block (1.1.1.2)"
    case quad9Recommended = "Quad9 Threat Intelligence (dns.quad9.net)"
    case cloudflareStandard = "Cloudflare Speed Privacy (1.1.1.1)"

    var id: String { rawValue }

    var serverURL: String {
        switch self {
        case .adguardTracking:
            return "https://dns.adguard-dns.com/dns-query"
        case .controlDPrivacy:
            return "https://freedns.controld.com/p2"
        case .cloudflareSecurity:
            return "https://security.cloudflare-dns.com/dns-query"
        case .quad9Recommended:
            return "https://dns.quad9.net/dns-query"
        case .cloudflareStandard:
            return "https://cloudflare-dns.com/dns-query"
        }
    }

    var serverAddresses: [String] {
        switch self {
        case .adguardTracking:
            return ["94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"]
        case .controlDPrivacy:
            return ["76.76.2.2", "76.76.10.2", "2606:1a40::2", "2606:1a40:1::2"]
        case .cloudflareSecurity:
            return ["1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002"]
        case .quad9Recommended:
            return ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"]
        case .cloudflareStandard:
            return ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"]
        }
    }

    var description: String {
        switch self {
        case .adguardTracking:
            return "Chặn SDK theo dõi, analytics chạy ngầm, quảng cáo và domain spyware ở tầng DNS."
        case .controlDPrivacy:
            return "Lọc đa tầng DNS: chặn tên miền độc hại, phishing, quảng cáo và beacon theo dõi."
        case .cloudflareSecurity:
            return "Tự động chặn tên miền chứa mã độc, lừa đảo và C2 botnet."
        case .quad9Recommended:
            return "Chặn mã độc theo dữ liệu tình báo mối đe dọa đa nguồn, không lưu log IP."
        case .cloudflareStandard:
            return "DNS-over-HTTPS tốc độ cao, mã hóa truy vấn chống ISP nghe lén DNS."
        }
    }
}

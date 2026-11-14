//
//  SecurityDashboardCoordinator.swift
//  iShieldPro
//
//  Central Orchestrator for Detection, 1-Tap Remediation, Prevention Policies & Audit Timeline
//

import Foundation
import SwiftUI
import UIKit

@MainActor
final class SecurityDashboardCoordinator: ObservableObject {
    @Published var selectedTab: Int = 0
    @Published var targetBundleID: String
    @Published var explicitAppGroupID: String = ""

    @Published private(set) var isDeepScanning = false
    @Published private(set) var isApplyingAutoFix = false
    @Published private(set) var lastDeepScanDate: Date?
    @Published private(set) var lastAutoFixMessage: String?
    @Published private(set) var securityScore: Int = 100
    @Published private(set) var overallSeverity: RiskSeverity = .info
    @Published private(set) var alerts: [SecurityAlertBanner] = []
    @Published private(set) var remediationTasks: [RemediationTask] = []
    @Published private(set) var eventLog: [SecurityEventEntry] = []

    @Published var policy: ProtectionPolicySettings {
        didSet {
            savePolicy()
            activeDefense.setContinuousWatchdog(enabled: policy.continuousWatchdogEnabled)
        }
    }

    let containerManager = ContainerManager()
    let auditEngine = SecurityAuditEngine()
    let networkScanner = NetworkPrivacyScanner()
    let dohManager = DoHProfileManager()
    let activeDefense = ActiveDefenseEngine()

    private static let policyStorageKey = "com.ishield.pro.protectionPolicy.v2"
    private static let eventLogStorageKey = "com.ishield.pro.securityEventLog.v2"

    init() {
        self.targetBundleID = Bundle.main.bundleIdentifier ?? "com.apple.mobile.MobileHouseArrest"

        if let data = UserDefaults.standard.data(forKey: Self.policyStorageKey),
           let decoded = try? JSONDecoder().decode(ProtectionPolicySettings.self, from: data) {
            self.policy = decoded
        } else {
            self.policy = ProtectionPolicySettings()
        }

        if let data = UserDefaults.standard.data(forKey: Self.eventLogStorageKey),
           let decoded = try? JSONDecoder().decode([SecurityEventEntry].self, from: data) {
            self.eventLog = decoded
        }

        activeDefense.onThreatDetected = { [weak self] entry in
            self?.appendEvent(entry)
        }
        activeDefense.setContinuousWatchdog(enabled: policy.continuousWatchdogEnabled)
    }

    // MARK: - Full Concurrent Scan

    func runDeepScan() async {
        guard !isDeepScanning else { return }
        isDeepScanning = true
        defer { isDeepScanning = false }

        let activeBundleID = targetBundleID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? (Bundle.main.bundleIdentifier ?? "com.apple.mobile.MobileHouseArrest")
            : targetBundleID.trimmingCharacters(in: .whitespacesAndNewlines)

        let groupIDs = explicitAppGroupID
            .split(separator: ",")
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        await containerManager.refreshInstalledApps()
        async let containerTask = containerManager.inspectContainer(
            bundleIdentifier: activeBundleID,
            explicitAppGroupIDs: groupIDs
        )
        async let auditTask = auditEngine.runFullAudit()
        async let networkTask = networkScanner.runScan()

        let containerReport = await containerTask
        let auditReport = await auditTask
        let networkReport = await networkTask

        activeDefense.refreshAudioAudit()
        activeDefense.sampleBackgroundAndTrafficGuard(maxUptimeDaysWarning: policy.maxUptimeDaysBeforeWarning)
        if policy.autoSanitizeClipboardOnScan {
            activeDefense.scanAndCleanClipboard(autoCleanTrackers: true)
        }

        recomputeScoreAndAlerts(
            container: containerReport,
            audit: auditReport,
            network: networkReport
        )
        lastDeepScanDate = Date()
        appendEvent(SecurityEventEntry(
            category: .deviceControl,
            severity: overallSeverity,
            actionTaken: "Quét toàn diện",
            title: "Hoàn tất rà soát 5 lớp hệ thống",
            detail: "Điểm an toàn: \(securityScore)/100 • Phát hiện \(alerts.count) cảnh báo."
        ))
    }

    func handleSceneDidBecomeActive() async {
        activeDefense.refreshAudioAudit()
        activeDefense.sampleBackgroundAndTrafficGuard(maxUptimeDaysWarning: policy.maxUptimeDaysBeforeWarning)
        activeDefense.setContinuousWatchdog(enabled: policy.continuousWatchdogEnabled)

        if policy.autoScanOnResume {
            let shouldRescan: Bool
            if let last = lastDeepScanDate {
                shouldRescan = Date().timeIntervalSince(last) > 20
            } else {
                shouldRescan = true
            }
            if shouldRescan && !isDeepScanning {
                await runDeepScan()
                return
            }
        }
        syncScoreFromCurrentReports()
    }

    func syncScoreFromCurrentReports() {
        recomputeScoreAndAlerts(
            container: containerManager.lastInspection,
            audit: auditEngine.lastReport,
            network: networkScanner.lastReport
        )
        if lastDeepScanDate == nil {
            lastDeepScanDate = Date()
        }
    }

    // MARK: - 1-Tap Automated Remediation & Task Executor

    func runOneTapAutoFix() async -> String {
        guard !isApplyingAutoFix else { return "Đang xử lý các tác vụ bảo vệ..." }
        isApplyingAutoFix = true
        defer { isApplyingAutoFix = false }

        var actionsDone: [String] = []

        // 1. Ensure Deep Scan data is fresh before fixing
        if containerManager.lastInspection == nil || auditEngine.lastReport == nil || networkScanner.lastReport == nil {
            await runDeepScan()
        }

        // 2. Clean & Quarantine active inspected container + sanitize suspicious .plist tracking keys
        if let inspection = containerManager.lastInspection {
            let summary = await containerManager.cleanTrackingCaches(
                for: inspection,
                sanitizeSuspiciousPreferences: true,
                quarantineCriticalArtifacts: true
            )
            if summary.removedItemsCount > 0 || summary.sanitizedPlistKeysCount > 0 || summary.quarantinedFilesCount > 0 {
                let freedStr = ByteCountFormatter.string(fromByteCount: summary.freedBytes, countStyle: .file)
                actionsDone.append("Dọn container \(inspection.bundleIdentifier): xóa \(summary.removedItemsCount) cache/tmp (\(freedStr)), cách ly \(summary.quarantinedFilesCount) tệp, khử \(summary.sanitizedPlistKeysCount) khóa .plist")
            }
        }

        // 3. Batch clean any other accessible containers discovered by MobileContainerManager
        let batchSummary = await containerManager.batchInspectAndRemediateAllAccessible(cleanAndSanitize: true)
        if batchSummary.cleanedAppsCount > 0 {
            let freedStr = ByteCountFormatter.string(fromByteCount: batchSummary.totalFreedBytes, countStyle: .file)
            actionsDone.append("Quét sâu \(batchSummary.accessibleAppsCount) app khả dụng: xử lý \(batchSummary.cleanedAppsCount) app (giải phóng \(freedStr), cách ly \(batchSummary.totalQuarantinedFiles) tệp)")
        }

        // 4. Scrub tracking links or wipe sensitive patterns in Clipboard
        activeDefense.scanAndCleanClipboard(autoCleanTrackers: true)
        if let clip = activeDefense.lastClipboardScan, !clip.detectedSensitivePatterns.isEmpty {
            activeDefense.wipeClipboardCompletely()
            actionsDone.append("Xóa trắng Clipboard chứa dữ liệu nhạy cảm")
        } else if let clip = activeDefense.lastClipboardScan, clip.wasCleaned {
            actionsDone.append("Gỡ tham số theo dõi trong link Clipboard")
        }

        // 5. Enable continuous anti-background watchdog & anti-eavesdrop guard if audio risk active
        if !policy.continuousWatchdogEnabled {
            policy.continuousWatchdogEnabled = true
            actionsDone.append("Bật Watchdog giám sát chạy ngầm & lưu lượng bất thường")
        }
        if let audio = activeDefense.audioAudit,
           audio.audioRiskLevel >= .warning,
           !activeDefense.isAcousticJammerActive,
           !activeDefense.isMicLockActive {
            activeDefense.toggleAcousticJammer()
            actionsDone.append("Kích hoạt nhiễu bảo vệ chống nghe lén âm thanh")
        }

        // 6. Refresh audit state & recompute score
        activeDefense.refreshAudioAudit()
        activeDefense.sampleBackgroundAndTrafficGuard(maxUptimeDaysWarning: policy.maxUptimeDaysBeforeWarning)
        syncScoreFromCurrentReports()

        let pendingManual = remediationTasks.filter { !$0.isResolved && !$0.canAutoFix }.count
        let resultMsg: String
        if actionsDone.isEmpty {
            resultMsg = pendingManual > 0
                ? "Không có rác/theo dõi nội bộ nào cần dọn thêm. Còn \(pendingManual) mục cấp hệ điều hành iOS cần bạn xác nhận trong Cài đặt bên dưới."
                : "Hệ thống đã được tối ưu sạch sẽ. Watchdog phòng ngừa đang hoạt động liên tục."
        } else {
            let joined = actionsDone.joined(separator: " • ")
            resultMsg = pendingManual > 0
                ? "Đã tự động xử lý: \(joined). Lưu ý: còn \(pendingManual) mục cấp hệ thống iOS cần 1 chạm mở Cài đặt để tắt/cài DoH."
                : "Đã xử lý toàn bộ mối nguy tự động: \(joined)."
        }

        lastAutoFixMessage = resultMsg
        appendEvent(SecurityEventEntry(
            category: .antiSpying,
            severity: .safe,
            actionTaken: "Tự động khắc phục 1 chạm",
            title: "Chạy quy trình Xử lý & Phòng ngừa tổng lực",
            detail: resultMsg
        ))
        return resultMsg
    }

    func executeRemediationTask(_ task: RemediationTask) async {
        switch task.actionKind {
        case .cleanContainer, .quarantineSuspiciousFiles:
            if let inspection = containerManager.lastInspection {
                let sum = await containerManager.cleanTrackingCaches(
                    for: inspection,
                    sanitizeSuspiciousPreferences: true,
                    quarantineCriticalArtifacts: true
                )
                lastAutoFixMessage = "Đã xử lý \(inspection.bundleIdentifier): xóa \(sum.removedItemsCount) tệp tạm, cách ly \(sum.quarantinedFilesCount) tệp nghi ngờ, khử \(sum.sanitizedPlistKeysCount) khóa .plist."
            } else {
                selectedTab = 2
            }
        case .wipeClipboard:
            activeDefense.wipeClipboardCompletely()
            lastAutoFixMessage = "Đã xóa trắng toàn bộ Clipboard."
        case .stripClipboardTracking:
            activeDefense.scanAndCleanClipboard(autoCleanTrackers: true)
            lastAutoFixMessage = activeDefense.lastClipboardScan?.statusNote ?? "Đã kiểm tra Clipboard."
        case .installDoHProfile:
            dohManager.installViaLocalSafari(
                for: .adguardTracking,
                enforceOnDemand: policy.enforceOnDemandDoH
            )
            lastAutoFixMessage = "Đang mở Safari cài đặt DNS Shield AdGuard chống tracker."
        case .enableAcousticJammer:
            if !activeDefense.isAcousticJammerActive {
                activeDefense.toggleAcousticJammer()
            }
            lastAutoFixMessage = "Đã bật bộ phát nhiễu chống nghe lén micro."
        case .enableMicLock:
            await activeDefense.toggleMicPreemptionLock()
            lastAutoFixMessage = activeDefense.statusMessage
        case .enableContinuousWatchdog:
            policy.continuousWatchdogEnabled = true
            lastAutoFixMessage = "Đã kích hoạt Watchdog bảo vệ chạy ngầm 24/7."
        case .openAppSettings, .guideDisableBackgroundRefresh, .guideDisableProxy, .guideRemoveMDM, .guideSetupPasscode:
            openIOSSettings()
            selectedTab = task.targetTab
        case .guideRebootDevice:
            selectedTab = task.targetTab
            lastAutoFixMessage = "Hãy khởi động lại iPhone (Tắt nguồn hoàn toàn -> Bật lại) để xóa sạch tiến trình gián điệp lưu trong RAM."
        }
        syncScoreFromCurrentReports()
    }

    func openIOSSettings() {
        if let url = URL(string: UIApplication.openSettingsURLString) {
            UIApplication.shared.open(url)
        }
    }

    func clearEventLog() {
        eventLog = []
        UserDefaults.standard.removeObject(forKey: Self.eventLogStorageKey)
    }

    func appendEvent(_ entry: SecurityEventEntry) {
        eventLog.insert(entry, at: 0)
        if eventLog.count > 100 {
            eventLog = Array(eventLog.prefix(100))
        }
        if let data = try? JSONEncoder().encode(eventLog) {
            UserDefaults.standard.set(data, forKey: Self.eventLogStorageKey)
        }
    }

    private func savePolicy() {
        if let data = try? JSONEncoder().encode(policy) {
            UserDefaults.standard.set(data, forKey: Self.policyStorageKey)
        }
    }

    // MARK: - Scoring, Alerts & Remediation Plan Builder

    func recomputeScoreAndAlerts(
        container: ContainerInspectionReport?,
        audit: SecurityAuditReport?,
        network: NetworkPrivacyReport?
    ) {
        var score = 100
        var newAlerts: [SecurityAlertBanner] = []
        var tasks: [RemediationTask] = []

        // 1. MDM / Supervision / MitM / Runtime Dylib / Ports (Target Tab 4: Device Control)
        if let audit {
            if audit.isSupervisedDetected {
                score -= 30
                newAlerts.append(SecurityAlertBanner(
                    category: .deviceControl,
                    severity: .critical,
                    title: "Thiết bị đang ở chế độ Giám sát (Supervised)",
                    detail: "Phát hiện cờ IsSupervised từ hồ sơ hệ thống — tổ chức quản lý có thể kiểm soát sâu thiết bị.",
                    targetTab: 4
                ))
                tasks.append(RemediationTask(
                    id: "task-supervised",
                    category: .deviceControl,
                    severity: .critical,
                    title: "Gỡ quyền Giám sát thiết bị (Supervised / MDM)",
                    detail: "Mở Cài đặt > Cài đặt chung > Quản lý VPN & Thiết bị để xóa profile. Nếu profile bị khóa không cho xóa, cần sao lưu thủ công và DFU Restore.",
                    isResolved: false,
                    canAutoFix: false,
                    actionLabel: "Mở Cài đặt",
                    actionKind: .guideRemoveMDM,
                    targetTab: 4
                ))
            }

            if audit.isMDMDetected {
                score -= 25
                let org = audit.mdmIndicators.compactMap(\.organizationName).first ?? "Không rõ tổ chức"
                newAlerts.append(SecurityAlertBanner(
                    category: .deviceControl,
                    severity: .critical,
                    title: "Phát hiện cấu hình quản lý từ xa (MDM)",
                    detail: "Thiết bị có dấu hiệu chịu quản lý MDM (\(org)). Cần kiểm tra Hồ sơ & Quản lý thiết bị.",
                    targetTab: 4
                ))
                tasks.append(RemediationTask(
                    id: "task-mdm",
                    category: .deviceControl,
                    severity: .critical,
                    title: "Xóa hồ sơ quản lý MDM (\(org))",
                    detail: "Vào Cài đặt > Cài đặt chung > Quản lý VPN & Thiết bị -> Xóa ngay cấu hình quản lý lạ.",
                    isResolved: false,
                    canAutoFix: false,
                    actionLabel: "Kiểm tra & Gỡ",
                    actionKind: .guideRemoveMDM,
                    targetTab: 4
                ))
            }

            if !audit.suspiciousDylibs.isEmpty {
                score -= min(35, audit.suspiciousDylibs.count * 20)
                let names = audit.suspiciousDylibs.prefix(3).map(\.name).joined(separator: ", ")
                newAlerts.append(SecurityAlertBanner(
                    category: .runtime,
                    severity: .critical,
                    title: "Phát hiện \(audit.suspiciousDylibs.count) thư viện .dylib đáng ngờ đang nạp",
                    detail: "Thư viện ngoài luồng hệ thống / nghi hook: \(names)",
                    targetTab: 4
                ))
                tasks.append(RemediationTask(
                    id: "task-dylib",
                    category: .runtime,
                    severity: .critical,
                    title: "Khởi động lại máy để xóa hook dylib khỏi bộ nhớ",
                    detail: "Xóa ứng dụng sideload không rõ nguồn gốc và tắt nguồn mở lại iPhone để dọn RAM.",
                    isResolved: false,
                    canAutoFix: false,
                    actionLabel: "Hướng dẫn xử lý",
                    actionKind: .guideRebootDevice,
                    targetTab: 4
                ))
            }

            if audit.debuggerAttached {
                score -= 15
                newAlerts.append(SecurityAlertBanner(
                    category: .runtime,
                    severity: .warning,
                    title: "Tiến trình đang bị gắn Debugger (P_TRACED)",
                    detail: "Phát hiện cờ debug đang gắn trên tiến trình iShield Pro.",
                    targetTab: 4
                ))
            }

            let openCriticalPorts = audit.openDangerousPorts.filter { $0.severityIfOpen >= .warning }
            if !openCriticalPorts.isEmpty {
                score -= min(30, openCriticalPorts.count * 15)
                let portList = openCriticalPorts.map { "\($0.port) (\($0.serviceName))" }.joined(separator: ", ")
                newAlerts.append(SecurityAlertBanner(
                    category: .runtime,
                    severity: .critical,
                    title: "Phát hiện cổng Backdoor nội bộ đang mở",
                    detail: "Loopback 127.0.0.1 đang lắng nghe tại cổng: \(portList)",
                    targetTab: 4
                ))
                tasks.append(RemediationTask(
                    id: "task-ports",
                    category: .runtime,
                    severity: .critical,
                    title: "Ngắt dịch vụ lắng nghe cổng nội bộ (\(portList))",
                    detail: "Tắt ngay các app proxy/debug nền, thu hồi chứng chỉ lạ và khởi động lại iPhone.",
                    isResolved: false,
                    canAutoFix: false,
                    actionLabel: "Xem chi tiết",
                    actionKind: .guideRebootDevice,
                    targetTab: 4
                ))
            }

            if audit.hasMitMRisk {
                score -= 20
                var reasons: [String] = []
                if audit.proxyReport.hasActiveProxy { reasons.append("Global/Scoped Proxy đang bật") }
                if let mitmCA = audit.tlsChainAudits.compactMap(\.suspectedMitMAuthority).first {
                    reasons.append("Chứng chỉ MitM (\(mitmCA))")
                }
                if audit.tlsChainAudits.contains(where: { !$0.trustEvaluatedValid }) {
                    reasons.append("TLS Trust Verification thất bại")
                }
                newAlerts.append(SecurityAlertBanner(
                    category: .deviceControl,
                    severity: .critical,
                    title: "Nguy cơ chặn bắt lưu lượng TLS / MitM",
                    detail: reasons.isEmpty ? "Phát hiện bất thường ở chuỗi chứng chỉ hoặc TrustStore." : reasons.joined(separator: " • "),
                    targetTab: 4
                ))
                tasks.append(RemediationTask(
                    id: "task-mitm-proxy",
                    category: .deviceControl,
                    severity: .critical,
                    title: "Tắt Proxy Wi-Fi & Thu hồi chứng chỉ CA MitM",
                    detail: "Vào Cài đặt > Wi-Fi > Định cấu hình Proxy -> Tắt; và Cài đặt chung > Giới thiệu > Cài đặt tin cậy chứng nhận -> Tắt CA lạ.",
                    isResolved: false,
                    canAutoFix: false,
                    actionLabel: "Mở Cài đặt",
                    actionKind: .guideDisableProxy,
                    targetTab: 4
                ))
            }
        }

        // 2. Network / Tunnel / DNS / Public IP (Target Tab 3: Network Shield)
        if let network {
            if !network.suspiciousTunnels.isEmpty {
                score -= 20
                let names = network.suspiciousTunnels.map(\.name).joined(separator: ", ")
                newAlerts.append(SecurityAlertBanner(
                    category: .network,
                    severity: .critical,
                    title: "Phát hiện Tunnel mạng ngầm đang hoạt động (\(names))",
                    detail: "Nếu bạn không bật VPN, lưu lượng mạng có thể đang bị định tuyến qua ứng dụng hoặc cấu hình ẩn.",
                    targetTab: 3
                ))
                tasks.append(RemediationTask(
                    id: "task-hidden-tunnel",
                    category: .network,
                    severity: .critical,
                    title: "Kiểm tra & ngắt Tunnel mạng ngầm (\(names))",
                    detail: "Vào Cài đặt > VPN & Quản lý thiết bị để xóa cấu hình VPN lạ không do bạn chủ động bật.",
                    isResolved: false,
                    canAutoFix: false,
                    actionLabel: "Mở Cài đặt",
                    actionKind: .openAppSettings,
                    targetTab: 3
                ))
            }

            let usingProtectedDoH = network.dnsServers.contains(where: \.isTrustedKnownDNS)
            if network.dnsHijackSuspected || !usingProtectedDoH {
                if network.dnsHijackSuspected { score -= 15 }
                let suspiciousDNS = network.dnsServers.filter { $0.riskLevel >= .warning }.map(\.address).joined(separator: ", ")
                if network.dnsHijackSuspected {
                    newAlerts.append(SecurityAlertBanner(
                        category: .network,
                        severity: .warning,
                        title: "Máy chủ DNS có dấu hiệu bất thường",
                        detail: "Phát hiện DNS ngoài danh sách tin cậy: \(suspiciousDNS). Khuyến nghị cài DNS Shield DoH.",
                        targetTab: 3
                    ))
                }
                tasks.append(RemediationTask(
                    id: "task-doh-shield",
                    category: .network,
                    severity: network.dnsHijackSuspected ? .warning : .info,
                    title: "Kích hoạt Lá chắn DNS-over-HTTPS chặn theo dõi",
                    detail: "Cài hồ sơ AdGuard / Control D DoH có On-Demand để mã hóa DNS và chặn domain tracker hệ thống.",
                    isResolved: usingProtectedDoH && !network.dnsHijackSuspected,
                    canAutoFix: true,
                    actionLabel: "Cài DoH Shield",
                    actionKind: .installDoHProfile,
                    targetTab: 3
                ))
            }

            if let ip = network.publicIP {
                if !ip.leakedHeaders.isEmpty {
                    score -= 10
                    newAlerts.append(SecurityAlertBanner(
                        category: .network,
                        severity: .warning,
                        title: "Rò rỉ HTTP Proxy Headers",
                        detail: "Header rò rỉ: \(ip.leakedHeaders.keys.sorted().joined(separator: ", "))",
                        targetTab: 3
                    ))
                }
                if ip.isRealIPExposed {
                    score -= 8
                    newAlerts.append(SecurityAlertBanner(
                        category: .network,
                        severity: .warning,
                        title: "IP Public thực đang lộ trực tiếp (\(ip.ip))",
                        detail: "Nhà mạng/ISP: \(ip.org ?? "Không rõ") (\(ip.city ?? ""), \(ip.country ?? "")). Chưa phát hiện lớp ẩn danh VPN.",
                        targetTab: 3
                    ))
                }
            }
        }

        // 3. Container Threats (Target Tab 2: Container Inspector)
        if let container {
            let criticalFiles = container.suspiciousFiles.filter { $0.severity == .critical }
            let warningFiles = container.suspiciousFiles.filter { $0.severity == .warning }
            let suspiciousPrefs = container.preferenceEntries.filter(\.isSuspicious).count

            if !criticalFiles.isEmpty {
                score -= min(25, criticalFiles.count * 15)
                newAlerts.append(SecurityAlertBanner(
                    category: .container,
                    severity: .critical,
                    title: "Container \(container.bundleIdentifier) chứa nhị phân lạ",
                    detail: "Tìm thấy \(criticalFiles.count) tệp .dylib / binary đáng ngờ bên trong vùng dữ liệu ứng dụng.",
                    targetTab: 2
                ))
            } else if !warningFiles.isEmpty || suspiciousPrefs > 0 {
                score -= min(10, max(3, warningFiles.count * 3 + (suspiciousPrefs > 0 ? 3 : 0)))
                newAlerts.append(SecurityAlertBanner(
                    category: .container,
                    severity: .warning,
                    title: "Phát hiện dấu vết theo dõi / cấu hình .plist nghi ngờ",
                    detail: "\(warningFiles.count) tệp nghi ngờ • \(suspiciousPrefs) khóa .plist theo dõi trong \(container.bundleIdentifier).",
                    targetTab: 2
                ))
            }

            if !container.suspiciousFiles.isEmpty || suspiciousPrefs > 0 || container.totalCleanableBytes > 10 * 1024 * 1024 {
                tasks.append(RemediationTask(
                    id: "task-clean-container",
                    category: .container,
                    severity: !criticalFiles.isEmpty ? .critical : .warning,
                    title: "Cách ly tệp lạ & Dọn sạch cache theo dõi (\(container.bundleIdentifier))",
                    detail: "Cách ly file nghi ngờ, xóa cache/tmp (\(ByteCountFormatter.string(fromByteCount: container.totalCleanableBytes, countStyle: .file))) và khử \(suspiciousPrefs) khóa .plist (có backup SHA-256).",
                    isResolved: false,
                    canAutoFix: true,
                    actionLabel: "Xử lý ngay",
                    actionKind: .cleanContainer,
                    targetTab: 2
                ))
            }
        }

        // 4. Anti-Eavesdropping, Anti-Tracking & Anti-Background (Target Tab 1: Active Defense)
        if let audio = activeDefense.audioAudit {
            if audio.activeCallDetected && !activeDefense.isMicLockActive {
                score -= 15
                newAlerts.append(SecurityAlertBanner(
                    category: .antiSpying,
                    severity: .critical,
                    title: "Phát hiện cuộc gọi / VoIP nền đang kích hoạt micro",
                    detail: audio.activeCallsSummary,
                    targetTab: 1
                ))
                tasks.append(RemediationTask(
                    id: "task-audio-jammer",
                    category: .antiSpying,
                    severity: .critical,
                    title: "Bật Khóa Micro hoặc Phát nhiễu chống nghe lén",
                    detail: "Chiếm giữ AudioSession độc quyền hoặc phát nhiễu âm thanh dải giọng nói để ngăn nghe lén.",
                    isResolved: false,
                    canAutoFix: true,
                    actionLabel: "Bật Lá Chắn",
                    actionKind: .enableAcousticJammer,
                    targetTab: 1
                ))
            } else if (audio.bluetoothMicConnected || audio.isOtherAudioPlaying) && !activeDefense.isMicLockActive && !activeDefense.isAcousticJammerActive {
                score -= 5
                tasks.append(RemediationTask(
                    id: "task-bt-mic",
                    category: .antiSpying,
                    severity: .warning,
                    title: "Kiểm tra tuyến micro Bluetooth / Âm thanh nền",
                    detail: audio.bluetoothMicConnected
                        ? "Có micro Bluetooth đang kết nối. Dùng Khóa Micro nếu cần chặn app nền thu âm qua Bluetooth."
                        : "Ứng dụng khác đang dùng âm thanh nền. Bật Phát nhiễu để ngắt phiên nền.",
                    isResolved: false,
                    canAutoFix: true,
                    actionLabel: "Chặn ngay",
                    actionKind: .enableAcousticJammer,
                    targetTab: 1
                ))
            }
        }

        if let clip = activeDefense.lastClipboardScan, !clip.detectedSensitivePatterns.isEmpty || !clip.detectedTrackingParams.isEmpty {
            score -= !clip.detectedSensitivePatterns.isEmpty ? 10 : 4
            let isSensitive = !clip.detectedSensitivePatterns.isEmpty
            tasks.append(RemediationTask(
                id: "task-clipboard",
                category: .antiSpying,
                severity: isSensitive ? .critical : .warning,
                title: isSensitive ? "Xóa dữ liệu nhạy cảm đang nằm trong Clipboard" : "Gỡ tham số theo dõi trong link Clipboard",
                detail: clip.statusNote,
                isResolved: false,
                canAutoFix: true,
                actionLabel: isSensitive ? "Xóa trắng" : "Gỡ tracker",
                actionKind: isSensitive ? .wipeClipboard : .stripClipboardTracking,
                targetTab: 1
            ))
        }

        if let bg = activeDefense.backgroundSnapshot {
            if let spike = bg.backgroundSpikeAlert {
                score -= 12
                newAlerts.append(SecurityAlertBanner(
                    category: .antiSpying,
                    severity: .warning,
                    title: "Lưu lượng tải lên bất thường ở tầng mạng",
                    detail: spike,
                    targetTab: 1
                ))
            }

            if bg.backgroundRefreshEnabled {
                score -= 4
                tasks.append(RemediationTask(
                    id: "task-bg-refresh",
                    category: .antiSpying,
                    severity: .info,
                    title: "Hạn chế Làm mới ứng dụng trong nền (Background Refresh)",
                    detail: "iOS đang cho phép app chạy nền tự do. Tắt các app không cần thiết trong Cài đặt > Cài đặt chung > Làm mới ứng dụng trong nền để chống rò rỉ dữ liệu & hao pin.",
                    isResolved: false,
                    canAutoFix: false,
                    actionLabel: "Mở Cài đặt",
                    actionKind: .guideDisableBackgroundRefresh,
                    targetTab: 1
                ))
            }

            if bg.needsRebootRecommended {
                score -= 5
                tasks.append(RemediationTask(
                    id: "task-reboot",
                    category: .antiSpying,
                    severity: .info,
                    title: "Khởi động lại iPhone định kỳ (\(String(format: "%.0f", bg.uptimeHours / 24)) ngày chưa tắt máy)",
                    detail: "Khởi động lại giúp xóa sạch tiến trình ẩn và mã khai thác không bền vững cư trú trong RAM.",
                    isResolved: false,
                    canAutoFix: false,
                    actionLabel: "Xem nhắc nhở",
                    actionKind: .guideRebootDevice,
                    targetTab: 1
                ))
            }

            if !bg.passcodeOrBiometricEnabled {
                score -= 15
                tasks.append(RemediationTask(
                    id: "task-passcode",
                    category: .deviceControl,
                    severity: .critical,
                    title: "Thiết lập Mật mã / Face ID bảo vệ máy",
                    detail: "Thiết bị chưa bật khóa bảo mật sinh trắc học hoặc passcode.",
                    isResolved: false,
                    canAutoFix: false,
                    actionLabel: "Mở Cài đặt",
                    actionKind: .guideSetupPasscode,
                    targetTab: 4
                ))
            }
        }

        if !policy.continuousWatchdogEnabled {
            tasks.append(RemediationTask(
                id: "task-watchdog",
                category: .antiSpying,
                severity: .info,
                title: "Bật Watchdog giám sát chống chạy ngầm liên tục",
                detail: "Theo dõi liên tục tốc độ tải lên mạng nền, cuộc gọi/micro và tuyến Bluetooth theo thời gian thực.",
                isResolved: false,
                canAutoFix: true,
                actionLabel: "Bật Watchdog",
                actionKind: .enableContinuousWatchdog,
                targetTab: 1
            ))
        }

        let clampedScore = max(0, min(100, score))
        securityScore = clampedScore
        alerts = newAlerts.sorted { $0.severity > $1.severity }
        remediationTasks = tasks.sorted { $0.severity > $1.severity }

        if newAlerts.contains(where: { $0.severity == .critical }) || clampedScore < 60 {
            overallSeverity = .critical
        } else if newAlerts.contains(where: { $0.severity == .warning }) || clampedScore < 85 {
            overallSeverity = .warning
        } else {
            overallSeverity = .safe
        }
    }
}

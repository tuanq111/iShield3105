//
//  DashboardView.swift
//  iShieldPro
//
//  Commercial Cyber Security Dashboard: Score, 1-Tap Auto-Fix, Remediation Queue & Prevention Policies
//

import SwiftUI

struct DashboardView: View {
    @ObservedObject var coordinator: SecurityDashboardCoordinator
    @ObservedObject var containerManager: ContainerManager
    @ObservedObject var auditEngine: SecurityAuditEngine
    @ObservedObject var networkScanner: NetworkPrivacyScanner
    @ObservedObject var activeDefense: ActiveDefenseEngine

    @State private var showTechDetails = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    headerStatusStrip
                    scoreAndActionCard
                    activeDefenseStrip
                    if let fixMsg = coordinator.lastAutoFixMessage {
                        autoFixBanner(fixMsg)
                    }
                    remediationQueueSection
                    alertsSection
                    moduleSummaryGrid
                    preventionPoliciesCard
                    recentEventLogCard
                    privateFrameworkDisclosure
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .background(CyberTheme.background.ignoresSafeArea())
            .navigationTitle("iShield Pro")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        Task { await coordinator.runDeepScan() }
                    } label: {
                        Image(systemName: "arrow.clockwise.circle.fill")
                            .foregroundColor(CyberTheme.neonCyan)
                    }
                    .disabled(coordinator.isDeepScanning || coordinator.isApplyingAutoFix)
                }
            }
        }
    }

    private var headerStatusStrip: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(CyberTheme.color(for: coordinator.overallSeverity))
                .frame(width: 9, height: 9)
            Text("MOBILE THREAT DEFENSE • \(coordinator.policy.continuousWatchdogEnabled ? "WATCHDOG ON" : "STANDBY")")
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundColor(CyberTheme.textSecondary)
                .lineLimit(1)
            Spacer()
            Text(CyberTheme.formatTimestamp(coordinator.lastDeepScanDate))
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(CyberTheme.textMuted)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(CyberTheme.cardSurface)
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(CyberTheme.border, lineWidth: 1)
        )
    }

    private var scoreAndActionCard: some View {
        VStack(spacing: 14) {
            SecurityScoreRing(
                score: coordinator.securityScore,
                severity: coordinator.overallSeverity,
                isScanning: coordinator.isDeepScanning || coordinator.isApplyingAutoFix
            )

            VStack(spacing: 4) {
                Text(scoreHeadline)
                    .font(.system(size: 17, weight: .bold))
                    .foregroundColor(CyberTheme.textPrimary)
                Text(scoreSubheadline)
                    .font(.system(size: 12))
                    .foregroundColor(CyberTheme.textSecondary)
                    .multilineTextAlignment(.center)
            }

            VStack(spacing: 10) {
                Button {
                    Task { await coordinator.runDeepScan() }
                } label: {
                    HStack(spacing: 8) {
                        if coordinator.isDeepScanning {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: CyberTheme.background))
                        } else {
                            Image(systemName: "dot.radiowaves.left.and.right")
                                .font(.system(size: 15, weight: .bold))
                        }
                        Text(coordinator.isDeepScanning ? "Đang quét 5 lớp bảo vệ..." : "Quét Toàn Diện (Deep Scan)")
                            .font(.system(size: 14, weight: .bold))
                    }
                    .foregroundColor(CyberTheme.background)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 13)
                    .background(
                        LinearGradient(
                            colors: [CyberTheme.neonCyan, Color(red: 0.0, green: 0.68, blue: 0.96)],
                            startPoint: .leading,
                            endPoint: .trailing
                        )
                    )
                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                }
                .disabled(coordinator.isDeepScanning || coordinator.isApplyingAutoFix)

                Button {
                    Task { _ = await coordinator.runOneTapAutoFix() }
                } label: {
                    HStack(spacing: 8) {
                        if coordinator.isApplyingAutoFix {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: CyberTheme.background))
                        } else {
                            Image(systemName: "bolt.shield.fill")
                                .font(.system(size: 15, weight: .bold))
                        }
                        Text(coordinator.isApplyingAutoFix ? "Đang cách ly & xử lý mối nguy..." : "Xử Lý & Khắc Phục Tự Động (1-Tap Fix)")
                            .font(.system(size: 14, weight: .bold))
                    }
                    .foregroundColor(CyberTheme.background)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 13)
                    .background(
                        LinearGradient(
                            colors: [CyberTheme.emerald, Color(red: 0.0, green: 0.72, blue: 0.45)],
                            startPoint: .leading,
                            endPoint: .trailing
                        )
                    )
                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                }
                .disabled(coordinator.isDeepScanning || coordinator.isApplyingAutoFix)
            }
        }
        .frame(maxWidth: .infinity)
        .cyberCard(borderColor: CyberTheme.color(for: coordinator.overallSeverity).opacity(0.35))
    }

    private var activeDefenseStrip: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ProtectionPill(
                    label: activeDefense.isWatchdogRunning ? "Chống Nền: LIVE" : "Chống Nền: TẮT",
                    isActive: activeDefense.isWatchdogRunning,
                    activeColor: CyberTheme.emerald
                )
                ProtectionPill(
                    label: (activeDefense.isAcousticJammerActive || activeDefense.isMicLockActive) ? "Chống Nghe Lén: BẬT" : "Nghe Lén: GIÁM SÁT",
                    isActive: activeDefense.isAcousticJammerActive || activeDefense.isMicLockActive,
                    activeColor: CyberTheme.neonCyan
                )
                ProtectionPill(
                    label: "ATT: \((activeDefense.backgroundSnapshot?.idfaExposed == false) ? "KHÓA IDFA" : "MỞ")",
                    isActive: activeDefense.backgroundSnapshot?.idfaExposed == false,
                    activeColor: CyberTheme.emerald
                )
                let dohOK = networkScanner.lastReport?.dnsServers.contains(where: \.isTrustedKnownDNS) ?? false
                ProtectionPill(
                    label: dohOK ? "DNS Shield: BẬT" : "DNS: MẶC ĐỊNH",
                    isActive: dohOK,
                    activeColor: dohOK ? CyberTheme.emerald : CyberTheme.amber
                )
            }
        }
    }

    private func autoFixBanner(_ message: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundColor(CyberTheme.emerald)
                .font(.system(size: 18))
            VStack(alignment: .leading, spacing: 3) {
                Text("Kết quả xử lý & phòng ngừa")
                    .font(.system(size: 12, weight: .bold))
                    .foregroundColor(CyberTheme.emerald)
                Text(message)
                    .font(.system(size: 11))
                    .foregroundColor(CyberTheme.textPrimary)
            }
            Spacer()
        }
        .cyberCard(borderColor: CyberTheme.emerald.opacity(0.45))
    }

    @ViewBuilder
    private var remediationQueueSection: some View {
        if !coordinator.remediationTasks.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                SectionHeaderView(
                    title: "Trung tâm Khắc phục & Phòng ngừa (\(coordinator.remediationTasks.filter { !$0.isResolved }.count) cần xử lý)",
                    systemImage: "wrench.and.screwdriver.fill",
                    subtitle: "Tự động xử lý ngay hoặc mở đúng mục hệ thống để vá lỗ hổng"
                )

                ForEach(coordinator.remediationTasks) { task in
                    RemediationTaskCard(task: task) {
                        Task { await coordinator.executeRemediationTask(task) }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var alertsSection: some View {
        if !coordinator.alerts.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                SectionHeaderView(
                    title: "Cảnh báo mối nguy (\(coordinator.alerts.count))",
                    systemImage: "exclamationmark.triangle.fill",
                    subtitle: "Chạm vào từng cảnh báo để điều tra chi tiết"
                )

                ForEach(coordinator.alerts) { alert in
                    AlertBannerCard(alert: alert) {
                        coordinator.selectedTab = alert.targetTab
                    }
                }
            }
        } else if coordinator.lastDeepScanDate != nil {
            HStack(spacing: 12) {
                Image(systemName: "checkmark.seal.fill")
                    .font(.system(size: 24))
                    .foregroundColor(CyberTheme.emerald)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Chưa ghi nhận mối nguy xâm phạm nghiêm trọng")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(CyberTheme.textPrimary)
                    Text("MDM, Runtime Dylib, Tunnel ngầm, Âm thanh và Container mục tiêu đang ổn định.")
                        .font(.system(size: 12))
                        .foregroundColor(CyberTheme.textSecondary)
                }
                Spacer()
            }
            .cyberCard(borderColor: CyberTheme.emerald.opacity(0.4))
        }
    }

    private var moduleSummaryGrid: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeaderView(
                title: "4 Trung tâm Bảo mật Chuyên sâu",
                systemImage: "square.grid.2x2.fill",
                subtitle: "Chạm để mở công cụ xử lý chuyên sâu"
            )

            LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)], spacing: 12) {
                moduleTile(
                    title: "Chống Nghe Lén & Nền",
                    icon: "ear.trianglebadge.exclamationmark",
                    metric: activeDefenseMetric,
                    severity: activeDefenseSeverity,
                    tabIndex: 1
                )
                moduleTile(
                    title: "Dọn App & Cách Ly",
                    icon: "shippingbox.fill",
                    metric: containerSummaryMetric,
                    severity: containerSummarySeverity,
                    tabIndex: 2
                )
                moduleTile(
                    title: "Mạng, VPN & DNS",
                    icon: "antenna.radiowaves.left.and.right",
                    metric: networkSummaryMetric,
                    severity: networkSummarySeverity,
                    tabIndex: 3
                )
                moduleTile(
                    title: "MDM, Root CA & Runtime",
                    icon: "lock.shield.fill",
                    metric: runtimeAndMDMMetric,
                    severity: runtimeAndMDMSeverity,
                    tabIndex: 4
                )
            }
        }
    }

    private func moduleTile(
        title: String,
        icon: String,
        metric: String,
        severity: RiskSeverity,
        tabIndex: Int
    ) -> some View {
        let tint = CyberTheme.color(for: severity)
        return Button {
            coordinator.selectedTab = tabIndex
        } label: {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Image(systemName: icon)
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundColor(tint)
                    Spacer()
                    SeverityBadge(severity: severity)
                }
                Text(title)
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(CyberTheme.textPrimary)
                    .lineLimit(2)
                    .multilineTextAlignment(.leading)
                Text(metric)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(CyberTheme.textSecondary)
                    .lineLimit(2)
                    .multilineTextAlignment(.leading)
            }
            .frame(maxWidth: .infinity, minHeight: 108, alignment: .topLeading)
            .cyberCard(borderColor: tint.opacity(0.32))
        }
        .buttonStyle(.plain)
    }

    private var preventionPoliciesCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeaderView(
                title: "Chính sách Phòng ngừa Tự động",
                systemImage: "shield.checkered",
                subtitle: "Duy trì bảo vệ liên tục và tự kiểm tra lại sau khi thay đổi Cài đặt iOS"
            )

            Toggle("Watchdog giám sát lưu lượng nền & nghe lén 24/7", isOn: $coordinator.policy.continuousWatchdogEnabled)
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(CyberTheme.textPrimary)
                .tint(CyberTheme.emerald)

            Toggle("Tự động quét lại khi quay lại ứng dụng", isOn: $coordinator.policy.autoScanOnResume)
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(CyberTheme.textPrimary)
                .tint(CyberTheme.neonCyan)

            Toggle("Tự gỡ link theo dõi Clipboard khi quét", isOn: $coordinator.policy.autoSanitizeClipboardOnScan)
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(CyberTheme.textPrimary)
                .tint(CyberTheme.neonCyan)

            Toggle("Khóa DNS On-Demand (Wi-Fi & 4G/5G) trong .mobileconfig", isOn: $coordinator.policy.enforceOnDemandDoH)
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(CyberTheme.textPrimary)
                .tint(CyberTheme.emerald)
        }
        .cyberCard()
    }

    private var recentEventLogCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                SectionHeaderView(
                    title: "Nhật ký Bảo vệ gần đây (\(coordinator.eventLog.count))",
                    systemImage: "clock.arrow.circlepath",
                    subtitle: "Lịch sử phát hiện, dọn dẹp & kích hoạt lá chắn"
                )
                Button("Xem tất cả") {
                    coordinator.selectedTab = 4
                }
                .font(.system(size: 11, weight: .bold))
                .foregroundColor(CyberTheme.neonCyan)
            }

            if coordinator.eventLog.isEmpty {
                Text("Chưa có sự kiện nào được ghi lại.")
                    .font(.system(size: 12))
                    .foregroundColor(CyberTheme.textSecondary)
            } else {
                ForEach(coordinator.eventLog.prefix(4)) { entry in
                    VStack(alignment: .leading, spacing: 2) {
                        HStack {
                            Text(entry.actionTaken.uppercased())
                                .font(.system(size: 9, weight: .bold, design: .monospaced))
                                .foregroundColor(CyberTheme.color(for: entry.severity))
                            Spacer()
                            Text(CyberTheme.formatTimestamp(entry.timestamp))
                                .font(.system(size: 9, design: .monospaced))
                                .foregroundColor(CyberTheme.textMuted)
                        }
                        Text(entry.title)
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(CyberTheme.textPrimary)
                        Text(entry.detail)
                            .font(.system(size: 11))
                            .foregroundColor(CyberTheme.textSecondary)
                            .lineLimit(2)
                    }
                    .padding(9)
                    .background(CyberTheme.elevatedSurface)
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                }
            }
        }
        .cyberCard()
    }

    private var privateFrameworkDisclosure: some View {
        DisclosureGroup("Chẩn đoán Hệ thống Cấp thấp (MobileContainerManager / SpringBoard)", isExpanded: $showTechDetails) {
            if let status = containerManager.frameworkStatus {
                VStack(spacing: 4) {
                    TelemetryKeyValueRow(
                        label: "Bundle Identity",
                        value: Bundle.main.bundleIdentifier ?? "com.apple.mobile.MobileHouseArrest"
                    )
                    TelemetryKeyValueRow(
                        label: "MobileContainerManager",
                        value: status.mobileContainerManagerLoaded ? "LOADED" : "UNAVAILABLE",
                        valueColor: status.mobileContainerManagerLoaded ? CyberTheme.emerald : CyberTheme.amber
                    )
                    TelemetryKeyValueRow(
                        label: "SpringBoardServices",
                        value: status.springBoardServicesLoaded ? "LOADED" : "UNAVAILABLE",
                        valueColor: status.springBoardServicesLoaded ? CyberTheme.emerald : CyberTheme.amber
                    )
                    TelemetryKeyValueRow(
                        label: "MCMAppDataContainer",
                        value: status.mcmAppDataClassResolved ? "RESOLVED" : "MISSING",
                        valueColor: status.mcmAppDataClassResolved ? CyberTheme.emerald : CyberTheme.crimson
                    )
                    TelemetryKeyValueRow(
                        label: "MCMSharedDataContainer",
                        value: status.mcmSharedDataClassResolved ? "RESOLVED" : "MISSING",
                        valueColor: status.mcmSharedDataClassResolved ? CyberTheme.emerald : CyberTheme.crimson
                    )
                }
                .padding(.top, 8)
            }
        }
        .font(.system(size: 12, weight: .semibold))
        .foregroundColor(CyberTheme.textSecondary)
        .cyberCard()
    }

    private var scoreHeadline: String {
        if coordinator.lastDeepScanDate == nil {
            return "Đang khởi tạo phân tích bảo mật"
        }
        switch coordinator.overallSeverity {
        case .safe: return "Thiết bị được bảo vệ ổn định"
        case .info: return "Đã hoàn tất rà soát tổng thể"
        case .warning: return "Phát hiện rủi ro cần xử lý"
        case .critical: return "Cảnh báo nguy cơ xâm phạm cao"
        }
    }

    private var scoreSubheadline: String {
        if coordinator.lastDeepScanDate == nil {
            return "Đang chạy đồng thời 5 phân hệ chống gián điệp, quét Container, Mạng & Kiểm soát thiết bị."
        }
        let openTasks = coordinator.remediationTasks.filter { !$0.isResolved }.count
        return "\(coordinator.alerts.count) cảnh báo • \(openTasks) đề xuất khắc phục & phòng ngừa."
    }

    private var activeDefenseMetric: String {
        let micStatus = activeDefense.isAcousticJammerActive ? "Nhiễu BẬT" : (activeDefense.isMicLockActive ? "Khóa Mic" : "Giám sát")
        let bg = activeDefense.backgroundSnapshot?.backgroundRefreshEnabled == true ? "Nền Bật" : "Nền Tắt"
        return "\(micStatus) • \(bg)"
    }

    private var activeDefenseSeverity: RiskSeverity {
        if let audio = activeDefense.audioAudit, audio.audioRiskLevel >= .critical {
            return .critical
        }
        if activeDefense.backgroundSnapshot?.backgroundSpikeAlert != nil {
            return .warning
        }
        return (activeDefense.isAcousticJammerActive || activeDefense.isMicLockActive) ? .safe : .info
    }

    private var runtimeAndMDMMetric: String {
        guard let audit = auditEngine.lastReport else { return "Chưa quét" }
        if audit.isSupervisedDetected || audit.isMDMDetected {
            return "Cảnh báo MDM/Supervised"
        }
        let openPorts = audit.openDangerousPorts.filter { $0.severityIfOpen >= .warning }.count
        return "\(audit.suspiciousDylibs.count) dylib lạ • \(openPorts) port mở"
    }

    private var runtimeAndMDMSeverity: RiskSeverity {
        guard let audit = auditEngine.lastReport else { return .info }
        if audit.isSupervisedDetected || audit.isMDMDetected || audit.hasMitMRisk
            || !audit.suspiciousDylibs.isEmpty
            || !audit.openDangerousPorts.filter({ $0.severityIfOpen >= .warning }).isEmpty {
            return .critical
        }
        return audit.debuggerAttached ? .warning : .safe
    }

    private var networkSummaryMetric: String {
        guard let net = networkScanner.lastReport else { return "Chưa quét" }
        let ipStr = net.publicIP?.ip.isEmpty == false ? net.publicIP!.ip : "N/A"
        return "IP: \(ipStr) • \(net.suspiciousTunnels.count) tunnel ẩn"
    }

    private var networkSummarySeverity: RiskSeverity {
        guard let net = networkScanner.lastReport else { return .info }
        if !net.suspiciousTunnels.isEmpty { return .critical }
        if net.dnsHijackSuspected || (net.publicIP?.isRealIPExposed == true) || !(net.publicIP?.leakedHeaders.isEmpty ?? true) {
            return .warning
        }
        return .safe
    }

    private var containerSummaryMetric: String {
        guard let c = containerManager.lastInspection else { return "Chưa kiểm tra" }
        return "\(CyberTheme.formatBytes(c.totalCleanableBytes)) cache • \(containerManager.quarantinedFiles.count) cách ly"
    }

    private var containerSummarySeverity: RiskSeverity {
        containerManager.lastInspection?.highestSeverity ?? .info
    }
}

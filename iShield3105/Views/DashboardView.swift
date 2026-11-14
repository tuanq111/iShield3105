//
//  DashboardView.swift
//  iShield3105
//

import SwiftUI

struct DashboardView: View {
    @ObservedObject var coordinator: SecurityDashboardCoordinator
    @ObservedObject var containerManager: ContainerManager
    @ObservedObject var auditEngine: SecurityAuditEngine
    @ObservedObject var networkScanner: NetworkPrivacyScanner

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    headerStatusStrip
                    scoreAndScanCard
                    alertsSection
                    moduleSummaryGrid
                    privateFrameworkCard
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .background(CyberTheme.background.ignoresSafeArea())
            .navigationTitle("iShield3105")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        Task { await coordinator.runDeepScan() }
                    } label: {
                        Image(systemName: "arrow.clockwise.circle.fill")
                            .foregroundColor(CyberTheme.neonCyan)
                    }
                    .disabled(coordinator.isDeepScanning)
                }
            }
        }
    }

    private var headerStatusStrip: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(CyberTheme.color(for: coordinator.overallSeverity))
                .frame(width: 9, height: 9)
            Text("BUNDLE TRUST: \(Bundle.main.bundleIdentifier ?? "com.apple.mobile.MobileHouseArrest")")
                .font(.system(size: 11, weight: .bold, design: .monospaced))
                .foregroundColor(CyberTheme.textSecondary)
                .lineLimit(1)
                .truncationMode(.middle)
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

    private var scoreAndScanCard: some View {
        VStack(spacing: 16) {
            SecurityScoreRing(
                score: coordinator.securityScore,
                severity: coordinator.overallSeverity,
                isScanning: coordinator.isDeepScanning
            )

            VStack(spacing: 4) {
                Text(scoreHeadline)
                    .font(.system(size: 16, weight: .bold))
                    .foregroundColor(CyberTheme.textPrimary)
                Text(scoreSubheadline)
                    .font(.system(size: 12))
                    .foregroundColor(CyberTheme.textSecondary)
                    .multilineTextAlignment(.center)
            }

            Button {
                Task { await coordinator.runDeepScan() }
            } label: {
                HStack(spacing: 10) {
                    if coordinator.isDeepScanning {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: CyberTheme.background))
                    } else {
                        Image(systemName: "dot.radiowaves.left.and.right")
                            .font(.system(size: 16, weight: .bold))
                    }
                    Text(coordinator.isDeepScanning ? "Đang quét 4 module hệ thống..." : "Quét Toàn Diện (Deep Scan)")
                        .font(.system(size: 15, weight: .bold))
                }
                .foregroundColor(CyberTheme.background)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(
                    LinearGradient(
                        colors: [CyberTheme.neonCyan, Color(red: 0.0, green: 0.68, blue: 0.96)],
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )
                .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            }
            .disabled(coordinator.isDeepScanning)
        }
        .frame(maxWidth: .infinity)
        .cyberCard(borderColor: CyberTheme.color(for: coordinator.overallSeverity).opacity(0.35))
    }

    @ViewBuilder
    private var alertsSection: some View {
        if !coordinator.alerts.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                SectionHeaderView(
                    title: "Cảnh báo bảo mật (\(coordinator.alerts.count))",
                    systemImage: "exclamationmark.triangle.fill",
                    subtitle: "Chạm vào từng cảnh báo để đi tới màn hình xử lý chi tiết"
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
                    Text("Không phát hiện mối đe dọa nghiêm trọng")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(CyberTheme.textPrimary)
                    Text("MDM, Runtime Dylib, Tunnel ngầm và Container mục tiêu ở trạng thái sạch.")
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
                title: "Trạng thái 4 Module Chuyên Sâu",
                systemImage: "square.grid.2x2.fill",
                subtitle: "Bấm để chuyển nhanh tới từng phân hệ"
            )

            LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)], spacing: 12) {
                moduleTile(
                    title: "MDM & Quyền Kiểm Soát",
                    icon: "lock.shield.fill",
                    metric: mdmSummaryMetric,
                    severity: mdmSummarySeverity,
                    tabIndex: 3
                )
                moduleTile(
                    title: "Runtime & Backdoor",
                    icon: "cpu.fill",
                    metric: runtimeSummaryMetric,
                    severity: runtimeSummarySeverity,
                    tabIndex: 3
                )
                moduleTile(
                    title: "Mạng, VPN & DNS",
                    icon: "antenna.radiowaves.left.and.right",
                    metric: networkSummaryMetric,
                    severity: networkSummarySeverity,
                    tabIndex: 2
                )
                moduleTile(
                    title: "Container 3105",
                    icon: "shippingbox.fill",
                    metric: containerSummaryMetric,
                    severity: containerSummarySeverity,
                    tabIndex: 1
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

    private var privateFrameworkCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeaderView(
                title: "Trạng thái Nạp Private Frameworks (dlopen)",
                systemImage: "wrench.and.screwdriver.fill",
                subtitle: "Tầng lõi tương tác MobileContainerManager & SpringBoardServices"
            )
            if let status = containerManager.frameworkStatus {
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
        }
        .cyberCard()
    }

    private var scoreHeadline: String {
        if coordinator.lastDeepScanDate == nil {
            return "Sẵn sàng kiểm tra bảo mật"
        }
        switch coordinator.overallSeverity {
        case .safe: return "Hệ thống ổn định & an toàn"
        case .info: return "Đã hoàn tất rà soát cơ bản"
        case .warning: return "Phát hiện điểm rủi ro cần xử lý"
        case .critical: return "Cảnh báo nguy cơ xâm phạm cao"
        }
    }

    private var scoreSubheadline: String {
        if coordinator.lastDeepScanDate == nil {
            return "Nhấn Quét Toàn Diện để chạy đồng thời kiểm tra MDM, Dylib, Tunnel/DNS/IP và Container 3105."
        }
        return "Tổng hợp \(coordinator.alerts.count) phát hiện từ 4 phân hệ kiểm tra thực tế."
    }

    private var mdmSummaryMetric: String {
        guard let audit = auditEngine.lastReport else { return "Chưa quét" }
        if audit.isSupervisedDetected || audit.isMDMDetected {
            return "Phát hiện Supervised/MDM"
        }
        if audit.hasMitMRisk {
            return "Phát hiện rủi ro MitM/Proxy"
        }
        return "Không phát hiện MDM / Proxy"
    }

    private var mdmSummarySeverity: RiskSeverity {
        guard let audit = auditEngine.lastReport else { return .info }
        if audit.isSupervisedDetected || audit.isMDMDetected || audit.hasMitMRisk {
            return .critical
        }
        return .safe
    }

    private var runtimeSummaryMetric: String {
        guard let audit = auditEngine.lastReport else { return "Chưa quét" }
        let dylibCount = audit.suspiciousDylibs.count
        let openPorts = audit.openDangerousPorts.filter { $0.severityIfOpen >= .warning }.count
        return "\(audit.dylibs.count) dylib • \(dylibCount) lạ • \(openPorts) port mở"
    }

    private var runtimeSummarySeverity: RiskSeverity {
        guard let audit = auditEngine.lastReport else { return .info }
        if !audit.suspiciousDylibs.isEmpty || !audit.openDangerousPorts.filter({ $0.severityIfOpen >= .warning }).isEmpty {
            return .critical
        }
        return audit.debuggerAttached ? .warning : .safe
    }

    private var networkSummaryMetric: String {
        guard let net = networkScanner.lastReport else { return "Chưa quét" }
        let ipStr = net.publicIP?.ip.isEmpty == false ? net.publicIP!.ip : "N/A"
        return "IP: \(ipStr) • \(net.suspiciousTunnels.count) tunnel nghi ngờ"
    }

    private var networkSummarySeverity: RiskSeverity {
        guard let net = networkScanner.lastReport else { return .info }
        if !net.suspiciousTunnels.isEmpty { return .critical }
        if net.dnsHijackSuspected || (net.publicIP?.isRealIPExposed == true) { return .warning }
        return .safe
    }

    private var containerSummaryMetric: String {
        guard let c = containerManager.lastInspection else { return "Chưa quét" }
        return "\(CyberTheme.formatBytes(c.totalCleanableBytes)) rác • \(c.suspiciousFiles.count) cảnh báo"
    }

    private var containerSummarySeverity: RiskSeverity {
        containerManager.lastInspection?.highestSeverity ?? .info
    }
}

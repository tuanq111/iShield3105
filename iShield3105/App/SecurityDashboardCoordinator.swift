//
//  SecurityDashboardCoordinator.swift
//  iShield3105
//

import Foundation
import SwiftUI

@MainActor
final class SecurityDashboardCoordinator: ObservableObject {
    @Published var selectedTab: Int = 0
    @Published var targetBundleID: String
    @Published var explicitAppGroupID: String = ""

    @Published private(set) var isDeepScanning = false
    @Published private(set) var lastDeepScanDate: Date?
    @Published private(set) var securityScore: Int = 100
    @Published private(set) var overallSeverity: RiskSeverity = .info
    @Published private(set) var alerts: [SecurityAlertBanner] = []

    let containerManager = ContainerManager()
    let auditEngine = SecurityAuditEngine()
    let networkScanner = NetworkPrivacyScanner()
    let dohManager = DoHProfileManager()

    init() {
        self.targetBundleID = Bundle.main.bundleIdentifier ?? "com.apple.mobile.MobileHouseArrest"
    }

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

        // Refresh installed app catalog first so group/plugin metadata is available to container inspection,
        // then run container, audit, and network modules concurrently.
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

        recomputeScoreAndAlerts(
            container: containerReport,
            audit: auditReport,
            network: networkReport
        )
        lastDeepScanDate = Date()
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

    func recomputeScoreAndAlerts(
        container: ContainerInspectionReport?,
        audit: SecurityAuditReport?,
        network: NetworkPrivacyReport?
    ) {
        var score = 100
        var newAlerts: [SecurityAlertBanner] = []

        // Module 1 & 3: MDM / Supervision / MitM / Runtime Dylib / Ports
        if let audit {
            if audit.isSupervisedDetected {
                score -= 30
                newAlerts.append(SecurityAlertBanner(
                    category: .deviceControl,
                    severity: .critical,
                    title: "Thiết bị đang ở chế độ Giám sát (Supervised)",
                    detail: "Phát hiện cờ IsSupervised từ hồ sơ cấu hình hệ thống — tổ chức quản lý có thể kiểm soát sâu thiết bị.",
                    targetTab: 3
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
                    targetTab: 3
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
                    targetTab: 3
                ))
            }

            if audit.debuggerAttached {
                score -= 15
                newAlerts.append(SecurityAlertBanner(
                    category: .runtime,
                    severity: .warning,
                    title: "Tiến trình đang bị gắn Debugger (P_TRACED)",
                    detail: "Phát hiện cờ debug trên tiến trình iShield3105.",
                    targetTab: 3
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
                    targetTab: 3
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
                    targetTab: 3
                ))
            }
        }

        // Module 4: Network / VPN Tunnel / DNS Hijack / Public IP Exposure
        if let network {
            if !network.suspiciousTunnels.isEmpty {
                score -= 20
                let names = network.suspiciousTunnels.map(\.name).joined(separator: ", ")
                newAlerts.append(SecurityAlertBanner(
                    category: .network,
                    severity: .critical,
                    title: "Phát hiện Tunnel mạng ngầm đang hoạt động (\(names))",
                    detail: "Nếu bạn không bật VPN, lưu lượng mạng có thể đang bị định tuyến qua ứng dụng hoặc cấu hình ẩn.",
                    targetTab: 2
                ))
            }

            if network.dnsHijackSuspected {
                score -= 15
                let suspiciousDNS = network.dnsServers.filter { $0.riskLevel >= .warning }.map(\.address).joined(separator: ", ")
                newAlerts.append(SecurityAlertBanner(
                    category: .network,
                    severity: .warning,
                    title: "Máy chủ DNS có dấu hiệu bất thường",
                    detail: "Phát hiện DNS ngoài danh sách tin cậy: \(suspiciousDNS). Khuyến nghị cài cấu hình DoH.",
                    targetTab: 2
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
                        targetTab: 2
                    ))
                }
                if ip.isRealIPExposed {
                    score -= 10
                    newAlerts.append(SecurityAlertBanner(
                        category: .network,
                        severity: .warning,
                        title: "IP Public thực đang lộ trực tiếp (\(ip.ip))",
                        detail: "Nhà mạng/ISP: \(ip.org ?? "Không rõ") (\(ip.city ?? ""), \(ip.country ?? "")). Chưa phát hiện lớp ẩn danh VPN.",
                        targetTab: 2
                    ))
                }
            }
        }

        // Module 2: 3105 Container Inspector
        if let container {
            let criticalFiles = container.suspiciousFiles.filter { $0.severity == .critical }
            let warningFiles = container.suspiciousFiles.filter { $0.severity == .warning }
            if !criticalFiles.isEmpty {
                score -= min(25, criticalFiles.count * 15)
                newAlerts.append(SecurityAlertBanner(
                    category: .container,
                    severity: .critical,
                    title: "Container \(container.bundleIdentifier) chứa nhị phân lạ",
                    detail: "Tìm thấy \(criticalFiles.count) tệp .dylib / binary đáng ngờ bên trong vùng dữ liệu ứng dụng.",
                    targetTab: 1
                ))
            } else if !warningFiles.isEmpty {
                score -= min(10, warningFiles.count * 3)
                newAlerts.append(SecurityAlertBanner(
                    category: .container,
                    severity: .warning,
                    title: "Phát hiện dấu vết theo dõi / cache phình to",
                    detail: "\(warningFiles.count) tệp nghi ngờ trong \(container.bundleIdentifier).",
                    targetTab: 1
                ))
            }
        }

        let clampedScore = max(0, min(100, score))
        securityScore = clampedScore
        alerts = newAlerts.sorted { $0.severity > $1.severity }

        if newAlerts.contains(where: { $0.severity == .critical }) || clampedScore < 60 {
            overallSeverity = .critical
        } else if newAlerts.contains(where: { $0.severity == .warning }) || clampedScore < 85 {
            overallSeverity = .warning
        } else {
            overallSeverity = .safe
        }
    }
}

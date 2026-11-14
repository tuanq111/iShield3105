//
//  DeviceControlCheckView.swift
//  iShield3105
//
//  Kiểm tra MDM, Supervised, Root CA / MitM, Runtime Dylib Injection, Port nội bộ & Hướng dẫn gỡ bỏ
//

import SwiftUI

struct DeviceControlCheckView: View {
    @ObservedObject var coordinator: SecurityDashboardCoordinator
    @ObservedObject var auditEngine: SecurityAuditEngine

    @State private var dylibSearchText = ""
    @State private var showOnlySuspiciousDylibs = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    actionHeaderCard
                    if let report = auditEngine.lastReport {
                        mdmAndSupervisionCard(report)
                        mitmAndProxyCard(report)
                        provisioningCard(report.provisioningInfo)
                        localPortsCard(report)
                        loadedDylibsCard(report)
                    }
                    remediationGuideCard
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .background(CyberTheme.background.ignoresSafeArea())
            .navigationTitle("Device Control Check")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var actionHeaderCard: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("Kiểm tra Chiếm quyền & Runtime")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(CyberTheme.textPrimary)
                Text("MDM • Supervised • MitM Proxy • _dyld • Loopback Ports")
                    .font(.system(size: 11))
                    .foregroundColor(CyberTheme.textSecondary)
            }
            Spacer()
            Button {
                Task {
                    _ = await auditEngine.runFullAudit()
                    coordinator.syncScoreFromCurrentReports()
                }
            } label: {
                HStack(spacing: 6) {
                    if auditEngine.isScanning {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: CyberTheme.background))
                    } else {
                        Image(systemName: "checkmark.shield.fill")
                    }
                    Text(auditEngine.isScanning ? "Đang kiểm tra..." : "Kiểm tra ngay")
                        .font(.system(size: 12, weight: .bold))
                }
                .foregroundColor(CyberTheme.background)
                .padding(.horizontal, 14)
                .padding(.vertical, 9)
                .background(CyberTheme.neonCyan)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
            .disabled(auditEngine.isScanning)
        }
        .cyberCard()
    }

    private func mdmAndSupervisionCard(_ report: SecurityAuditReport) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                SectionHeaderView(
                    title: "Trạng thái Giám sát (Supervised) & MDM",
                    systemImage: "building.2.crop.circle.fill",
                    subtitle: "CloudConfigurationDetails.plist, UserSettings.plist & cfprefsd"
                )
                SeverityBadge(
                    severity: (report.isSupervisedDetected || report.isMDMDetected) ? .critical : .safe,
                    customText: (report.isSupervisedDetected || report.isMDMDetected) ? "BỊ QUẢN LÝ" : "KHÔNG PHÁT HIỆN"
                )
            }

            TelemetryKeyValueRow(
                label: "IsSupervised",
                value: report.isSupervisedDetected ? "TRUE (ĐANG GIÁM SÁT)" : "Chưa ghi nhận cờ Supervised",
                valueColor: report.isSupervisedDetected ? CyberTheme.crimson : CyberTheme.emerald
            )
            TelemetryKeyValueRow(
                label: "MDM Enrollment",
                value: report.isMDMDetected ? "PHÁT HIỆN TỔ CHỨC QUẢN LÝ" : "Không phát hiện hồ sơ MDM đọc được",
                valueColor: report.isMDMDetected ? CyberTheme.crimson : CyberTheme.emerald
            )

            ForEach(report.mdmIndicators) { indicator in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(indicator.sourceName)
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(CyberTheme.textPrimary)
                        Spacer()
                        SeverityBadge(
                            severity: (indicator.isSupervised == true || indicator.mdmEnrolled == true)
                                ? .critical
                                : (indicator.isReadable ? .safe : .info),
                            customText: indicator.isReadable ? "ĐỌC ĐƯỢC" : "SANDBOXED"
                        )
                    }
                    Text(indicator.sourcePath)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(CyberTheme.textMuted)
                    Text(indicator.accessStatus)
                        .font(.system(size: 11))
                        .foregroundColor(CyberTheme.textSecondary)

                    if let org = indicator.organizationName {
                        TelemetryKeyValueRow(label: "Tổ chức MDM", value: org, valueColor: CyberTheme.crimson)
                    }
                    if let url = indicator.configurationURL {
                        TelemetryKeyValueRow(label: "Server MDM", value: url, valueColor: CyberTheme.amber)
                    }
                }
                .padding(10)
                .background(CyberTheme.elevatedSurface)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
        }
        .cyberCard(borderColor: (report.isSupervisedDetected || report.isMDMDetected) ? CyberTheme.crimson.opacity(0.55) : CyberTheme.border)
    }

    private func mitmAndProxyCard(_ report: SecurityAuditReport) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                SectionHeaderView(
                    title: "Chứng chỉ Root CA & Global Proxy (MitM)",
                    systemImage: "network.badge.shield.half.filled",
                    subtitle: "CFNetworkCopySystemProxySettings & Live TLS Trust Chain"
                )
                SeverityBadge(severity: report.hasMitMRisk ? .critical : .safe)
            }

            let proxy = report.proxyReport
            TelemetryKeyValueRow(
                label: "HTTP Proxy",
                value: proxy.httpProxyEnabled ? "\(proxy.httpProxyHost ?? "?"):\(proxy.httpProxyPort ?? 0)" : "Tắt",
                valueColor: proxy.httpProxyEnabled ? CyberTheme.crimson : CyberTheme.emerald
            )
            TelemetryKeyValueRow(
                label: "HTTPS Proxy",
                value: proxy.httpsProxyEnabled ? "\(proxy.httpsProxyHost ?? "?"):\(proxy.httpsProxyPort ?? 0)" : "Tắt",
                valueColor: proxy.httpsProxyEnabled ? CyberTheme.crimson : CyberTheme.emerald
            )
            TelemetryKeyValueRow(
                label: "SOCKS / PAC",
                value: (proxy.socksProxyEnabled || proxy.pacEnabled) ? (proxy.pacURL ?? "\(proxy.socksProxyHost ?? "?"):\(proxy.socksProxyPort ?? 0)") : "Tắt",
                valueColor: (proxy.socksProxyEnabled || proxy.pacEnabled) ? CyberTheme.amber : CyberTheme.emerald
            )

            ForEach(proxy.scopedInterfaceProxies.keys.sorted(), id: \.self) { iface in
                TelemetryKeyValueRow(
                    label: "Scoped [\(iface)]",
                    value: proxy.scopedInterfaceProxies[iface] ?? "",
                    valueColor: CyberTheme.crimson
                )
            }

            ForEach(report.tlsChainAudits) { tls in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text("TLS Chain: \(tls.targetHost)")
                            .font(.system(size: 12, weight: .bold, design: .monospaced))
                            .foregroundColor(CyberTheme.textPrimary)
                        Spacer()
                        SeverityBadge(
                            severity: (!tls.trustEvaluatedValid || tls.suspectedMitMAuthority != nil) ? .critical : .safe,
                            customText: tls.trustEvaluatedValid ? "VALID CHAIN" : "TRUST FAILED"
                        )
                    }
                    if let mitm = tls.suspectedMitMAuthority {
                        Text("CẢNH BÁO: Phát hiện CA chặn bắt gói tin '\(mitm)'")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(CyberTheme.crimson)
                    }
                    if !tls.certificateSubjects.isEmpty {
                        Text("Chuỗi CA: " + tls.certificateSubjects.joined(separator: " -> "))
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(CyberTheme.textSecondary)
                    }
                    if let err = tls.evaluationError {
                        Text("Chi tiết: \(err)")
                            .font(.system(size: 10))
                            .foregroundColor(CyberTheme.amber)
                    }
                }
                .padding(9)
                .background(CyberTheme.elevatedSurface)
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            }

            ForEach(report.trustStoreFindings, id: \.self) { finding in
                Text("• \(finding)")
                    .font(.system(size: 11))
                    .foregroundColor(CyberTheme.amber)
            }
        }
        .cyberCard()
    }

    private func provisioningCard(_ info: ProvisioningAuditInfo) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeaderView(
                title: "Chứng chỉ Ký & Provisioning Profile",
                systemImage: "signature",
                subtitle: "embedded.mobileprovision"
            )
            if info.hasEmbeddedProvision {
                TelemetryKeyValueRow(label: "Team / Chứng chỉ", value: info.teamName ?? "Không rõ")
                TelemetryKeyValueRow(
                    label: "Enterprise Cert",
                    value: info.provisionsAllDevices ? "YES (ProvisionsAllDevices)" : "Developer / AdHoc",
                    valueColor: info.provisionsAllDevices ? CyberTheme.neonCyan : CyberTheme.textPrimary
                )
                if let exp = info.expirationDate {
                    TelemetryKeyValueRow(label: "Hết hạn", value: CyberTheme.formatTimestamp(exp))
                }
            } else {
                Text("Không tìm thấy embedded.mobileprovision (chạy ở chế độ Simulator hoặc Unsigned).")
                    .font(.system(size: 12))
                    .foregroundColor(CyberTheme.textSecondary)
            }
        }
        .cyberCard()
    }

    private func localPortsCard(_ report: SecurityAuditReport) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeaderView(
                title: "Quét cổng Backdoor Loopback (127.0.0.1)",
                systemImage: "door.left.hand.open",
                subtitle: "Kiểm tra SSH (22), Frida (27042), Reverse Shell (4444)..."
            )

            LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)], spacing: 10) {
                ForEach(report.localPorts) { port in
                    let tint: Color = port.isOpen ? CyberTheme.color(for: port.severityIfOpen) : CyberTheme.emerald
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(":\(port.port)")
                                .font(.system(size: 14, weight: .heavy, design: .monospaced))
                                .foregroundColor(tint)
                            Spacer()
                            Text(port.isOpen ? "OPEN" : "CLOSED")
                                .font(.system(size: 10, weight: .bold, design: .monospaced))
                                .foregroundColor(tint)
                        }
                        Text(port.serviceName)
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(CyberTheme.textPrimary)
                        Text(port.description)
                            .font(.system(size: 10))
                            .foregroundColor(CyberTheme.textMuted)
                            .lineLimit(2)
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(CyberTheme.elevatedSurface)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .stroke(port.isOpen ? tint.opacity(0.6) : CyberTheme.border, lineWidth: 1)
                    )
                }
            }
        }
        .cyberCard()
    }

    private func loadedDylibsCard(_ report: SecurityAuditReport) -> some View {
        let filtered = report.dylibs.filter { dylib in
            let matchesToggle = !showOnlySuspiciousDylibs || dylib.isSuspicious
            let q = dylibSearchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let matchesQuery = q.isEmpty || dylib.name.lowercased().contains(q) || dylib.path.lowercased().contains(q)
            return matchesToggle && matchesQuery
        }

        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                SectionHeaderView(
                    title: "Thư viện động trong bộ nhớ (_dyld)",
                    systemImage: "memorychip.fill",
                    subtitle: "Tổng \(report.dylibs.count) images • \(report.suspiciousDylibs.count) bất thường"
                )
                SeverityBadge(
                    severity: report.suspiciousDylibs.isEmpty ? .safe : .critical,
                    customText: report.suspiciousDylibs.isEmpty ? "SẠCH" : "\(report.suspiciousDylibs.count) LẠ"
                )
            }

            HStack {
                TextField("Tìm tên .dylib hoặc đường dẫn...", text: $dylibSearchText)
                    .font(.system(size: 12, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .padding(8)
                    .background(CyberTheme.elevatedSurface)
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

                Button {
                    showOnlySuspiciousDylibs.toggle()
                } label: {
                    Text(showOnlySuspiciousDylibs ? "Chỉ lạ" : "Tất cả")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(showOnlySuspiciousDylibs ? CyberTheme.background : CyberTheme.neonCyan)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 8)
                        .background(showOnlySuspiciousDylibs ? CyberTheme.crimson : CyberTheme.neonCyan.opacity(0.15))
                        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                }
            }

            ForEach(filtered.prefix(80)) { dylib in
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(dylib.name)
                            .font(.system(size: 12, weight: .bold, design: .monospaced))
                            .foregroundColor(dylib.isSuspicious ? CyberTheme.crimson : CyberTheme.textPrimary)
                        Spacer()
                        Text(dylib.architecture)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(CyberTheme.textMuted)
                    }
                    Text(dylib.path)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(CyberTheme.textSecondary)
                        .lineLimit(2)
                    if let reason = dylib.riskReason {
                        Text(reason)
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundColor(CyberTheme.crimson)
                    }
                }
                .padding(8)
                .background(CyberTheme.elevatedSurface)
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
            if filtered.count > 80 {
                Text("Đang hiển thị 80/\(filtered.count) thư viện — dùng bộ lọc để tra cứu cụ thể.")
                    .font(.system(size: 11))
                    .foregroundColor(CyberTheme.textMuted)
            }
        }
        .cyberCard()
    }

    private var remediationGuideCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeaderView(
                title: "Hướng dẫn Gỡ bỏ Quyền Điều Khiển & Khắc phục",
                systemImage: "lifepreserver.fill",
                subtitle: "Quy trình xử lý chuẩn khi phát hiện xâm phạm trên iPhone"
            )

            guideStep(
                number: "1",
                title: "Gỡ hồ sơ MDM & Chứng chỉ doanh nghiệp lạ",
                detail: "Vào Cài đặt > Cài đặt chung > Quản lý VPN & Thiết bị -> Xóa toàn bộ hồ sơ cấu hình (Profile) không rõ nguồn gốc và thu hồi tin cậy các chứng chỉ không thuộc tổ chức bạn biết."
            )
            guideStep(
                number: "2",
                title: "Tắt tin cậy Root CA chặn bắt TLS (MitM)",
                detail: "Vào Cài đặt > Cài đặt chung > Giới thiệu > Cài đặt tin cậy chứng nhận -> Tắt toàn bộ Root CA lạ (Charles, mitmproxy, proxy nội bộ), sau đó vào Wi-Fi đang kết nối > Định cấu hình Proxy > chọn Tắt."
            )
            guideStep(
                number: "3",
                title: "Xử lý máy bị gắn cờ Supervised / MDM không thể xóa",
                detail: "Nếu IsSupervised = true và hồ sơ khóa nút Gỡ bỏ (IsMDMUnremovable), cần sao lưu dữ liệu cá nhân thủ công (không dùng bản sao lưu iTunes/iCloud chứa cấu hình MDM), đưa máy về DFU Restore qua Finder/iTunes."
            )
            guideStep(
                number: "4",
                title: "Xử lý khi phát hiện Frida / Dylib lạ / Cổng Backdoor",
                detail: "Xóa ngay các file .ipa sideload nghi bị tiêm dylib, khởi động lại máy để xóa trạng thái jailbreak/tweak trong RAM, đổi mật khẩu Apple ID và toàn bộ tài khoản ngân hàng/email."
            )
        }
        .cyberCard(borderColor: CyberTheme.neonCyan.opacity(0.3))
    }

    private func guideStep(number: String, title: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Text(number)
                .font(.system(size: 12, weight: .heavy, design: .monospaced))
                .foregroundColor(CyberTheme.background)
                .frame(width: 22, height: 22)
                .background(CyberTheme.neonCyan)
                .clipShape(Circle())

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(CyberTheme.textPrimary)
                Text(detail)
                    .font(.system(size: 11))
                    .foregroundColor(CyberTheme.textSecondary)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(CyberTheme.elevatedSurface)
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

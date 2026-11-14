//
//  NetworkShieldView.swift
//  iShield3105
//
//  Kiểm tra Lộ IP Public, VPN Tunnel ẩn (utun/ipsec/ppp), Rò rỉ DNS & Cài đặt DoH .mobileconfig
//

import SwiftUI

struct NetworkShieldView: View {
    @ObservedObject var coordinator: SecurityDashboardCoordinator
    @ObservedObject var networkScanner: NetworkPrivacyScanner
    @ObservedObject var dohManager: DoHProfileManager

    @State private var selectedDoHProvider: DoHProviderOption = .cloudflareSecurity
    @State private var showXMLPreview = false
    @State private var shareFileURL: URL?
    @State private var showShareSheet = false
    @State private var alertError: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    scanActionBar
                    if let report = networkScanner.lastReport {
                        publicIPCard(report)
                        dnsAuditCard(report)
                        interfacesAndTunnelsCard(report)
                    }
                    dohProfileGeneratorCard
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .background(CyberTheme.background.ignoresSafeArea())
            .navigationTitle("Network & IP Shield")
            .navigationBarTitleDisplayMode(.inline)
            .sheet(isPresented: $showShareSheet) {
                if let url = shareFileURL {
                    ShareSheet(items: [url])
                }
            }
            .alert("Thông báo", isPresented: Binding(
                get: { alertError != nil },
                set: { if !$0 { alertError = nil } }
            )) {
                Button("Đóng", role: .cancel) {}
            } message: {
                Text(alertError ?? "")
            }
        }
    }

    private var scanActionBar: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Trạng thái tuyến mạng")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(CyberTheme.textPrimary)
                Text(networkScanner.lastReport?.nwPathSummary ?? "Chưa chạy quét mạng")
                    .font(.system(size: 11))
                    .foregroundColor(CyberTheme.textSecondary)
            }
            Spacer()
            Button {
                Task {
                    _ = await networkScanner.runScan()
                    coordinator.syncScoreFromCurrentReports()
                }
            } label: {
                HStack(spacing: 6) {
                    if networkScanner.isScanning {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: CyberTheme.background))
                    } else {
                        Image(systemName: "waveform.path.ecg")
                    }
                    Text(networkScanner.isScanning ? "Đang quét..." : "Quét Mạng")
                        .font(.system(size: 12, weight: .bold))
                }
                .foregroundColor(CyberTheme.background)
                .padding(.horizontal, 14)
                .padding(.vertical, 9)
                .background(CyberTheme.neonCyan)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
            .disabled(networkScanner.isScanning)
        }
        .cyberCard()
    }

    private func publicIPCard(_ report: NetworkPrivacyReport) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                SectionHeaderView(
                    title: "IP Public & Phân tích ISP",
                    systemImage: "globe.asia.australia.fill",
                    subtitle: report.publicIP?.sourceEndpoint ?? "ipinfo.io / ipify"
                )
                if let ip = report.publicIP {
                    SeverityBadge(
                        severity: ip.isRealIPExposed ? .warning : (ip.errorMessage != nil ? .info : .safe),
                        customText: ip.isRealIPExposed ? "LỘ IP THỰC" : (ip.isHostingOrVPN ? "QUA VPN/HOSTING" : "CHƯA RÕ")
                    )
                }
            }

            if let ip = report.publicIP {
                if let err = ip.errorMessage {
                    Text(err)
                        .font(.system(size: 12))
                        .foregroundColor(CyberTheme.amber)
                } else {
                    TelemetryKeyValueRow(
                        label: "IP Public",
                        value: ip.ip,
                        valueColor: ip.isRealIPExposed ? CyberTheme.amber : CyberTheme.emerald
                    )
                    TelemetryKeyValueRow(label: "Nhà mạng / ASN", value: ip.org ?? "Không rõ")
                    TelemetryKeyValueRow(
                        label: "Vị trí địa lý",
                        value: [ip.city, ip.region, ip.country].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: ", ")
                    )
                    if let hostname = ip.hostname, !hostname.isEmpty {
                        TelemetryKeyValueRow(label: "Hostname", value: hostname)
                    }
                    TelemetryKeyValueRow(
                        label: "Trạng thái Proxy/Hosting",
                        value: ip.isHostingOrVPN ? "Phát hiện nút VPN / Datacenter" : "IP dân cư / Di động trực tiếp",
                        valueColor: ip.isHostingOrVPN ? CyberTheme.emerald : CyberTheme.amber
                    )

                    if !ip.leakedHeaders.isEmpty {
                        Divider().background(CyberTheme.border)
                        Text("Cảnh báo Rò rỉ Header Proxy:")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(CyberTheme.crimson)
                        ForEach(ip.leakedHeaders.keys.sorted(), id: \.self) { k in
                            TelemetryKeyValueRow(label: k, value: ip.leakedHeaders[k] ?? "", valueColor: CyberTheme.crimson)
                        }
                    }
                }
            }
        }
        .cyberCard(borderColor: (report.publicIP?.isRealIPExposed == true) ? CyberTheme.amber.opacity(0.45) : CyberTheme.border)
    }

    private func dnsAuditCard(_ report: NetworkPrivacyReport) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                SectionHeaderView(
                    title: "Kiểm tra DNS (<resolv.h>)",
                    systemImage: "server.rack",
                    subtitle: "Đọc trực tiếp từ res_ninit() & res_getservers()"
                )
                SeverityBadge(
                    severity: report.dnsHijackSuspected ? .warning : .safe,
                    customText: report.dnsHijackSuspected ? "NGHI VẤN DNS" : "ỔN ĐỊNH"
                )
            }

            if let err = report.dnsSnapshotError {
                Text(err)
                    .font(.system(size: 12))
                    .foregroundColor(CyberTheme.amber)
            }

            if report.dnsServers.isEmpty {
                Text("Không tìm thấy máy chủ DNS đang cấu hình trong resolver state.")
                    .font(.system(size: 12))
                    .foregroundColor(CyberTheme.textSecondary)
            } else {
                ForEach(report.dnsServers) { dns in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(dns.address)
                                .font(.system(size: 13, weight: .bold, design: .monospaced))
                                .foregroundColor(CyberTheme.textPrimary)
                            Spacer()
                            SeverityBadge(severity: dns.riskLevel, customText: dns.providerName)
                        }
                        Text(dns.note)
                            .font(.system(size: 11))
                            .foregroundColor(CyberTheme.textSecondary)
                    }
                    .padding(10)
                    .background(CyberTheme.elevatedSurface)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                }
            }
        }
        .cyberCard()
    }

    private func interfacesAndTunnelsCard(_ report: NetworkPrivacyReport) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeaderView(
                title: "Giao diện mạng & Tunnel ngầm (\(report.interfaces.count))",
                systemImage: "point.3.connected.trianglepath.dotted",
                subtitle: "Quét BSD getifaddrs(): en0, pdp_ip0, utun*, ipsec*, ppp*, tun*"
            )

            if !report.suspiciousTunnels.isEmpty {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "exclamationmark.octagon.fill")
                        .foregroundColor(CyberTheme.crimson)
                    Text("Phát hiện \(report.suspiciousTunnels.count) đường hầm ảo hoạt động ngầm (\(report.suspiciousTunnels.map(\.name).joined(separator: ", "))). Nếu bạn không bật VPN, hãy kiểm tra mục Cài đặt > VPN & Quản lý thiết bị!")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(CyberTheme.crimson)
                }
                .padding(10)
                .background(CyberTheme.crimson.opacity(0.14))
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            }

            ForEach(report.interfaces) { iface in
                VStack(alignment: .leading, spacing: 5) {
                    HStack {
                        Text(iface.name)
                            .font(.system(size: 13, weight: .bold, design: .monospaced))
                            .foregroundColor(iface.isSuspiciousHiddenTunnel ? CyberTheme.crimson : CyberTheme.neonCyan)
                        Text("• \(iface.category.rawValue)")
                            .font(.system(size: 11))
                            .foregroundColor(CyberTheme.textSecondary)
                        Spacer()
                        SeverityBadge(
                            severity: iface.isSuspiciousHiddenTunnel ? .critical : (iface.isUp && iface.isRunning ? .safe : .info),
                            customText: iface.isUp && iface.isRunning ? "UP/RUNNING" : "DOWN"
                        )
                    }
                    if !iface.ipv4Addresses.isEmpty {
                        Text("IPv4: \(iface.ipv4Addresses.joined(separator: ", "))")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(CyberTheme.textPrimary)
                    }
                    if !iface.ipv6Addresses.isEmpty {
                        Text("IPv6: \(iface.ipv6Addresses.joined(separator: ", "))")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(CyberTheme.textMuted)
                            .lineLimit(2)
                    }
                    if let note = iface.tunnelAssessment {
                        Text(note)
                            .font(.system(size: 11))
                            .foregroundColor(iface.isSuspiciousHiddenTunnel ? CyberTheme.amber : CyberTheme.textSecondary)
                    }
                }
                .padding(10)
                .background(CyberTheme.elevatedSurface)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
        }
        .cyberCard()
    }

    private var dohProfileGeneratorCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeaderView(
                title: "Trình tạo Cấu hình DNS-over-HTTPS (.mobileconfig)",
                systemImage: "lock.doc.fill",
                subtitle: "Mã hóa toàn bộ truy vấn DNS hệ thống iOS chống rò rỉ & chặn tracking"
            )

            Picker("Nhà cung cấp DoH", selection: $selectedDoHProvider) {
                ForEach(DoHProviderOption.allCases) { option in
                    Text(option.rawValue).tag(option)
                }
            }
            .pickerStyle(.menu)
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(CyberTheme.elevatedSurface)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))

            VStack(alignment: .leading, spacing: 4) {
                Text(selectedDoHProvider.description)
                    .font(.system(size: 12))
                    .foregroundColor(CyberTheme.textSecondary)
                Text("DoH URL: \(selectedDoHProvider.serverURL)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(CyberTheme.neonCyan)
            }

            HStack(spacing: 10) {
                Button {
                    dohManager.installViaLocalSafari(for: selectedDoHProvider)
                } label: {
                    HStack {
                        Image(systemName: "safari.fill")
                        Text("Cài qua Safari")
                            .font(.system(size: 13, weight: .bold))
                    }
                    .foregroundColor(CyberTheme.background)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 11)
                    .background(CyberTheme.emerald)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                }

                Button {
                    do {
                        shareFileURL = try dohManager.exportTemporaryProfileURL(for: selectedDoHProvider)
                        showShareSheet = true
                    } catch {
                        alertError = error.localizedDescription
                    }
                } label: {
                    HStack {
                        Image(systemName: "square.and.arrow.up")
                        Text("Xuất File")
                            .font(.system(size: 13, weight: .bold))
                    }
                    .foregroundColor(CyberTheme.neonCyan)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 11)
                    .background(CyberTheme.neonCyan.opacity(0.15))
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                }
            }

            if let msg = dohManager.lastStatusMessage {
                Text(msg)
                    .font(.system(size: 11))
                    .foregroundColor(CyberTheme.neonCyan)
            }

            DisclosureGroup("Xem trước mã XML .mobileconfig", isExpanded: $showXMLPreview) {
                ScrollView(.horizontal, showsIndicators: true) {
                    Text(dohManager.generateMobileConfigXML(for: selectedDoHProvider))
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(CyberTheme.textSecondary)
                        .padding(.top, 8)
                }
                .frame(maxHeight: 220)
            }
            .font(.system(size: 12, weight: .semibold))
            .foregroundColor(CyberTheme.textPrimary)
        }
        .cyberCard(borderColor: CyberTheme.neonCyan.opacity(0.35))
    }
}

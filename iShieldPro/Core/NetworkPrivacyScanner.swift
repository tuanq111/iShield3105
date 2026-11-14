//
//  NetworkPrivacyScanner.swift
//  iShieldPro
//
//  Low-level BSD Interface (<ifaddrs.h>), DNS Resolver (<resolv.h>), Hidden Tunnel & IP Exposure Scanner
//

import Foundation
import Darwin
import Network
import CFNetwork

private final class NWPathContinuationGate: @unchecked Sendable {
    private let lock = NSLock()
    private var finished = false

    func tryComplete() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !finished else { return false }
        finished = true
        return true
    }
}

@MainActor
final class NetworkPrivacyScanner: ObservableObject {
    @Published private(set) var lastReport: NetworkPrivacyReport?
    @Published private(set) var isScanning = false

    nonisolated private static let trustedDNSDirectory: [String: String] = [
        "1.1.1.1": "Cloudflare DNS",
        "1.0.0.1": "Cloudflare DNS",
        "1.1.1.2": "Cloudflare Malware Block",
        "1.0.0.2": "Cloudflare Malware Block",
        "1.1.1.3": "Cloudflare Family",
        "1.0.0.3": "Cloudflare Family",
        "2606:4700:4700::1111": "Cloudflare IPv6",
        "2606:4700:4700::1001": "Cloudflare IPv6",
        "8.8.8.8": "Google Public DNS",
        "8.8.4.4": "Google Public DNS",
        "2001:4860:4860::8888": "Google IPv6",
        "2001:4860:4860::8844": "Google IPv6",
        "9.9.9.9": "Quad9 Secure DNS",
        "149.112.112.112": "Quad9 Secure DNS",
        "2620:fe::fe": "Quad9 IPv6",
        "2620:fe::9": "Quad9 IPv6",
        "94.140.14.14": "AdGuard DNS",
        "94.140.15.15": "AdGuard DNS",
        "2a10:50c0::ad1:ff": "AdGuard IPv6",
        "2a10:50c0::ad2:ff": "AdGuard IPv6",
        "76.76.2.2": "Control D Privacy DNS",
        "76.76.10.2": "Control D Privacy DNS",
        "2606:1a40::2": "Control D IPv6",
        "2606:1a40:1::2": "Control D IPv6",
        "208.67.222.222": "OpenDNS / Cisco",
        "208.67.220.220": "OpenDNS / Cisco"
    ]

    nonisolated private static let hostingOrVPNKeywords: [String] = [
        "cloudflare", "mullvad", "proton", "nordvpn", "expressvpn", "surfshark",
        "m247", "datacamp", "digitalocean", "linode", "akamai", "hetzner",
        "ovh", "vultr", "amazon", "aws", "google cloud", "oracle", "azure",
        "leaseweb", "choopa", "psychz", "fly.io", "tailscale", "wireguard",
        "vpn", "hosting", "colo", "proxy"
    ]

    func runScan() async -> NetworkPrivacyReport {
        isScanning = true
        defer { isScanning = false }

        let report: NetworkPrivacyReport = await Task.detached(priority: .userInitiated) {
            async let pathSnapshot = Self.probeNWPathSnapshot()
            async let publicIPResult = Self.fetchPublicIPAndHeaders()

            let (usesVPNHint, pathSummary) = await pathSnapshot
            let interfaces = Self.scanNetworkInterfaces(nwPathReportsVPN: usesVPNHint)
            let activeTunnels = interfaces.filter { $0.category == .virtualTunnel && $0.isUp && $0.isRunning }
            let suspiciousTunnels = activeTunnels.filter(\.isSuspiciousHiddenTunnel)

            let dnsSnap = ISContainerBridge.shared().fetchSystemDNSServers()
            let auditedDNS = Self.auditDNSServers(dnsSnap.servers)
            let hijackSuspected = auditedDNS.contains { $0.riskLevel >= .warning }

            let ipReport = await publicIPResult

            return NetworkPrivacyReport(
                scannedAt: Date(),
                interfaces: interfaces,
                activeTunnels: activeTunnels,
                suspiciousTunnels: suspiciousTunnels,
                dnsServers: auditedDNS,
                dnsSnapshotError: dnsSnap.errorMessage,
                dnsHijackSuspected: hijackSuspected,
                publicIP: ipReport,
                nwPathUsesVPN: usesVPNHint,
                nwPathSummary: pathSummary
            )
        }.value

        lastReport = report
        return report
    }

    // MARK: - 1. BSD getifaddrs() Interface & Hidden Tunnel Scanner

    nonisolated private static func scanNetworkInterfaces(nwPathReportsVPN: Bool) -> [NetworkInterfaceItem] {
        var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrPtr) == 0, let firstAddr = ifaddrPtr else {
            return []
        }
        defer { freeifaddrs(ifaddrPtr) }

        struct InterfaceAccumulator {
            var ipv4: [String] = []
            var ipv6: [String] = []
            var isUp = false
            var isRunning = false
            var isPointToPoint = false
        }

        var map: [String: InterfaceAccumulator] = [:]

        for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
            let iface = ptr.pointee
            let name = String(cString: iface.ifa_name)
            let flags = Int32(iface.ifa_flags)

            var acc = map[name] ?? InterfaceAccumulator()
            acc.isUp = acc.isUp || ((flags & IFF_UP) != 0)
            acc.isRunning = acc.isRunning || ((flags & IFF_RUNNING) != 0)
            acc.isPointToPoint = acc.isPointToPoint || ((flags & IFF_POINTOPOINT) != 0)

            if let addr = iface.ifa_addr {
                let family = addr.pointee.sa_family
                if family == UInt8(AF_INET) || family == UInt8(AF_INET6) {
                    var hostBuffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    let rc = getnameinfo(
                        addr,
                        socklen_t(addr.pointee.sa_len),
                        &hostBuffer,
                        socklen_t(hostBuffer.count),
                        nil,
                        0,
                        NI_NUMERICHOST
                    )
                    if rc == 0 {
                        let rawIP = String(cString: hostBuffer)
                        let cleanIP = rawIP.split(separator: "%").first.map(String.init) ?? rawIP
                        if family == UInt8(AF_INET) {
                            if !acc.ipv4.contains(cleanIP) {
                                acc.ipv4.append(cleanIP)
                            }
                        } else if !acc.ipv6.contains(cleanIP) {
                            acc.ipv6.append(cleanIP)
                        }
                    }
                }
            }
            map[name] = acc
        }

        // Inspect scoped proxies from CFNetwork to identify tunnel-bound interception
        let scopedInterfaces: Set<String> = {
            guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any],
                  let scoped = settings["__SCOPED__"] as? [String: Any] else {
                return []
            }
            return Set(scoped.keys)
        }()

        var items: [NetworkInterfaceItem] = []
        for (name, acc) in map {
            let category = classifyInterface(name: name)
            let hasRoutableIPv4 = acc.ipv4.contains { !$0.hasPrefix("169.254.") && $0 != "127.0.0.1" }
            let hasRoutableIPv6 = acc.ipv6.contains { !$0.hasPrefix("fe80:") && $0 != "::1" }
            let hasRoutable = hasRoutableIPv4 || hasRoutableIPv6

            var suspiciousTunnel = false
            var assessment: String?

            if category == .virtualTunnel && acc.isUp && acc.isRunning {
                let isNonAppleTunnelType = name.hasPrefix("tun") || name.hasPrefix("tap") || name.hasPrefix("ppp")
                let hasScopedProxy = scopedInterfaces.contains(name)

                if isNonAppleTunnelType {
                    suspiciousTunnel = true
                    assessment = "Giao diện \(name) bất thường trên iOS (nghi vấn tunnel ẩn hoặc proxy tool)."
                } else if hasRoutable && hasScopedProxy {
                    suspiciousTunnel = true
                    assessment = "Đường hầm \(name) đang chạy kèm cấu hình proxy SCOPED — có thể chặn bắt/định tuyến lưu lượng."
                } else if hasRoutable && !nwPathReportsVPN {
                    suspiciousTunnel = true
                    assessment = "Phát hiện đường hầm \(name) có IP định tuyến hoạt động ngầm dù đường mạng chính không báo VPN."
                } else if hasRoutable {
                    suspiciousTunnel = true
                    assessment = "Đường hầm VPN/Relay đang hoạt động (\(name)). Nếu bạn KHÔNG chủ động bật VPN, hãy kiểm tra cấu hình VPN/ứng dụng định tuyến."
                } else {
                    assessment = "Giao diện nội bộ hệ thống (chỉ có link-local / iOS service tunnel)."
                }
            }

            items.append(NetworkInterfaceItem(
                id: name,
                name: name,
                category: category,
                ipv4Addresses: acc.ipv4,
                ipv6Addresses: acc.ipv6,
                isUp: acc.isUp,
                isRunning: acc.isRunning,
                isPointToPoint: acc.isPointToPoint,
                hasRoutableIP: hasRoutable,
                isSuspiciousHiddenTunnel: suspiciousTunnel,
                tunnelAssessment: assessment
            ))
        }

        return items.sorted { lhs, rhs in
            if lhs.isSuspiciousHiddenTunnel != rhs.isSuspiciousHiddenTunnel {
                return lhs.isSuspiciousHiddenTunnel && !rhs.isSuspiciousHiddenTunnel
            }
            let priority: [NetworkInterfaceCategory: Int] = [
                .virtualTunnel: 0,
                .wifi: 1,
                .cellular: 2,
                .awdl: 3,
                .other: 4,
                .loopback: 5
            ]
            let pL = priority[lhs.category] ?? 9
            let pR = priority[rhs.category] ?? 9
            if pL != pR { return pL < pR }
            return lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
        }
    }

    nonisolated private static func classifyInterface(name: String) -> NetworkInterfaceCategory {
        if name == "en0" || name.hasPrefix("en") { return .wifi }
        if name.hasPrefix("pdp_ip") { return .cellular }
        if name.hasPrefix("utun") || name.hasPrefix("ipsec") || name.hasPrefix("ppp")
            || name.hasPrefix("tun") || name.hasPrefix("tap") || name.hasPrefix("wg") {
            return .virtualTunnel
        }
        if name == "lo0" { return .loopback }
        if name.hasPrefix("awdl") || name.hasPrefix("llw") { return .awdl }
        return .other
    }

    // MARK: - 2. NWPathMonitor Snapshot

    nonisolated private static func probeNWPathSnapshot() async -> (Bool, String) {
        await withCheckedContinuation { continuation in
            let monitor = NWPathMonitor()
            let queue = DispatchQueue(label: "com.ishield.pro.nwpath")
            let gate = NWPathContinuationGate()

            monitor.pathUpdateHandler = { path in
                guard gate.tryComplete() else { return }
                monitor.cancel()

                var parts: [String] = []
                switch path.status {
                case .satisfied: parts.append("Kết nối ổn định")
                case .unsatisfied: parts.append("Mất kết nối")
                case .requiresConnection: parts.append("Chờ thiết lập kết nối")
                @unknown default: parts.append("Trạng thái không xác định")
                }

                if path.usesInterfaceType(.wifi) { parts.append("Wi-Fi") }
                if path.usesInterfaceType(.cellular) { parts.append("Cellular") }
                if path.usesInterfaceType(.wiredEthernet) { parts.append("Ethernet") }
                if path.usesInterfaceType(.other) { parts.append("Tunnel/Other") }

                let usesVPNOrTunnel = path.availableInterfaces.contains { iface in
                    let n = iface.name
                    return n.hasPrefix("utun") || n.hasPrefix("ipsec") || n.hasPrefix("ppp")
                } || path.usesInterfaceType(.other)

                continuation.resume(returning: (usesVPNOrTunnel, parts.joined(separator: " • ")))
            }

            monitor.start(queue: queue)

            queue.asyncAfter(deadline: .now() + 1.0) {
                guard gate.tryComplete() else { return }
                monitor.cancel()
                continuation.resume(returning: (false, "Hết thời gian chờ NWPathMonitor"))
            }
        }
    }

    // MARK: - 3. DNS Hijacking Audit (<resolv.h>)

    nonisolated private static func auditDNSServers(_ servers: [String]) -> [DNSServerAuditItem] {
        servers.map { ip in
            if let knownProvider = trustedDNSDirectory[ip] {
                return DNSServerAuditItem(
                    address: ip,
                    providerName: knownProvider,
                    isTrustedKnownDNS: true,
                    isPrivateLAN: false,
                    riskLevel: .safe,
                    note: "Máy chủ DNS công cộng đáng tin cậy."
                )
            }

            if isPrivateOrLinkLocalIP(ip) {
                return DNSServerAuditItem(
                    address: ip,
                    providerName: "Router / Gateway nội bộ",
                    isTrustedKnownDNS: false,
                    isPrivateLAN: true,
                    riskLevel: .info,
                    note: "DNS cấp qua DHCP mạng Wi-Fi/nhà mạng (nên bật DoH để tránh ISP theo dõi/chèn DNS)."
                )
            }

            if ip == "127.0.0.1" || ip == "::1" {
                return DNSServerAuditItem(
                    address: ip,
                    providerName: "Local Loopback DNS Stub",
                    isTrustedKnownDNS: false,
                    isPrivateLAN: true,
                    riskLevel: .warning,
                    note: "DNS đang trỏ về tiến trình proxy/tunnel cục bộ trên máy (127.0.0.1)."
                )
            }

            return DNSServerAuditItem(
                address: ip,
                providerName: "Máy chủ DNS lạ / Không xác định",
                isTrustedKnownDNS: false,
                isPrivateLAN: false,
                riskLevel: .warning,
                note: "Cảnh báo DNS không thuộc danh sách tin cậy (nguy cơ DNS Hijacking hoặc DNS của nhà mạng/tunnel lạ)."
            )
        }
    }

    nonisolated private static func isPrivateOrLinkLocalIP(_ ip: String) -> Bool {
        if ip.hasPrefix("10.") || ip.hasPrefix("192.168.") || ip.hasPrefix("169.254.") || ip.hasPrefix("100.64.") {
            return true
        }
        if ip.hasPrefix("172.") {
            let parts = ip.split(separator: ".")
            if parts.count >= 2, let second = Int(parts[1]), (16...31).contains(second) {
                return true
            }
        }
        let lower = ip.lowercased()
        if lower.hasPrefix("fe80:") || lower.hasPrefix("fc") || lower.hasPrefix("fd") {
            return true
        }
        return false
    }

    // MARK: - 4. Public IP & Header Leak Check (ipinfo.io + ipify fallback)

    nonisolated private static func fetchPublicIPAndHeaders() async -> PublicIPInfoReport {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 10
        config.timeoutIntervalForResource = 12
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData

        let session = URLSession(configuration: config)
        defer { session.finishTasksAndInvalidate() }

        // Primary: ipinfo.io/json
        if let ipInfoURL = URL(string: "https://ipinfo.io/json") {
            var req = URLRequest(url: ipInfoURL)
            req.setValue("application/json", forHTTPHeaderField: "Accept")
            req.setValue("iShieldPro/2.0", forHTTPHeaderField: "User-Agent")

            if let (data, response) = try? await session.data(for: req),
               let httpResp = response as? HTTPURLResponse,
               (200...299).contains(httpResp.statusCode),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let ip = json["ip"] as? String {

                let headers = extractHeaders(from: httpResp)
                let leaked = detectLeakedProxyHeaders(in: headers)
                let org = json["org"] as? String
                let hostname = json["hostname"] as? String
                let privacy = json["privacy"] as? [String: Any]
                let isVPNOrHosting = isLikelyVPNOrHosting(org: org, hostname: hostname, privacy: privacy)

                return PublicIPInfoReport(
                    ip: ip,
                    hostname: hostname,
                    city: json["city"] as? String,
                    region: json["region"] as? String,
                    country: json["country"] as? String,
                    org: org,
                    timezone: json["timezone"] as? String,
                    isHostingOrVPN: isVPNOrHosting,
                    leakedHeaders: leaked,
                    observedResponseHeaders: headers,
                    sourceEndpoint: "https://ipinfo.io/json",
                    fetchedAt: Date(),
                    errorMessage: nil
                )
            }
        }

        // Fallback: api.ipify.org?format=json
        if let ipifyURL = URL(string: "https://api.ipify.org?format=json") {
            var req = URLRequest(url: ipifyURL)
            req.setValue("application/json", forHTTPHeaderField: "Accept")

            do {
                let (data, response) = try await session.data(for: req)
                if let httpResp = response as? HTTPURLResponse,
                   let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let ip = json["ip"] as? String {
                    let headers = extractHeaders(from: httpResp)
                    let leaked = detectLeakedProxyHeaders(in: headers)
                    return PublicIPInfoReport(
                        ip: ip,
                        hostname: nil,
                        city: nil,
                        region: nil,
                        country: nil,
                        org: "Chưa rõ ISP (Fallback api.ipify.org)",
                        timezone: nil,
                        isHostingOrVPN: false,
                        leakedHeaders: leaked,
                        observedResponseHeaders: headers,
                        sourceEndpoint: "https://api.ipify.org?format=json",
                        fetchedAt: Date(),
                        errorMessage: nil
                    )
                }
            } catch {
                return PublicIPInfoReport(
                    ip: "",
                    hostname: nil,
                    city: nil,
                    region: nil,
                    country: nil,
                    org: nil,
                    timezone: nil,
                    isHostingOrVPN: false,
                    leakedHeaders: [:],
                    observedResponseHeaders: [:],
                    sourceEndpoint: "https://ipinfo.io/json",
                    fetchedAt: Date(),
                    errorMessage: "Không thể truy vấn IP Public: \(error.localizedDescription)"
                )
            }
        }

        return PublicIPInfoReport(
            ip: "",
            hostname: nil,
            city: nil,
            region: nil,
            country: nil,
            org: nil,
            timezone: nil,
            isHostingOrVPN: false,
            leakedHeaders: [:],
            observedResponseHeaders: [:],
            sourceEndpoint: "https://ipinfo.io/json",
            fetchedAt: Date(),
            errorMessage: "Không nhận được phản hồi hợp lệ từ máy chủ kiểm tra IP."
        )
    }

    nonisolated private static func extractHeaders(from response: HTTPURLResponse) -> [String: String] {
        var result: [String: String] = [:]
        for (k, v) in response.allHeaderFields {
            result[String(describing: k)] = String(describing: v)
        }
        return result
    }

    nonisolated private static func detectLeakedProxyHeaders(in headers: [String: String]) -> [String: String] {
        let sensitiveNames = ["via", "x-forwarded-for", "forwarded", "x-real-ip", "proxy-connection", "x-proxy-id", "client-ip"]
        var leaked: [String: String] = [:]
        for (k, v) in headers {
            if sensitiveNames.contains(k.lowercased()) {
                leaked[k] = v
            }
        }
        return leaked
    }

    nonisolated private static func isLikelyVPNOrHosting(
        org: String?,
        hostname: String?,
        privacy: [String: Any]?
    ) -> Bool {
        if let privacy {
            if (privacy["vpn"] as? Bool == true)
                || (privacy["proxy"] as? Bool == true)
                || (privacy["tor"] as? Bool == true)
                || (privacy["relay"] as? Bool == true)
                || (privacy["hosting"] as? Bool == true) {
                return true
            }
        }

        let combined = [org ?? "", hostname ?? ""].joined(separator: " ").lowercased()
        return hostingOrVPNKeywords.contains { combined.contains($0) }
    }
}

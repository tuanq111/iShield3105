//
//  DoHProfileManager.swift
//  iShield3105
//
//  Generates iOS DNS-over-HTTPS (.mobileconfig) Profiles & Serves via Local Loopback for 1-Tap Safari Install
//

import Foundation
import Network
import UIKit

@MainActor
final class DoHProfileManager: ObservableObject {
    @Published private(set) var isServingProfile = false
    @Published private(set) var lastStatusMessage: String?

    private var listener: NWListener?
    private var autoStopTask: Task<Void, Never>?
    private let listenerQueue = DispatchQueue(label: "com.ishield3105.dohserver")

    func generateMobileConfigXML(for provider: DoHProviderOption) -> String {
        let payloadUUID = UUID().uuidString.uppercased()
        let rootUUID = UUID().uuidString.uppercased()
        let identifierSlug = provider.serverURL
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "/", with: ".")
            .replacingOccurrences(of: "[^A-Za-z0-9.-]", with: "", options: .regularExpression)

        let addressesXML = provider.serverAddresses
            .map { "                    <string>\(xmlEscaped($0))</string>" }
            .joined(separator: "\n")

        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>PayloadContent</key>
            <array>
                <dict>
                    <key>DNSSettings</key>
                    <dict>
                        <key>DNSProtocol</key>
                        <string>HTTPS</string>
                        <key>ServerURL</key>
                        <string>\(xmlEscaped(provider.serverURL))</string>
                        <key>ServerAddresses</key>
                        <array>
        \(addressesXML)
                        </array>
                    </dict>
                    <key>PayloadDescription</key>
                    <string>Cấu hình DNS-over-HTTPS chống rò rỉ DNS và chặn tên miền theo dõi bởi iShield3105</string>
                    <key>PayloadDisplayName</key>
                    <string>\(xmlEscaped(provider.rawValue)) (DoH)</string>
                    <key>PayloadIdentifier</key>
                    <string>com.ishield3105.dnsSettings.\(identifierSlug)</string>
                    <key>PayloadType</key>
                    <string>com.apple.dnsSettings.managed</string>
                    <key>PayloadUUID</key>
                    <string>\(payloadUUID)</string>
                    <key>PayloadVersion</key>
                    <integer>1</integer>
                    <key>ProhibitDisablement</key>
                    <false/>
                </dict>
            </array>
            <key>PayloadDescription</key>
            <string>\(xmlEscaped(provider.description))</string>
            <key>PayloadDisplayName</key>
            <string>iShield3105 Shield - \(xmlEscaped(provider.rawValue))</string>
            <key>PayloadIdentifier</key>
            <string>com.ishield3105.profile.doh.\(identifierSlug)</string>
            <key>PayloadOrganization</key>
            <string>iShield3105 Local Security</string>
            <key>PayloadRemovalDisallowed</key>
            <false/>
            <key>PayloadType</key>
            <string>Configuration</string>
            <key>PayloadUUID</key>
            <string>\(rootUUID)</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
        </plist>
        """
    }

    func exportTemporaryProfileURL(for provider: DoHProviderOption) throws -> URL {
        let xml = generateMobileConfigXML(for: provider)
        guard let data = xml.data(using: .utf8) else {
            throw NSError(domain: "iShield3105.DoH", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Không thể mã hóa dữ liệu UTF-8 cho .mobileconfig"
            ])
        }

        let safeName: String
        switch provider {
        case .cloudflareStandard: safeName = "iShield3105-Cloudflare-1111.mobileconfig"
        case .cloudflareSecurity: safeName = "iShield3105-Cloudflare-MalwareBlock.mobileconfig"
        case .quad9Recommended: safeName = "iShield3105-Quad9-DoH.mobileconfig"
        case .adguardTracking: safeName = "iShield3105-AdGuard-DoH.mobileconfig"
        }

        let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent(safeName)
        try data.write(to: tempURL, options: .atomic)
        lastStatusMessage = "Đã tạo tệp cấu hình \(safeName)"
        return tempURL
    }

    func installViaLocalSafari(for provider: DoHProviderOption) {
        stopServer()

        let xml = generateMobileConfigXML(for: provider)
        guard let payloadData = xml.data(using: .utf8) else {
            lastStatusMessage = "Lỗi tạo dữ liệu .mobileconfig."
            return
        }

        do {
            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true
            params.requiredLocalEndpoint = NWEndpoint.hostPort(host: .ipv4(.loopback), port: .any)
            let newListener = try NWListener(using: params)

            newListener.stateUpdateHandler = { [weak self] state in
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    switch state {
                    case .ready:
                        if let port = newListener.port?.rawValue,
                           let url = URL(string: "http://127.0.0.1:\(port)/ishield-doh.mobileconfig") {
                            self.isServingProfile = true
                            self.lastStatusMessage = "Đang mở Safari để tải cấu hình DoH (http://127.0.0.1:\(port))..."
                            UIApplication.shared.open(url)
                        }
                    case .failed(let error):
                        self.isServingProfile = false
                        self.lastStatusMessage = "Không thể khởi tạo local server cài profile: \(error.localizedDescription)"
                    case .cancelled:
                        self.isServingProfile = false
                    default:
                        break
                    }
                }
            }

            newListener.newConnectionHandler = { connection in
                Self.handleLoopbackHTTPConnection(connection, payload: payloadData)
            }

            listener = newListener
            newListener.start(queue: listenerQueue)

            // Automatically shut down loopback listener after 90 seconds
            autoStopTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: 90_000_000_000)
                guard !Task.isCancelled else { return }
                self?.stopServer()
            }
        } catch {
            lastStatusMessage = "Lỗi tạo local HTTP server: \(error.localizedDescription)"
        }
    }

    func stopServer() {
        autoStopTask?.cancel()
        autoStopTask = nil
        listener?.cancel()
        listener = nil
        isServingProfile = false
    }

    nonisolated private static func handleLoopbackHTTPConnection(_ connection: NWConnection, payload: Data) {
        connection.start(queue: DispatchQueue.global(qos: .userInitiated))
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { _, _, _, _ in
            let header = [
                "HTTP/1.1 200 OK",
                "Content-Type: application/x-apple-aspen-config",
                "Content-Disposition: attachment; filename=\"iShield3105-DoH.mobileconfig\"",
                "Content-Length: \(payload.count)",
                "Cache-Control: no-store",
                "Connection: close",
                "",
                ""
            ].joined(separator: "\r\n")

            var responseData = Data(header.utf8)
            responseData.append(payload)

            connection.send(content: responseData, completion: .contentProcessed { _ in
                connection.cancel()
            })
        }
    }

    private func xmlEscaped(_ input: String) -> String {
        input
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
    }
}

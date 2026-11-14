//
//  CyberTheme.swift
//  iShield3105
//

import SwiftUI

enum CyberTheme {
    static let background = Color(red: 0.027, green: 0.043, blue: 0.071)       // #070B12
    static let cardSurface = Color(red: 0.059, green: 0.086, blue: 0.141)      // #0F1624
    static let elevatedSurface = Color(red: 0.082, green: 0.122, blue: 0.196)  // #151F32
    static let border = Color.white.opacity(0.08)

    static let neonCyan = Color(red: 0.0, green: 0.898, blue: 1.0)             // #00E5FF
    static let emerald = Color(red: 0.0, green: 0.902, blue: 0.463)            // #00E676
    static let amber = Color(red: 1.0, green: 0.702, blue: 0.0)                // #FFB300
    static let crimson = Color(red: 1.0, green: 0.231, blue: 0.361)            // #FF3B5C

    static let textPrimary = Color.white
    static let textSecondary = Color(white: 0.68)
    static let textMuted = Color(white: 0.48)

    static func color(for severity: RiskSeverity) -> Color {
        switch severity {
        case .safe: return emerald
        case .info: return neonCyan
        case .warning: return amber
        case .critical: return crimson
        }
    }

    static func formatBytes(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    static func formatTimestamp(_ date: Date?) -> String {
        guard let date else { return "Chưa quét" }
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss dd/MM/yyyy"
        return formatter.string(from: date)
    }
}

struct CyberCardModifier: ViewModifier {
    var borderColor: Color = CyberTheme.border

    func body(content: Content) -> some View {
        content
            .padding(14)
            .background(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(CyberTheme.cardSurface)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .stroke(borderColor, lineWidth: 1)
            )
    }
}

extension View {
    func cyberCard(borderColor: Color = CyberTheme.border) -> some View {
        modifier(CyberCardModifier(borderColor: borderColor))
    }
}

//
//  SecurityComponents.swift
//  iShield3105
//

import SwiftUI
import UIKit

struct SeverityBadge: View {
    let severity: RiskSeverity
    var customText: String? = nil

    var body: some View {
        let tint = CyberTheme.color(for: severity)
        Text(customText ?? severity.label)
            .font(.system(size: 10, weight: .bold, design: .monospaced))
            .foregroundColor(tint)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(
                Capsule(style: .continuous)
                    .fill(tint.opacity(0.16))
            )
            .overlay(
                Capsule(style: .continuous)
                    .stroke(tint.opacity(0.45), lineWidth: 1)
            )
    }
}

struct SectionHeaderView: View {
    let title: String
    let systemImage: String
    var subtitle: String? = nil

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: systemImage)
                .font(.system(size: 15, weight: .semibold))
                .foregroundColor(CyberTheme.neonCyan)
                .frame(width: 28, height: 28)
                .background(CyberTheme.neonCyan.opacity(0.14))
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 15, weight: .bold))
                    .foregroundColor(CyberTheme.textPrimary)
                if let subtitle {
                    Text(subtitle)
                        .font(.system(size: 11))
                        .foregroundColor(CyberTheme.textSecondary)
                }
            }
            Spacer()
        }
    }
}

struct SecurityScoreRing: View {
    let score: Int
    let severity: RiskSeverity
    let isScanning: Bool

    var body: some View {
        let tint = CyberTheme.color(for: severity)
        let progress = Double(max(0, min(100, score))) / 100.0

        ZStack {
            Circle()
                .stroke(Color.white.opacity(0.08), lineWidth: 14)

            Circle()
                .trim(from: 0, to: progress)
                .stroke(
                    AngularGradient(
                        gradient: Gradient(colors: [tint.opacity(0.5), tint]),
                        center: .center
                    ),
                    style: StrokeStyle(lineWidth: 14, lineCap: .round)
                )
                .rotationEffect(.degrees(-90))
                .animation(.spring(response: 0.6, dampingFraction: 0.8), value: score)

            VStack(spacing: 4) {
                if isScanning {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: CyberTheme.neonCyan))
                        .scaleEffect(1.2)
                    Text("ĐANG QUÉT")
                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                        .foregroundColor(CyberTheme.neonCyan)
                } else {
                    Text("\(score)")
                        .font(.system(size: 42, weight: .heavy, design: .monospaced))
                        .foregroundColor(tint)
                    Text("ĐIỂM AN TOÀN")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundColor(CyberTheme.textSecondary)
                    SeverityBadge(severity: severity)
                        .padding(.top, 2)
                }
            }
        }
        .frame(width: 170, height: 170)
    }
}

struct TelemetryKeyValueRow: View {
    let label: String
    let value: String
    var valueColor: Color = CyberTheme.textPrimary
    var monospacedValue: Bool = true

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text(label)
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(CyberTheme.textSecondary)
                .frame(minWidth: 100, alignment: .leading)
            Spacer(minLength: 4)
            Text(value)
                .font(.system(size: 12, weight: .semibold, design: monospacedValue ? .monospaced : .default))
                .foregroundColor(valueColor)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
        .padding(.vertical, 3)
    }
}

struct AlertBannerCard: View {
    let alert: SecurityAlertBanner
    let onTapInspect: () -> Void

    var body: some View {
        let tint = CyberTheme.color(for: alert.severity)
        Button(action: onTapInspect) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: alert.severity == .critical ? "exclamationmark.shield.fill" : "exclamationmark.triangle.fill")
                    .font(.system(size: 20))
                    .foregroundColor(tint)
                    .padding(.top, 2)

                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(alert.category.rawValue.uppercased())
                            .font(.system(size: 10, weight: .bold, design: .monospaced))
                            .foregroundColor(tint)
                        Spacer()
                        Image(systemName: "chevron.right")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(CyberTheme.textMuted)
                    }
                    Text(alert.title)
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(CyberTheme.textPrimary)
                        .multilineTextAlignment(.leading)
                    Text(alert.detail)
                        .font(.system(size: 12))
                        .foregroundColor(CyberTheme.textSecondary)
                        .multilineTextAlignment(.leading)
                }
            }
            .padding(12)
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(tint.opacity(0.12))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(tint.opacity(0.55), lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
    }
}

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

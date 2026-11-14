//
//  SecurityComponents.swift
//  iShieldPro
//
//  Reusable Commercial Security Dashboard Components & Remediation Controls
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

struct ProtectionPill: View {
    let label: String
    let isActive: Bool
    let activeColor: Color

    var body: some View {
        HStack(spacing: 5) {
            Circle()
                .fill(isActive ? activeColor : CyberTheme.textMuted)
                .frame(width: 7, height: 7)
            Text(label)
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundColor(isActive ? activeColor : CyberTheme.textSecondary)
                .lineLimit(1)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 5)
        .background(
            Capsule(style: .continuous)
                .fill(isActive ? activeColor.opacity(0.14) : CyberTheme.elevatedSurface)
        )
        .overlay(
            Capsule(style: .continuous)
                .stroke(isActive ? activeColor.opacity(0.45) : CyberTheme.border, lineWidth: 1)
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
                    Text("CHỈ SỐ AN TOÀN")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundColor(CyberTheme.textSecondary)
                    SeverityBadge(severity: severity)
                        .padding(.top, 2)
                }
            }
        }
        .frame(width: 168, height: 168)
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

struct RemediationTaskCard: View {
    let task: RemediationTask
    let onExecute: () -> Void

    var body: some View {
        let tint = task.isResolved ? CyberTheme.emerald : CyberTheme.color(for: task.severity)
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: task.isResolved ? "checkmark.shield.fill" : (task.canAutoFix ? "bolt.shield.fill" : "gear.badge.xmark"))
                    .font(.system(size: 18))
                    .foregroundColor(tint)

                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(task.category.rawValue.uppercased())
                            .font(.system(size: 9, weight: .bold, design: .monospaced))
                            .foregroundColor(tint)
                        Spacer()
                        SeverityBadge(
                            severity: task.isResolved ? .safe : task.severity,
                            customText: task.isResolved ? "ĐÃ KHẮC PHỤC" : (task.canAutoFix ? "TỰ ĐỘNG XỬ LÝ" : "HƯỚNG DẪN iOS")
                        )
                    }
                    Text(task.title)
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(CyberTheme.textPrimary)
                    Text(task.detail)
                        .font(.system(size: 11))
                        .foregroundColor(CyberTheme.textSecondary)
                }
            }

            if !task.isResolved {
                HStack {
                    Spacer()
                    Button(action: onExecute) {
                        HStack(spacing: 6) {
                            Image(systemName: task.canAutoFix ? "wand.and.stars" : "arrow.up.forward.app")
                                .font(.system(size: 11, weight: .bold))
                            Text(task.actionLabel)
                                .font(.system(size: 12, weight: .bold))
                        }
                        .foregroundColor(task.canAutoFix ? CyberTheme.background : CyberTheme.textPrimary)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 7)
                        .background(task.canAutoFix ? tint : CyberTheme.cardSurface)
                        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                        .overlay(
                            RoundedRectangle(cornerRadius: 8, style: .continuous)
                                .stroke(tint.opacity(0.6), lineWidth: task.canAutoFix ? 0 : 1)
                        )
                    }
                }
            }
        }
        .padding(11)
        .background(CyberTheme.elevatedSurface)
        .clipShape(RoundedRectangle(cornerRadius: 11, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 11, style: .continuous)
                .stroke(tint.opacity(0.35), lineWidth: 1)
        )
    }
}

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

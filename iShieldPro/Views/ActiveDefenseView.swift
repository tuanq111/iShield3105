//
//  ActiveDefenseView.swift
//  iShieldPro
//
//  Anti-Eavesdropping (Audio/Call/Acoustic Jammer/Mic Lock), Anti-Tracking (Clipboard/URL/EXIF)
//  and Anti-Background Exfiltration Console
//

import SwiftUI
import PhotosUI
import UIKit

struct ActiveDefenseView: View {
    @ObservedObject var coordinator: SecurityDashboardCoordinator
    @ObservedObject var defense: ActiveDefenseEngine

    @State private var manualURLInput = ""
    @State private var sanitizedOutputText: String?
    @State private var removedParamsList: [String] = []
    @State private var selectedPhotoItem: PhotosPickerItem?
    @State private var isStrippingPhoto = false
    @State private var shareCleanImageURL: URL?
    @State private var showPhotoShareSheet = false
    @State private var localAlertMessage: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    antiEavesdroppingCard
                    antiTrackingCard
                    photoMetadataStripperCard
                    antiBackgroundGuardCard
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .background(CyberTheme.background.ignoresSafeArea())
            .navigationTitle("Chống Gián Điệp")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        defense.refreshAudioAudit()
                        defense.sampleBackgroundAndTrafficGuard(maxUptimeDaysWarning: coordinator.policy.maxUptimeDaysBeforeWarning)
                        coordinator.syncScoreFromCurrentReports()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                            .foregroundColor(CyberTheme.neonCyan)
                    }
                }
            }
            .sheet(isPresented: $showPhotoShareSheet) {
                if let url = shareCleanImageURL {
                    ShareSheet(items: [url])
                }
            }
            .onChange(of: selectedPhotoItem) { newItem in
                guard let newItem else { return }
                Task { await handlePickedPhoto(newItem) }
            }
            .alert("iShield Pro", isPresented: Binding(
                get: { localAlertMessage != nil },
                set: { if !$0 { localAlertMessage = nil } }
            )) {
                Button("Đóng", role: .cancel) {}
            } message: {
                Text(localAlertMessage ?? "")
            }
        }
    }

    // MARK: - 1. Anti-Eavesdropping (Chống Nghe Lén)

    private var antiEavesdroppingCard: some View {
        let audit = defense.audioAudit
        return VStack(alignment: .leading, spacing: 12) {
            HStack {
                SectionHeaderView(
                    title: "Chống Nghe Lén Micro & Cuộc Gọi",
                    systemImage: "ear.trianglebadge.exclamationmark",
                    subtitle: "AVAudioSession • CallKit Sentinel • Acoustic Jammer"
                )
                SeverityBadge(
                    severity: (defense.isAcousticJammerActive || defense.isMicLockActive)
                        ? .safe
                        : (audit?.audioRiskLevel ?? .info),
                    customText: defense.isMicLockActive
                        ? "KHÓA MICRO"
                        : (defense.isAcousticJammerActive ? "ĐANG PHÁT NHIỄU" : (audit?.audioRiskLevel.label ?? "GIÁM SÁT"))
                )
            }

            if let audit {
                TelemetryKeyValueRow(
                    label: "Cuộc gọi / VoIP nền",
                    value: audit.activeCallsSummary,
                    valueColor: audit.activeCallDetected ? CyberTheme.crimson : CyberTheme.emerald,
                    monospacedValue: false
                )
                TelemetryKeyValueRow(
                    label: "Âm thanh app khác",
                    value: audit.isOtherAudioPlaying ? "ĐANG HOẠT ĐỘNG NỀN" : "Im lặng",
                    valueColor: audit.isOtherAudioPlaying ? CyberTheme.amber : CyberTheme.emerald
                )
                TelemetryKeyValueRow(
                    label: "Micro Bluetooth",
                    value: audit.bluetoothMicConnected ? "PHÁT HIỆN THIẾT BỊ BT" : "Không kết nối",
                    valueColor: audit.bluetoothMicConnected ? CyberTheme.amber : CyberTheme.emerald
                )
                TelemetryKeyValueRow(
                    label: "Quyền Micro iOS",
                    value: audit.micPermissionLabel,
                    valueColor: CyberTheme.textPrimary,
                    monospacedValue: false
                )
                if !audit.activeInputs.isEmpty {
                    TelemetryKeyValueRow(
                        label: "Ngõ vào đang hoạt động",
                        value: audit.activeInputs.map(\.portName).joined(separator: ", "),
                        valueColor: CyberTheme.neonCyan
                    )
                }
                Text("Sự kiện tuyến âm thanh: \(audit.lastEventSummary)")
                    .font(.system(size: 11))
                    .foregroundColor(CyberTheme.textSecondary)
            }

            Divider().background(CyberTheme.border)

            // Active Guard 1: Acoustic Jammer
            VStack(alignment: .leading, spacing: 8) {
                Button {
                    defense.toggleAcousticJammer()
                    coordinator.syncScoreFromCurrentReports()
                } label: {
                    HStack {
                        Image(systemName: defense.isAcousticJammerActive ? "speaker.slash.fill" : "waveform.path")
                        Text(defense.isAcousticJammerActive
                            ? "Tắt Phát Nhiễu Chống Nghe Lén"
                            : "Bật Phát Nhiễu Âm Thanh Bảo Vệ Hội Thoại")
                            .font(.system(size: 13, weight: .bold))
                    }
                    .foregroundColor(CyberTheme.background)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 11)
                    .background(defense.isAcousticJammerActive ? CyberTheme.amber : CyberTheme.neonCyan)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                }

                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text("Cường độ nhiễu dải giọng nói")
                            .font(.system(size: 11))
                            .foregroundColor(CyberTheme.textSecondary)
                        Spacer()
                        Text("\(Int(defense.jammerVolume * 100))%")
                            .font(.system(size: 11, weight: .bold, design: .monospaced))
                            .foregroundColor(CyberTheme.neonCyan)
                    }
                    Slider(value: $defense.jammerVolume, in: 0.05...0.60)
                        .tint(CyberTheme.neonCyan)
                }
            }

            // Active Guard 2: Hardware Mic Preemption Lock
            Button {
                Task {
                    await defense.toggleMicPreemptionLock()
                    coordinator.syncScoreFromCurrentReports()
                }
            } label: {
                HStack {
                    Image(systemName: defense.isMicLockActive ? "mic.slash.fill" : "mic.fill")
                    Text(defense.isMicLockActive
                        ? "Nhả Khóa Micro Phần Cứng"
                        : "Chiếm Quyền Khóa Micro (Chặn Bluetooth HFP)")
                        .font(.system(size: 13, weight: .bold))
                }
                .foregroundColor(defense.isMicLockActive ? CyberTheme.background : CyberTheme.textPrimary)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 11)
                .background(defense.isMicLockActive ? CyberTheme.emerald : CyberTheme.elevatedSurface)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .stroke(CyberTheme.emerald.opacity(0.6), lineWidth: defense.isMicLockActive ? 0 : 1)
                )
            }

            Text("Gợi ý bảo mật: Chế độ Phát Nhiễu ngắt các phiên phát âm thanh nền và che phủ giọng nói không cần cấp quyền Micro; Chế độ Khóa Micro chiếm độc quyền phần cứng thu (không ghi/lưu âm thanh) và vô hiệu hóa ngõ vào Bluetooth HFP trong suốt cuộc họp mật.")
                .font(.system(size: 10))
                .foregroundColor(CyberTheme.textMuted)
        }
        .cyberCard(borderColor: (defense.isAcousticJammerActive || defense.isMicLockActive) ? CyberTheme.emerald.opacity(0.5) : CyberTheme.border)
    }

    // MARK: - 2. Anti-Tracking: Clipboard, URL Tracker & IDFA

    private var antiTrackingCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeaderView(
                title: "Chống Theo Dõi Clipboard, Link & IDFA",
                systemImage: "eye.slash.fill",
                subtitle: "Phát hiện mã bí mật rò rỉ, gỡ tham số utm/fbclid/gclid và chặn IDFA"
            )

            if let bg = defense.backgroundSnapshot {
                TelemetryKeyValueRow(
                    label: "App Tracking (ATT)",
                    value: bg.attStatusLabel,
                    valueColor: bg.idfaExposed ? CyberTheme.crimson : CyberTheme.emerald,
                    monospacedValue: false
                )
                TelemetryKeyValueRow(
                    label: "Mã quảng cáo IDFA",
                    value: bg.idfaExposed ? "ĐANG MỞ (Rủi ro theo dõi)" : "ĐÃ VÔ HIỆU HÓA (0000...)",
                    valueColor: bg.idfaExposed ? CyberTheme.crimson : CyberTheme.emerald
                )
            }

            HStack(spacing: 10) {
                Button {
                    defense.scanAndCleanClipboard(autoCleanTrackers: true)
                    coordinator.syncScoreFromCurrentReports()
                } label: {
                    HStack {
                        Image(systemName: "doc.on.clipboard.fill")
                        Text("Quét & Gỡ Link Bẩn")
                            .font(.system(size: 12, weight: .bold))
                    }
                    .foregroundColor(CyberTheme.background)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(CyberTheme.neonCyan)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                }

                Button {
                    defense.wipeClipboardCompletely()
                    coordinator.syncScoreFromCurrentReports()
                } label: {
                    HStack {
                        Image(systemName: "trash.fill")
                        Text("Xóa Trắng Clipboard")
                            .font(.system(size: 12, weight: .bold))
                    }
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(CyberTheme.crimson)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                }
            }

            if let clip = defense.lastClipboardScan {
                VStack(alignment: .leading, spacing: 4) {
                    Text(clip.statusNote)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(clip.detectedSensitivePatterns.isEmpty ? CyberTheme.emerald : CyberTheme.crimson)
                    if !clip.detectedTrackingParams.isEmpty {
                        Text("Tham số đã phát hiện: \(clip.detectedTrackingParams.joined(separator: ", "))")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(CyberTheme.amber)
                    }
                }
                .padding(9)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(CyberTheme.elevatedSurface)
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            }

            Divider().background(CyberTheme.border)

            Text("Bộ khử tham số theo dõi URL thủ công (UTM, fbclid, igshid, ttclid...):")
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(CyberTheme.textSecondary)

            HStack(spacing: 8) {
                TextField("Dán link nghi có tracker...", text: $manualURLInput)
                    .font(.system(size: 12, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .padding(9)
                    .background(CyberTheme.elevatedSurface)
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

                Button("Khử ngay") {
                    let result = defense.sanitizeInputURLString(manualURLInput)
                    sanitizedOutputText = result.cleaned
                    removedParamsList = result.removedParams
                }
                .font(.system(size: 12, weight: .bold))
                .foregroundColor(CyberTheme.background)
                .padding(.horizontal, 12)
                .padding(.vertical, 9)
                .background(CyberTheme.emerald)
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                .disabled(manualURLInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }

            if let sanitizedOutputText {
                VStack(alignment: .leading, spacing: 6) {
                    Text(removedParamsList.isEmpty
                         ? "Không tìm thấy tham số tracking nào trong URL."
                         : "Đã gỡ \(removedParamsList.count) tham số: \(removedParamsList.joined(separator: ", "))")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(removedParamsList.isEmpty ? CyberTheme.textSecondary : CyberTheme.emerald)
                    Text(sanitizedOutputText)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(CyberTheme.neonCyan)
                        .textSelection(.enabled)
                    Button("Chép Link Sạch") {
                        UIPasteboard.general.string = sanitizedOutputText
                        localAlertMessage = "Đã chép link sạch vào Clipboard."
                    }
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(CyberTheme.neonCyan)
                }
                .padding(9)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(CyberTheme.elevatedSurface)
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
        }
        .cyberCard()
    }

    // MARK: - 3. Photo EXIF / GPS Metadata Stripper

    private var photoMetadataStripperCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeaderView(
                title: "Tẩy Tọa Độ GPS & EXIF Ảnh Trước Khi Gửi",
                systemImage: "photo.badge.checkmark.fill",
                subtitle: "Xóa tọa độ vị trí nhà ở, model iPhone & dấu vết thời gian khỏi ảnh"
            )

            PhotosPicker(selection: $selectedPhotoItem, matching: .images) {
                HStack {
                    if isStrippingPhoto {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: CyberTheme.background))
                    } else {
                        Image(systemName: "photo.on.rectangle.angled")
                    }
                    Text(isStrippingPhoto ? "Đang tẩy metadata ảnh..." : "Chọn Ảnh để Xóa GPS & EXIF")
                        .font(.system(size: 13, weight: .bold))
                }
                .foregroundColor(CyberTheme.background)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 11)
                .background(CyberTheme.neonCyan)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
            .disabled(isStrippingPhoto)

            if let strip = defense.lastPhotoStrip {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Đã xóa sạch siêu dữ liệu: \(strip.removedTags.joined(separator: ", "))")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(CyberTheme.emerald)
                    Text("Dung lượng: \(CyberTheme.formatBytes(Int64(strip.originalBytes))) -> \(CyberTheme.formatBytes(Int64(strip.cleanedBytes)))")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(CyberTheme.textSecondary)
                    Button {
                        shareCleanImageURL = strip.cleanedFileURL
                        showPhotoShareSheet = true
                    } label: {
                        Label("Lưu / Chia sẻ Ảnh Sạch", systemImage: "square.and.arrow.up")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(CyberTheme.background)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(CyberTheme.emerald)
                            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                    }
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(CyberTheme.elevatedSurface)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
        }
        .cyberCard()
    }

    // MARK: - 4. Anti-Background & Live Kernel Network Exfiltration Watchdog

    private var antiBackgroundGuardCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                SectionHeaderView(
                    title: "Chống Chạy Ngầm & Giám Sát Đẩy Dữ Liệu Nền",
                    systemImage: "waveform.path.ecg.rectangle.fill",
                    subtitle: "Đo byte kernel (<net/if.h>), Background Refresh, Nhiệt độ & Uptime"
                )
                SeverityBadge(
                    severity: defense.backgroundSnapshot?.backgroundSpikeAlert != nil ? .warning : (defense.isWatchdogRunning ? .safe : .info),
                    customText: defense.isWatchdogRunning ? "LIVE 2s" : "TẠM DỪNG"
                )
            }

            Toggle("Watchdog Giám sát thời gian thực (mỗi 2 giây)", isOn: $coordinator.policy.continuousWatchdogEnabled)
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(CyberTheme.textPrimary)
                .tint(CyberTheme.emerald)

            if let bg = defense.backgroundSnapshot {
                if let spike = bg.backgroundSpikeAlert {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(CyberTheme.crimson)
                        Text(spike)
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(CyberTheme.crimson)
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(CyberTheme.crimson.opacity(0.14))
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                }

                TelemetryKeyValueRow(
                    label: "Làm mới nền iOS",
                    value: bg.backgroundRefreshStatusLabel,
                    valueColor: bg.backgroundRefreshEnabled ? CyberTheme.amber : CyberTheme.emerald,
                    monospacedValue: false
                )
                TelemetryKeyValueRow(
                    label: "Nhiệt độ thiết bị",
                    value: bg.thermalStateLabel,
                    valueColor: bg.thermalElevated ? CyberTheme.crimson : CyberTheme.emerald,
                    monospacedValue: false
                )
                TelemetryKeyValueRow(
                    label: "Thời gian từ lúc Reboot",
                    value: String(format: "%.1f giờ (%.1f ngày)", bg.uptimeHours, bg.uptimeHours / 24.0),
                    valueColor: bg.needsRebootRecommended ? CyberTheme.amber : CyberTheme.emerald
                )
                TelemetryKeyValueRow(
                    label: "RAM / Luồng tiến trình",
                    value: "\(CyberTheme.formatBytes(Int64(bg.residentMemoryBytes))) • \(bg.activeThreadCount) threads"
                )
                TelemetryKeyValueRow(
                    label: "Mật mã / Sinh trắc học",
                    value: bg.passcodeOrBiometricEnabled ? "ĐÃ BẬT BẢO VỆ" : "CHƯA BẬT MẬT MÃ!",
                    valueColor: bg.passcodeOrBiometricEnabled ? CyberTheme.emerald : CyberTheme.crimson
                )

                if bg.backgroundRefreshEnabled {
                    Button {
                        coordinator.openIOSSettings()
                    } label: {
                        HStack {
                            Image(systemName: "gearshape.fill")
                            Text("Mở Cài đặt iOS để tắt Làm mới ứng dụng trong nền")
                                .font(.system(size: 12, weight: .bold))
                        }
                        .foregroundColor(CyberTheme.neonCyan)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 9)
                        .background(CyberTheme.neonCyan.opacity(0.14))
                        .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
                    }
                }

                Divider().background(CyberTheme.border)

                Text("Lưu lượng Giao diện Mạng Real-Time (Kernel RX/TX)")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(CyberTheme.textSecondary)

                ForEach(bg.trafficRates.prefix(6)) { rate in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text("\(rate.interfaceName) (\(rate.category.rawValue))")
                                .font(.system(size: 12, weight: .bold, design: .monospaced))
                                .foregroundColor(rate.isBackgroundSpikeSuspected ? CyberTheme.crimson : CyberTheme.neonCyan)
                            Spacer()
                            Text("↑ \(CyberTheme.formatRateBytesPerSec(rate.txBytesPerSec)) | ↓ \(CyberTheme.formatRateBytesPerSec(rate.rxBytesPerSec))")
                                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                .foregroundColor(rate.isBackgroundSpikeSuspected ? CyberTheme.crimson : CyberTheme.textPrimary)
                        }
                        Text("Tổng phiên: ↑ \(CyberTheme.formatBytes(Int64(rate.totalTxBytes))) • ↓ \(CyberTheme.formatBytes(Int64(rate.totalRxBytes)))")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(CyberTheme.textMuted)
                    }
                    .padding(9)
                    .background(CyberTheme.elevatedSurface)
                    .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
                }
            }
        }
        .cyberCard()
    }

    private func handlePickedPhoto(_ item: PhotosPickerItem) async {
        isStrippingPhoto = true
        defer { isStrippingPhoto = false }
        do {
            guard let data = try await item.loadTransferable(type: Data.self) else {
                localAlertMessage = "Không thể đọc dữ liệu ảnh được chọn."
                return
            }
            let result = try defense.stripImageMetadata(imageData: data, originalFileName: "selected-photo.jpg")
            localAlertMessage = "Đã tẩy sạch GPS & EXIF thành công (\(result.removedTags.count) nhóm metadata). Bấm nút Lưu / Chia sẻ Ảnh Sạch để xuất ảnh."
        } catch {
            localAlertMessage = "Lỗi xử lý ảnh: \(error.localizedDescription)"
        }
    }
}

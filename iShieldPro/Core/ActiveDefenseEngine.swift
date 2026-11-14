//
//  ActiveDefenseEngine.swift
//  iShieldPro
//
//  Commercial Anti-Eavesdropping (Audio/Call/Bluetooth/Jammer), Anti-Tracking (Clipboard/URL/EXIF/ATT),
//  and Anti-Background Exfiltration Engine
//

import Foundation
@preconcurrency import AVFoundation
import CallKit
import UIKit
import ImageIO
import UniformTypeIdentifiers
import AppTrackingTransparency
import AdSupport
import LocalAuthentication

private final class AcousticSynthesizerCore: @unchecked Sendable {
    private let lock = NSLock()
    private var _gain: Float = 0.22
    private var prngState: UInt32 = 0x6C8E9CF5
    private var b0: Float = 0
    private var b1: Float = 0
    private var b2: Float = 0
    private var smooth: Float = 0

    func setGain(_ newValue: Float) {
        lock.lock()
        _gain = max(0.02, min(0.65, newValue))
        lock.unlock()
    }

    func currentGain() -> Float {
        lock.lock()
        let val = _gain
        lock.unlock()
        return val
    }

    func fill(frameCount: Int, bufferList: UnsafeMutableAudioBufferListPointer) {
        lock.lock()
        let targetGain = _gain
        var localState = prngState
        var lb0 = b0
        var lb1 = b1
        var lb2 = b2
        var lSmooth = smooth

        for frame in 0..<frameCount {
            // Fast xorshift32 deterministic PRNG for real-time audio callback safety
            var x = localState
            x ^= x << 13
            x ^= x >> 17
            x ^= x << 5
            localState = x == 0 ? 0x13579BDF : x

            let white = (Float(Int32(bitPattern: localState)) / Float(Int32.max))
            // 3-pole pink/speech-band acoustic masking filter
            lb0 = 0.99765 * lb0 + white * 0.0990460
            lb1 = 0.96300 * lb1 + white * 0.2965164
            lb2 = 0.57000 * lb2 + white * 1.0526913
            let pink = (lb0 + lb1 + lb2 + white * 0.1848) * 0.16
            lSmooth = lSmooth * 0.55 + pink * 0.45
            let sample = max(-0.85, min(0.85, lSmooth * targetGain))

            for buf in bufferList {
                guard let mData = buf.mData else { continue }
                let samples = mData.assumingMemoryBound(to: Float.self)
                samples[frame] = sample
            }
        }

        prngState = localState
        b0 = lb0
        b1 = lb1
        b2 = lb2
        smooth = lSmooth
        lock.unlock()
    }
}

private final class CallObserverBridge: NSObject, CXCallObserverDelegate, @unchecked Sendable {
    private let observer = CXCallObserver()
    private let onUpdate: @Sendable () -> Void

    init(onUpdate: @escaping @Sendable () -> Void) {
        self.onUpdate = onUpdate
        super.init()
        observer.setDelegate(self, queue: DispatchQueue.main)
    }

    func callObserver(_ callObserver: CXCallObserver, callChanged call: CXCall) {
        onUpdate()
    }

    func snapshot() -> (hasActiveCall: Bool, summary: String) {
        let activeCalls = observer.calls.filter { !$0.hasEnded }
        guard !activeCalls.isEmpty else {
            return (false, "Không có cuộc gọi / VoIP nền đang hoạt động")
        }
        let descriptions = activeCalls.map { call -> String in
            let dir = call.isOutgoing ? "Gọi đi" : "Gọi đến"
            let state = call.hasConnected ? "Đã kết nối" : (call.isOnHold ? "Đang giữ" : "Đang đổ chuông")
            return "\(dir) (\(state))"
        }
        return (true, descriptions.joined(separator: ", "))
    }
}

private final class DefenseLifecycleBag: @unchecked Sendable {
    private let lock = NSLock()
    private var tokens: [NSObjectProtocol] = []
    private var watchdogTask: Task<Void, Never>?

    func addToken(_ token: NSObjectProtocol) {
        lock.lock()
        tokens.append(token)
        lock.unlock()
    }

    func replaceWatchdogTask(_ task: Task<Void, Never>?) {
        lock.lock()
        watchdogTask?.cancel()
        watchdogTask = task
        lock.unlock()
    }

    deinit {
        lock.lock()
        let oldTokens = tokens
        tokens.removeAll()
        let task = watchdogTask
        watchdogTask = nil
        lock.unlock()

        task?.cancel()
        for token in oldTokens {
            NotificationCenter.default.removeObserver(token)
        }
    }
}

@MainActor
final class ActiveDefenseEngine: ObservableObject {
    @Published private(set) var audioAudit: AudioEavesdropAudit?
    @Published private(set) var lastClipboardScan: ClipboardScanResult?
    @Published private(set) var lastPhotoStrip: PhotoPrivacyStripResult?
    @Published private(set) var backgroundSnapshot: BackgroundGuardSnapshot?
    @Published private(set) var isWatchdogRunning = false
    @Published private(set) var isAcousticJammerActive = false
    @Published private(set) var isMicLockActive = false
    @Published private(set) var statusMessage: String?
    @Published var jammerVolume: Float = 0.22 {
        didSet {
            synthesizerCore.setGain(jammerVolume)
        }
    }

    private let lifecycleBag = DefenseLifecycleBag()
    private let synthesizerCore = AcousticSynthesizerCore()
    private var callObserverBridge: CallObserverBridge?
    private var audioEngine: AVAudioEngine?
    private var sourceNode: AVAudioSourceNode?
    private var hasInstalledInputTap = false
    private var previousSamples: [String: (rx: UInt64, tx: UInt64)] = [:]
    private var previousSampleDate: Date?
    private var lastAudioEventText = "Đang theo dõi tuyến âm thanh thời gian thực."
    private var configuredMaxUptimeDays = 7

    var onThreatDetected: ((SecurityEventEntry) -> Void)?

    nonisolated private static let trackingQueryParameters: Set<String> = [
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
        "fbclid", "gclid", "gbraid", "wbraid", "ttclid", "igshid", "igsh", "mc_eid", "mc_cid",
        "_hsenc", "_hsmi", "si", "spm", "yclid", "mibextid", "ref_src", "ref_url", "wickedid", "_ga"
    ]

    init() {
        setupAudioAndCallObservers()
        refreshAudioAudit()
        sampleBackgroundAndTrafficGuard()
    }

    // MARK: - Observers & Continuous Watchdog

    private func setupAudioAndCallObservers() {
        callObserverBridge = CallObserverBridge { [weak self] in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.lastAudioEventText = "Phát hiện thay đổi trạng thái cuộc gọi hệ thống (CallKit)."
                self.refreshAudioAudit()
                if self.audioAudit?.activeCallDetected == true {
                    self.onThreatDetected?(SecurityEventEntry(
                        category: .antiSpying,
                        severity: .critical,
                        actionTaken: "Phát hiện cuộc gọi đang mở",
                        title: "Cuộc gọi / VoIP đang kích hoạt micro",
                        detail: self.audioAudit?.activeCallsSummary ?? "Có phiên cuộc gọi chưa kết thúc."
                    ))
                }
            }
        }

        let nc = NotificationCenter.default
        lifecycleBag.addToken(nc.addObserver(
            forName: AVAudioSession.routeChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            let reasonRaw = notification.userInfo?[AVAudioSessionRouteChangeReasonKey] as? UInt ?? 0
            Task { @MainActor [weak self] in
                guard let self else { return }
                let reason = AVAudioSession.RouteChangeReason(rawValue: reasonRaw) ?? .unknown
                self.lastAudioEventText = "Tuyến âm thanh thay đổi (\(Self.describeRouteChange(reason)))."
                self.refreshAudioAudit()
            }
        })

        lifecycleBag.addToken(nc.addObserver(
            forName: AVAudioSession.interruptionNotification,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            let typeRaw = notification.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt ?? 0
            Task { @MainActor [weak self] in
                guard let self else { return }
                let type = AVAudioSession.InterruptionType(rawValue: typeRaw) ?? .ended
                if type == .began {
                    self.lastAudioEventText = "Cảnh báo: Tiến trình khác vừa ngắt/chiếm phiên âm thanh!"
                    if self.isAcousticJammerActive || self.isMicLockActive {
                        self.onThreatDetected?(SecurityEventEntry(
                            category: .antiSpying,
                            severity: .warning,
                            actionTaken: "Ghi nhận chiếm dụng AudioSession",
                            title: "Tiến trình khác cố chiếm tuyến âm thanh",
                            detail: "AVAudioSession bị gián đoạn khi chế độ bảo vệ micro đang bật."
                        ))
                    }
                } else {
                    self.lastAudioEventText = "Phiên âm thanh được khôi phục."
                }
                self.refreshAudioAudit()
            }
        })

        lifecycleBag.addToken(nc.addObserver(
            forName: AVAudioSession.silenceSecondaryAudioHintNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.lastAudioEventText = "Phát hiện tín hiệu âm thanh nền từ ứng dụng khác."
                self?.refreshAudioAudit()
            }
        })
    }

    func setContinuousWatchdog(enabled: Bool) {
        if enabled {
            guard !isWatchdogRunning else { return }
            isWatchdogRunning = true
            let task = Task { [weak self] in
                while !Task.isCancelled {
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                    guard !Task.isCancelled else { break }
                    await MainActor.run { [weak self] in
                        guard let self else { return }
                        self.sampleBackgroundAndTrafficGuard(maxUptimeDaysWarning: self.configuredMaxUptimeDays)
                        self.refreshAudioAudit()
                    }
                }
            }
            lifecycleBag.replaceWatchdogTask(task)
        } else {
            isWatchdogRunning = false
            lifecycleBag.replaceWatchdogTask(nil)
        }
    }

    // MARK: - 1. Anti-Eavesdropping Audit & Active Guards

    func refreshAudioAudit() {
        let session = AVAudioSession.sharedInstance()
        let activeInputs = (session.currentRoute.inputs).map { Self.mapPort($0) }
        let availableInputs = (session.availableInputs ?? []).map { Self.mapPort($0) }
        let bluetoothConnected = activeInputs.contains(where: \.isBluetooth)
            || availableInputs.contains(where: \.isBluetooth)

        let callState = callObserverBridge?.snapshot() ?? (false, "Chưa khởi tạo CallKit")
        let perm = Self.currentMicPermissionLabel()

        var deviceTypes: [AVCaptureDevice.DeviceType] = [.builtInWideAngleCamera, .builtInUltraWideCamera]
        if #available(iOS 17.0, *) {
            deviceTypes.append(.microphone)
            deviceTypes.append(.external)
        } else {
            deviceTypes.append(.builtInMicrophone)
        }
        let discovery = AVCaptureDevice.DiscoverySession(
            deviceTypes: deviceTypes,
            mediaType: nil,
            position: .unspecified
        )
        let captureNames = discovery.devices.map { dev in
            if #available(iOS 17.0, *), dev.deviceType == .external {
                return "[Ngoại vi] \(dev.localizedName)"
            }
            return dev.localizedName
        }

        let isOtherAudio = session.isOtherAudioPlaying
        let secondarySilenced = session.secondaryAudioShouldBeSilencedHint

        var risk: RiskSeverity = .safe
        if callState.hasActiveCall && !isMicLockActive {
            risk = .critical
        } else if bluetoothConnected && !isMicLockActive {
            risk = .warning
        } else if isOtherAudio || secondarySilenced {
            risk = .warning
        }

        audioAudit = AudioEavesdropAudit(
            auditedAt: Date(),
            isOtherAudioPlaying: isOtherAudio,
            secondaryAudioSilenced: secondarySilenced,
            activeCallDetected: callState.hasActiveCall,
            activeCallsSummary: callState.summary,
            activeInputs: activeInputs,
            availableInputs: availableInputs,
            externalCaptureDevices: captureNames,
            micPermissionLabel: perm.label,
            bluetoothMicConnected: bluetoothConnected,
            isAcousticJammerActive: isAcousticJammerActive,
            isMicLockActive: isMicLockActive,
            audioRiskLevel: risk,
            lastEventSummary: lastAudioEventText
        )
    }

    func toggleAcousticJammer() {
        if isAcousticJammerActive {
            stopAudioGuards()
            lastAudioEventText = "Đã tắt bộ phát nhiễu âm thanh bảo vệ hội thoại."
            refreshAudioAudit()
            return
        }

        startAudioGuardEngine(claimMicrophoneLock: false)
    }

    func toggleMicPreemptionLock() async {
        if isMicLockActive {
            stopAudioGuards()
            lastAudioEventText = "Đã nhả khóa micro phần cứng."
            refreshAudioAudit()
            return
        }

        let granted = await Self.requestMicrophoneAccess()
        guard granted else {
            statusMessage = "Bạn chưa cấp quyền Micro trong Cài đặt iOS nên không thể bật chế độ chiếm quyền khóa phần cứng. Bạn vẫn có thể dùng Bộ Phát Nhiễu Chống Nghe Lén (không cần quyền Micro)."
            refreshAudioAudit()
            return
        }

        startAudioGuardEngine(claimMicrophoneLock: true)
    }

    private func startAudioGuardEngine(claimMicrophoneLock: Bool) {
        stopAudioGuards()
        synthesizerCore.setGain(jammerVolume)

        let session = AVAudioSession.sharedInstance()
        do {
            if claimMicrophoneLock {
                // Deliberately omit .allowBluetoothHFP so hidden Bluetooth headset mics cannot silently hijack input
                try session.setCategory(.playAndRecord, mode: .measurement, options: [.defaultToSpeaker])
            } else {
                // Omitting .mixWithOthers forces iOS to interrupt/pause background audio spies
                try session.setCategory(.playback, mode: .default, options: [])
            }
            try session.setActive(true)
        } catch {
            statusMessage = "Không thể kích hoạt AudioSession bảo vệ: \(error.localizedDescription)"
            refreshAudioAudit()
            return
        }

        let engine = AVAudioEngine()
        let mainMixer = engine.mainMixerNode
        let format = mainMixer.outputFormat(forBus: 0)
        let synth = synthesizerCore

        if !claimMicrophoneLock {
            let node = Self.makeAcousticJammerNode(format: format, synth: synth)
            engine.attach(node)
            engine.connect(node, to: mainMixer, format: format)
            sourceNode = node
        } else {
            // Claim active input pipeline while dropping all audio buffers immediately (never records or stores audio)
            let inputNode = engine.inputNode
            let inputFormat = inputNode.outputFormat(forBus: 0)
            if inputFormat.channelCount > 0 && inputFormat.sampleRate > 0 {
                Self.installZeroRetentionTap(on: inputNode, format: inputFormat)
                hasInstalledInputTap = true
            }
            mainMixer.outputVolume = 0
        }

        do {
            try engine.start()
            audioEngine = engine
            isAcousticJammerActive = !claimMicrophoneLock
            isMicLockActive = claimMicrophoneLock
            lastAudioEventText = claimMicrophoneLock
                ? "Đang khóa độc quyền Micro phần cứng & chặn mic Bluetooth HFP."
                : "Đang phát nhiễu dải giọng nói & ngắt các phiên âm thanh nền."
            statusMessage = lastAudioEventText
            onThreatDetected?(SecurityEventEntry(
                category: .antiSpying,
                severity: .safe,
                actionTaken: claimMicrophoneLock ? "Bật Khóa Micro" : "Bật Phát Nhiễu Chống Nghe Lén",
                title: claimMicrophoneLock ? "Khóa phần cứng Micro đã kích hoạt" : "Lá chắn Nhiễu Âm Thanh đã kích hoạt",
                detail: lastAudioEventText
            ))
        } catch {
            stopAudioGuards()
            statusMessage = "Lỗi khởi động AVAudioEngine: \(error.localizedDescription)"
        }

        refreshAudioAudit()
    }

    func stopAudioGuards() {
        if let engine = audioEngine {
            if hasInstalledInputTap {
                engine.inputNode.removeTap(onBus: 0)
                hasInstalledInputTap = false
            }
            engine.stop()
            if let node = sourceNode {
                engine.detach(node)
            }
        }
        sourceNode = nil
        audioEngine = nil
        isAcousticJammerActive = false
        isMicLockActive = false
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }

    nonisolated private static func makeAcousticJammerNode(
        format: AVAudioFormat,
        synth: AcousticSynthesizerCore
    ) -> AVAudioSourceNode {
        AVAudioSourceNode(format: format) { _, _, frameCount, audioBufferList -> OSStatus in
            let abl = UnsafeMutableAudioBufferListPointer(audioBufferList)
            synth.fill(frameCount: Int(frameCount), bufferList: abl)
            return noErr
        }
    }

    nonisolated private static func installZeroRetentionTap(
        on inputNode: AVAudioInputNode,
        format: AVAudioFormat
    ) {
        inputNode.installTap(onBus: 0, bufferSize: 1024, format: format) { _, _ in
            // Zero-retention live hardware preemption lock
        }
    }

    // MARK: - 2. Anti-Tracking: Clipboard, URL Sanitizer & EXIF/GPS Stripper

    func wipeClipboardCompletely() {
        UIPasteboard.general.items = []
        lastClipboardScan = ClipboardScanResult(
            scannedAt: Date(),
            hasContent: false,
            detectedSensitivePatterns: [],
            detectedTrackingParams: [],
            originalPreview: nil,
            sanitizedText: nil,
            wasCleaned: true,
            statusNote: "Đã xóa trắng toàn bộ dữ liệu trong Clipboard (không để lộ chuỗi cho app khác đọc ngầm)."
        )
        statusMessage = "Đã xóa sạch Clipboard hệ thống."
        onThreatDetected?(SecurityEventEntry(
            category: .antiSpying,
            severity: .safe,
            actionTaken: "Xóa Clipboard",
            title: "Đã xóa dữ liệu nhạy cảm khỏi Clipboard",
            detail: "Ghi đè UIPasteboard.general.items = [] để ngăn ứng dụng chạy nền đọc trộm."
        ))
    }

    func scanAndCleanClipboard(autoCleanTrackers: Bool = true) {
        let pb = UIPasteboard.general
        guard pb.hasStrings || pb.hasURLs else {
            lastClipboardScan = ClipboardScanResult(
                scannedAt: Date(),
                hasContent: false,
                detectedSensitivePatterns: [],
                detectedTrackingParams: [],
                originalPreview: nil,
                sanitizedText: nil,
                wasCleaned: false,
                statusNote: "Clipboard hiện đang trống."
            )
            return
        }

        guard let rawText = pb.string, !rawText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            lastClipboardScan = ClipboardScanResult(
                scannedAt: Date(),
                hasContent: false,
                detectedSensitivePatterns: [],
                detectedTrackingParams: [],
                originalPreview: nil,
                sanitizedText: nil,
                wasCleaned: false,
                statusNote: "Clipboard không chứa chuỗi văn bản."
            )
            return
        }

        let sensitive = Self.detectSensitivePatterns(in: rawText)
        let (cleanedURLText, strippedParams) = Self.stripTrackingParametersFromText(rawText)
        var didClean = false
        var note = "Không phát hiện tham số theo dõi hoặc khóa nhạy cảm."

        if autoCleanTrackers && !strippedParams.isEmpty, let cleanedURLText {
            pb.string = cleanedURLText
            didClean = true
            note = "Đã tự động gỡ \(strippedParams.count) tham số theo dõi (\(strippedParams.joined(separator: ", "))) khỏi link trong Clipboard."
            onThreatDetected?(SecurityEventEntry(
                category: .antiSpying,
                severity: .safe,
                actionTaken: "Gỡ Tracker Link",
                title: "Làm sạch liên kết theo dõi trong Clipboard",
                detail: note
            ))
        } else if !sensitive.isEmpty {
            note = "Cảnh báo: Clipboard đang chứa dữ liệu nhạy cảm (\(sensitive.joined(separator: ", "))). Hãy bấm Xóa Clipboard ngay!"
        } else if !strippedParams.isEmpty {
            note = "Phát hiện \(strippedParams.count) tham số theo dõi trong liên kết."
        }

        let preview = rawText.count > 90 ? String(rawText.prefix(87)) + "..." : rawText
        lastClipboardScan = ClipboardScanResult(
            scannedAt: Date(),
            hasContent: true,
            detectedSensitivePatterns: sensitive,
            detectedTrackingParams: strippedParams,
            originalPreview: preview,
            sanitizedText: cleanedURLText,
            wasCleaned: didClean,
            statusNote: note
        )
        statusMessage = note
    }

    func sanitizeInputURLString(_ rawInput: String) -> (cleaned: String, removedParams: [String]) {
        let (cleaned, removed) = Self.stripTrackingParametersFromText(rawInput)
        return (cleaned ?? rawInput, removed)
    }

    func stripImageMetadata(imageData: Data, originalFileName: String = "photo.jpg") throws -> PhotoPrivacyStripResult {
        guard let source = CGImageSourceCreateWithData(imageData as CFData, nil),
              let cgImage = CGImageSourceCreateImageAtIndex(source, 0, nil) else {
            throw NSError(domain: "iShieldPro.Privacy", code: 101, userInfo: [
                NSLocalizedDescriptionKey: "Không thể giải mã tệp ảnh được chọn."
            ])
        }

        let props = (CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any]) ?? [:]
        var removedTags: [String] = []
        if props[kCGImagePropertyGPSDictionary] != nil { removedTags.append("GPS Vị trí & Độ cao") }
        if props[kCGImagePropertyExifDictionary] != nil { removedTags.append("EXIF Thời gian & Thông số ống kính") }
        if props[kCGImagePropertyTIFFDictionary] != nil { removedTags.append("TIFF Tên thiết bị & OS") }
        if props[kCGImagePropertyIPTCDictionary] != nil { removedTags.append("IPTC Tác giả / Từ khóa") }
        if props["{MakerApple}" as CFString] != nil { removedTags.append("Apple MakerNote") }
        if removedTags.isEmpty {
            removedTags.append("Đã chuẩn hóa lại pixel (không còn metadata ẩn)")
        }

        let outData = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(outData, UTType.jpeg.identifier as CFString, 1, nil) else {
            throw NSError(domain: "iShieldPro.Privacy", code: 102, userInfo: [
                NSLocalizedDescriptionKey: "Không thể tạo luồng xuất ảnh JPEG sạch."
            ])
        }

        var destProps: [CFString: Any] = [
            kCGImageDestinationLossyCompressionQuality: 0.92,
            kCGImagePropertyGPSDictionary: kCFNull,
            kCGImagePropertyExifDictionary: kCFNull,
            kCGImagePropertyTIFFDictionary: kCFNull,
            kCGImagePropertyIPTCDictionary: kCFNull,
            "{MakerApple}" as CFString: kCFNull
        ]
        if let orientation = props[kCGImagePropertyOrientation] {
            destProps[kCGImagePropertyOrientation] = orientation
        }

        CGImageDestinationAddImage(dest, cgImage, destProps as CFDictionary)
        guard CGImageDestinationFinalize(dest) else {
            throw NSError(domain: "iShieldPro.Privacy", code: 103, userInfo: [
                NSLocalizedDescriptionKey: "Không thể đóng gói ảnh đã xóa EXIF."
            ])
        }

        let baseName = URL(fileURLWithPath: originalFileName).deletingPathExtension().lastPathComponent
        let cleanName = "\(baseName.isEmpty ? "CleanPhoto" : baseName)-NoEXIF.jpg"
        let cleanURL = FileManager.default.temporaryDirectory.appendingPathComponent(cleanName)
        let resultData = outData as Data
        try resultData.write(to: cleanURL, options: .atomic)

        let result = PhotoPrivacyStripResult(
            originalFileName: originalFileName,
            removedTags: removedTags,
            originalBytes: imageData.count,
            cleanedBytes: resultData.count,
            cleanedFileURL: cleanURL,
            strippedAt: Date()
        )
        lastPhotoStrip = result
        onThreatDetected?(SecurityEventEntry(
            category: .antiSpying,
            severity: .safe,
            actionTaken: "Xóa EXIF/GPS Ảnh",
            title: "Đã tẩy dấu vết EXIF & GPS khỏi ảnh",
            detail: "Đã gỡ: \(removedTags.joined(separator: ", "))."
        ))
        return result
    }

    // MARK: - 3. Anti-Background & Kernel Traffic Exfiltration Monitor

    func sampleBackgroundAndTrafficGuard(maxUptimeDaysWarning: Int = 7) {
        configuredMaxUptimeDays = maxUptimeDaysWarning
        let bridge = ISContainerBridge.shared()
        let rawSamples = bridge.fetchNetworkTrafficSamples()
        let procSnap = bridge.fetchProcessTelemetry()

        let now = Date()
        let elapsed = max(0.25, now.timeIntervalSince(previousSampleDate ?? now.addingTimeInterval(-1.0)))

        var rates: [InterfaceTrafficRate] = []
        var spikeAlert: String?

        var newSampleDict: [String: (rx: UInt64, tx: UInt64)] = [:]
        for sample in rawSamples {
            let name = sample.interfaceName
            let category = Self.classifyInterface(name: name)
            guard category == .wifi || category == .cellular || category == .virtualTunnel else {
                continue
            }
            guard sample.isUp || sample.receivedBytes > 0 || sample.sentBytes > 0 else {
                continue
            }

            newSampleDict[name] = (sample.receivedBytes, sample.sentBytes)
            let prev = previousSamples[name]

            var rxPerSec: Double = 0
            var txPerSec: Double = 0
            if let prev, previousSampleDate != nil {
                let deltaRx = sample.receivedBytes >= prev.rx ? (sample.receivedBytes - prev.rx) : 0
                let deltaTx = sample.sentBytes >= prev.tx ? (sample.sentBytes - prev.tx) : 0
                rxPerSec = Double(deltaRx) / elapsed
                txPerSec = Double(deltaTx) / elapsed
            }

            let isSpike = txPerSec > 350 * 1024 // > 350 KB/s sustained outbound burst
            if isSpike && category == .virtualTunnel {
                spikeAlert = "Phát hiện luồng tải lên bất thường (\(Int(txPerSec / 1024)) KB/s) qua tunnel \(name)!"
            } else if isSpike && spikeAlert == nil {
                spikeAlert = "Lưu lượng tải lên cao (\(Int(txPerSec / 1024)) KB/s) trên giao diện \(name)."
            }

            rates.append(InterfaceTrafficRate(
                id: name,
                interfaceName: name,
                category: category,
                totalRxBytes: sample.receivedBytes,
                totalTxBytes: sample.sentBytes,
                rxBytesPerSec: rxPerSec,
                txBytesPerSec: txPerSec,
                isBackgroundSpikeSuspected: isSpike
            ))
        }

        previousSamples = newSampleDict
        previousSampleDate = now

        rates.sort { a, b in
            if a.isBackgroundSpikeSuspected != b.isBackgroundSpikeSuspected {
                return a.isBackgroundSpikeSuspected && !b.isBackgroundSpikeSuspected
            }
            return a.totalTxBytes > b.totalTxBytes
        }

        let bgStatus = UIApplication.shared.backgroundRefreshStatus
        let bgEnabled = (bgStatus == .available)
        let bgLabel: String
        switch bgStatus {
        case .available: bgLabel = "ĐANG BẬT (Nền chạy tự do)"
        case .denied: bgLabel = "ĐÃ TẮT (Hạn chế chạy ngầm)"
        case .restricted: bgLabel = "BỊ GIỚI HẠN HỆ THỐNG"
        @unknown default: bgLabel = "Không rõ"
        }

        let thermal = ProcessInfo.processInfo.thermalState
        let thermalLabel: String
        let thermalElevated: Bool
        switch thermal {
        case .nominal:
            thermalLabel = "Bình thường"
            thermalElevated = false
        case .fair:
            thermalLabel = "Hơi ấm (Fair)"
            thermalElevated = false
        case .serious:
            thermalLabel = "Nóng cao bất thường (Serious)"
            thermalElevated = true
        case .critical:
            thermalLabel = "Quá nhiệt nghiêm trọng (Critical)"
            thermalElevated = true
        @unknown default:
            thermalLabel = "Không rõ"
            thermalElevated = false
        }

        let uptimeHours = ProcessInfo.processInfo.systemUptime / 3600.0
        let needsReboot = uptimeHours > Double(max(1, maxUptimeDaysWarning) * 24)

        let laContext = LAContext()
        var authError: NSError?
        let passcodeEnabled = laContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: &authError)

        let attStatus = ATTrackingManager.trackingAuthorizationStatus
        let attLabel: String
        switch attStatus {
        case .notDetermined: attLabel = "Chưa hỏi quyền (Khóa IDFA)"
        case .restricted: attLabel = "Bị hạn chế (An toàn)"
        case .denied: attLabel = "Đã từ chối theo dõi (An toàn)"
        case .authorized: attLabel = "ĐÃ CHO PHÉP THEO DÕI"
        @unknown default: attLabel = "Không rõ"
        }
        let idfaUUID = ASIdentifierManager.shared().advertisingIdentifier.uuidString
        let idfaExposed = (attStatus == .authorized) && idfaUUID != "00000000-0000-0000-0000-000000000000"

        backgroundSnapshot = BackgroundGuardSnapshot(
            sampledAt: now,
            backgroundRefreshStatusLabel: bgLabel,
            backgroundRefreshEnabled: bgEnabled,
            thermalStateLabel: thermalLabel,
            thermalElevated: thermalElevated,
            isLowPowerMode: ProcessInfo.processInfo.isLowPowerModeEnabled,
            uptimeHours: uptimeHours,
            needsRebootRecommended: needsReboot,
            residentMemoryBytes: procSnap.residentMemoryBytes,
            activeThreadCount: Int(procSnap.activeThreadCount),
            passcodeOrBiometricEnabled: passcodeEnabled,
            attStatusLabel: attLabel,
            idfaExposed: idfaExposed,
            trafficRates: rates,
            backgroundSpikeAlert: spikeAlert
        )
    }

    // MARK: - Helpers

    private static func mapPort(_ port: AVAudioSessionPortDescription) -> AudioRouteInputInfo {
        let isBT = port.portType == .bluetoothHFP || port.portType == .bluetoothLE || port.portType == .bluetoothA2DP
        let isExt = port.portType == .usbAudio || port.portType == .carAudio
        return AudioRouteInputInfo(
            id: port.uid,
            portName: port.portName,
            portType: port.portType.rawValue,
            isBluetooth: isBT,
            isExternalAccessory: isExt
        )
    }

    private static func describeRouteChange(_ reason: AVAudioSession.RouteChangeReason) -> String {
        switch reason {
        case .newDeviceAvailable: return "Thiết bị âm thanh mới kết nối"
        case .oldDeviceUnavailable: return "Thiết bị âm thanh ngắt kết nối"
        case .categoryChange: return "Thay đổi chế độ AudioSession"
        case .override: return "Hệ thống ghi đè tuyến âm thanh"
        case .wakeFromSleep: return "Thức dậy từ chế độ ngủ"
        case .noSuitableRouteForCategory: return "Không tìm thấy tuyến phù hợp"
        case .routeConfigurationChange: return "Đổi cấu hình tuyến"
        default: return "Thay đổi tuyến"
        }
    }

    private static func currentMicPermissionLabel() -> (granted: Bool, denied: Bool, label: String) {
        if #available(iOS 17.0, *) {
            switch AVAudioApplication.shared.recordPermission {
            case .granted: return (true, false, "Đã cấp (Cẩn trọng app nền)")
            case .denied: return (false, true, "Đã chặn ở mức iOS (An toàn)")
            case .undetermined: return (false, false, "Chưa cấp quyền cho iShield Pro")
            @unknown default: return (false, false, "Không xác định")
            }
        } else {
            switch AVAudioSession.sharedInstance().recordPermission {
            case .granted: return (true, false, "Đã cấp (Cẩn trọng app nền)")
            case .denied: return (false, true, "Đã chặn ở mức iOS (An toàn)")
            case .undetermined: return (false, false, "Chưa cấp quyền cho iShield Pro")
            @unknown default: return (false, false, "Không xác định")
            }
        }
    }

    private static func requestMicrophoneAccess() async -> Bool {
        if #available(iOS 17.0, *) {
            return await AVAudioApplication.requestRecordPermission()
        } else {
            return await withCheckedContinuation { continuation in
                AVAudioSession.sharedInstance().requestRecordPermission { allowed in
                    continuation.resume(returning: allowed)
                }
            }
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

    nonisolated private static func detectSensitivePatterns(in text: String) -> [String] {
        var found: [String] = []
        if text.range(of: #"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"#, options: .regularExpression) != nil {
            found.append("JWT Token")
        }
        if text.range(of: #"\b0x[a-fA-F0-9]{40}\b"#, options: .regularExpression) != nil {
            found.append("Địa chỉ ví EVM/ETH (nguy cơ clipboard hijacker)")
        }
        if text.range(of: #"(sk_live_|ghp_|gho_|AIza[0-9A-Za-z_-]{20,})"#, options: .regularExpression) != nil {
            found.append("API Key / Secret Token")
        }
        let words = text.split { $0.isWhitespace || $0.isNewline }
        if (words.count == 12 || words.count == 24) && words.allSatisfy({ $0.allSatisfy(\.isLetter) }) {
            found.append("Chuỗi 12/24 từ nghi Seed Phrase")
        }
        return found
    }

    nonisolated private static func stripTrackingParametersFromText(_ input: String) -> (cleaned: String?, removedParams: [String]) {
        guard let detector = try? NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue) else {
            return (nil, [])
        }
        let fullRange = NSRange(input.startIndex..., in: input)
        let matches = detector.matches(in: input, options: [], range: fullRange)
        guard !matches.isEmpty else { return (nil, []) }

        var mutableText = input
        var allRemoved: [String] = []

        for match in matches.reversed() {
            guard let url = match.url,
                  var components = URLComponents(url: url, resolvingAgainstBaseURL: false),
                  let items = components.queryItems, !items.isEmpty,
                  let swiftRange = Range(match.range, in: mutableText) else {
                continue
            }

            var kept: [URLQueryItem] = []
            var removedHere: [String] = []
            for item in items {
                let lower = item.name.lowercased()
                if trackingQueryParameters.contains(lower) || lower.hasPrefix("utm_") {
                    removedHere.append(item.name)
                } else {
                    kept.append(item)
                }
            }

            guard !removedHere.isEmpty else { continue }
            allRemoved.append(contentsOf: removedHere)
            components.queryItems = kept.isEmpty ? nil : kept
            if let cleanURLString = components.string {
                mutableText.replaceSubrange(swiftRange, with: cleanURLString)
            }
        }

        if allRemoved.isEmpty {
            return (nil, [])
        }
        return (mutableText, Array(Set(allRemoved)).sorted())
    }
}

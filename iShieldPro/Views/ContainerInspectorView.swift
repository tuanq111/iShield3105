//
//  ContainerInspectorView.swift
//  iShieldPro
//
//  App Deep Guard: Container Inspection, Batch Cleanup, Tracking Sanitizer & Quarantine Vault
//

import SwiftUI

struct ContainerInspectorView: View {
    @ObservedObject var coordinator: SecurityDashboardCoordinator
    @ObservedObject var containerManager: ContainerManager

    @State private var showingAppPicker = false
    @State private var showingCleanConfirm = false
    @State private var showingBatchConfirm = false
    @State private var sanitizePlistKeys = true
    @State private var quarantineBeforeClean = true
    @State private var preferenceSearchText = ""
    @State private var showOnlySuspiciousPrefs = false
    @State private var alertMessage: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    batchRemediationCard
                    targetInputCard
                    if let report = containerManager.lastInspection {
                        containerPathsCard(report)
                        cacheAndCleanCard(report)
                        suspiciousArtifactsCard(report)
                        preferencesInspectorCard(report)
                    } else {
                        emptyStateCard
                    }
                    quarantineFilesCard
                    quarantineBackupsCard
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .background(CyberTheme.background.ignoresSafeArea())
            .navigationTitle("App Deep Guard")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        Task { await containerManager.refreshInstalledApps() }
                    } label: {
                        Image(systemName: "arrow.triangle.2.circlepath")
                            .foregroundColor(CyberTheme.neonCyan)
                    }
                }
            }
            .sheet(isPresented: $showingAppPicker) {
                InstalledAppPickerSheet(
                    apps: containerManager.installedApps,
                    isLoading: containerManager.isLoadingApps,
                    onRefresh: { await containerManager.refreshInstalledApps() },
                    onSelect: { app in
                        coordinator.targetBundleID = app.bundleIdentifier
                        showingAppPicker = false
                        Task { await inspectCurrentTarget() }
                    }
                )
            }
            .confirmationDialog(
                "Xác nhận làm sạch & cách ly?",
                isPresented: $showingCleanConfirm,
                titleVisibility: .visible
            ) {
                Button("Thực hiện Dọn Cache, Cách Ly & Khử .plist", role: .destructive) {
                    if let report = containerManager.lastInspection {
                        Task {
                            let summary = await containerManager.cleanTrackingCaches(
                                for: report,
                                sanitizeSuspiciousPreferences: sanitizePlistKeys,
                                quarantineCriticalArtifacts: quarantineBeforeClean
                            )
                            coordinator.syncScoreFromCurrentReports()
                            let msg = "Đã xóa \(summary.removedItemsCount) mục (\(CyberTheme.formatBytes(summary.freedBytes))), cách ly \(summary.quarantinedFilesCount) tệp, sao lưu \(summary.backedUpPlistCount) .plist, khử \(summary.sanitizedPlistKeysCount) khóa theo dõi."
                            coordinator.appendEvent(SecurityEventEntry(
                                category: .container,
                                severity: .safe,
                                actionTaken: "Dọn Container App",
                                title: "Làm sạch & Khử theo dõi \(report.bundleIdentifier)",
                                detail: msg
                            ))
                            alertMessage = msg
                        }
                    }
                }
                Button("Hủy", role: .cancel) {}
            } message: {
                Text("Thao tác xóa chỉ thực hiện trong Library/Caches và tmp. Tệp nhị phân/proxy nghi ngờ sẽ được cách ly an toàn, và tệp .plist gốc luôn sao lưu SHA-256 trước khi sửa.")
            }
            .confirmationDialog(
                "Quét & Dọn hàng loạt ứng dụng khả dụng?",
                isPresented: $showingBatchConfirm,
                titleVisibility: .visible
            ) {
                Button("Quét sâu & Dọn toàn bộ App khả dụng", role: .destructive) {
                    Task {
                        let sum = await containerManager.batchInspectAndRemediateAllAccessible(cleanAndSanitize: true)
                        coordinator.syncScoreFromCurrentReports()
                        let msg = "Đã rà soát \(sum.scannedAppsCount) app (\(sum.accessibleAppsCount) container đọc được), xử lý \(sum.cleanedAppsCount) app, giải phóng \(CyberTheme.formatBytes(sum.totalFreedBytes)), cách ly \(sum.totalQuarantinedFiles) tệp, khử \(sum.totalSanitizedPlistKeys) khóa .plist."
                        coordinator.appendEvent(SecurityEventEntry(
                            category: .container,
                            severity: .safe,
                            actionTaken: "Dọn Hàng Loạt App",
                            title: "Quét & Xử lý hàng loạt Container",
                            detail: msg
                        ))
                        alertMessage = msg
                    }
                }
                Button("Hủy", role: .cancel) {}
            } message: {
                Text("iShield Pro sẽ kiểm tra các container ứng dụng có quyền đọc, tự động cách ly file lạ, xóa cache/tmp và sao lưu SHA-256 trước khi gỡ khóa theo dõi .plist.")
            }
            .alert("Thông báo App Deep Guard", isPresented: Binding(
                get: { alertMessage != nil },
                set: { if !$0 { alertMessage = nil } }
            )) {
                Button("Đóng", role: .cancel) {}
            } message: {
                Text(alertMessage ?? "")
            }
        }
    }

    private var batchRemediationCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeaderView(
                title: "Xử lý Hàng Loạt Toàn Bộ App Khả Dụng",
                systemImage: "sparkles.rectangle.stack.fill",
                subtitle: "Tự động rà soát, cách ly tệp nghi ngờ & xóa cache theo dõi trên nhiều app cùng lúc"
            )

            Button {
                showingBatchConfirm = true
            } label: {
                HStack {
                    if containerManager.isBatchProcessing {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: CyberTheme.background))
                    } else {
                        Image(systemName: "bolt.fill")
                    }
                    Text(containerManager.isBatchProcessing ? "Đang quét & dọn hàng loạt..." : "Quét Sâu & Dọn Hàng Loạt App")
                        .font(.system(size: 13, weight: .bold))
                }
                .foregroundColor(CyberTheme.background)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 11)
                .background(CyberTheme.emerald)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
            .disabled(containerManager.isBatchProcessing || containerManager.isInspecting)

            if let batch = containerManager.lastBatchSummary {
                Text("Gần nhất: xử lý \(batch.cleanedAppsCount)/\(batch.accessibleAppsCount) app khả dụng • giải phóng \(CyberTheme.formatBytes(batch.totalFreedBytes)) • cách ly \(batch.totalQuarantinedFiles) tệp • khử \(batch.totalSanitizedPlistKeys) khóa .plist")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(CyberTheme.neonCyan)
            }
        }
        .cyberCard(borderColor: CyberTheme.emerald.opacity(0.35))
    }

    private var targetInputCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeaderView(
                title: "Kiểm tra Container Ứng Dụng Mục Tiêu",
                systemImage: "magnifyingglass.circle.fill",
                subtitle: "Truy xuất qua MCMAppDataContainer & MCMSharedDataContainer"
            )

            HStack(spacing: 8) {
                TextField("Nhập Bundle ID (vd: com.apple.mobilesafari)", text: $coordinator.targetBundleID)
                    .font(.system(size: 13, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .padding(10)
                    .background(CyberTheme.elevatedSurface)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))

                Button {
                    showingAppPicker = true
                    if containerManager.installedApps.isEmpty {
                        Task { await containerManager.refreshInstalledApps() }
                    }
                } label: {
                    Label("Chọn App", systemImage: "list.bullet")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(CyberTheme.neonCyan)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 10)
                        .background(CyberTheme.neonCyan.opacity(0.15))
                        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                }
            }

            TextField("App Group ID bổ sung (tùy chọn, phân tách dấu phẩy)", text: $coordinator.explicitAppGroupID)
                .font(.system(size: 12, design: .monospaced))
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .padding(10)
                .background(CyberTheme.elevatedSurface)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))

            Button {
                Task { await inspectCurrentTarget() }
            } label: {
                HStack {
                    if containerManager.isInspecting {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: CyberTheme.background))
                    } else {
                        Image(systemName: "doc.text.magnifyingglass")
                    }
                    Text(containerManager.isInspecting ? "Đang phân tích Container..." : "Quét Container & Preferences")
                        .font(.system(size: 14, weight: .bold))
                }
                .foregroundColor(CyberTheme.background)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 11)
                .background(CyberTheme.neonCyan)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
            .disabled(containerManager.isInspecting)

            if let msg = containerManager.statusMessage {
                Text(msg)
                    .font(.system(size: 11))
                    .foregroundColor(CyberTheme.textSecondary)
            }
        }
        .cyberCard()
    }

    private func containerPathsCard(_ report: ContainerInspectionReport) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeaderView(
                title: "Đường dẫn Sandbox & Quyền Nền Ứng Dụng",
                systemImage: "folder.badge.gearshape",
                subtitle: report.bundleIdentifier
            )

            if let url = report.dataContainerURL {
                TelemetryKeyValueRow(label: "Data Container", value: url.path, valueColor: CyberTheme.emerald)
                TelemetryKeyValueRow(
                    label: "Quyền đọc Sandbox",
                    value: report.dataContainerReadable ? "ĐỌC ĐƯỢC (Accessible)" : "BỊ SANDBOX CHẶN",
                    valueColor: report.dataContainerReadable ? CyberTheme.emerald : CyberTheme.amber
                )
                TelemetryKeyValueRow(
                    label: "Sandbox Token",
                    value: report.sandboxTokenConsumed ? "CONSUMED" : "NONE / STANDARD",
                    valueColor: report.sandboxTokenConsumed ? CyberTheme.emerald : CyberTheme.textSecondary
                )
            } else {
                TelemetryKeyValueRow(
                    label: "Data Container",
                    value: report.dataContainerError ?? "Không truy xuất được",
                    valueColor: CyberTheme.crimson
                )
            }

            if !report.backgroundModesDetected.isEmpty {
                TelemetryKeyValueRow(
                    label: "UIBackgroundModes",
                    value: report.backgroundModesDetected.joined(separator: ", "),
                    valueColor: report.backgroundModesDetected.contains(where: { $0 == "audio" || $0 == "voip" || $0 == "location" })
                        ? CyberTheme.amber
                        : CyberTheme.neonCyan
                )
            }

            TelemetryKeyValueRow(
                label: "AppGroup Containers",
                value: report.resolvedGroupContainers.isEmpty ? "Không phát hiện" : "\(report.resolvedGroupContainers.count) nhóm",
                valueColor: report.resolvedGroupContainers.isEmpty ? CyberTheme.textSecondary : CyberTheme.neonCyan
            )
            ForEach(report.resolvedGroupContainers.keys.sorted(), id: \.self) { key in
                if let url = report.resolvedGroupContainers[key] {
                    TelemetryKeyValueRow(label: key, value: url.path, valueColor: CyberTheme.textSecondary)
                }
            }

            if !report.resolvedPluginContainers.isEmpty {
                TelemetryKeyValueRow(
                    label: "PluginKit Extensions",
                    value: "\(report.resolvedPluginContainers.count) extension",
                    valueColor: CyberTheme.neonCyan
                )
            }
        }
        .cyberCard()
    }

    private func cacheAndCleanCard(_ report: ContainerInspectionReport) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeaderView(
                title: "Dọn Dẹp, Cách Ly & Khử Theo Dõi An Toàn",
                systemImage: "wand.and.stars",
                subtitle: "Xóa an toàn trong Library/Caches & tmp, giữ nguyên dữ liệu người dùng"
            )

            HStack(spacing: 12) {
                statBox(
                    title: "Library/Caches",
                    value: CyberTheme.formatBytes(report.cachesSizeBytes),
                    sub: "\(report.cachesFileCount) tệp"
                )
                statBox(
                    title: "tmp/",
                    value: CyberTheme.formatBytes(report.tmpSizeBytes),
                    sub: "\(report.tmpFileCount) tệp"
                )
                statBox(
                    title: "Preferences",
                    value: "\(report.preferencesFileCount)",
                    sub: "\(report.preferenceEntries.filter(\.isSuspicious).count) khóa nghi ngờ"
                )
            }

            Toggle(isOn: $quarantineBeforeClean) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Cách ly tệp .dylib / proxy lạ vào Kho Cách Ly")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(CyberTheme.textPrimary)
                    Text("Di chuyển nhị phân đáng ngờ ra khỏi vùng chạy của app trước khi dọn dẹp")
                        .font(.system(size: 11))
                        .foregroundColor(CyberTheme.textSecondary)
                }
            }
            .tint(CyberTheme.emerald)

            Toggle(isOn: $sanitizePlistKeys) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Sao lưu SHA-256 & khử khóa theo dõi .plist")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(CyberTheme.textPrimary)
                    Text("Gỡ proxy, IDFA, fingerprint, telemetry và giữ bản sao lưu khôi phục 1 chạm")
                        .font(.system(size: 11))
                        .foregroundColor(CyberTheme.textSecondary)
                }
            }
            .tint(CyberTheme.neonCyan)

            Button {
                showingCleanConfirm = true
            } label: {
                HStack {
                    Image(systemName: "trash.fill")
                    Text("Làm sạch, Cách Ly & Khử Theo Dõi")
                        .font(.system(size: 14, weight: .bold))
                }
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .background(CyberTheme.crimson)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
            .disabled(report.dataContainerURL == nil)

            if let cleanup = containerManager.lastCleanup, cleanup.bundleIdentifier == report.bundleIdentifier {
                Text("Lần dọn gần nhất: xóa \(cleanup.removedItemsCount) mục (\(CyberTheme.formatBytes(cleanup.freedBytes))), cách ly \(cleanup.quarantinedFilesCount) tệp, backup \(cleanup.backedUpPlistCount) plist, khử \(cleanup.sanitizedPlistKeysCount) khóa.")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(CyberTheme.emerald)
            }
        }
        .cyberCard()
    }

    private func statBox(title: String, value: String, sub: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(CyberTheme.textSecondary)
            Text(value)
                .font(.system(size: 15, weight: .bold, design: .monospaced))
                .foregroundColor(CyberTheme.neonCyan)
            Text(sub)
                .font(.system(size: 10))
                .foregroundColor(CyberTheme.textMuted)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(CyberTheme.elevatedSurface)
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    private func suspiciousArtifactsCard(_ report: ContainerInspectionReport) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeaderView(
                title: "Tệp đáng ngờ trong Container (\(report.suspiciousFiles.count))",
                systemImage: "ladybug.fill",
                subtitle: "Kiểm tra .dylib lạ, cấu hình proxy/tracking và tệp phình to"
            )

            if report.suspiciousFiles.isEmpty {
                Text("Không phát hiện tệp bất thường trong Library/Caches, tmp hoặc Preferences.")
                    .font(.system(size: 12))
                    .foregroundColor(CyberTheme.emerald)
            } else {
                ForEach(report.suspiciousFiles) { file in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(file.kind.rawValue)
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(CyberTheme.color(for: file.severity))
                            Spacer()
                            SeverityBadge(severity: file.severity)
                        }
                        Text(file.relativePath)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(CyberTheme.textPrimary)
                        HStack {
                            Text("\(file.reason) • \(CyberTheme.formatBytes(file.sizeBytes))")
                                .font(.system(size: 11))
                                .foregroundColor(CyberTheme.textSecondary)
                            Spacer()
                            Button("Cách ly ngay") {
                                Task {
                                    let res = await containerManager.quarantineSingleFile(file, bundleIdentifier: report.bundleIdentifier)
                                    coordinator.syncScoreFromCurrentReports()
                                    switch res {
                                    case .success(let rec):
                                        alertMessage = "Đã cách ly \(rec.fileName) an toàn."
                                    case .failure(let err):
                                        alertMessage = "Không thể cách ly: \(err.localizedDescription)"
                                    }
                                }
                            }
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(CyberTheme.background)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(CyberTheme.amber)
                            .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                        }
                    }
                    .padding(10)
                    .background(CyberTheme.elevatedSurface)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                }
            }
        }
        .cyberCard()
    }

    private func preferencesInspectorCard(_ report: ContainerInspectionReport) -> some View {
        let filtered = report.preferenceEntries.filter { entry in
            let matchesToggle = !showOnlySuspiciousPrefs || entry.isSuspicious
            let q = preferenceSearchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let matchesQuery = q.isEmpty
                || entry.key.lowercased().contains(q)
                || entry.plistFileName.lowercased().contains(q)
                || entry.valuePreview.lowercased().contains(q)
            return matchesToggle && matchesQuery
        }

        return VStack(alignment: .leading, spacing: 10) {
            SectionHeaderView(
                title: "Khóa cấu hình Library/Preferences (*.plist)",
                systemImage: "list.bullet.rectangle.portrait.fill",
                subtitle: "Hiển thị \(filtered.count)/\(report.preferenceEntries.count) khóa"
            )

            HStack {
                TextField("Lọc tên khóa hoặc plist...", text: $preferenceSearchText)
                    .font(.system(size: 12, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .padding(8)
                    .background(CyberTheme.elevatedSurface)
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

                Toggle("Chỉ khóa nghi ngờ", isOn: $showOnlySuspiciousPrefs)
                    .labelsHidden()
                    .tint(CyberTheme.amber)
            }

            if filtered.isEmpty {
                Text("Không có khóa cấu hình phù hợp bộ lọc.")
                    .font(.system(size: 12))
                    .foregroundColor(CyberTheme.textSecondary)
            } else {
                ForEach(filtered.prefix(60)) { entry in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(entry.key)
                                .font(.system(size: 12, weight: .bold, design: .monospaced))
                                .foregroundColor(entry.isSuspicious ? CyberTheme.amber : CyberTheme.neonCyan)
                            Spacer()
                            Text(entry.plistFileName)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(CyberTheme.textMuted)
                        }
                        Text(entry.valuePreview)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(CyberTheme.textSecondary)
                            .lineLimit(3)
                        if let reason = entry.suspicionReason {
                            Text(reason)
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundColor(CyberTheme.crimson)
                        }
                    }
                    .padding(9)
                    .background(CyberTheme.elevatedSurface)
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                }
            }
        }
        .cyberCard()
    }

    private var quarantineFilesCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeaderView(
                title: "Kho Cách Ly Tệp Nguy Hiểm (\(containerManager.quarantinedFiles.count))",
                systemImage: "lock.rectangle.stack.fill",
                subtitle: "Các tệp đáng ngờ đã bị cô lập khỏi container ứng dụng"
            )

            if containerManager.quarantinedFiles.isEmpty {
                Text("Kho cách ly đang trống.")
                    .font(.system(size: 12))
                    .foregroundColor(CyberTheme.textSecondary)
            } else {
                ForEach(containerManager.quarantinedFiles.prefix(15)) { rec in
                    HStack(alignment: .center, spacing: 10) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(rec.fileName) • \(rec.bundleIdentifier)")
                                .font(.system(size: 12, weight: .bold, design: .monospaced))
                                .foregroundColor(CyberTheme.amber)
                            Text("\(rec.kind.rawValue) • \(CyberTheme.formatBytes(rec.sizeBytes))")
                                .font(.system(size: 11))
                                .foregroundColor(CyberTheme.textSecondary)
                            Text("SHA-256: \(rec.sha256.prefix(16))... • \(CyberTheme.formatTimestamp(rec.quarantinedAt))")
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(CyberTheme.textMuted)
                        }
                        Spacer()
                        Button("Xóa hẳn") {
                            do {
                                try containerManager.deleteQuarantinedRecord(rec)
                            } catch {
                                alertMessage = "Lỗi xóa tệp cách ly: \(error.localizedDescription)"
                            }
                        }
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.white)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(CyberTheme.crimson)
                        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                    }
                    .padding(10)
                    .background(CyberTheme.elevatedSurface)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                }
            }
        }
        .cyberCard()
    }

    private var quarantineBackupsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeaderView(
                title: "Kho Sao Lưu & Khôi Phục .plist (\(containerManager.backups.count))",
                systemImage: "externaldrive.badge.timemachine",
                subtitle: "Bản sao lưu gốc trước khi can thiệp (xác thực SHA-256)"
            )

            if containerManager.backups.isEmpty {
                Text("Chưa có bản sao lưu .plist nào.")
                    .font(.system(size: 12))
                    .foregroundColor(CyberTheme.textSecondary)
            } else {
                ForEach(containerManager.backups.prefix(15)) { record in
                    HStack(alignment: .center, spacing: 10) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(record.originalFileName) (\(record.bundleIdentifier))")
                                .font(.system(size: 12, weight: .bold, design: .monospaced))
                                .foregroundColor(CyberTheme.textPrimary)
                            Text("SHA-256: \(record.sha256.prefix(16))... • \(CyberTheme.formatTimestamp(record.createdAt))")
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(CyberTheme.textMuted)
                            Text(record.note)
                                .font(.system(size: 11))
                                .foregroundColor(CyberTheme.textSecondary)
                        }
                        Spacer()
                        Button("Khôi phục") {
                            do {
                                try containerManager.restorePlistBackup(record)
                                alertMessage = "Đã khôi phục thành công \(record.originalFileName)."
                            } catch {
                                alertMessage = "Lỗi khôi phục: \(error.localizedDescription)"
                            }
                        }
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(CyberTheme.background)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(CyberTheme.emerald)
                        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                    }
                    .padding(10)
                    .background(CyberTheme.elevatedSurface)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                }
            }
        }
        .cyberCard()
    }

    private var emptyStateCard: some View {
        VStack(spacing: 8) {
            Image(systemName: "shippingbox.circle")
                .font(.system(size: 36))
                .foregroundColor(CyberTheme.neonCyan)
            Text("Chưa phân tích Container nào")
                .font(.system(size: 14, weight: .bold))
                .foregroundColor(CyberTheme.textPrimary)
            Text("Chọn một ứng dụng hoặc nhập Bundle ID rồi bấm Quét Container để kiểm tra Library/Caches, tmp và Preferences.")
                .font(.system(size: 12))
                .foregroundColor(CyberTheme.textSecondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .cyberCard()
    }

    private func inspectCurrentTarget() async {
        let groups = coordinator.explicitAppGroupID
            .split(separator: ",")
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        _ = await containerManager.inspectContainer(
            bundleIdentifier: coordinator.targetBundleID,
            explicitAppGroupIDs: groups
        )
        coordinator.syncScoreFromCurrentReports()
    }
}

private struct InstalledAppPickerSheet: View {
    let apps: [InstalledAppItem]
    let isLoading: Bool
    let onRefresh: () async -> Void
    let onSelect: (InstalledAppItem) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var searchText = ""

    var body: some View {
        NavigationStack {
            List {
                if isLoading {
                    HStack {
                        ProgressView()
                        Text("Đang truy vấn danh sách ứng dụng hệ thống...")
                            .font(.system(size: 12))
                    }
                }
                ForEach(filteredApps) { app in
                    Button {
                        onSelect(app)
                    } label: {
                        VStack(alignment: .leading, spacing: 3) {
                            HStack {
                                Text(app.displayName)
                                    .font(.system(size: 14, weight: .bold))
                                    .foregroundColor(.white)
                                Spacer()
                                Text(app.applicationType)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(CyberTheme.neonCyan)
                            }
                            Text(app.bundleIdentifier)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(CyberTheme.textSecondary)
                            if let url = app.dataContainerURL {
                                Text(url.path)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(CyberTheme.textMuted)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                        }
                    }
                }
            }
            .searchable(text: $searchText, prompt: "Tìm tên app hoặc Bundle ID")
            .navigationTitle("Ứng dụng trên thiết bị")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Đóng") { dismiss() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        Task { await onRefresh() }
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                }
            }
        }
    }

    private var filteredApps: [InstalledAppItem] {
        let q = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return apps }
        return apps.filter {
            $0.displayName.lowercased().contains(q) || $0.bundleIdentifier.lowercased().contains(q)
        }
    }
}

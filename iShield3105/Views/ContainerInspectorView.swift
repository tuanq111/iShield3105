//
//  ContainerInspectorView.swift
//  iShield3105
//
//  Cơ chế 3105: Kiểm tra Data/AppGroup Container, Library/Caches, tmp, Preferences/*.plist & Quarantine
//

import SwiftUI

struct ContainerInspectorView: View {
    @ObservedObject var coordinator: SecurityDashboardCoordinator
    @ObservedObject var containerManager: ContainerManager

    @State private var showingAppPicker = false
    @State private var showingCleanConfirm = false
    @State private var sanitizePlistKeys = true
    @State private var preferenceSearchText = ""
    @State private var showOnlySuspiciousPrefs = false
    @State private var alertMessage: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    targetInputCard
                    if let report = containerManager.lastInspection {
                        containerPathsCard(report)
                        cacheAndCleanCard(report)
                        suspiciousArtifactsCard(report)
                        preferencesInspectorCard(report)
                    } else {
                        emptyStateCard
                    }
                    quarantineBackupsCard
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .background(CyberTheme.background.ignoresSafeArea())
            .navigationTitle("Container 3105")
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
                "Xác nhận làm sạch Container 3105?",
                isPresented: $showingCleanConfirm,
                titleVisibility: .visible
            ) {
                Button("Làm sạch Library/Caches & tmp" + (sanitizePlistKeys ? " + Khử khóa theo dõi .plist" : ""), role: .destructive) {
                    if let report = containerManager.lastInspection {
                        Task {
                            let summary = await containerManager.cleanTrackingCaches(
                                for: report,
                                sanitizeSuspiciousPreferences: sanitizePlistKeys
                            )
                            coordinator.syncScoreFromCurrentReports()
                            alertMessage = "Đã xóa \(summary.removedItemsCount) mục (giải phóng \(CyberTheme.formatBytes(summary.freedBytes))). Sao lưu \(summary.backedUpPlistCount) .plist, khử \(summary.sanitizedPlistKeysCount) khóa theo dõi."
                        }
                    }
                }
                Button("Hủy", role: .cancel) {}
            } message: {
                Text("Thao tác xóa chỉ thực hiện trong Library/Caches và tmp. Nếu bật khử khóa .plist, tệp gốc luôn được sao lưu SHA-256 vào Quarantine trước khi sửa.")
            }
            .alert("Thông báo Container 3105", isPresented: Binding(
                get: { alertMessage != nil },
                set: { if !$0 { alertMessage = nil } }
            )) {
                Button("Đóng", role: .cancel) {}
            } message: {
                Text(alertMessage ?? "")
            }
        }
    }

    private var targetInputCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeaderView(
                title: "Mục tiêu Container (Cơ chế 3105)",
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
                title: "Đường dẫn Sandbox thực tế",
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
                    label: "Sandbox Token (3105)",
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
                    label: "PluginKit Containers",
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
                title: "Dọn dẹp & Khử theo dõi an toàn",
                systemImage: "wand.and.stars",
                subtitle: "Chỉ xóa bên trong Library/Caches và tmp"
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

            Toggle(isOn: $sanitizePlistKeys) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Sao lưu & khử khóa theo dõi trong .plist")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(CyberTheme.textPrimary)
                    Text("Tạo bản sao lưu SHA-256 trước khi gỡ các khóa tracking/proxy")
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
                    Text("Làm sạch & Khử theo dõi (Clean Tracking Cache)")
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
                Text("Lần dọn gần nhất: xóa \(cleanup.removedItemsCount) mục (\(CyberTheme.formatBytes(cleanup.freedBytes))), backup \(cleanup.backedUpPlistCount) plist, khử \(cleanup.sanitizedPlistKeysCount) khóa.")
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
                    VStack(alignment: .leading, spacing: 4) {
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
                        Text("\(file.reason) • \(CyberTheme.formatBytes(file.sizeBytes))")
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
                if filtered.count > 60 {
                    Text("Đang hiển thị 60 khóa đầu tiên — dùng ô tìm kiếm để lọc chi tiết.")
                        .font(.system(size: 11))
                        .foregroundColor(CyberTheme.textMuted)
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
                        Text("Đang truy vấn SpringBoardServices / LSApplicationWorkspace...")
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

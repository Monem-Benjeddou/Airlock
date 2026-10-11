// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import AppKit
import SwiftUI

/// F4: every app on the phone, with confirm-first changes and brand debloat presets.
struct AppsView: View {
    @Bindable var model: AppsModel
    let brand: DeviceBrand
    @State private var selection = Set<PackageName>()
    @State private var showPresets = false

    var body: some View {
        content
            .navigationTitle("Apps")
            .searchable(text: $model.searchText, prompt: "Search package names")
            .toolbar { toolbar }
            .task(id: model.device) { await model.reload() }
            .confirmationDialog(
                model.pendingChange?.title ?? "",
                isPresented: Binding(get: { model.pendingChange != nil }, set: { if !$0 { model.cancelPendingChange() } }),
                presenting: model.pendingChange,
                actions: confirmationActions,
                message: { Text($0.message) }
            )
            .sheet(isPresented: $showPresets) { PresetSheet(model: model, brand: brand) }
    }

    private var content: some View {
        VStack(spacing: 0) {
            if let error = model.lastError {
                Text(error).foregroundStyle(Palette.danger).padding(8)
            }
            ResultsBanner(results: model.results)
            table
        }
    }

    private var table: some View {
        Table(model.visibleApps, selection: $selection) {
            TableColumn("App") { (app: InstalledApp) in
                VStack(alignment: .leading) {
                    Text(app.label ?? app.packageName.rawValue)
                    if app.label != nil { Text(app.packageName.rawValue).font(.caption) }
                }
            }
            TableColumn("Version") { (app: InstalledApp) in Text(app.versionName ?? String(app.versionCode)) }.width(90)
            TableColumn("Source") { (app: InstalledApp) in Text(app.installSource) }.width(150)
            TableColumn("State") { (app: InstalledApp) in Text(stateText(app)) }.width(110)
        }
        .accessibilityIdentifier("appsTable")
    }

    @ToolbarContentBuilder private var toolbar: some ToolbarContent {
        ToolbarItemGroup {
            Picker("Show", selection: $model.filter) {
                ForEach(AppsModel.Filter.allCases) { Text($0.rawValue).tag($0) }
            }
            .accessibilityIdentifier("appsFilter")
            Button("Disable", systemImage: "pause.circle") { model.request(.disableForUser, for: Array(selection)) }
                .disabled(selection.isEmpty)
            Button("Remove", systemImage: "minus.circle") { model.request(.uninstallForUser, for: Array(selection)) }
                .disabled(selection.isEmpty)
                .help("Remove for this user. Restorable from History.")
            Button("Export", systemImage: "square.and.arrow.up") { exportSelection() }
                .disabled(selection.count != 1)
            Button("Debloat Presets", systemImage: "wand.and.stars") { showPresets = true }
                .accessibilityIdentifier("presetsButton")
            Button("Reload", systemImage: "arrow.clockwise") { Task { await model.reload() } }
        }
    }

    @ViewBuilder private func confirmationActions(_ change: AppsModel.PendingChange) -> some View {
        Button(change.operation.isDestructive ? "Confirm" : "Continue", role: change.operation.isDestructive ? .destructive : nil) {
            Task { await model.confirm(change) }
        }
        .accessibilityIdentifier("confirmChange")
        Button("Cancel", role: .cancel) { model.cancelPendingChange() }
    }

    private func stateText(_ app: InstalledApp) -> String {
        switch app.state {
        case .enabled: app.isSystem ? "System" : "Installed"
        case .disabled: "Disabled"
        case .uninstalledForUser: "Removed"
        }
    }

    private func exportSelection() {
        guard let package = selection.first else { return }
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.prompt = "Export Here"
        guard panel.runModal() == .OK, let folder = panel.url else { return }
        Task {
            let files = await model.export(package, to: folder)
            if let first = files.first { NSWorkspace.shared.activateFileViewerSelecting([first]) }
        }
    }
}

struct ResultsBanner: View {
    let results: [AppsModel.ChangeResult]

    var body: some View {
        let failures = results.filter { $0.error != nil }
        if !results.isEmpty {
            VStack(alignment: .leading, spacing: 2) {
                let summary = failures.isEmpty
                    ? "Done: \(results.count) change(s) applied."
                    : "\(failures.count) of \(results.count) change(s) failed."
                Text(summary)
                    .fontWeight(.semibold)
                ForEach(failures, id: \.package) { failure in
                    Text("\(failure.package.rawValue): \(failure.error ?? "")").font(.caption)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
            .background(failures.isEmpty ? Palette.success.opacity(0.12) : Palette.warning.opacity(0.15))
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Results")
            .accessibilityIdentifier("resultsBanner")
        }
    }
}

struct PresetSheet: View {
    let model: AppsModel
    let brand: DeviceBrand
    @Environment(\.dismiss) private var dismiss
    @State private var presetID: String?
    @State private var maximumRisk: DebloatRisk = .safe
    @State private var chosen = Set<PackageName>()

    var body: some View {
        let presets = model.presets(for: brand)
        let preset = presets.first { $0.id == presetID } ?? presets.first
        let entries = preset.map { model.applicableEntries(of: $0, maximumRisk: maximumRisk) } ?? []
        VStack(alignment: .leading, spacing: 12) {
            Text("Debloat presets").font(.title2.bold())
            Text("Lists come from the Universal Android Debloater (UAD-ng) project. Every change can be undone from History, "
                + "and core system apps can never be removed.")
            HStack {
                Picker("Preset", selection: Binding(get: { preset?.id }, set: { presetID = $0; chosen = [] })) {
                    ForEach(presets) { Text("\($0.name) (\($0.entries.count))").tag(Optional($0.id)) }
                }
                Picker("Include", selection: $maximumRisk) {
                    Text("Safe only").tag(DebloatRisk.safe)
                    Text("Safe and caution").tag(DebloatRisk.caution)
                    Text("Everything (expert)").tag(DebloatRisk.expert)
                }
                .accessibilityIdentifier("riskPicker")
            }
            List(entries) { entry in
                Toggle(isOn: Binding(get: { chosen.contains(entry.packageName) }, set: {
                    if $0 { chosen.insert(entry.packageName) } else { chosen.remove(entry.packageName) }
                })) {
                    VStack(alignment: .leading) {
                        HStack {
                            Text(entry.packageName.rawValue)
                            Text(entry.risk.rawValue.capitalized).font(.caption)
                                .padding(.horizontal, 6).background(Capsule().fill(riskColor(entry.risk).opacity(0.2)))
                        }
                        Text(entry.description).font(.caption).lineLimit(2)
                    }
                }
            }
            .overlay { if entries.isEmpty { Text("Nothing from this preset is active on this phone.") } }
            HStack {
                Button("Select All") { chosen = Set(entries.map(\.packageName)) }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                Button("Remove \(chosen.count) App(s)…") {
                    model.request(.uninstallForUser, for: Array(chosen))
                    dismiss()
                }
                .disabled(chosen.isEmpty)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(minWidth: 640, minHeight: 520)
    }

    private func riskColor(_ risk: DebloatRisk) -> Color { Palette.debloat(risk) }
}

struct HistoryView: View {
    let model: AppsModel
    @State private var undoInstall: JournalEntry?

    var body: some View {
        List(model.history) { entry in
            HStack {
                VStack(alignment: .leading) {
                    Text(entry.packageName.rawValue).font(.headline)
                    let date = entry.createdAt.formatted(date: .abbreviated, time: .shortened)
                    Text("\(describe(entry.kind)) · \(date) · \(entry.status.rawValue)")
                        .font(.caption)
                }
                Spacer()
                if entry.isRestorable {
                    Button("Restore") {
                        if entry.restore == .uninstallInstalled {
                            undoInstall = entry
                        } else {
                            Task { await model.restore(entry) }
                        }
                    }
                    .accessibilityIdentifier("restoreButton")
                }
            }
        }
        .overlay { if model.history.isEmpty { Text("Changes you make appear here and can be undone.") } }
        .navigationTitle("History")
        .task(id: model.device) { await model.reload() }
        .confirmationDialog(
            "Uninstall \(undoInstall?.packageName.rawValue ?? "")?",
            isPresented: Binding(get: { undoInstall != nil }, set: { if !$0 { undoInstall = nil } }),
            presenting: undoInstall
        ) { entry in
            Button("Uninstall", role: .destructive) { Task { await model.restore(entry, confirmed: true) } }
        } message: { _ in
            Text("Undoing this install removes the app and its data from the phone.")
        }
    }

    private func describe(_ kind: JournalEntry.Kind) -> String {
        switch kind {
        case .operation(let operation):
            switch operation {
            case .uninstall: "Uninstalled"
            case .uninstallForUser: "Removed"
            case .disableForUser: "Disabled"
            case .enable: "Enabled"
            case .installExisting: "Restored"
            }
        case .install(let version, let update): update ? "Updated to \(version)" : "Installed \(version)"
        }
    }
}

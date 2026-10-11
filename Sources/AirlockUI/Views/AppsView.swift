// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import AppKit
import SwiftUI

/// F4: every app on the phone, with confirm-first changes and brand debloat presets.
///
/// Filter and search on top, the table in the middle, and the selected app in an inspector on the right
/// with the changes it allows.
struct AppsView: View {
    @Bindable var model: AppsModel
    let brand: DeviceBrand
    @State private var selection = Set<PackageName>()
    @State private var showPresets = false
    @State private var showInspector = false

    var body: some View {
        VStack(spacing: 0) {
            FilterBar(model: model)
            Divider()
            if let error = model.lastError {
                ContentUnavailableView {
                    Label("Couldn't read the apps", systemImage: "exclamationmark.triangle")
                } description: {
                    Text(error)
                } actions: {
                    Button("Try Again") { Task { await model.reload() } }
                }
            } else {
                table
            }
            ResultsBanner(model: model)
        }
        .searchable(text: $model.searchText, placement: .toolbar, prompt: "Search apps")
        .toolbar { toolbar }
        .inspector(isPresented: $showInspector) {
            AppInspector(model: model, brand: brand, selection: selection, export: export)
                .inspectorColumnWidth(min: 240, ideal: 280, max: 360)
        }
        .task(id: model.device) { await model.reload() }
        // The inspector opens on the first selection; after that the toolbar button decides.
        .onChange(of: selection) { old, new in
            if old.isEmpty, !new.isEmpty { showInspector = true }
        }
        .confirmationDialog(
            model.pendingChange?.title ?? "",
            isPresented: Binding(get: { model.pendingChange != nil }, set: { if !$0 { model.cancelPendingChange() } }),
            presenting: model.pendingChange,
            actions: confirmationActions,
            message: { Text($0.message) }
        )
        .sheet(isPresented: $showPresets) { PresetSheet(model: model, brand: brand) }
    }

    private var table: some View {
        Table(model.visibleApps, selection: $selection) {
            TableColumn("App") { (app: InstalledApp) in AppCell(app: app) }
                .width(min: 200, ideal: 300)
            TableColumn("Version") { (app: InstalledApp) in
                Text(app.versionName ?? String(app.versionCode)).foregroundStyle(.secondary)
            }
            .width(min: 50, ideal: 80)
            TableColumn("Source") { (app: InstalledApp) in Text(app.installSource).foregroundStyle(.secondary) }
                .width(min: 80, ideal: 120)
            TableColumn("State") { (app: InstalledApp) in AppStateLabel(app: app) }
                .width(min: 80, ideal: 100)
        }
        .alternatingRowBackgrounds(.disabled)
        .contextMenu(forSelectionType: PackageName.self) { packages in
            if !packages.isEmpty {
                Button("Turn Off") { model.request(.disableForUser, for: Array(packages)) }
                Button("Remove for This User") { model.request(.uninstallForUser, for: Array(packages)) }
                if packages.count == 1, let package = packages.first {
                    Divider()
                    Button("Export APK…") { export(package) }
                }
            }
        }
        .overlay {
            if model.isLoading, model.apps.isEmpty {
                ProgressView("Reading apps…")
            } else if model.visibleApps.isEmpty, !model.apps.isEmpty {
                ContentUnavailableView.search(text: model.searchText)
            }
        }
        .accessibilityLabel("Installed apps")
        .accessibilityIdentifier("appsTable")
    }

    @ToolbarContentBuilder private var toolbar: some ToolbarContent {
        ToolbarItemGroup {
            Button("Debloat…", systemImage: "wand.and.stars") { showPresets = true }
                .labelStyle(.titleAndIcon)
                .help("Turn off apps that brand debloat lists recommend")
                .accessibilityIdentifier("presetsButton")
            Button("Reload", systemImage: "arrow.clockwise") { Task { await model.reload() } }
                .help("Read the app list again")
            Button("Details", systemImage: "sidebar.right") { showInspector.toggle() }
                .help(showInspector ? "Hide app details" : "Show app details")
        }
    }

    @ViewBuilder private func confirmationActions(_ change: AppsModel.PendingChange) -> some View {
        Button(change.operation.isDestructive ? "Confirm" : "Continue", role: change.operation.isDestructive ? .destructive : nil) {
            Task { await model.confirm(change) }
        }
        .accessibilityIdentifier("confirmChange")
        Button("Cancel", role: .cancel) { model.cancelPendingChange() }
    }

    private func export(_ package: PackageName) {
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

/// The filter as a segmented control with counts, so the numbers answer "how much is on my phone".
struct FilterBar: View {
    @Bindable var model: AppsModel

    var body: some View {
        HStack {
            Picker("Show", selection: $model.filter) {
                ForEach(AppsModel.Filter.allCases) { filter in
                    Text("\(filter.rawValue) \(model.count(for: filter))").tag(filter)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .accessibilityIdentifier("appsFilter")
            Spacer()
        }
        .padding(.horizontal, Spacing.large)
        .padding(.vertical, Spacing.small)
    }
}

/// An app as people know it: tile, name, and the package underneath.
struct AppCell: View {
    let app: InstalledApp

    var body: some View {
        let name = AppCell.name(of: app)
        HStack(spacing: Spacing.small) {
            AppTile(name: name, seed: app.packageName.rawValue, size: 26)
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: Spacing.xSmall) {
                    Text(name)
                    if AppsModel.isProtected(app.packageName) {
                        Image(systemName: "lock.fill")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .accessibilityLabel("Protected")
                            .help("A core part of Android. Airlock never turns it off or removes it.")
                    }
                }
                Text(app.packageName.rawValue).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier(app.packageName.rawValue)
    }

    static func name(of app: InstalledApp) -> String {
        app.label ?? AppNaming.name(forPackage: app.packageName.rawValue)
    }
}

struct AppStateLabel: View {
    let app: InstalledApp

    var body: some View {
        switch app.state {
        case .enabled: Text(app.isSystem ? "System" : "Installed").foregroundStyle(.secondary)
        case .disabled: Label("Turned off", systemImage: "pause.circle.fill").foregroundStyle(.primary)
        case .uninstalledForUser: Label("Removed", systemImage: "minus.circle.fill").foregroundStyle(.primary)
        }
    }
}

/// The selected app: what it is, what the debloat lists say, and the changes it allows, as labelled buttons.
struct AppInspector: View {
    let model: AppsModel
    let brand: DeviceBrand
    let selection: Set<PackageName>
    let export: (PackageName) -> Void

    var body: some View {
        let selected = model.apps.filter { selection.contains($0.packageName) }
        Group {
            if selected.isEmpty {
                Text("Select an app to see what you can do with it.")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(Spacing.xLarge)
                    .frame(maxHeight: .infinity)
            } else if selected.count == 1, let app = selected.first {
                single(app)
            } else {
                several(selected)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }

    private func single(_ app: InstalledApp) -> some View {
        let name = AppCell.name(of: app)
        let advice = model.debloatAdvice(for: app.packageName, brand: brand)
        let protected = AppsModel.isProtected(app.packageName)
        return ScrollView {
            VStack(alignment: .leading, spacing: Spacing.large) {
                VStack(alignment: .leading, spacing: Spacing.small) {
                    AppTile(name: name, seed: app.packageName.rawValue, size: 56)
                    Text(name).font(.title3.weight(.semibold))
                    Text(app.packageName.rawValue).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                }
                Grid(alignment: .leading, horizontalSpacing: Spacing.medium, verticalSpacing: Spacing.xSmall) {
                    GridRow { Text("Version").foregroundStyle(.secondary); Text(app.versionName ?? String(app.versionCode)) }
                    GridRow { Text("Source").foregroundStyle(.secondary); Text(app.installSource) }
                    GridRow { Text("State").foregroundStyle(.secondary); AppStateLabel(app: app) }
                }
                .font(.callout)
                if protected {
                    Label("A core part of Android. Airlock never turns it off or removes it.", systemImage: "lock.fill")
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                } else if let advice {
                    DebloatAdvice(entry: advice)
                }
                VStack(alignment: .leading, spacing: Spacing.small) {
                    actions(for: app, protected: protected)
                }
                .controlSize(.large)
            }
            .padding(Spacing.large)
        }
    }

    @ViewBuilder private func actions(for app: InstalledApp, protected: Bool) -> some View {
        switch app.state {
        case .enabled:
            Button("Turn Off") { model.request(.disableForUser, for: [app.packageName]) }
                .help("The app stops running until you turn it on again. Undo from History.")
            Button("Remove for This User", role: .destructive) { model.request(.uninstallForUser, for: [app.packageName]) }
                .help("Hidden and stopped, still on the phone. Restore from History.")
        case .disabled:
            Button("Turn On") { model.request(.enable, for: [app.packageName]) }
        case .uninstalledForUser:
            Button("Restore") { model.request(.installExisting, for: [app.packageName]) }
        }
        if app.state == .enabled || !protected {
            Button("Export APK…") { export(app.packageName) }
        }
    }

    private func several(_ apps: [InstalledApp]) -> some View {
        VStack(alignment: .leading, spacing: Spacing.medium) {
            Text("\(apps.count) apps selected").font(.title3.weight(.semibold))
            Text(apps.map { AppCell.name(of: $0) }.joined(separator: ", "))
                .foregroundStyle(.secondary)
                .lineLimit(6)
            Button("Turn Off \(apps.count) Apps") { model.request(.disableForUser, for: apps.map(\.packageName)) }
            Button("Remove \(apps.count) Apps for This User", role: .destructive) {
                model.request(.uninstallForUser, for: apps.map(\.packageName))
            }
        }
        .controlSize(.large)
        .padding(Spacing.large)
    }
}

/// What UAD-ng says about an app, with its risk in words and colour.
struct DebloatAdvice: View {
    let entry: DebloatEntry

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.xSmall) {
            Label(DebloatAdvice.title(entry.risk), systemImage: "wand.and.stars")
                .font(.callout.weight(.semibold))
                .foregroundStyle(Palette.debloat(entry.risk))
            Text(entry.description)
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(8)
                .fixedSize(horizontal: false, vertical: true)
            Text("From the UAD-ng debloat list").font(.caption).foregroundStyle(.secondary)
        }
        .padding(Spacing.medium)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
    }

    static func title(_ risk: DebloatRisk) -> String {
        switch risk {
        case .safe: "Fine to turn off"
        case .caution: "Turn off with care"
        case .expert: "Experts only"
        }
    }
}

/// The outcome of the last change, under the table, until dismissed.
struct ResultsBanner: View {
    let model: AppsModel

    var body: some View {
        let results = model.results
        let failures = results.filter { $0.error != nil }
        if !results.isEmpty {
            HStack(alignment: .top, spacing: Spacing.small) {
                Image(systemName: failures.isEmpty ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .foregroundStyle(failures.isEmpty ? Palette.success : Palette.warning)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(AppsModel.summary(of: results)).fontWeight(.semibold)
                    ForEach(failures, id: \.package) { failure in
                        Text("\(failure.package.rawValue): \(failure.error ?? "")").font(.callout)
                    }
                }
                Spacer()
                Button("Dismiss") { model.dismissResults() }.buttonStyle(.borderless)
            }
            .padding(.horizontal, Spacing.large)
            .padding(.vertical, Spacing.small)
            .background(failures.isEmpty ? Palette.success.opacity(0.10) : Palette.warning.opacity(0.14))
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

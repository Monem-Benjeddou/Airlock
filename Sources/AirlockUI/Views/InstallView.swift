// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import SwiftUI
import UniformTypeIdentifiers

/// F2: drop files, watch the queue, review risky packages, fix failures.
///
/// The whole page takes drops. Empty, it is one invitation to drop; with files, it is the queue under a
/// one-line summary.
struct InstallView: View {
    let queue: InstallQueueModel
    let device: DeviceInfo?
    @State private var isTargeted = false
    @State private var showImporter = false
    @State private var pendingFix: (id: UUID, package: String)?

    var body: some View {
        Group {
            if queue.items.isEmpty {
                EmptyDropState(deviceName: device?.displayName) { showImporter = true }
            } else {
                queueContent
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .contentShape(Rectangle())
        .onDrop(of: [.fileURL], isTargeted: $isTargeted) { providers in
            load(providers)
            return true
        }
        .overlay { if isTargeted { DropHighlight() } }
        .toolbar {
            ToolbarItem {
                Button("Add Files…", systemImage: "plus") { showImporter = true }
                    .labelStyle(.titleAndIcon)
                    .accessibilityIdentifier("addFiles")
            }
        }
        .fileImporter(isPresented: $showImporter, allowedContentTypes: [.data, .folder], allowsMultipleSelection: true) { result in
            if case .success(let urls) = result { queue.add(urls) }
        }
        .sheet(item: reviewBinding) { review in
            ReviewSheet(plan: review.plan, queue: queue)
        }
        .confirmationDialog(
            "Uninstall the existing app first?",
            isPresented: Binding(get: { pendingFix != nil }, set: { if !$0 { pendingFix = nil } }),
            presenting: pendingFix
        ) { fix in
            Button("Uninstall and Install", role: .destructive) {
                guard let name = PackageName(rawValue: fix.package) else { return }
                let confirmation = ConfirmedOperation(userConfirmed: .uninstall, on: name)
                Task { await queue.applyFix(.uninstallExistingThenInstall, to: fix.id, confirmation: confirmation) }
            }
        } message: { _ in
            Text("The app on your phone and its data are deleted. "
                + "Airlock keeps a copy of the old app so you can reinstall it from History.")
        }
    }

    private var queueContent: some View {
        VStack(spacing: 0) {
            QueueHeader(queue: queue, deviceName: device?.displayName)
            Divider()
            if let notice = queue.notice {
                Label(notice, systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, Spacing.xLarge)
                    .padding(.vertical, Spacing.small)
                    .background(Palette.warning.opacity(0.12))
            }
            // A plain stack, not a List: List's reused table rows sometimes kept showing an old state when a
            // row changed height (an install finishing), so a finished install still looked stuck.
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(queue.items) { item in
                        QueueRow(item: item, queue: queue) { id, package in pendingFix = (id, package) }
                            .padding(.horizontal, Spacing.xLarge)
                            .padding(.vertical, Spacing.medium)
                        Divider().padding(.leading, Spacing.xLarge + 40 + Spacing.medium)
                    }
                }
            }
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Install queue")
            .accessibilityIdentifier("installQueue")
            Text("Drop more files anywhere on this page")
                .font(.callout)
                .foregroundStyle(.secondary)
                .padding(Spacing.medium)
        }
    }

    private struct Review: Identifiable {
        let id: UUID
        let plan: InstallPlan
    }

    private var reviewBinding: Binding<Review?> {
        Binding(
            get: {
                for item in queue.items {
                    if case .needsReview(let plan) = item.state { return Review(id: item.id, plan: plan) }
                }
                return nil
            },
            set: { _ in }
        )
    }

    private func load(_ providers: [NSItemProvider]) {
        for provider in providers {
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                guard let url else { return }
                Task { @MainActor in queue.add([url]) }
            }
        }
    }
}

/// The page before anything is dropped: one clear invitation.
struct EmptyDropState: View {
    let deviceName: String?
    let choose: () -> Void

    var body: some View {
        VStack(spacing: Spacing.large) {
            Image(systemName: "arrow.down.app")
                .font(.system(size: 56, weight: .light))
                .foregroundStyle(Color.accentColor)
                .accessibilityHidden(true)
            VStack(spacing: Spacing.small) {
                Text("Drop Android apps to check them")
                    .font(.title2.weight(.semibold))
                Text("Airlock checks every file before it goes on " + (deviceName ?? "your phone") + ".")
                    .foregroundStyle(.secondary)
            }
            Button("Choose Files…", action: choose)
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .accessibilityIdentifier("chooseFiles")
            Text("APK, APKS, XAPK, APKM, or a folder of split APKs")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .multilineTextAlignment(.center)
        .padding(Spacing.xxLarge)
        // `.contain` keeps the identifier on the container; without it SwiftUI copies it onto every child,
        // replacing the button's own identifier.
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Drop files to install")
        .accessibilityIdentifier("dropZone")
    }
}

/// Drawn over the page while files are dragged over it.
struct DropHighlight: View {
    var body: some View {
        RoundedRectangle(cornerRadius: 14, style: .continuous)
            .strokeBorder(Color.accentColor, lineWidth: 3)
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Color.accentColor.opacity(0.08)))
            .overlay {
                Label("Drop to check", systemImage: "arrow.down.app")
                    .font(.title3.weight(.semibold))
                    .padding(.horizontal, Spacing.large)
                    .padding(.vertical, Spacing.small)
                    .background(.regularMaterial, in: Capsule())
            }
            .padding(Spacing.small)
            .allowsHitTesting(false)
            .accessibilityHidden(true)
    }
}

/// What the queue is doing, in one line, with Clear Finished beside it.
struct QueueHeader: View {
    let queue: InstallQueueModel
    let deviceName: String?

    var body: some View {
        HStack(spacing: Spacing.medium) {
            symbol.font(.title2).frame(width: 28).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(queue.summary ?? "")
                    .font(.title3.weight(.semibold))
                    .accessibilityIdentifier("queueSummary")
                if let deviceName { Text("On \(deviceName)").font(.callout).foregroundStyle(.secondary) }
            }
            Spacer()
            Button("Clear Finished") { queue.clearFinished() }
                .disabled(!queue.items.contains { $0.state.isFinished })
                .accessibilityIdentifier("clearFinished")
        }
        .padding(.horizontal, Spacing.xLarge)
        .padding(.vertical, Spacing.large)
    }

    @ViewBuilder private var symbol: some View {
        let finished = queue.items.allSatisfy(\.state.isFinished)
        let allInstalled = queue.items.allSatisfy { if case .installed = $0.state { true } else { false } }
        if queue.items.contains(where: { if case .needsReview = $0.state { true } else { false } }) {
            Image(systemName: "exclamationmark.shield.fill").foregroundStyle(Palette.warning)
        } else if !finished {
            ProgressView().controlSize(.small)
        } else if allInstalled {
            Image(systemName: "checkmark.circle.fill").foregroundStyle(Palette.success)
        } else {
            Image(systemName: "exclamationmark.circle.fill").foregroundStyle(Palette.warning)
        }
    }
}

struct QueueRow: View {
    let item: InstallQueueModel.Item
    let queue: InstallQueueModel
    let requestUninstallFix: (UUID, String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.small) {
            HStack(spacing: Spacing.medium) {
                AppTile(name: name, seed: item.package?.packageName ?? item.displayName, size: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(name).font(.headline).lineLimit(1)
                    Text(QueueRow.subtitle(of: item))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                Spacer(minLength: Spacing.large)
                if let level = item.riskLevel { CompactRiskBadge(level: level) }
                status.frame(minWidth: 150, alignment: .trailing)
            }
            if case .failed(let error) = item.state {
                FailureView(error: error, item: item, queue: queue, requestUninstallFix: requestUninstallFix)
                    .padding(.leading, 40 + Spacing.medium)
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(name)
        .accessibilityIdentifier("queueItem")
    }

    private var name: String {
        item.package.map { AppNaming.name(forPackage: $0.packageName) } ?? AppNaming.name(forFile: item.file)
    }

    /// "com.demo.notes · version 1.0 · 12 MB", or the file name before the file is read.
    static func subtitle(of item: InstallQueueModel.Item) -> String {
        guard let package = item.package else { return item.displayName }
        let bytes = package.base.sizeBytes + package.splits.reduce(0) { $0 + $1.sizeBytes }
        let size = ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
        return [package.packageName, "version \(package.base.manifest.versionName ?? String(package.base.manifest.versionCode))", size]
            .joined(separator: " · ")
    }

    @ViewBuilder private var status: some View {
        switch item.state {
        case .waiting: statusText("Waiting", color: .secondary)
        case .inspecting:
            HStack(spacing: Spacing.small) { ProgressView().controlSize(.small); statusText("Checking…", color: .secondary) }
        case .needsReview: statusText("Waiting for your review", color: .primary)
        case .installing(let progress):
            HStack(spacing: Spacing.small) {
                ProgressView(value: progress.totalFraction)
                    .frame(width: 90)
                    .accessibilityLabel(progress.message)
                Button("Stop") { queue.cancelCurrent() }.accessibilityIdentifier("cancelInstall")
            }
        case .installed:
            HStack(spacing: Spacing.xSmall) {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(Palette.success).accessibilityHidden(true)
                statusText("Installed", color: .primary)
            }
        case .skipped: statusText("Not installed", color: .secondary)
        case .cancelled: statusText("Cancelled", color: .secondary)
        case .failed:
            HStack(spacing: Spacing.xSmall) {
                Image(systemName: "xmark.octagon.fill").foregroundStyle(Palette.danger).accessibilityHidden(true)
                statusText("Failed", color: .primary)
            }
        }
    }

    private func statusText(_ text: String, color: Color) -> some View {
        Text(text).foregroundStyle(color).accessibilityIdentifier("itemStatus")
    }
}

/// The verdict at row size: a coloured symbol and the level in primary text.
struct CompactRiskBadge: View {
    let level: RiskLevel

    var body: some View {
        HStack(spacing: Spacing.xSmall) {
            Image(systemName: Palette.verdictSymbol(level)).foregroundStyle(Palette.verdict(level)).accessibilityHidden(true)
            Text(level.title)
        }
        .font(.callout)
        .padding(.horizontal, Spacing.small)
        .padding(.vertical, 3)
        .background(Capsule().fill(Palette.verdict(level).opacity(0.14)))
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("rowRisk")
    }
}

struct FailureView: View {
    let error: InstallError
    let item: InstallQueueModel.Item
    let queue: InstallQueueModel
    let requestUninstallFix: (UUID, String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(InstallErrorText.title(error)).fontWeight(.semibold)
            Text(InstallErrorText.explanation(error)).fixedSize(horizontal: false, vertical: true)
            if case .packageManager(let explained) = error, let fix = explained.fix {
                Button(fix.buttonTitle) {
                    if fix == .uninstallExistingThenInstall {
                        requestUninstallFix(item.id, item.package?.packageName ?? "")
                    } else {
                        Task { await queue.applyFix(fix, to: item.id, confirmation: nil) }
                    }
                }
                .accessibilityIdentifier("fixButton")
            }
        }
    }
}

/// Plain-English text for every install error, used by the queue and tests.
enum InstallErrorText {
    static func title(_ error: InstallError) -> String {
        switch error {
        case .packageManager(let explained): explained.title
        case .preCheckFailed: "This app cannot be installed yet"
        case .cancelled: "Cancelled"
        case .obbVerificationFailed: "Game data did not copy correctly"
        case .verificationFailed: "The install could not be confirmed"
        case .deviceDisconnected: "The phone was disconnected"
        case .unsupportedFile: "Not an Android app"
        case .unsafeArchive: "This file is unsafe"
        case .transport: "Something went wrong"
        }
    }

    static func explanation(_ error: InstallError) -> String {
        switch error {
        case .packageManager(let explained): explained.explanation
        case .preCheckFailed(let problems): problems.map(PreCheckText.describe).joined(separator: " ")
        case .cancelled: "Nothing was changed on the phone."
        case .obbVerificationFailed(let file): "\(file) was not copied completely. Free some space on the phone and try again."
        case .verificationFailed(let detail): detail
        case .deviceDisconnected: "Reconnect the phone and try again. Nothing was left half-installed."
        case .unsupportedFile(let message): message
        case .unsafeArchive(let message): message + " Airlock did not open it."
        case .transport(let message): message
        }
    }
}

enum PreCheckText {
    static func describe(_ problem: PreCheckProblem) -> String {
        switch problem {
        case .deviceSDKTooOld(let required, let device):
            "It needs Android API level \(required); this phone has \(device)."
        case .insufficientStorage(let required, let free):
            "It needs about \(format(required)) free on the phone; only \(format(free)) is free."
        case .versionDowngrade(let installed, let incoming):
            "The phone has a newer version (\(installed)) than this file (\(incoming)). Installing it means uninstalling first."
        case .signerMismatch:
            "It is signed by a different developer than the app already on the phone. Installing it means uninstalling first."
        case .splitPackageMismatch(let file):
            "\(file) belongs to a different app or version."
        case .noMatchingABI(let available):
            "It only contains code for \(available.joined(separator: ", ")), which this phone does not support."
        }
    }

    private static func format(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }
}

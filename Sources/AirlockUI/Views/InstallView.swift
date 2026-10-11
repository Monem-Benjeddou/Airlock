// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import SwiftUI
import UniformTypeIdentifiers

/// F2: drop files, watch the queue, review risky packages, fix failures.
struct InstallView: View {
    let queue: InstallQueueModel
    let device: DeviceInfo?
    @State private var isTargeted = false
    @State private var showImporter = false
    @State private var pendingFix: (id: UUID, package: String)?

    var body: some View {
        VStack(spacing: 0) {
            DropZone(isTargeted: isTargeted, deviceName: device?.model) { showImporter = true }
                .padding()
                .onDrop(of: [.fileURL], isTargeted: $isTargeted) { providers in
                    load(providers)
                    return true
                }
            if let notice = queue.notice {
                Text(notice).font(.callout).foregroundStyle(Palette.warning).padding(.horizontal)
            }
            List {
                ForEach(queue.items) { item in
                    QueueRow(item: item, queue: queue) { id, package in pendingFix = (id, package) }
                }
            }
            .accessibilityIdentifier("installQueue")
            .overlay {
                if queue.items.isEmpty {
                    Text("Files you drop appear here.").foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("Install")
        .toolbar {
            ToolbarItem {
                Button("Clear Finished", systemImage: "checkmark.circle") { queue.clearFinished() }
                    .disabled(!queue.items.contains { $0.state.isFinished })
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

struct DropZone: View {
    let isTargeted: Bool
    let deviceName: String?
    let choose: () -> Void

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: "arrow.down.app").font(.system(size: 40)).foregroundStyle(Color.accentColor)
                .accessibilityHidden(true)
            Text("Drop APK, APKS, XAPK or APKM files or a folder of split APKs")
                .font(.headline)
            Text("Every file is checked before it is installed" + (deviceName.map { " on \($0)." } ?? "."))
                .foregroundStyle(.secondary)
            Button("Choose Files…", action: choose).accessibilityIdentifier("chooseFiles")
        }
        .frame(maxWidth: .infinity, minHeight: 170)
        .background(
            RoundedRectangle(cornerRadius: 14)
                .strokeBorder(style: StrokeStyle(lineWidth: 2, dash: [8]))
                .foregroundStyle(isTargeted ? Color.accentColor : .secondary.opacity(0.5))
        )
        // `.contain` keeps the identifier on the container; without it SwiftUI copies it onto every child,
        // replacing the button's own identifier.
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("dropZone")
    }
}

struct QueueRow: View {
    let item: InstallQueueModel.Item
    let queue: InstallQueueModel
    let requestUninstallFix: (UUID, String) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            icon.font(.title2).frame(width: 28)
            VStack(alignment: .leading, spacing: 4) {
                Text(item.package?.packageName ?? item.displayName).font(.headline)
                detail
            }
            Spacer()
            if case .installing = item.state {
                Button("Cancel") { queue.cancelCurrent() }.accessibilityIdentifier("cancelInstall")
            }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("queueItem")
    }

    /// Hidden from VoiceOver: the text beside it already says the state.
    private var icon: some View {
        stateSymbol.accessibilityHidden(true)
    }

    @ViewBuilder private var stateSymbol: some View {
        switch item.state {
        case .waiting: Image(systemName: "clock").foregroundStyle(.secondary)
        case .inspecting: ProgressView().controlSize(.small)
        case .needsReview: Image(systemName: "exclamationmark.shield").foregroundStyle(Palette.warning)
        case .installing: Image(systemName: "arrow.down.circle").foregroundStyle(Color.accentColor)
        case .installed: Image(systemName: "checkmark.circle.fill").foregroundStyle(Palette.success)
        case .failed: Image(systemName: "xmark.octagon.fill").foregroundStyle(Palette.danger)
        case .skipped, .cancelled: Image(systemName: "minus.circle").foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var detail: some View {
        switch item.state {
        case .waiting: Text("Waiting").foregroundStyle(.secondary)
        case .inspecting: Text("Checking the file…").foregroundStyle(.secondary)
        case .needsReview(let plan): Text("\(plan.report.level.title): review before installing").foregroundStyle(Palette.warning)
        case .installing(let progress):
            ProgressView(value: progress.totalFraction) { Text(progress.message).font(.caption) }
        case .installed(let outcome): Text("Installed version \(outcome.versionCode)").foregroundStyle(.secondary)
        case .skipped: Text("Not installed").foregroundStyle(.secondary)
        case .cancelled: Text("Cancelled. Nothing was changed on the phone.").foregroundStyle(.secondary)
        case .failed(let error): FailureView(error: error, item: item, queue: queue, requestUninstallFix: requestUninstallFix)
        }
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
            Text(InstallErrorText.explanation(error)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
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

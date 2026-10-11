// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation
import Observation

/// F2: a queue of up to 20 dropped files, installed one after another.
///
/// Low-risk packages without problems install straight away; anything Medium or High risk, or with a
/// pre-check problem, waits for the user's decision. One failure never stops the rest of the queue.
@MainActor
@Observable
public final class InstallQueueModel {
    public static let maximumItems = 20

    public enum State: Equatable, Sendable {
        case waiting
        case inspecting
        case needsReview(InstallPlan)
        case installing(InstallProgress)
        case installed(InstallOutcome)
        case failed(InstallError)
        case skipped
        case cancelled

        public var isFinished: Bool {
            switch self {
            case .installed, .failed, .skipped, .cancelled: true
            case .waiting, .inspecting, .needsReview, .installing: false
            }
        }
    }

    public struct Item: Identifiable, Equatable, Sendable {
        public let id: UUID
        public let file: URL
        public var state: State
        public var package: InspectedPackage?
        /// The safety verdict, kept after the install so the row still shows it.
        public var riskLevel: RiskLevel?

        public var displayName: String { file.lastPathComponent }
    }

    public private(set) var items: [Item] = []
    /// Shown when files were refused (queue full, nothing to add).
    public private(set) var notice: String?

    private let pipeline: any InstallPipeline
    private let appManager: any AppManager
    private var worker: Task<Void, Never>?
    private var currentInstall: Task<InstallOutcome, any Error>?
    private var reviewContinuation: CheckedContinuation<InstallPlan?, Never>?
    public var targetDevice: DeviceSerial?
    private let keepAwake: @MainActor (String) -> @MainActor () -> Void

    /// - Parameter keepAwake: starts a hold against App Nap and idle sleep and returns its release; App Nap
    ///   throttles timers and I/O in the background, which stalls adb transfers and trips their timeouts.
    public init(
        pipeline: any InstallPipeline,
        appManager: any AppManager,
        keepAwake: @escaping @MainActor (String) -> @MainActor () -> Void = InstallQueueModel.systemKeepAwake
    ) {
        self.pipeline = pipeline
        self.appManager = appManager
        self.keepAwake = keepAwake
    }

    public static func systemKeepAwake(_ reason: String) -> @MainActor () -> Void {
        let activity = ProcessInfo.processInfo.beginActivity(options: .userInitiated, reason: reason)
        return { ProcessInfo.processInfo.endActivity(activity) }
    }

    public var isBusy: Bool { worker != nil }

    /// One line over the queue, computed from the items so it is right even when a row is slow to redraw.
    public var summary: String? {
        guard !items.isEmpty else { return nil }
        if items.contains(where: { if case .needsReview = $0.state { true } else { false } }) {
            return "Waiting for your review"
        }
        let finished = items.filter(\.state.isFinished)
        guard finished.count == items.count else { return "Installing \(finished.count + 1) of \(items.count)" }
        let installed = items.filter { if case .installed = $0.state { true } else { false } }.count
        let missed = items.count - installed
        if missed == 0 { return items.count == 1 ? "Installed" : "All \(items.count) installed" }
        if installed == 0 { return items.count == 1 ? "Not installed" : "None of the \(items.count) installed" }
        return "\(installed) of \(items.count) installed, \(missed) not installed"
    }

    // MARK: Adding

    public func add(_ files: [URL]) {
        let open = items.filter { !$0.state.isFinished }.count
        let room = max(Self.maximumItems - open, 0)
        let accepted = files.prefix(room)
        items += accepted.map { Item(id: UUID(), file: $0, state: .waiting, riskLevel: nil) }
        notice = files.count > accepted.count
            ? "Airlock installs up to \(Self.maximumItems) files at a time. \(files.count - accepted.count) file(s) were not added."
            : nil
        startIfNeeded()
    }

    public func clearFinished() {
        items.removeAll { $0.state.isFinished }
    }

    // MARK: Review decisions

    /// Installs the reviewed item with the (possibly edited) split selection.
    public func approve(_ plan: InstallPlan) {
        resumeReview(with: plan)
    }

    public func skipReview() {
        resumeReview(with: nil)
    }

    /// Cancels the running install; the pipeline abandons the session so nothing is left on the phone.
    public func cancelCurrent() {
        currentInstall?.cancel()
        if reviewContinuation != nil { resumeReview(with: nil) }
    }

    /// Runs a suggested fix for a failed item, then retries it.
    public func applyFix(_ fix: FixAction, to id: UUID, confirmation: ConfirmedOperation?) async {
        guard let index = items.firstIndex(where: { $0.id == id }), let serial = targetDevice else { return }
        if fix == .uninstallExistingThenInstall {
            guard let confirmation else { return }
            do {
                _ = try await appManager.perform(confirmation, on: serial)
            } catch {
                items[index].state = .failed(.transport("Could not uninstall the existing app: \(error)"))
                return
            }
        }
        items[index].state = .waiting
        startIfNeeded()
    }

    // MARK: Processing

    private func startIfNeeded() {
        guard worker == nil else { return }
        let release = keepAwake("Installing apps on a phone")
        worker = Task { [weak self] in
            await self?.processQueue()
            self?.worker = nil
            release()
        }
    }

    private func processQueue() async {
        while let index = items.firstIndex(where: { $0.state == .waiting }) {
            await process(itemAt: index)
        }
    }

    private func process(itemAt index: Int) async {
        let id = items[index].id
        guard let serial = targetDevice else {
            update(id) { $0.state = .failed(.deviceDisconnected) }
            return
        }
        update(id) { $0.state = .inspecting }
        do {
            let package: InspectedPackage
            if let existing = items.first(where: { $0.id == id })?.package {
                package = existing
            } else {
                package = try await pipeline.inspect(items[index].file)
                update(id) { $0.package = package }
            }
            var plan = try await pipeline.plan(package, for: serial)
            update(id) { $0.riskLevel = plan.report.level }
            if plan.report.level.requiresConfirmation || !plan.problems.isEmpty {
                update(id) { $0.state = .needsReview(plan) }
                guard let approved = await waitForReview() else {
                    update(id) { $0.state = .skipped }
                    await pipeline.discard(package)
                    return
                }
                plan = approved
            }
            let outcome = try await install(plan, id: id)
            update(id) { $0.state = .installed(outcome) }
            await pipeline.discard(package)
        } catch let error as InstallError {
            update(id) { $0.state = error == .cancelled ? .cancelled : .failed(error) }
        } catch {
            update(id) { $0.state = .failed(.transport(String(describing: error))) }
        }
    }

    private func install(_ plan: InstallPlan, id: UUID) async throws -> InstallOutcome {
        let pipeline = pipeline
        let task = Task<InstallOutcome, any Error> {
            try await pipeline.install(plan) { progress in
                Task { @MainActor [weak self] in self?.reportProgress(progress, for: id) }
            }
        }
        currentInstall = task
        defer { currentInstall = nil }
        update(id) { $0.state = .installing(InstallProgress(step: .preparing, stepFraction: 0, totalFraction: 0, message: "Starting")) }
        return try await task.value
    }

    /// Progress can arrive after the item finished; it must never overwrite a final state.
    private func reportProgress(_ progress: InstallProgress, for id: UUID) {
        update(id) { item in
            if case .installing = item.state { item.state = .installing(progress) }
        }
    }

    private func waitForReview() async -> InstallPlan? {
        await withCheckedContinuation { continuation in
            reviewContinuation = continuation
        }
    }

    private func resumeReview(with plan: InstallPlan?) {
        reviewContinuation?.resume(returning: plan)
        reviewContinuation = nil
    }

    private func update(_ id: UUID, _ change: (inout Item) -> Void) {
        guard let index = items.firstIndex(where: { $0.id == id }) else { return }
        change(&items[index])
    }
}

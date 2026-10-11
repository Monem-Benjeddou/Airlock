// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation
import Observation

/// F4: the app list, debloat presets, confirmations and the change history.
@MainActor
@Observable
public final class AppsModel {
    public enum Filter: String, CaseIterable, Identifiable, Sendable {
        case all = "All"
        case user = "Yours"
        case system = "System"
        case disabled = "Turned Off"
        public var id: String { rawValue }
    }

    /// A destructive change waiting for the user to confirm in a dialog.
    public struct PendingChange: Identifiable, Equatable, Sendable {
        public let id = UUID()
        public let operation: DeviceOperation
        public let packages: [PackageName]

        public var title: String {
            let target = packages.count == 1 ? packages[0].rawValue : "\(packages.count) apps"
            switch operation {
            case .uninstall: return "Uninstall \(target)?"
            case .uninstallForUser: return "Remove \(target) for this user?"
            case .disableForUser: return "Turn off \(target)?"
            case .enable: return "Turn on \(target)?"
            case .installExisting: return "Restore \(target)?"
            }
        }

        public var message: String {
            switch operation {
            case .uninstall: "The app and its data are deleted. Airlock keeps a copy of the app (not its data) so you can reinstall it."
            case .uninstallForUser: "The app is hidden and stops running. You can restore it from History at any time."
            case .disableForUser: "The app stops running until you turn it on again here or from History."
            case .enable, .installExisting: "The app becomes available again."
            }
        }
    }

    public struct ChangeResult: Equatable, Sendable {
        public let package: PackageName
        public let error: String?
    }

    public private(set) var apps: [InstalledApp] = []
    public private(set) var history: [JournalEntry] = []
    public private(set) var isLoading = false
    public private(set) var lastError: String?
    public private(set) var results: [ChangeResult] = []
    public var searchText = ""
    public var filter: Filter = .all
    public var pendingChange: PendingChange?

    private let manager: any AppManager
    public var device: DeviceSerial?

    public init(manager: any AppManager) {
        self.manager = manager
    }

    public var visibleApps: [InstalledApp] {
        apps.filter { Self.matches($0, filter) }
            .filter { searchText.isEmpty || $0.packageName.rawValue.localizedCaseInsensitiveContains(searchText)
                || ($0.label?.localizedCaseInsensitiveContains(searchText) ?? false) }
    }

    /// How many apps a filter shows, before searching.
    public func count(for filter: Filter) -> Int {
        apps.filter { Self.matches($0, filter) }.count
    }

    private static func matches(_ app: InstalledApp, _ filter: Filter) -> Bool {
        switch filter {
        case .all: true
        case .user: !app.isSystem
        case .system: app.isSystem
        case .disabled: app.state != .enabled
        }
    }

    /// What the debloat lists say about a package, from the presets for this brand, if anything.
    public func debloatAdvice(for package: PackageName, brand: DeviceBrand) -> DebloatEntry? {
        for preset in presets(for: brand) {
            if let entry = preset.entries.first(where: { $0.packageName == package }) { return entry }
        }
        return nil
    }

    /// Core parts of Android that Airlock never disables or removes.
    public static func isProtected(_ package: PackageName) -> Bool {
        if case .blocked = CriticalDenylist.standard.check(rawPackage: package.rawValue, operation: .disableForUser) {
            return true
        }
        return false
    }

    /// "1 change applied", or "1 of 2 changes failed".
    public static func summary(of results: [ChangeResult]) -> String {
        let failures = results.filter { $0.error != nil }.count
        let noun = results.count == 1 ? "change" : "changes"
        return failures == 0 ? "\(results.count) \(noun) applied" : "\(failures) of \(results.count) \(noun) failed"
    }

    public func dismissResults() {
        results = []
    }

    public func presets(for brand: DeviceBrand) -> [DebloatPreset] {
        manager.presets(for: brand)
    }

    /// Preset entries that are actually installed and enabled on this phone, up to `maximumRisk`.
    public func applicableEntries(of preset: DebloatPreset, maximumRisk: DebloatRisk) -> [DebloatEntry] {
        let active = Set(apps.filter { $0.state == .enabled }.map(\.packageName))
        return preset.entries.filter { $0.risk <= maximumRisk && active.contains($0.packageName) }
    }

    // MARK: Loading

    public func reload() async {
        guard let device else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            apps = try await manager.listApps(on: device)
            history = try await manager.history(on: device)
            lastError = nil
        } catch {
            lastError = "Could not read the app list. Check that the phone is connected and unlocked."
        }
    }

    // MARK: Changes

    /// Step 1: ask. Nothing touches the phone until ``confirm(_:)``.
    public func request(_ operation: DeviceOperation, for packages: [PackageName]) {
        guard !packages.isEmpty else { return }
        pendingChange = PendingChange(operation: operation, packages: packages)
    }

    public func cancelPendingChange() {
        pendingChange = nil
    }

    /// Step 2: the user pressed the confirm button for `change`, the one the dialog presented. It is passed in
    /// rather than read back from ``pendingChange`` because dismissing the dialog clears that first.
    public func confirm(_ change: PendingChange) async {
        guard let device else { return }
        pendingChange = nil
        var outcomes: [ChangeResult] = []
        for package in change.packages {
            let confirmed = ConfirmedOperation(userConfirmed: change.operation, on: package)
            do {
                _ = try await manager.perform(confirmed, on: device)
                outcomes.append(ChangeResult(package: package, error: nil))
            } catch {
                outcomes.append(ChangeResult(package: package, error: Self.describe(error)))
            }
        }
        results = outcomes
        await reload()
    }

    /// Restores one history entry. Undoing an install removes the app, so it needs `confirmed`.
    public func restore(_ entry: JournalEntry, confirmed: Bool = false) async {
        guard let device else { return }
        let confirmation = confirmed ? ConfirmedOperation(userConfirmed: .uninstall, on: entry.packageName) : nil
        do {
            _ = try await manager.restore(entry, on: device, confirmation: confirmation)
            results = [ChangeResult(package: entry.packageName, error: nil)]
        } catch {
            results = [ChangeResult(package: entry.packageName, error: Self.describe(error))]
        }
        await reload()
    }

    public func export(_ package: PackageName, to folder: URL) async -> [URL] {
        guard let device else { return [] }
        do {
            return try await manager.exportAPKs(of: package, on: device, to: folder)
        } catch {
            results = [ChangeResult(package: package, error: Self.describe(error))]
            return []
        }
    }

    static func describe(_ error: any Error) -> String {
        switch error {
        case AppManagerError.blockedByDenylist(_, let reason): reason.explanation
        case AppManagerError.commandFailed(let message): message
        case AppManagerError.notRestorable: "This change cannot be undone."
        case AppManagerError.confirmationRequired: "This needs your confirmation first."
        case AppManagerError.deviceNotReady: "The phone is not ready."
        default: String(describing: error)
        }
    }
}

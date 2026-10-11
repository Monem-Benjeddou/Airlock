// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

// The four core services the UI depends on. Concrete implementations live in AirlockServices and are
// tested against a fake adb layer; views only ever see these protocols.

// MARK: - F1 Devices

public protocol DeviceService: Sendable {
    /// Emits the full device list whenever it changes, starting with the current list.
    func deviceUpdates() -> AsyncStream<[ConnectedDevice]>
    /// Reads model, Android version, battery and split-selection properties of a ready device.
    func info(for serial: DeviceSerial) async throws -> DeviceInfo
}

// MARK: - F2 Install

public enum InstallStep: String, Hashable, Sendable, Codable, CaseIterable {
    case preparing, installing, pushingOBB, verifying, cleaningUp
}

public struct InstallProgress: Hashable, Sendable {
    public let step: InstallStep
    /// Progress of the current step, 0...1.
    public let stepFraction: Double
    /// Progress of the whole install, 0...1.
    public let totalFraction: Double
    public let message: String

    public init(step: InstallStep, stepFraction: Double, totalFraction: Double, message: String) {
        self.step = step
        self.stepFraction = min(max(stepFraction, 0), 1)
        self.totalFraction = min(max(totalFraction, 0), 1)
        self.message = message
    }
}

/// A problem found before anything touches the device.
public enum PreCheckProblem: Hashable, Sendable {
    case deviceSDKTooOld(required: Int, device: Int)
    case insufficientStorage(requiredBytes: Int64, freeBytes: Int64)
    case versionDowngrade(installed: Int64, incoming: Int64)
    case signerMismatch
    case splitPackageMismatch(String)
    case noMatchingABI(available: [String])
}

/// Everything decided before install: what goes to the phone and what the user was warned about.
public struct InstallPlan: Hashable, Sendable {
    public let package: InspectedPackage
    public let device: DeviceInfo
    public let selectedSplits: [InspectedAPK]
    public let existing: InstalledApp?
    public let report: SafetyReport
    /// Problems that block install until resolved (for example by uninstalling first).
    public let problems: [PreCheckProblem]

    public init(
        package: InspectedPackage,
        device: DeviceInfo,
        selectedSplits: [InspectedAPK],
        existing: InstalledApp?,
        report: SafetyReport,
        problems: [PreCheckProblem]
    ) {
        self.package = package
        self.device = device
        self.selectedSplits = selectedSplits
        self.existing = existing
        self.report = report
        self.problems = problems
    }

    /// A copy with a user-edited split selection.
    public func with(selectedSplits: [InspectedAPK]) -> InstallPlan {
        InstallPlan(
            package: package, device: device, selectedSplits: selectedSplits,
            existing: existing, report: report, problems: problems
        )
    }
}

public enum InstallError: Error, Hashable, Sendable {
    /// The package manager rejected the install.
    case packageManager(ExplainedFailure)
    case preCheckFailed([PreCheckProblem])
    /// Cancelled; the install session was abandoned so nothing was left behind.
    case cancelled
    case obbVerificationFailed(fileName: String)
    /// `pm path` / versionCode check after install did not match.
    case verificationFailed(String)
    case deviceDisconnected
    case unsupportedFile(String)
    case unsafeArchive(String)
    case transport(String)
}

public struct InstallOutcome: Hashable, Sendable {
    public let packageName: PackageName
    public let versionCode: Int64
    public let journalEntryID: UUID?

    public init(packageName: PackageName, versionCode: Int64, journalEntryID: UUID?) {
        self.packageName = packageName
        self.versionCode = versionCode
        self.journalEntryID = journalEntryID
    }
}

public protocol InstallPipeline: Sendable {
    /// Identifies, safely extracts and parses a dropped file. Nothing touches the device.
    func inspect(_ file: URL) async throws(InstallError) -> InspectedPackage
    /// Runs the safety report, reads the device, resolves splits and runs pre-checks.
    func plan(_ package: InspectedPackage, for serial: DeviceSerial) async throws(InstallError) -> InstallPlan
    /// Installs atomically. Task cancellation abandons the session and throws ``InstallError/cancelled``.
    func install(
        _ plan: InstallPlan,
        progress: @escaping @Sendable (InstallProgress) -> Void
    ) async throws(InstallError) -> InstallOutcome
    /// Deletes the job's work folder.
    func discard(_ package: InspectedPackage) async
}

// MARK: - F3 Safety

public protocol SafetyEngine: Sendable {
    /// - Parameter installedSigners: SHA-256 of the signer certificates of the installed copy, if any.
    func report(for package: InspectedPackage, installedSigners: [String]?) async -> SafetyReport
}

// MARK: - F4 Manage

public enum AppManagerError: Error, Hashable, Sendable {
    case blockedByDenylist(PackageName, DenylistReason)
    case notRestorable(UUID)
    /// Undoing this entry removes an app, so it needs the user's confirmation.
    case confirmationRequired(PackageName)
    case commandFailed(String)
    case deviceNotReady
}

public protocol AppManager: Sendable {
    func listApps(on serial: DeviceSerial) async throws -> [InstalledApp]
    /// Checks the denylist, journals, then runs the operation.
    func perform(_ operation: ConfirmedOperation, on serial: DeviceSerial) async throws -> JournalEntry
    /// Undoes one journaled change. Undoing an install uninstalls the app, which requires `confirmation`.
    func restore(_ entry: JournalEntry, on serial: DeviceSerial, confirmation: ConfirmedOperation?) async throws -> JournalEntry
    func history(on serial: DeviceSerial) async throws -> [JournalEntry]
    /// Copies the base and split APKs of a package to a folder on the Mac.
    func exportAPKs(of package: PackageName, on serial: DeviceSerial, to folder: URL) async throws -> [URL]
    /// Copies the app's shared-storage folders (`Android/data`, `Android/obb`) to the Mac, where Android allows it.
    func backupAccessibleData(of package: PackageName, on serial: DeviceSerial, to folder: URL) async throws -> [URL]
    func presets(for brand: DeviceBrand) -> [DebloatPreset]
}

/// A file-reputation service queried by hash only.
public protocol ReputationLookup: Sendable {
    func lookup(sha256: String) async -> ReputationResult
}

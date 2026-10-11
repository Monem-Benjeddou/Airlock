// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Proof that the user explicitly confirmed a destructive operation.
///
/// The app manager only accepts destructive operations wrapped in this type. Views create it from the
/// confirmation dialog's button handler; nothing else in the codebase should.
public struct ConfirmedOperation: Hashable, Sendable {
    public let operation: DeviceOperation
    public let package: PackageName
    public let confirmedAt: Date

    public init(userConfirmed operation: DeviceOperation, on package: PackageName, at date: Date = Date()) {
        self.operation = operation
        self.package = package
        confirmedAt = date
    }
}

/// How a journaled change can be undone.
public enum RestoreAction: Hashable, Sendable, Codable {
    /// `cmd package install-existing` for packages removed for user 0.
    case installExisting
    /// `pm enable` for disabled packages.
    case enable
    /// Reinstall APKs that were backed up to the Mac before an uninstall. App data is not restored.
    case reinstallFromBackup(apkPaths: [String])
    /// Uninstall an app Airlock installed (it was not on the phone before).
    case uninstallInstalled
    /// Nothing can undo it (for example an update over an older version).
    case notRestorable
}

/// One device change, appended before the command runs and updated with its result.
public struct JournalEntry: Hashable, Sendable, Codable, Identifiable {
    public enum Status: String, Hashable, Sendable, Codable {
        /// Recorded, command not yet confirmed by the device. Seen after a crash mid-operation.
        case pending
        case applied
        case failed
        case restored
    }

    public enum Kind: Hashable, Sendable, Codable {
        case operation(DeviceOperation)
        case install(versionCode: Int64, wasUpdate: Bool)
    }

    public let id: UUID
    /// Stable hardware identity (`ro.serialno`), so USB and Wi-Fi sessions share one history.
    public let deviceID: String
    public let packageName: PackageName
    public let kind: Kind
    public let restore: RestoreAction
    public let createdAt: Date
    public var status: Status
    public var updatedAt: Date
    public var note: String?

    public init(
        id: UUID = UUID(),
        deviceID: String,
        packageName: PackageName,
        kind: Kind,
        restore: RestoreAction,
        createdAt: Date = Date(),
        status: Status = .pending,
        updatedAt: Date? = nil,
        note: String? = nil
    ) {
        self.id = id
        self.deviceID = deviceID
        self.packageName = packageName
        self.kind = kind
        self.restore = restore
        self.createdAt = createdAt
        self.status = status
        self.updatedAt = updatedAt ?? createdAt
        self.note = note
    }

    public var isRestorable: Bool {
        status == .applied && restore != .notRestorable
    }
}

public protocol JournalStore: Sendable {
    func append(_ entry: JournalEntry) async throws
    func update(id: UUID, status: JournalEntry.Status, note: String?) async throws
    func entries(deviceID: String) async throws -> [JournalEntry]
    /// Entries left `pending` by a crash, for reconciliation on next launch.
    func pendingEntries() async throws -> [JournalEntry]
}

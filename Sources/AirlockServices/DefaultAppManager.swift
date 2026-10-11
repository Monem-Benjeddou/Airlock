// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockADB
import AirlockCore
import Foundation

/// F4: lists apps and makes journaled, restorable changes.
///
/// Every change follows the same order: denylist check, backup if needed, journal entry (pending),
/// device command, journal update. A crash between the last two leaves a pending entry that is
/// reconciled on next launch.
public struct DefaultAppManager: AppManager {
    /// HOME handlers that are placeholders, not launchers a user can switch to.
    static let placeholderLaunchers: Set<String> = ["com.android.settings", "com.android.provision"]

    private let adb: ADBClient
    private let journal: any JournalStore
    private let library: PresetLibrary
    private let denylist: CriticalDenylist
    private let backupRoot: URL

    public init(
        adb: ADBClient,
        journal: any JournalStore,
        presets: PresetLibrary,
        denylist: CriticalDenylist = .standard,
        backupRoot: URL
    ) {
        self.adb = adb
        self.journal = journal
        library = presets
        self.denylist = denylist
        self.backupRoot = backupRoot
    }

    // MARK: Listing

    public func listApps(on serial: DeviceSerial) async throws -> [InstalledApp] {
        let channel = adb.device(serial)
        let entries = try await channel.packages(includingUninstalled: true)
        let installed = try await channel.packageNames(.all)
        let system = try await channel.packageNames(.system, includingUninstalled: true)
        let disabled = try await channel.packageNames(.disabled)

        return entries.map { entry in
            let name = entry.packageName.rawValue
            let state: InstalledApp.State = !installed.contains(name) ? .uninstalledForUser : disabled.contains(name) ? .disabled : .enabled
            return InstalledApp(
                packageName: entry.packageName,
                versionCode: entry.versionCode ?? 0,
                isSystem: system.contains(name),
                state: state,
                apkPaths: entry.apkPath.isEmpty ? [] : [entry.apkPath],
                installerPackage: entry.installer,
                uid: entry.uid
            )
        }
        .sorted { $0.packageName < $1.packageName }
    }

    public func presets(for brand: DeviceBrand) -> [DebloatPreset] {
        library.presets(for: brand)
    }

    public func history(on serial: DeviceSerial) async throws -> [JournalEntry] {
        try await journal.entries(deviceID: try await deviceID(serial))
    }

    // MARK: Changes

    public func perform(_ confirmed: ConfirmedOperation, on serial: DeviceSerial) async throws -> JournalEntry {
        let channel = adb.device(serial)
        let package = confirmed.package
        try await checkDenylist(package, operation: confirmed.operation, channel: channel)

        let restore: RestoreAction
        switch confirmed.operation {
        case .uninstall: restore = .reinstallFromBackup(apkPaths: try await backupAPKs(package, channel: channel, serial: serial))
        case .uninstallForUser:
            // Only system apps survive `pm uninstall --user 0`; a user app is deleted outright, so it
            // needs a backup to be restorable (found on a real Android 15 device).
            restore = try await isSystemApp(package, channel: channel)
                ? .installExisting
                : .reinstallFromBackup(apkPaths: try await backupAPKs(package, channel: channel, serial: serial))
        case .disableForUser: restore = .enable
        case .enable, .installExisting: restore = .notRestorable
        }

        let entry = JournalEntry(
            deviceID: try await deviceID(serial), packageName: package, kind: .operation(confirmed.operation), restore: restore
        )
        try await journal.append(entry)
        do {
            try await run(confirmed.operation, package, channel: channel)
        } catch {
            try await record(entry.id, .failed, note: Self.message(error))
            throw AppManagerError.commandFailed(Self.message(error))
        }
        try await record(entry.id, .applied, note: nil)
        var applied = entry
        applied.status = .applied
        return applied
    }

    public func restore(_ entry: JournalEntry, on serial: DeviceSerial, confirmation: ConfirmedOperation?) async throws -> JournalEntry {
        guard entry.isRestorable else { throw AppManagerError.notRestorable(entry.id) }
        let channel = adb.device(serial)
        let package = entry.packageName
        let undo: DeviceOperation

        switch entry.restore {
        case .installExisting:
            undo = .installExisting
            try await run(.installExisting, package, channel: channel)
        case .enable:
            undo = .enable
            try await run(.enable, package, channel: channel)
        case .reinstallFromBackup(let paths):
            undo = .installExisting
            try await reinstall(paths, channel: channel)
        case .uninstallInstalled:
            guard let confirmation, confirmation.operation == .uninstall, confirmation.package == package else {
                throw AppManagerError.confirmationRequired(package)
            }
            try await checkDenylist(package, operation: .uninstall, channel: channel)
            undo = .uninstall
            try await run(.uninstall, package, channel: channel)
        case .notRestorable:
            throw AppManagerError.notRestorable(entry.id)
        }

        try await journal.update(id: entry.id, status: .restored, note: nil)
        try await journal.append(JournalEntry(
            deviceID: entry.deviceID, packageName: package, kind: .operation(undo), restore: .notRestorable,
            status: .applied, note: "Restore of \(entry.id.uuidString)"
        ))
        var restored = entry
        restored.status = .restored
        return restored
    }

    // MARK: Export and backup

    public func exportAPKs(of package: PackageName, on serial: DeviceSerial, to folder: URL) async throws -> [URL] {
        try await pullAPKs(package, channel: adb.device(serial), into: folder.appendingPathComponent(package.rawValue))
    }

    public func backupAccessibleData(of package: PackageName, on serial: DeviceSerial, to folder: URL) async throws -> [URL] {
        let channel = adb.device(serial)
        let destination = folder.appendingPathComponent("\(package.rawValue)-data")
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        var copied: [URL] = []
        for area in ["data", "obb"] {
            let remote = try RemotePath("/sdcard/Android/\(area)/\(package.rawValue)")
            let local = destination.appendingPathComponent(area)
            // A missing folder simply means the app keeps nothing there.
            if (try? await channel.pull(remote, to: local)) != nil { copied.append(local) }
        }
        return copied
    }

    // MARK: Helpers

    private func checkDenylist(_ package: PackageName, operation: DeviceOperation, channel: DeviceChannel) async throws {
        guard operation.isDestructive else { return }
        let launchers = try await channel.launchers().filter { !Self.placeholderLaunchers.contains($0) }
        let keyboards = try await channel.inputMethods()
        let context = DenylistContext(
            launchers: Set(launchers.compactMap(PackageName.init(rawValue:))),
            inputMethods: Set(keyboards.compactMap(PackageName.init(rawValue:)))
        )
        if case .blocked(let reason) = denylist.check(package, operation: operation, context: context) {
            throw AppManagerError.blockedByDenylist(package, reason)
        }
    }

    private func isSystemApp(_ package: PackageName, channel: DeviceChannel) async throws -> Bool {
        do {
            return try await channel.dump(package).isSystem
        } catch {
            throw AppManagerError.commandFailed(Self.message(error))
        }
    }

    private func run(_ operation: DeviceOperation, _ package: PackageName, channel: DeviceChannel) async throws {
        do {
            switch operation {
            case .uninstall: try await channel.uninstall(package)
            case .uninstallForUser: try await channel.uninstallForUser(package)
            case .disableForUser: try await channel.disableForUser(package)
            case .enable: try await channel.enable(package)
            case .installExisting: try await channel.installExisting(package)
            }
        } catch {
            throw AppManagerError.commandFailed(Self.message(error))
        }
    }

    private func backupAPKs(_ package: PackageName, channel: DeviceChannel, serial: DeviceSerial) async throws -> [String] {
        let folder = backupRoot
            .appendingPathComponent(try await deviceID(serial))
            .appendingPathComponent(package.rawValue)
            .appendingPathComponent(ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-"))
        return try await pullAPKs(package, channel: channel, into: folder).map(\.path)
    }

    private func pullAPKs(_ package: PackageName, channel: DeviceChannel, into folder: URL) async throws -> [URL] {
        let paths = try await channel.apkPaths(package)
        guard !paths.isEmpty else { throw AppManagerError.commandFailed("\(package) is not installed.") }
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        var urls: [URL] = []
        for path in paths {
            let remote: RemotePath
            do {
                remote = try RemotePath(path)
            } catch {
                throw AppManagerError.commandFailed("Unexpected APK path \(path).")
            }
            let fileName = (path as NSString).lastPathComponent
            let local = folder.appendingPathComponent(fileName)
            do {
                try await channel.pull(remote, to: local)
            } catch {
                throw AppManagerError.commandFailed("Could not copy \(fileName): \(Self.message(error))")
            }
            urls.append(local)
        }
        return urls
    }

    private func reinstall(_ paths: [String], channel: DeviceChannel) async throws {
        let apks = try paths.map { path in
            let url = URL(fileURLWithPath: path)
            let size = try FileManager.default.attributesOfItem(atPath: path)[.size] as? Int64 ?? 0
            return StagedAPK(localURL: url, sizeBytes: size)
        }
        do {
            try await SessionInstaller(channel: channel).install(apks) { _ in }
        } catch {
            throw AppManagerError.commandFailed(String(describing: error))
        }
    }

    /// Journal updates after a device command must land even if the calling task was cancelled.
    private func record(_ id: UUID, _ status: JournalEntry.Status, note: String?) async throws {
        let journal = journal
        try await Task.detached { try await journal.update(id: id, status: status, note: note) }.value
    }

    private func deviceID(_ serial: DeviceSerial) async throws -> String {
        let value = try await adb.device(serial).property("ro.serialno")
        return value.isEmpty ? serial.rawValue : value
    }

    static func message(_ error: any Error) -> String {
        switch error {
        case ADBError.commandFailed(_, _, let output): output
        case AppManagerError.commandFailed(let message): message
        default: String(describing: error)
        }
    }
}

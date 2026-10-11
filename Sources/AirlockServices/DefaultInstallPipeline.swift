// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockADB
import AirlockCore
import Foundation

/// F2: inspect → plan (safety report, split selection, pre-checks) → install.
///
/// Install order is chosen so that cancelling or failing never leaves a half-installed app:
/// OBB files are pushed and verified first, then all APKs are committed in one package-manager
/// session. If anything fails before the commit, pushed OBB files are removed again.
public struct DefaultInstallPipeline: InstallPipeline {
    /// Free space required on `/data`, as a multiple of the package size (APKs are copied and optimised).
    public static let storageFactor = 2.5

    private let adb: ADBClient
    private let inspector: any PackageInspector
    private let safety: any SafetyEngine
    private let devices: any DeviceService
    private let journal: any JournalStore

    public init(
        adb: ADBClient,
        inspector: any PackageInspector,
        safety: any SafetyEngine,
        devices: any DeviceService,
        journal: any JournalStore
    ) {
        self.adb = adb
        self.inspector = inspector
        self.safety = safety
        self.devices = devices
        self.journal = journal
    }

    public func inspect(_ file: URL) async throws(InstallError) -> InspectedPackage {
        try await inspector.inspect(file)
    }

    // MARK: Plan

    public func plan(_ package: InspectedPackage, for serial: DeviceSerial) async throws(InstallError) -> InstallPlan {
        let packageName = try Self.packageName(package)
        let channel = adb.device(serial)
        let device: DeviceInfo
        do {
            device = try await devices.info(for: serial)
        } catch let error as ADBError {
            throw SessionInstaller.map(error)
        } catch {
            throw .transport(String(describing: error))
        }

        let existing = try await installedApp(packageName, channel: channel)
        let installedSigners = existing == nil
            ? nil
            : await signers(of: packageName, channel: channel, workDirectory: package.workDirectory)
        let report = await safety.report(for: package, installedSigners: installedSigners)

        var problems: [PreCheckProblem] = []
        var selected: [InspectedAPK] = []
        do {
            let chosen = try SplitResolver.resolve(splits: package.splitAPKs, for: device.properties)
            let names = Set(chosen.map(\.fileName))
            selected = package.splits.filter { names.contains($0.fileName) }
        } catch {
            switch error {
            case .noMatchingABI(let available): problems.append(.noMatchingABI(available: available))
            }
        }
        problems += preChecks(package, device: device, existing: existing, report: report)
        problems += try await storageCheck(package, channel: channel)

        return InstallPlan(
            package: package, device: device, selectedSplits: selected, existing: existing, report: report, problems: problems
        )
    }

    private func preChecks(
        _ package: InspectedPackage,
        device: DeviceInfo,
        existing: InstalledApp?,
        report: SafetyReport
    ) -> [PreCheckProblem] {
        let base = package.base
        var problems: [PreCheckProblem] = []
        if let minSdk = base.manifest.minSdk, minSdk > device.properties.sdkLevel {
            problems.append(.deviceSDKTooOld(required: minSdk, device: device.properties.sdkLevel))
        }
        if let existing, existing.versionCode > base.manifest.versionCode {
            problems.append(.versionDowngrade(installed: existing.versionCode, incoming: base.manifest.versionCode))
        }
        if report.signerMatch == .differsFromInstalled {
            problems.append(.signerMismatch)
        }
        for split in package.splits
        where split.manifest.packageName != base.manifest.packageName || split.manifest.versionCode != base.manifest.versionCode {
            problems.append(.splitPackageMismatch(split.fileName))
        }
        let hasABISplits = package.splitAPKs.contains { if case .abi = $0.kind { true } else { false } }
        if !hasABISplits, !base.nativeABIs.isEmpty, !base.nativeABIs.contains(where: device.properties.abis.contains) {
            problems.append(.noMatchingABI(available: base.nativeABIs))
        }
        return problems
    }

    private func storageCheck(_ package: InspectedPackage, channel: DeviceChannel) async throws(InstallError) -> [PreCheckProblem] {
        let required = Int64(Double(package.totalSizeBytes) * Self.storageFactor)
        let free = try await adb { try await channel.freeBytes() }
        return free < required ? [.insufficientStorage(requiredBytes: required, freeBytes: free)] : []
    }

    private func installedApp(_ package: PackageName, channel: DeviceChannel) async throws(InstallError) -> InstalledApp? {
        do {
            let dump = try await channel.dump(package)
            guard dump.userState?.installed ?? true else { return nil }
            return InstalledApp(
                packageName: package, versionName: dump.versionName, versionCode: dump.versionCode, isSystem: dump.isSystem,
                state: dump.userState?.enabledState.isEnabled == false ? .disabled : .enabled,
                apkPaths: dump.codePath.map { [$0] } ?? [], installerPackage: dump.installer
            )
        } catch .parse(.packageNotFound) {
            return nil
        } catch {
            throw SessionInstaller.map(error)
        }
    }

    /// Copies the installed base APK to read its signer. Unknown (nil) when that is not possible.
    private func signers(of package: PackageName, channel: DeviceChannel, workDirectory: URL) async -> [String]? {
        guard let path = try? await channel.apkPaths(package).first, let remote = try? RemotePath(path) else { return nil }
        let local = workDirectory.appendingPathComponent("installed-base.apk")
        guard (try? await channel.pull(remote, to: local)) != nil else { return nil }
        return try? await inspector.signerDigests(ofAPKAt: local)
    }

    // MARK: Install

    public func install(
        _ plan: InstallPlan,
        progress: @escaping @Sendable (InstallProgress) -> Void
    ) async throws(InstallError) -> InstallOutcome {
        guard plan.problems.isEmpty else { throw .preCheckFailed(plan.problems) }
        let packageName = try Self.packageName(plan.package)
        let channel = adb.device(plan.device.serial)
        let base = plan.package.base
        let apks = [base] + plan.selectedSplits
        let apkBytes = apks.reduce(0) { $0 + $1.sizeBytes }
        let obbBytes = plan.package.obbFiles.reduce(0) { $0 + $1.sizeBytes }
        let obbShare = Double(obbBytes) / Double(max(apkBytes + obbBytes, 1))
        let tracker = ProgressTracker(report: progress)

        let entry = JournalEntry(
            deviceID: plan.device.stableID, packageName: packageName,
            kind: .install(versionCode: base.manifest.versionCode, wasUpdate: plan.existing != nil),
            restore: plan.existing == nil ? .uninstallInstalled : .notRestorable
        )
        do {
            try await journal.append(entry)
        } catch {
            throw .transport("Could not write the action journal: \(error)")
        }

        var pushedOBB: [RemotePath] = []
        do {
            tracker.update(.preparing, 1, total: 0.05, "Preparing")
            pushedOBB = try await pushOBB(plan.package, packageName, channel: channel) { fraction in
                tracker.update(.pushingOBB, fraction, total: 0.05 + 0.85 * obbShare * fraction, "Copying game data")
            }
            let folder = plan.package.workDirectory
            let staged = apks.map { StagedAPK(localURL: folder.appendingPathComponent($0.fileName), sizeBytes: $0.sizeBytes) }
            try await SessionInstaller(channel: channel).install(staged) { fraction in
                tracker.update(.installing, fraction, total: 0.05 + 0.85 * obbShare + 0.85 * (1 - obbShare) * fraction, "Installing")
            }
            tracker.update(.verifying, 0, total: 0.95, "Checking the installed app")
            try await verifyInstalled(packageName, versionCode: base.manifest.versionCode, channel: channel)
        } catch {
            await removeOBB(pushedOBB, channel: channel)
            await record(entry.id, .failed, note: String(describing: error))
            throw error
        }

        await record(entry.id, .applied, note: nil)
        tracker.update(.cleaningUp, 1, total: 1, "Done")
        return InstallOutcome(packageName: packageName, versionCode: base.manifest.versionCode, journalEntryID: entry.id)
    }

    private func pushOBB(
        _ package: InspectedPackage,
        _ name: PackageName,
        channel: DeviceChannel,
        progress: @escaping @Sendable (Double) -> Void
    ) async throws(InstallError) -> [RemotePath] {
        guard !package.obbFiles.isEmpty else { return [] }
        let directory = RemotePath.obbDirectory(for: name)
        try await adb { try await channel.makeDirectory(directory) }
        let total = max(package.obbFiles.reduce(0) { $0 + $1.sizeBytes }, 1)
        var done: Int64 = 0
        var pushed: [RemotePath] = []
        do {
            for file in package.obbFiles {
                if Task.isCancelled { throw InstallError.cancelled }
                let remote: RemotePath
                do {
                    remote = try directory.appending(file.fileName)
                } catch {
                    throw InstallError.unsafeArchive("OBB file name \(file.fileName)")
                }
                pushed.append(remote)
                try await adb { try await channel.push(file.localURL, to: remote) }
                try await verifyOBB(file, at: remote, channel: channel)
                done += file.sizeBytes
                progress(Double(done) / Double(total))
            }
        } catch let error as InstallError {
            await removeOBB(pushed, channel: channel)
            throw error
        } catch {
            await removeOBB(pushed, channel: channel)
            throw .transport(String(describing: error))
        }
        return pushed
    }

    private func verifyOBB(_ file: OBBFile, at remote: RemotePath, channel: DeviceChannel) async throws(InstallError) {
        let size = try await adb { try await channel.fileSize(remote) }
        guard size == file.sizeBytes else { throw .obbVerificationFailed(fileName: file.fileName) }
        do {
            let digest = try await channel.sha256(remote)
            guard digest == file.sha256 else { throw InstallError.obbVerificationFailed(fileName: file.fileName) }
        } catch let error as InstallError {
            throw error
        } catch ADBError.process(.cancelled) {
            throw .cancelled
        } catch {
            // Devices without `sha256sum` keep the size check only.
        }
    }

    /// Journal updates must land even when the install task was cancelled.
    private func record(_ id: UUID, _ status: JournalEntry.Status, note: String?) async {
        let journal = journal
        await SessionInstaller.uncancellable { try? await journal.update(id: id, status: status, note: note) }
    }

    private func removeOBB(_ paths: [RemotePath], channel: DeviceChannel) async {
        guard !paths.isEmpty else { return }
        await SessionInstaller.uncancellable {
            for path in paths { try? await channel.removeOBBFile(path) }
        }
    }

    private func verifyInstalled(_ package: PackageName, versionCode: Int64, channel: DeviceChannel) async throws(InstallError) {
        let dump = try await adb { try await channel.dump(package) }
        guard dump.versionCode == versionCode else {
            throw .verificationFailed("Expected version \(versionCode) but the phone reports \(dump.versionCode).")
        }
    }

    public func discard(_ package: InspectedPackage) async {
        // Only ever delete folders that are Airlock job folders.
        guard package.workDirectory.pathComponents.suffix(3).dropLast().elementsEqual(["Airlock", "jobs"]) else { return }
        try? FileManager.default.removeItem(at: package.workDirectory)
    }

    // MARK: Helpers

    private static func packageName(_ package: InspectedPackage) throws(InstallError) -> PackageName {
        guard let name = PackageName(rawValue: package.packageName) else {
            throw .unsupportedFile("The app has an invalid package name.")
        }
        return name
    }

    private func adb<T>(_ body: () async throws -> T) async throws(InstallError) -> T {
        do {
            return try await body()
        } catch let error as ADBError {
            throw SessionInstaller.map(error)
        } catch let error as InstallError {
            throw error
        } catch {
            throw .transport(String(describing: error))
        }
    }
}

/// Keeps overall progress monotonic across steps.
private final class ProgressTracker: @unchecked Sendable {
    private let lock = NSLock()
    private var highest = 0.0
    private let report: @Sendable (InstallProgress) -> Void

    init(report: @escaping @Sendable (InstallProgress) -> Void) {
        self.report = report
    }

    func update(_ step: InstallStep, _ stepFraction: Double, total: Double, _ message: String) {
        let value = lock.withLock {
            highest = max(highest, total)
            return highest
        }
        report(InstallProgress(step: step, stepFraction: stepFraction, totalFraction: value, message: message))
    }
}

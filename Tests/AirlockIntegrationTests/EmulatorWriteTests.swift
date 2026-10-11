// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockADB
import AirlockCore
import AirlockInspection
import AirlockJournal
import AirlockSafety
@testable import AirlockServices
import AirlockTestSupport
import Foundation
import Testing

/// Installs, removes and restores apps for real. Runs ONLY on an emulator:
///
///     AIRLOCK_INTEGRATION=1 AIRLOCK_EMULATOR=emulator-5554 swift test --filter EmulatorWrite
///
/// The serial must start with `emulator-`; anything else disables the suite, so it can never
/// change a personal phone.
enum EmulatorEnvironment {
    static var serial: DeviceSerial? {
        guard IntegrationEnvironment.enabled, let raw = ProcessInfo.processInfo.environment["AIRLOCK_EMULATOR"],
              raw.hasPrefix("emulator-") else { return nil }
        return DeviceSerial(rawValue: raw)
    }

    static let fixturePackage = PackageName(rawValue: "org.airlock.fixture") ?? { preconditionFailure("fixture name") }()
}

/// Shared wiring for one test: real adb, real inspector, real safety engine, in-memory journal.
struct EmulatorHarness {
    let serial: DeviceSerial
    let adb: ADBClient
    let journal: SQLiteJournalStore
    let pipeline: DefaultInstallPipeline
    let manager: DefaultAppManager
    let scratch: URL

    init() throws {
        serial = try #require(EmulatorEnvironment.serial)
        adb = try IntegrationEnvironment.client()
        journal = try SQLiteJournalStore.inMemory()
        scratch = FileManager.default.temporaryDirectory.appendingPathComponent("airlock-emu-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        let devices = DefaultDeviceService(adb: adb)
        pipeline = DefaultInstallPipeline(
            adb: adb, inspector: LocalPackageInspector(),
            safety: DefaultSafetyEngine(catalog: try SafetyCatalog.bundled(), reputation: nil),
            devices: devices, journal: journal
        )
        manager = DefaultAppManager(adb: adb, journal: journal, presets: try PresetLibrary.bundled(), backupRoot: scratch)
    }

    var channel: DeviceChannel { adb.device(serial) }

    func file(_ apk: FixtureAPKs.APK, as name: String) throws -> URL {
        let url = scratch.appendingPathComponent(name)
        try FixtureAPKs.data(apk).write(to: url)
        return url
    }

    /// Removes the fixture app if a previous test left it installed. Test setup only, on an emulator.
    func removeFixture() async {
        try? await channel.uninstall(EmulatorEnvironment.fixturePackage)
    }

    func isInstalled() async throws -> Bool {
        try await !channel.apkPaths(EmulatorEnvironment.fixturePackage).isEmpty
    }

    func install(_ url: URL) async throws -> InstallOutcome {
        let package = try await pipeline.inspect(url)
        let plan = try await pipeline.plan(package, for: serial)
        defer { Task { await pipeline.discard(package) } }
        return try await pipeline.install(plan) { _ in }
    }
}

@Suite("EmulatorWrite", .serialized, .enabled(if: EmulatorEnvironment.serial != nil))
struct EmulatorWriteTests {
    @Test func installsASignedAPKAndVerifiesIt() async throws {
        let harness = try EmulatorHarness()
        await harness.removeFixture()
        let outcome = try await harness.install(try harness.file(.v123RSA, as: "fixture.apk"))
        #expect(outcome.versionCode == 42)
        #expect(try await harness.isInstalled())
        let dump = try await harness.channel.dump(EmulatorEnvironment.fixturePackage)
        #expect(dump.versionCode == 42)
        let history = try await harness.journal.entries(deviceID: try await harness.channel.property("ro.serialno"))
        #expect(history.first?.status == .applied)
        await harness.removeFixture()
    }

    @Test func installsAnAPKSBundleWithTheRightSplit() async throws {
        let harness = try EmulatorHarness()
        await harness.removeFixture()
        let container = ZipBuilder(files: [
            ("splits/base-master.apk", Array(try FixtureAPKs.data(.v2RSA))),
            ("splits/base-arm64_v8a.apk", Array(try FixtureAPKs.data(.splitArm64))),
        ])
        let url = harness.scratch.appendingPathComponent("fixture.apks")
        try container.build().write(to: url)
        let package = try await harness.pipeline.inspect(url)
        let plan = try await harness.pipeline.plan(package, for: harness.serial)
        #expect(plan.selectedSplits.map(\.manifest.splitName) == ["config.arm64_v8a"])
        _ = try await harness.pipeline.install(plan) { _ in }
        let paths = try await harness.channel.apkPaths(EmulatorEnvironment.fixturePackage)
        #expect(paths.count == 2, "base and split are both installed: \(paths)")
        await harness.pipeline.discard(package)
        await harness.removeFixture()
    }

    @Test func pushesAndVerifiesOBBData() async throws {
        let harness = try EmulatorHarness()
        await harness.removeFixture()
        let manifest = """
        {"package_name": "org.airlock.fixture", "version_code": "42",
         "split_apks": [{"file": "org.airlock.fixture.apk", "id": "base"}],
         "expansions": [{"file": "Android/obb/org.airlock.fixture/main.42.org.airlock.fixture.obb",
                         "install_location": "EXTERNAL_STORAGE",
                         "install_path": "Android/obb/org.airlock.fixture/main.42.org.airlock.fixture.obb"}]}
        """
        let obb = (0..<300_000).map { UInt8($0 % 251) }
        let container = ZipBuilder(files: [
            ("manifest.json", Array(manifest.utf8)),
            ("org.airlock.fixture.apk", Array(try FixtureAPKs.data(.v2RSA))),
            ("Android/obb/org.airlock.fixture/main.42.org.airlock.fixture.obb", obb),
        ])
        let url = harness.scratch.appendingPathComponent("fixture.xapk")
        try container.build().write(to: url)
        _ = try await harness.install(url)
        let remote = try RemotePath("/sdcard/Android/obb/org.airlock.fixture/main.42.org.airlock.fixture.obb")
        #expect(try await harness.channel.fileSize(remote) == 300_000)
        try await harness.channel.removeOBBFile(remote)
        await harness.removeFixture()
    }

    @Test func signerMismatchIsCaughtBeforeInstallAndMappedIfForced() async throws {
        let harness = try EmulatorHarness()
        await harness.removeFixture()
        _ = try await harness.install(try harness.file(.v2RSA, as: "rsa.apk"))

        // Same package, different signing key.
        let package = try await harness.pipeline.inspect(try harness.file(.v2EC, as: "ec.apk"))
        let plan = try await harness.pipeline.plan(package, for: harness.serial)
        #expect(plan.report.signerMatch == .differsFromInstalled)
        #expect(plan.problems.contains(.signerMismatch))

        // Bypassing the pre-check proves the phone's own error is mapped to plain English.
        let local = package.workDirectory.appendingPathComponent(package.base.fileName)
        let apk = StagedAPK(localURL: local, sizeBytes: package.base.sizeBytes)
        await #expect {
            try await SessionInstaller(channel: harness.channel).install([apk]) { _ in }
        } throws: { error in
            guard case InstallError.packageManager(let explained) = error else { return false }
            return explained.code == "INSTALL_FAILED_UPDATE_INCOMPATIBLE" && explained.fix == .uninstallExistingThenInstall
        }
        await harness.pipeline.discard(package)
        await harness.removeFixture()
    }

    @Test func cancelDuringInstallLeavesNoPartialApp() async throws {
        let harness = try EmulatorHarness()
        await harness.removeFixture()
        // A large OBB makes the copy slow enough to cancel in the middle.
        let manifest = """
        {"package_name": "org.airlock.fixture", "version_code": "42",
         "split_apks": [{"file": "base.apk", "id": "base"}],
         "expansions": [{"file": "Android/obb/org.airlock.fixture/main.42.org.airlock.fixture.obb",
                         "install_location": "EXTERNAL_STORAGE",
                         "install_path": "Android/obb/org.airlock.fixture/main.42.org.airlock.fixture.obb"}]}
        """
        let big = [UInt8](repeating: 0x5a, count: 400 * 1024 * 1024)
        var builder = ZipBuilder(files: [("manifest.json", Array(manifest.utf8)), ("base.apk", Array(try FixtureAPKs.data(.v2RSA)))])
        builder.entries.append(ZipBuilder.Entry(name: "Android/obb/org.airlock.fixture/main.42.org.airlock.fixture.obb", data: big))
        let url = harness.scratch.appendingPathComponent("big.xapk")
        try builder.build().write(to: url)

        let package = try await harness.pipeline.inspect(url)
        let plan = try await harness.pipeline.plan(package, for: harness.serial)
        let remote = try RemotePath("/sdcard/Android/obb/org.airlock.fixture/main.42.org.airlock.fixture.obb")
        // A separate client has its own queue, so it can watch the copy while the install runs.
        let probe = try IntegrationEnvironment.client().device(harness.serial)
        try? await probe.removeOBBFile(remote)
        let task = Task { try await harness.pipeline.install(plan) { _ in } }
        let deadline = ContinuousClock.now + .seconds(60)
        while ContinuousClock.now < deadline {
            if let size = try? await probe.fileSize(remote), size > 0 { break }
            try await Task.sleep(for: .milliseconds(20))
        }
        task.cancel()
        let result = await task.result
        #expect(throws: InstallError.cancelled) { try result.get() }
        #expect(try await !harness.isInstalled(), "the app must not be installed after cancel")
        await #expect(throws: (any Error).self, "the partial OBB must be removed") { try await harness.channel.fileSize(remote) }
        await harness.pipeline.discard(package)
    }

    @Test func disableAndRestore() async throws {
        let harness = try EmulatorHarness()
        await harness.removeFixture()
        _ = try await harness.install(try harness.file(.v2RSA, as: "fixture.apk"))
        let name = EmulatorEnvironment.fixturePackage

        let entry = try await harness.manager.perform(ConfirmedOperation(userConfirmed: .disableForUser, on: name), on: harness.serial)
        #expect(try await harness.channel.packageNames(.disabled).contains(name.rawValue))
        _ = try await harness.manager.restore(entry, on: harness.serial, confirmation: nil)
        #expect(try await !harness.channel.packageNames(.disabled).contains(name.rawValue))
        await harness.removeFixture()
    }

    @Test func removeForUserAndRestoreWithInstallExisting() async throws {
        let harness = try EmulatorHarness()
        await harness.removeFixture()
        _ = try await harness.install(try harness.file(.v2RSA, as: "fixture.apk"))
        let name = EmulatorEnvironment.fixturePackage

        let entry = try await harness.manager.perform(ConfirmedOperation(userConfirmed: .uninstallForUser, on: name), on: harness.serial)
        #expect(try await !harness.channel.packageNames(.all).contains(name.rawValue))
        guard case .reinstallFromBackup = entry.restore else {
            Issue.record("a user app removed for the user must be restorable from a backup, got \(entry.restore)")
            return
        }

        _ = try await harness.manager.restore(entry, on: harness.serial, confirmation: nil)
        #expect(try await harness.channel.packageNames(.all).contains(name.rawValue))
        await harness.removeFixture()
    }

    @Test func uninstallBacksUpAndRestoreReinstalls() async throws {
        let harness = try EmulatorHarness()
        await harness.removeFixture()
        _ = try await harness.install(try harness.file(.v2RSA, as: "fixture.apk"))
        let name = EmulatorEnvironment.fixturePackage

        let entry = try await harness.manager.perform(ConfirmedOperation(userConfirmed: .uninstall, on: name), on: harness.serial)
        #expect(try await !harness.isInstalled())
        guard case .reinstallFromBackup(let paths) = entry.restore else {
            Issue.record("expected a backup")
            return
        }
        #expect(paths.allSatisfy { FileManager.default.fileExists(atPath: $0) })

        _ = try await harness.manager.restore(entry, on: harness.serial, confirmation: nil)
        #expect(try await harness.isInstalled())
        await harness.removeFixture()
    }

    @Test func criticalPackagesAreRefusedOnARealDevice() async throws {
        let harness = try EmulatorHarness()
        let systemUI = try #require(PackageName(rawValue: "com.android.systemui"))
        await #expect(throws: AppManagerError.self) {
            try await harness.manager.perform(ConfirmedOperation(userConfirmed: .disableForUser, on: systemUI), on: harness.serial)
        }
        #expect(try await !harness.channel.packageNames(.disabled).contains("com.android.systemui"))
    }

    @Test func exportsInstalledAPKs() async throws {
        let harness = try EmulatorHarness()
        await harness.removeFixture()
        _ = try await harness.install(try harness.file(.v2RSA, as: "fixture.apk"))
        let urls = try await harness.manager.exportAPKs(of: EmulatorEnvironment.fixturePackage, on: harness.serial, to: harness.scratch)
        #expect(urls.count == 1)
        #expect(try Data(contentsOf: urls[0]) == FixtureAPKs.data(.v2RSA))
        await harness.removeFixture()
    }
}

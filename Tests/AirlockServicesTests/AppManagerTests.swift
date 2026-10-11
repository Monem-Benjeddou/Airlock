// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockADB
import AirlockCore
import AirlockJournal
@testable import AirlockServices
import AirlockTestSupport
import Foundation
import Testing

/// Wires a DefaultAppManager to FakeADB, an in-memory journal and a temp backup folder.
struct AppManagerHarness {
    let fake = FakeADB()
    let journal: SQLiteJournalStore
    let backups: URL
    let manager: DefaultAppManager
    let serial: DeviceSerial

    init(presets: PresetLibrary = PresetLibrary(presets: [])) throws {
        journal = try SQLiteJournalStore.inMemory()
        backups = FileManager.default.temporaryDirectory.appendingPathComponent("airlock-backups-\(UUID().uuidString)")
        serial = try DeviceSerial(s24Serial)
        manager = DefaultAppManager(adb: makeADB(fake), journal: journal, presets: presets, backupRoot: backups)
        fake.on(shell("getprop", "ro.serialno"), .ok("FIXTURESERIAL01\n"))
        fake.on(Self.homeQuery, .ok(Fixture.adb(s24, "home-activities.txt")))
        fake.on(shell("ime", "list", "-s"), .ok(Fixture.adb(s24, "ime-list.txt")))
    }

    static let homeQuery = shell(
        "cmd", "package", "query-activities", "--brief", "-a", "android.intent.action.MAIN", "-c", "android.intent.category.HOME"
    )

    func confirm(_ operation: DeviceOperation, _ name: String) -> ConfirmedOperation {
        ConfirmedOperation(userConfirmed: operation, on: pkg(name))
    }

    func commands(containing word: String) -> [[String]] {
        fake.calls.filter { $0.contains(word) }
    }
}

@Suite("DefaultAppManager listing")
struct AppManagerListingTests {
    @Test func listsEveryAppWithStateFromRecordedS24() async throws {
        let harness = try AppManagerHarness()
        let fake = harness.fake
        fake.on(shell("pm", "list", "packages", "--user", "0", "-f", "-U", "--show-versioncode", "-i", "-u"),
                .ok(Fixture.adb(s24, "pm-list-packages.txt")))
        fake.on(shell("pm", "list", "packages", "--user", "0"), .ok(Fixture.adb(s24, "pm-list-including-uninstalled.txt")))
        fake.on(shell("pm", "list", "packages", "--user", "0", "-s", "-u"), .ok(Fixture.adb(s24, "pm-list-system.txt")))
        fake.on(shell("pm", "list", "packages", "--user", "0", "-d"), .ok(Fixture.adb(s24, "pm-list-disabled.txt")))

        let apps = try await harness.manager.listApps(on: harness.serial)
        #expect(apps.count == 597)
        #expect(apps.filter(\.isSystem).count == 497)
        #expect(apps.filter { $0.state == .disabled }.count == 20)
        let galaxy = try #require(apps.first { $0.packageName.rawValue == "com.mygalaxy.service" })
        #expect(galaxy.state == .disabled)
        let store = try #require(apps.first { $0.packageName.rawValue == "com.samsung.android.inputshare" })
        #expect(store.installSource == "Galaxy Store")
        #expect(store.apkPaths.first?.hasSuffix("base.apk") == true)
        #expect(apps == apps.sorted { $0.packageName < $1.packageName })
    }

    @Test func packagesRemovedForUserAreMarked() async throws {
        let harness = try AppManagerHarness()
        let fake = harness.fake
        fake.on(shell("pm", "list", "packages", "--user", "0", "-f", "-U", "--show-versioncode", "-i", "-u"), .ok("""
        package:/system/app/A/A.apk=com.example.kept versionCode:1 installer=null uid:1
        package:/system/app/B/B.apk=com.example.removed versionCode:2 installer=null uid:2
        """))
        fake.on(shell("pm", "list", "packages", "--user", "0"), .ok("package:com.example.kept\n"))
        fake.on(shell("pm", "list", "packages", "--user", "0", "-s", "-u"), .ok("package:com.example.kept\npackage:com.example.removed\n"))
        fake.on(shell("pm", "list", "packages", "--user", "0", "-d"), .ok(""))
        let apps = try await harness.manager.listApps(on: harness.serial)
        #expect(apps.map(\.state) == [.enabled, .uninstalledForUser])
    }

    @Test func presetsComeFromTheLibrary() throws {
        let entry = DebloatEntry(packageName: pkg("com.samsung.android.bixby.agent"), risk: .caution, description: "Bixby")
        let library = PresetLibrary(presets: [DebloatPreset(id: "samsung", name: "Samsung", brand: .samsung, entries: [entry])])
        let harness = try AppManagerHarness(presets: library)
        #expect(harness.manager.presets(for: .samsung).map(\.id) == ["samsung"])
        #expect(harness.manager.presets(for: .xiaomi).isEmpty)
    }
}

@Suite("DefaultAppManager changes")
struct AppManagerChangeTests {
    @Test func disableIsJournaledBeforeRunningAndMarkedApplied() async throws {
        let harness = try AppManagerHarness()
        let name = "com.facebook.appmanager"
        harness.fake.on(shell("pm", "disable-user", "--user", "0", name), .ok("Package \(name) new state: disabled-user\n"))
        let entry = try await harness.manager.perform(harness.confirm(.disableForUser, name), on: harness.serial)
        #expect(entry.status == .applied)
        #expect(entry.restore == .enable)
        #expect(entry.deviceID == "FIXTURESERIAL01")
        #expect(entry.kind == .operation(.disableForUser))
        let history = try await harness.manager.history(on: harness.serial)
        #expect(history.map(\.id) == [entry.id])
        #expect(history.first?.status == .applied)
    }

    @Test func uninstallForUserRestoresWithInstallExisting() async throws {
        let harness = try AppManagerHarness()
        let name = "com.samsung.android.game.gos"
        harness.fake.on(shell("pm", "uninstall", "-k", "--user", "0", name), .ok("Success\n"))
        harness.fake.on(shell("cmd", "package", "install-existing", "--user", "0", name), .ok("Package \(name) installed for user: 0\n"))
        let entry = try await harness.manager.perform(harness.confirm(.uninstallForUser, name), on: harness.serial)
        #expect(entry.restore == .installExisting)

        let restored = try await harness.manager.restore(entry, on: harness.serial, confirmation: nil)
        #expect(restored.status == .restored)
        #expect(harness.commands(containing: "install-existing").count == 1)
        let history = try await harness.manager.history(on: harness.serial)
        #expect(history.count == 2, "the restore itself is journaled")
        #expect(history.contains { $0.id == entry.id && $0.status == .restored })
        #expect(history.contains { $0.kind == .operation(.installExisting) && $0.status == .applied })
    }

    @Test func restoredEntryCannotBeRestoredTwice() async throws {
        let harness = try AppManagerHarness()
        let name = "com.example.bloat"
        harness.fake.on(shell("pm", "disable-user", "--user", "0", name), .ok("Package \(name) new state: disabled-user\n"))
        harness.fake.on(shell("pm", "enable", "--user", "0", name), .ok("Package \(name) new state: enabled\n"))
        let entry = try await harness.manager.perform(harness.confirm(.disableForUser, name), on: harness.serial)
        let restored = try await harness.manager.restore(entry, on: harness.serial, confirmation: nil)
        await #expect(throws: AppManagerError.notRestorable(entry.id)) {
            try await harness.manager.restore(restored, on: harness.serial, confirmation: nil)
        }
    }

    @Test(arguments: ["com.android.systemui", "com.android.settings", "com.android.phone", "com.android.shell"])
    func denylistBlocksCriticalPackagesWithoutRunningAnything(_ name: String) async throws {
        let harness = try AppManagerHarness()
        for operation in [DeviceOperation.uninstall, .uninstallForUser, .disableForUser] {
            await #expect(throws: AppManagerError.self) {
                try await harness.manager.perform(harness.confirm(operation, name), on: harness.serial)
            }
        }
        #expect(harness.commands(containing: "uninstall").isEmpty)
        #expect(harness.commands(containing: "disable-user").isEmpty)
        #expect(try await harness.manager.history(on: harness.serial).isEmpty, "nothing is journaled for a blocked change")
    }

    @Test func launcherWithARealAlternativeIsAllowed() async throws {
        let harness = try AppManagerHarness()
        let home = AppManagerHarness.homeQuery
        harness.fake.replace(home, .ok("com.sec.android.app.launcher/.Launcher\ncom.teslacoilsw.launcher/.NovaLauncher\n"))
        let name = "com.sec.android.app.launcher"
        harness.fake.on(shell("pm", "disable-user", "--user", "0", name), .ok("Package \(name) new state: disabled-user\n"))
        _ = try await harness.manager.perform(harness.confirm(.disableForUser, name), on: harness.serial)
    }

    @Test func onlyLauncherIsBlocked() async throws {
        let harness = try AppManagerHarness()
        let home = AppManagerHarness.homeQuery
        harness.fake.replace(home, .ok("com.sec.android.app.launcher/.activities.LauncherActivity\n"))
        await #expect(throws: AppManagerError.blockedByDenylist(pkg("com.sec.android.app.launcher"), .onlyLauncher)) {
            try await harness.manager.perform(harness.confirm(.disableForUser, "com.sec.android.app.launcher"), on: harness.serial)
        }
    }

    @Test func settingsFallbackHomeIsNotARealLauncher() async throws {
        // Regression from the recorded S24: HOME resolves to the One UI launcher AND Settings' FallbackHome.
        // FallbackHome is only a boot placeholder, so the launcher is still the only real one.
        let harness = try AppManagerHarness()
        let name = "com.sec.android.app.launcher"
        harness.fake.on(shell("pm", "disable-user", "--user", "0", name), .ok("Package \(name) new state: disabled-user\n"))
        await #expect(throws: AppManagerError.blockedByDenylist(pkg(name), .onlyLauncher)) {
            try await harness.manager.perform(harness.confirm(.disableForUser, name), on: harness.serial)
        }
    }

    @Test func failedCommandIsJournaledAsFailed() async throws {
        let harness = try AppManagerHarness()
        let name = "com.example.protected"
        harness.fake.on(shell("pm", "disable-user", "--user", "0", name),
                        FakeADB.Response(stderr: "java.lang.SecurityException: Cannot disable a protected package", exitCode: 255))
        await #expect {
            try await harness.manager.perform(harness.confirm(.disableForUser, name), on: harness.serial)
        } throws: { error in
            guard case AppManagerError.commandFailed(let message) = error else { return false }
            return message.contains("protected package")
        }
        let history = try await harness.manager.history(on: harness.serial)
        #expect(history.first?.status == .failed)
        #expect(history.first?.isRestorable == false)
    }

    @Test func uninstallingAUserAppBacksUpItsAPKsFirst() async throws {
        let harness = try AppManagerHarness()
        let name = "com.example.userapp1"
        let folder = "/data/app/~~a==/com.example.userapp1-b=="
        harness.fake.on(shell("pm", "path", name), .ok("package:\(folder)/base.apk\npackage:\(folder)/split_config.en.apk\n"))
        harness.fake.onPrefix(["-s", s24Serial, "pull"], .ok("1 file pulled\n"))
        harness.fake.on(shell("pm", "uninstall", name), .ok("Success\n"))
        let entry = try await harness.manager.perform(harness.confirm(.uninstall, name), on: harness.serial)
        guard case .reinstallFromBackup(let paths) = entry.restore else {
            Issue.record("expected backup restore, got \(entry.restore)")
            return
        }
        #expect(paths.count == 2)
        #expect(paths.allSatisfy { $0.hasPrefix(harness.backups.path) })
        let pulls = harness.commands(containing: "pull")
        #expect(pulls.count == 2)
        let uninstallIndex = harness.fake.calls.firstIndex { $0.suffix(2) == ["uninstall", name] }
        let lastPull = harness.fake.calls.lastIndex { $0.contains("pull") }
        #expect(try #require(lastPull) < #require(uninstallIndex), "backup happens before the uninstall")
    }

    @Test func uninstallAbortsWhenBackupFails() async throws {
        let harness = try AppManagerHarness()
        let name = "com.example.userapp1"
        harness.fake.on(shell("pm", "path", name), .ok("package:/data/app/x/base.apk\n"))
        harness.fake.onPrefix(["-s", s24Serial, "pull"], .failure("adb: error: failed to stat remote object"))
        await #expect(throws: AppManagerError.self) {
            try await harness.manager.perform(harness.confirm(.uninstall, name), on: harness.serial)
        }
        #expect(harness.commands(containing: "uninstall").isEmpty)
    }

    @Test func restoreFromBackupReinstallsThroughASession() async throws {
        let harness = try AppManagerHarness()
        let folder = harness.backups.appendingPathComponent("manual")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let apk = folder.appendingPathComponent("base.apk")
        try Data(repeating: 1, count: 100).write(to: apk)
        let entry = JournalEntry(
            deviceID: "FIXTURESERIAL01", packageName: pkg("com.example.userapp1"), kind: .operation(.uninstall),
            restore: .reinstallFromBackup(apkPaths: [apk.path]), status: .applied
        )
        try await harness.journal.append(entry)
        let fake = harness.fake
        fake.onPrefix(shell("mkdir", "-p"), .ok())
        fake.onPrefix(["-s", s24Serial, "push"], .ok("1 file pushed\n"))
        fake.on(shell("pm", "install-create", "-r", "-S", "100"), .ok("Success: created install session [5]\n"))
        fake.onPrefix(shell("pm", "install-write"), .ok("Success: streamed 100 bytes\n"))
        fake.on(shell("pm", "install-commit", "5"), .ok("Success\n"))
        fake.onPrefix(shell("rm", "-rf"), .ok())
        let restored = try await harness.manager.restore(entry, on: harness.serial, confirmation: nil)
        #expect(restored.status == .restored)
        #expect(harness.commands(containing: "install-commit").count == 1)
    }

    @Test func undoingAnInstallNeedsMatchingConfirmation() async throws {
        let harness = try AppManagerHarness()
        let name = "com.example.newgame"
        let entry = JournalEntry(
            deviceID: "FIXTURESERIAL01", packageName: pkg(name), kind: .install(versionCode: 3, wasUpdate: false),
            restore: .uninstallInstalled, status: .applied
        )
        try await harness.journal.append(entry)
        harness.fake.on(shell("pm", "uninstall", name), .ok("Success\n"))
        await #expect(throws: AppManagerError.confirmationRequired(pkg(name))) {
            try await harness.manager.restore(entry, on: harness.serial, confirmation: nil)
        }
        await #expect(throws: AppManagerError.confirmationRequired(pkg(name))) {
            try await harness.manager.restore(entry, on: harness.serial, confirmation: harness.confirm(.uninstall, "com.other.app"))
        }
        #expect(harness.commands(containing: "uninstall").isEmpty)
        let restored = try await harness.manager.restore(entry, on: harness.serial, confirmation: harness.confirm(.uninstall, name))
        #expect(restored.status == .restored)
    }

    @Test func undoingAnInstallStillHonoursTheDenylist() async throws {
        let harness = try AppManagerHarness()
        let entry = JournalEntry(
            deviceID: "FIXTURESERIAL01", packageName: pkg("com.android.settings"), kind: .install(versionCode: 3, wasUpdate: false),
            restore: .uninstallInstalled, status: .applied
        )
        await #expect(throws: AppManagerError.self) {
            try await harness.manager.restore(entry, on: harness.serial, confirmation: harness.confirm(.uninstall, "com.android.settings"))
        }
    }

    @Test func notRestorableEntryThrows() async throws {
        let harness = try AppManagerHarness()
        let entry = JournalEntry(
            deviceID: "X", packageName: pkg("com.a.b"), kind: .install(versionCode: 1, wasUpdate: true),
            restore: .notRestorable, status: .applied
        )
        await #expect(throws: AppManagerError.notRestorable(entry.id)) {
            try await harness.manager.restore(entry, on: harness.serial, confirmation: nil)
        }
    }

    @Test func enableAndInstallExistingNeedNoBackupAndAreNotRestorable() async throws {
        let harness = try AppManagerHarness()
        let name = "com.example.bloat"
        harness.fake.on(shell("pm", "enable", "--user", "0", name), .ok("Package \(name) new state: enabled\n"))
        let entry = try await harness.manager.perform(harness.confirm(.enable, name), on: harness.serial)
        #expect(entry.restore == .notRestorable)
    }
}

@Suite("DefaultAppManager export and backup")
struct AppManagerExportTests {
    @Test func exportsBaseAndSplitAPKs() async throws {
        let harness = try AppManagerHarness()
        let name = "com.example.userapp1"
        let remote = "/data/app/~~a==/x-b=="
        harness.fake.on(shell("pm", "path", name), .ok("package:\(remote)/base.apk\npackage:\(remote)/split_config.arm64_v8a.apk\n"))
        harness.fake.onPrefix(["-s", s24Serial, "pull"], .ok("1 file pulled\n"))
        let folder = harness.backups.appendingPathComponent("export")
        let urls = try await harness.manager.exportAPKs(of: pkg(name), on: harness.serial, to: folder)
        #expect(urls.map(\.lastPathComponent) == ["base.apk", "split_config.arm64_v8a.apk"])
        #expect(urls.allSatisfy { $0.path.hasPrefix(folder.appendingPathComponent(name).path) })
    }

    @Test func exportOfMissingPackageThrows() async throws {
        let harness = try AppManagerHarness()
        harness.fake.on(shell("pm", "path", "com.not.there"), FakeADB.Response(exitCode: 1))
        await #expect(throws: AppManagerError.self) {
            try await harness.manager.exportAPKs(of: pkg("com.not.there"), on: harness.serial, to: harness.backups)
        }
    }

    @Test func exportRejectsHostileRemoteFileNames() async throws {
        let harness = try AppManagerHarness()
        harness.fake.on(shell("pm", "path", "com.a.b"), .ok("package:/data/app/x/../../evil.apk\n"))
        await #expect(throws: AppManagerError.self) {
            try await harness.manager.exportAPKs(of: pkg("com.a.b"), on: harness.serial, to: harness.backups)
        }
    }

    @Test func backsUpAccessibleDataFolders() async throws {
        let harness = try AppManagerHarness()
        let name = "com.example.game"
        harness.fake.on(["-s", s24Serial, "pull", "/sdcard/Android/data/\(name)",
                         harness.backups.appendingPathComponent("\(name)-data/data").path], .ok("10 files pulled\n"))
        harness.fake.on(["-s", s24Serial, "pull", "/sdcard/Android/obb/\(name)",
                         harness.backups.appendingPathComponent("\(name)-data/obb").path], .failure("remote object does not exist"))
        let urls = try await harness.manager.backupAccessibleData(of: pkg(name), on: harness.serial, to: harness.backups)
        #expect(urls.map(\.lastPathComponent) == ["data"])
    }
}

@Suite("PresetLibrary")
struct PresetLibraryTests {
    @Test func bundledPresetsLoadForEveryBrand() throws {
        let library = try PresetLibrary.bundled()
        #expect(Set(library.presets.map(\.id)) == ["samsung", "xiaomi", "oneplus", "pixel", "google", "carrier", "misc"])
        for brand in [DeviceBrand.samsung, .xiaomi, .oneplus, .pixel] {
            let presets = library.presets(for: brand)
            #expect(presets.first?.brand == brand)
            #expect(presets.contains { $0.id == "google" })
        }
        #expect(library.presets(for: .other).allSatisfy { $0.brand == .other })
    }

    @Test func bundledPresetsNeverContainCriticalPackages() throws {
        let library = try PresetLibrary.bundled()
        for preset in library.presets {
            for entry in preset.entries {
                #expect(CriticalDenylist.standard.check(rawPackage: entry.packageName.rawValue, operation: .uninstallForUser) == .allowed)
            }
        }
    }

    @Test func denylistedEntriesAreFilteredOut() throws {
        let entries = [
            DebloatEntry(packageName: pkg("com.android.systemui"), risk: .expert, description: "x"),
            DebloatEntry(packageName: pkg("com.example.bloat"), risk: .safe, description: "y"),
        ]
        let library = PresetLibrary(presets: [DebloatPreset(id: "t", name: "T", brand: .samsung, entries: entries)])
        #expect(library.presets.first?.entries.map(\.packageName.rawValue) == ["com.example.bloat"])
    }

    @Test func samsungPresetMatchesRealS24Packages() throws {
        let installed = PackageListParser.names(Fixture.adb(s24, "pm-list-system.txt"))
        let samsung = try #require(try PresetLibrary.bundled().presets.first { $0.id == "samsung" })
        let present = samsung.entries.filter { installed.contains($0.packageName.rawValue) }
        #expect(present.count > 50, "the preset should cover a real share of a Galaxy S24's system apps")
        #expect(Set(samsung.entries.map(\.risk)).isSubset(of: [.safe, .caution, .expert]))
    }
}

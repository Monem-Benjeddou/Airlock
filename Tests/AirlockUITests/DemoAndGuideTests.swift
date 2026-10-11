// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import AirlockInspection
import AirlockReputation
import AirlockTestSupport
@testable import AirlockUI
import AppKit
import Foundation
import Testing

@Suite("OnboardingGuide")
struct OnboardingGuideTests {
    @Test(arguments: DeviceBrand.allCases)
    func everyBrandStartsWithDeveloperOptionsAndEndsWithConnect(_ brand: DeviceBrand) {
        let steps = OnboardingGuide.steps(for: brand)
        #expect(steps.first?.title == "Turn on Developer options")
        #expect(steps.dropFirst().first?.title == "Turn on USB debugging")
        #expect(steps.last?.title == "Connect and allow")
        #expect(Set(steps.map(\.id)).count == steps.count, "step ids are unique")
        #expect(steps.allSatisfy { !$0.detail.isEmpty && !$0.symbol.isEmpty })
        #expect(!OnboardingGuide.title(for: brand).isEmpty)
    }

    @Test func brandSpecificStepsAreThirdAndOnlyWhereNeeded() {
        #expect(OnboardingGuide.steps(for: .samsung)[2].title == "Turn off Auto Blocker")
        #expect(OnboardingGuide.steps(for: .xiaomi)[2].title == "Turn on Install via USB")
        for brand in [DeviceBrand.pixel, .oneplus, .other] {
            #expect(OnboardingGuide.steps(for: brand).count == 3)
        }
    }

    @Test func titlesMatchThePickerLabelsUsedByTheUITests() {
        #expect(OnboardingGuide.title(for: .samsung) == "Samsung Galaxy")
        #expect(OnboardingGuide.title(for: .xiaomi) == "Xiaomi, Redmi or POCO")
    }

    @Test func everyStageHasAnExplanation() {
        let stages: [OnboardingStage] = [.noDevice, .tapAllow, .offline, .noPermission, .unsupportedMode("recovery"), .ready]
        for stage in stages {
            let text = OnboardingGuide.explanation(for: stage)
            #expect(!text.title.isEmpty && !text.detail.isEmpty)
        }
        #expect(OnboardingGuide.explanation(for: .noDevice).title == "Connect your Android phone")
        #expect(OnboardingGuide.explanation(for: .unsupportedMode("sideload")).title.contains("sideload"))
    }
}

/// The XCUITests drive the app through these demo services, so their behaviour is pinned here where it can run
/// without Xcode.
@MainActor
@Suite("Demo environment")
struct DemoEnvironmentTests {
    @Test func launchArgumentsPickTheEnvironment() async {
        let empty = AppEnvironment.fromLaunchArguments(["Airlock", "--demo-no-device"])
        await empty.devices.apply([])
        #expect(empty.devices.stage == .noDevice)
        #expect(empty.startupProblem == nil)

        let demo = AppEnvironment.fromLaunchArguments(["Airlock", "--demo"])
        #expect(demo.adbLocation == nil)
        #expect(demo.installQueue.items.isEmpty)
    }

    @Test func demoDeviceIsReadyWithModelAndBattery() async throws {
        let service = DemoDeviceService(withDevice: true)
        var updates = service.deviceUpdates().makeAsyncIterator()
        let devices = try #require(await updates.next())
        #expect(devices.map(\.state) == [.ready])
        let info = try await service.info(for: DemoDeviceService.serial)
        #expect(info.model == "Pixel 9 (demo)")
        #expect(info.androidVersion == "16")
        #expect(info.batteryPercent == 82)

        var none = DemoDeviceService(withDevice: false).deviceUpdates().makeAsyncIterator()
        #expect(await none.next() == [])
    }

    /// A demo queue after the window has done its part: the phone is ready and is the install target.
    private func readyQueue(_ files: [String]) async -> InstallQueueModel {
        let environment = AppEnvironment.demo(queuedFiles: files)
        #expect(environment.installQueue.items.isEmpty, "nothing is queued before the phone is ready")
        await environment.devices.apply([ConnectedDevice(serial: DemoDeviceService.serial, state: .ready)])
        environment.installQueue.targetDevice = environment.devices.selectedSerial
        return environment.installQueue
    }

    @Test func lowRiskFileInstallsWithoutReview() async {
        let queue = await readyQueue(["notes.apk"])
        #expect(await eventually { queue.items.first?.state.isFinished == true })
        guard case .installed(let outcome) = queue.items[0].state else {
            Issue.record("expected installed, got \(queue.items[0].state)")
            return
        }
        #expect(outcome.packageName.rawValue == "com.demo.notes")
        #expect(outcome.versionCode == 3)
    }

    @Test func riskyFileWaitsForReviewAndNeverSaysSafe() async {
        let queue = await readyQueue(["risky.apk"])
        #expect(await eventually { if case .needsReview = queue.items.first?.state { true } else { false } })
        guard case .needsReview(let plan) = queue.items[0].state else { return }
        #expect(plan.report.level == .high)
        #expect(!plan.report.reasons.isEmpty)
        let words = plan.report.reasons.map(\.message) + plan.report.permissions.map(\.plainLanguage)
        #expect(words.allSatisfy { !$0.localizedCaseInsensitiveContains("safe") })
        queue.skipReview()
        #expect(await eventually { queue.items.first?.state == .skipped })
    }

    @Test func riskyFileInstallsAfterApproval() async {
        let queue = await readyQueue(["risky.apk"])
        #expect(await eventually { if case .needsReview = queue.items.first?.state { true } else { false } })
        guard case .needsReview(let plan) = queue.items[0].state else { return }
        queue.approve(plan)
        #expect(await eventually { if case .installed = queue.items.first?.state { true } else { false } })
    }

    @Test func severalFilesInstallInOrder() async {
        let queue = await readyQueue(["one.apk", "two.apk", "three.apk"])
        #expect(await eventually { queue.items.count == 3 && queue.items.allSatisfy { $0.state.isFinished } })
        let names = queue.items.compactMap { item -> String? in
            if case .installed(let outcome) = item.state { outcome.packageName.rawValue } else { nil }
        }
        #expect(names == ["com.demo.one", "com.demo.two", "com.demo.three"])
    }

    @Test func disableNeedsConfirmationAndCanBeRestored() async throws {
        let apps = AppEnvironment.demo().apps
        apps.device = DemoDeviceService.serial
        await apps.reload()
        let bloat = try #require(PackageName(rawValue: "com.example.bloat"))
        apps.request(.disableForUser, for: [bloat])
        #expect(apps.apps.first { $0.packageName == bloat }?.state == .enabled, "nothing changes before confirmation")
        await apps.confirm(try #require(apps.pendingChange))
        #expect(apps.results == [AppsModel.ChangeResult(package: bloat, error: nil)])
        #expect(apps.apps.first { $0.packageName == bloat }?.state == .disabled)
        let entry = try #require(apps.history.first)
        #expect(entry.restore == .enable)

        await apps.restore(entry)
        #expect(apps.apps.first { $0.packageName == bloat }?.state == .enabled)
        #expect(apps.history.first?.status == .restored)
    }

    @Test func criticalAppsAreRefusedWithAPlainReason() async throws {
        let apps = AppEnvironment.demo().apps
        apps.device = DemoDeviceService.serial
        await apps.reload()
        let settings = try #require(PackageName(rawValue: "com.android.settings"))
        apps.request(.disableForUser, for: [settings])
        await apps.confirm(try #require(apps.pendingChange))
        let error = try #require(apps.results.first?.error)
        #expect(error.contains("core part of Android"))
        #expect(apps.apps.first { $0.packageName == settings }?.state == .enabled)
    }

    @Test func demoPresetOffersTheInstalledBloat() async {
        let apps = AppEnvironment.demo().apps
        apps.device = DemoDeviceService.serial
        await apps.reload()
        let presets = apps.presets(for: .pixel)
        #expect(presets.count == 1)
        let entries = presets.flatMap { apps.applicableEntries(of: $0, maximumRisk: .safe) }
        #expect(entries.map(\.packageName.rawValue) == ["com.example.bloat"])
    }

    @Test func qrPairingShowsACodeAndWaits() async {
        let pairing = AppEnvironment.demo().pairing
        pairing.startQRPairing()
        #expect(pairing.qrImage != nil)
        #expect(pairing.session != nil)
        pairing.stop()
    }

    @Test func codePairingAndLegacyWirelessSucceed() async throws {
        let demo = DemoPairing()
        let paired = try await demo.pairWithCode(host: "192.168.1.20", pairingPort: 40_001, code: "123456", connectPort: 5555)
        #expect(paired.port == 5555)
        let legacy = try await demo.enableLegacyWireless(usb: DemoDeviceService.serial, port: 5555)
        #expect(legacy.host == "192.168.1.20")
        #expect(await demo.reconnectRemembered().isEmpty)
        #expect(demo.rememberedDevices().isEmpty)
        #expect(await demo.diagnose(phoneAddress: nil) == .noServiceSeen)
    }

    @Test func demoKeysRejectBlankAndForget() throws {
        let keys = DemoKeys()
        #expect(throws: KeychainError.emptyKey) { try keys.save("  ") }
        try keys.save("abc")
        #expect(keys.apiKey() == "abc")
        try keys.delete()
        #expect(keys.apiKey() == nil)
    }
}

@Suite("Palette and About")
struct PaletteAndAboutTests {
    @Test func riskScalesShareOneSetOfColours() {
        #expect(Palette.verdict(.low) == Palette.success)
        #expect(Palette.verdict(.medium) == Palette.warning)
        #expect(Palette.verdict(.high) == Palette.danger)
        #expect(Palette.debloat(.safe) == Palette.verdict(.low))
        #expect(Palette.debloat(.caution) == Palette.verdict(.medium))
        #expect(Palette.debloat(.expert) == Palette.verdict(.high))
    }

    @Test func aLowRiskReasonIsNeutralNotGreen() {
        #expect(Palette.reason(.low) == .secondary)
        #expect(Palette.reason(.high) == Palette.danger)
        #expect(Set(RiskLevel.allCases.map(Palette.reasonSymbol)).count == RiskLevel.allCases.count)
    }

    @Test func aboutCreditsNameTheLicenceAndLinkTheSource() throws {
        let credits = AboutPanel.credits()
        #expect(credits.string.contains("GNU GPL 3.0"))
        #expect(credits.string.contains("UAD-ng"))
        let range = (credits.string as NSString).range(of: "Source code")
        let link = credits.attribute(.link, at: range.location, effectiveRange: nil) as? URL
        #expect(link?.absoluteString == AboutPanel.sourceURL)
    }
}

@MainActor
@Suite("Demo with a real inspector")
struct DemoRealInspectorTests {
    @Test func realFilesAreInspectedAndTheirJobFolderIsRemoved() async throws {
        let scratch = FileManager.default.temporaryDirectory.appendingPathComponent("airlock-demo-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: scratch) }
        let jobs = scratch.appendingPathComponent("Airlock/jobs")
        let apk = scratch.appendingPathComponent("game.apk")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        try FixtureAPKs.data(.v2RSA).write(to: apk)

        let pipeline = DemoPipeline(inspector: LocalPackageInspector(jobsRoot: jobs))
        let package = try await pipeline.inspect(apk)
        #expect(package.packageName == "org.airlock.fixture")
        #expect(FileManager.default.fileExists(atPath: package.workDirectory.path))
        await pipeline.discard(package)
        #expect(!FileManager.default.fileExists(atPath: package.workDirectory.path))

        let demo = try await pipeline.inspect(URL(fileURLWithPath: "/demo/notes.apk"))
        #expect(demo.packageName == "com.demo.notes", "made-up names never reach the inspector")
    }

    @Test func discardNeverTouchesFoldersOutsideAJobsFolder() async throws {
        let keep = FileManager.default.temporaryDirectory.appendingPathComponent("airlock-keep-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: keep, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: keep) }
        let real = try await DemoPipeline().inspect(URL(fileURLWithPath: "/demo/x.apk"))
        let package = InspectedPackage(sourceFile: keep.appendingPathComponent("x.apk"), format: .apk, sourceSHA256: "00",
                                       base: real.base, splits: [], obbFiles: [], workDirectory: keep)
        await DemoPipeline().discard(package)
        #expect(FileManager.default.fileExists(atPath: keep.path))
    }
}

@Suite("Device row")
struct DeviceRowTests {
    private func info(model: String, displayName: String?, battery: Int?) throws -> DeviceInfo {
        DeviceInfo(
            serial: try DeviceSerial("R58"), stableID: "R58", model: model, displayName: displayName,
            manufacturer: "samsung", brand: .samsung, androidVersion: "16",
            properties: DeviceProperties(abis: [], densityDPI: 0, locales: [], sdkLevel: 36), batteryPercent: battery
        )
    }

    @Test func aFriendlyNameKeepsTheModelCodeUnderIt() throws {
        let details = DeviceRow.details(of: try info(model: "SM-S928B", displayName: "Galaxy S24 Ultra", battery: 87))
        #expect(details == "SM-S928B · Android 16 · 87%")
    }

    @Test func aReadyDeviceSaysWhetherItsDetailsAreLoadingOrFailed() throws {
        #expect(DeviceRow.status(of: .ready, info: nil, failed: false) == "Reading details…")
        #expect(DeviceRow.status(of: .ready, info: nil, failed: true) == "Couldn't read details. Click to retry.")
        let loaded = try info(model: "SM-S928B", displayName: nil, battery: 50)
        #expect(DeviceRow.status(of: .ready, info: loaded, failed: true) == "Android 16 · 50%")
        #expect(DeviceRow.status(of: .unauthorized, info: nil, failed: false) == "Waiting for Allow")
    }

    @Test func theModelCodeIsNotRepeatedWhenItIsTheName() throws {
        #expect(DeviceRow.details(of: try info(model: "CPH2581", displayName: nil, battery: nil)) == "Android 16")
    }
}

@Suite("Starting section")
struct StartingSectionTests {
    @Test func theEnvironmentPicksTheStartingPage() {
        #expect(Section.initial(["AIRLOCK_SECTION": "apps"]) == .apps)
        #expect(Section.initial(["AIRLOCK_SECTION": "History"]) == .history)
    }

    @Test func anythingElseStartsOnInstall() {
        #expect(Section.initial([:]) == .install)
        #expect(Section.initial(["AIRLOCK_SECTION": "settings"]) == .install)
    }
}

@MainActor
@Suite("Sidebar")
struct SidebarTests {
    @Test func badgesCountQueuedFilesAppsAndChanges() async {
        let environment = AppEnvironment.demo()
        #expect(Sidebar.badge(for: .install, environment: environment) == 0)
        environment.installQueue.add([URL(fileURLWithPath: "/demo/notes.apk")])
        #expect(Sidebar.badge(for: .install, environment: environment) == 1)
        environment.apps.device = DemoDeviceService.serial
        await environment.apps.reload()
        #expect(Sidebar.badge(for: .apps, environment: environment) == environment.apps.apps.count)
        #expect(Sidebar.badge(for: .history, environment: environment) == environment.apps.history.count)
    }

    @Test func aDeviceIsNamedByItsDetailsThenAdbsModelThenItsSerial() throws {
        let serial = try DeviceSerial("R58")
        #expect(DeviceRow.name(of: ConnectedDevice(serial: serial, state: .ready, model: "Pixel_9"), info: nil) == "Pixel 9")
        #expect(DeviceRow.name(of: ConnectedDevice(serial: serial, state: .ready), info: nil) == "R58")
    }
}

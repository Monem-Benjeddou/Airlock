// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import AirlockPairing
@testable import AirlockUI
import Foundation
import Testing

@MainActor
@Suite("DevicesModel")
struct DevicesModelTests {
    private func device(_ raw: String, _ state: DeviceConnectionState) -> ConnectedDevice {
        ConnectedDevice(serial: serial(raw), state: state)
    }

    @Test func walksThroughOnboardingStagesAsTheDeviceChanges() async {
        let model = DevicesModel(service: FakeDeviceService(snapshots: []))
        #expect(model.stage == .noDevice)
        await model.apply([device("R58", .unauthorized)])
        #expect(model.stage == .tapAllow)
        await model.apply([device("R58", .offline)])
        #expect(model.stage == .offline)
        await model.apply([device("R58", .noPermissions)])
        #expect(model.stage == .noPermission)
        await model.apply([device("R58", .other("recovery"))])
        #expect(model.stage == .unsupportedMode("recovery"))
        await model.apply([device("R58", .ready)])
        #expect(model.stage == .ready)
        #expect(model.selectedInfo?.model == "SM-S928B")
        await model.apply([])
        #expect(model.stage == .noDevice)
        #expect(model.details.isEmpty)
    }

    @Test func prefersAReadyDeviceAndKeepsTheSelection() async {
        let model = DevicesModel(service: FakeDeviceService(snapshots: []))
        await model.apply([device("A", .unauthorized), device("B", .ready)])
        #expect(model.selectedSerial == serial("B"))
        model.selectedSerial = serial("A")
        await model.apply([device("A", .ready), device("B", .ready), device("C", .ready)])
        #expect(model.selectedSerial == serial("A"))
        #expect(model.details.count == 3)
    }

    @Test func detailErrorsAreReported() async {
        let model = DevicesModel(service: FakeDeviceService(snapshots: [], failing: ["R58"]))
        await model.apply([device("R58", .ready)])
        #expect(model.detailErrors[serial("R58")] != nil)
        #expect(model.selectedInfo == nil)
    }

    @Test func runConsumesTheServiceStream() async {
        let snapshots = [[device("A", .ready)], [device("A", .ready), device("B", .offline)]]
        let model = DevicesModel(service: FakeDeviceService(snapshots: snapshots))
        await model.run()
        #expect(model.devices.count == 2)
    }
}

@MainActor
@Suite("InstallQueueModel")
struct InstallQueueModelTests {
    private func url(_ name: String) -> URL { URL(fileURLWithPath: "/tmp/\(name).apk") }

    private func queue(_ pipeline: FakePipeline, manager: FakeAppManager = FakeAppManager()) -> InstallQueueModel {
        let model = InstallQueueModel(pipeline: pipeline, appManager: manager)
        model.targetDevice = serial("R58")
        return model
    }

    @Test func lowRiskFilesInstallInOrderWithoutQuestions() async {
        let pipeline = FakePipeline()
        let model = queue(pipeline)
        model.add([url("com.a.one"), url("com.a.two"), url("com.a.three")])
        #expect(await eventually { model.items.allSatisfy { $0.state.isFinished } })
        #expect(pipeline.installed.get() == ["com.a.one", "com.a.two", "com.a.three"])
        #expect(await eventually { pipeline.discarded.get().count == 3 }, "temp folders are cleaned after every outcome")
    }

    @Test func oneFailureDoesNotStopTheRest() async {
        let olderSDK = InstallErrorMapper.explain(InstallFailure(code: "INSTALL_FAILED_OLDER_SDK"))
        let pipeline = FakePipeline(failures: ["com.a.two": .packageManager(olderSDK)])
        let model = queue(pipeline)
        model.add([url("com.a.one"), url("com.a.two"), url("notanapp"), url("com.a.four")])
        #expect(await eventually { model.items.allSatisfy { $0.state.isFinished } })
        #expect(pipeline.installed.get() == ["com.a.one", "com.a.four"])
        guard case .failed(.unsupportedFile) = model.items[2].state else {
            Issue.record("non-app file should be rejected with a clear message")
            return
        }
    }

    @Test func mediumRiskWaitsForApproval() async {
        let pipeline = FakePipeline(levels: ["com.a.risky": .medium])
        let model = queue(pipeline)
        model.add([url("com.a.risky"), url("com.a.next")])
        #expect(await eventually {
            if case .needsReview = model.items[0].state { true } else { false }
        })
        #expect(pipeline.installed.get().isEmpty, "nothing installs while a review is pending")
        guard case .needsReview(let plan) = model.items[0].state else { return }
        model.approve(plan)
        #expect(await eventually { model.items.allSatisfy { $0.state.isFinished } })
        #expect(pipeline.installed.get() == ["com.a.risky", "com.a.next"])
    }

    @Test func skippingAReviewMovesOn() async {
        let pipeline = FakePipeline(levels: ["com.a.risky": .high])
        let model = queue(pipeline)
        model.add([url("com.a.risky"), url("com.a.next")])
        #expect(await eventually { if case .needsReview = model.items[0].state { true } else { false } })
        model.skipReview()
        #expect(await eventually { model.items.allSatisfy { $0.state.isFinished } })
        #expect(model.items[0].state == .skipped)
        #expect(pipeline.installed.get() == ["com.a.next"])
    }

    @Test func queueIsCappedAtTwenty() {
        let model = queue(FakePipeline(installDelay: .seconds(10)))
        model.add((0..<25).map { url("com.a.app\($0)") })
        #expect(model.items.count == 20)
        #expect(model.notice?.contains("5 file(s)") == true)
        model.cancelCurrent()
    }

    @Test func cancelStopsTheCurrentInstall() async {
        let pipeline = FakePipeline(installDelay: .seconds(30))
        let model = queue(pipeline)
        model.add([url("com.a.slow")])
        #expect(await eventually { if case .installing = model.items[0].state { true } else { false } })
        model.cancelCurrent()
        #expect(await eventually { model.items[0].state == .cancelled })
        #expect(pipeline.installed.get().isEmpty)
    }

    @Test func noDeviceFailsClearly() async {
        let model = InstallQueueModel(pipeline: FakePipeline(), appManager: FakeAppManager())
        model.add([url("com.a.one")])
        #expect(await eventually { model.items[0].state == .failed(.deviceDisconnected) })
    }

    @Test func uninstallFixRunsTheConfirmedUninstallThenRetries() async {
        let explained = InstallErrorMapper.explain(InstallFailure(code: "INSTALL_FAILED_UPDATE_INCOMPATIBLE"))
        let pipeline = FakePipeline(failures: ["com.a.game": .packageManager(explained)])
        let manager = FakeAppManager()
        let model = queue(pipeline, manager: manager)
        model.add([url("com.a.game")])
        #expect(await eventually { model.items[0].state.isFinished })
        let id = model.items[0].id

        await model.applyFix(.uninstallExistingThenInstall, to: id, confirmation: nil)
        #expect(manager.performed.get().isEmpty, "no uninstall without confirmation")

        let confirmation = ConfirmedOperation(userConfirmed: .uninstall, on: pkg("com.a.game"))
        await model.applyFix(.uninstallExistingThenInstall, to: id, confirmation: confirmation)
        #expect(manager.performed.get().map(\.operation) == [.uninstall])
        #expect(await eventually { model.items[0].state.isFinished })
    }

    @Test func clearFinishedKeepsPendingItems() async {
        let model = queue(FakePipeline())
        model.add([url("com.a.one")])
        #expect(await eventually { model.items[0].state.isFinished })
        model.clearFinished()
        #expect(model.items.isEmpty)
    }
}

@MainActor
@Suite("AppsModel")
struct AppsModelTests {
    private func model(_ manager: FakeAppManager) -> AppsModel {
        let model = AppsModel(manager: manager)
        model.device = serial("R58")
        return model
    }

    private let apps = [
        Sample.app("com.user.notes"),
        Sample.app("com.samsung.bloat.safe", system: true),
        Sample.app("com.samsung.bloat.caution", system: true),
        Sample.app("com.samsung.bloat.expert", system: true),
        Sample.app("com.samsung.old", system: true, state: .disabled),
    ]

    @Test func filtersAndSearch() async {
        let model = model(FakeAppManager(apps: apps))
        await model.reload()
        #expect(model.visibleApps.count == 5)
        model.filter = .user
        #expect(model.visibleApps.map(\.packageName.rawValue) == ["com.user.notes"])
        model.filter = .system
        #expect(model.visibleApps.count == 4)
        model.filter = .disabled
        #expect(model.visibleApps.map(\.packageName.rawValue) == ["com.samsung.old"])
        model.filter = .all
        model.searchText = "CAUTION"
        #expect(model.visibleApps.count == 1)
    }

    @Test func nothingChangesBeforeConfirmation() async {
        let manager = FakeAppManager(apps: apps)
        let model = model(manager)
        model.request(.disableForUser, for: [pkg("com.samsung.bloat.safe")])
        #expect(model.pendingChange?.title == "Disable com.samsung.bloat.safe?")
        #expect(manager.performed.get().isEmpty)
        model.cancelPendingChange()
        #expect(model.pendingChange == nil)
        await model.confirmPendingChange()
        #expect(manager.performed.get().isEmpty)
    }

    @Test func confirmedBatchRunsEachChangeAndReportsResults() async {
        let manager = FakeAppManager(apps: apps)
        manager.blocked = ["com.samsung.bloat.expert"]
        let model = model(manager)
        model.request(.uninstallForUser, for: [pkg("com.samsung.bloat.safe"), pkg("com.samsung.bloat.expert")])
        #expect(model.pendingChange?.title == "Remove 2 apps for this user?")
        await model.confirmPendingChange()
        #expect(manager.performed.get().map(\.package.rawValue) == ["com.samsung.bloat.safe"])
        #expect(model.results.count == 2)
        #expect(model.results[1].error?.contains("core part of Android") == true)
        #expect(model.history.count == 1)
    }

    @Test func presetEntriesAreLimitedByRiskAndWhatIsInstalled() async {
        let manager = FakeAppManager(apps: apps)
        let model = model(manager)
        await model.reload()
        let preset = model.presets(for: .samsung)[0]
        #expect(model.applicableEntries(of: preset, maximumRisk: .safe).map(\.packageName.rawValue) == ["com.samsung.bloat.safe"])
        #expect(model.applicableEntries(of: preset, maximumRisk: .caution).count == 2)
        #expect(model.applicableEntries(of: preset, maximumRisk: .expert).count == 3)
    }

    @Test func undoingAnInstallNeedsConfirmation() async {
        let manager = FakeAppManager(apps: apps)
        let model = model(manager)
        let entry = JournalEntry(deviceID: "R58", packageName: pkg("com.new.game"), kind: .install(versionCode: 1, wasUpdate: false),
                                 restore: .uninstallInstalled, status: .applied)
        await model.restore(entry)
        #expect(model.results.first?.error == "This needs your confirmation first.")
        await model.restore(entry, confirmed: true)
        #expect(model.results.first?.error == nil)
        #expect(manager.restored.get().first?.1?.operation == .uninstall)
    }

    @Test func exportReturnsFiles() async {
        let model = model(FakeAppManager(apps: apps))
        let urls = await model.export(pkg("com.user.notes"), to: URL(fileURLWithPath: "/tmp"))
        #expect(urls.map(\.lastPathComponent) == ["base.apk"])
    }

    @Test(arguments: DeviceOperation.allCases)
    func everyChangeExplainsItself(_ operation: DeviceOperation) {
        let change = AppsModel.PendingChange(operation: operation, packages: [pkg("com.a.b")])
        #expect(!change.title.isEmpty && change.message.hasSuffix("."))
    }

    @Test func errorDescriptions() {
        #expect(AppsModel.describe(AppManagerError.notRestorable(UUID())) == "This change cannot be undone.")
        #expect(AppsModel.describe(AppManagerError.deviceNotReady) == "The phone is not ready.")
        #expect(AppsModel.describe(AppManagerError.commandFailed("boom")) == "boom")
    }
}

@MainActor
@Suite("PairingModel")
struct PairingModelTests {
    private let device = PairedDevice(name: "adb-R58-x", host: "192.168.1.20", port: 41235)

    @Test func qrPairingShowsACodeThenSucceeds() async {
        let model = PairingModel(pairing: FakePairing(result: .success(device), delay: .milliseconds(50)))
        model.startQRPairing()
        #expect(model.state == .waitingForScan)
        #expect(model.qrImage != nil)
        #expect(await eventually { model.state == .paired(device) })
        #expect(model.session == nil)
        #expect(model.remembered == [device])
    }

    @Test func qrFailureIsExplained() async {
        let model = PairingModel(pairing: FakePairing(result: .failure(.notFound(.noServiceSeen))))
        model.startQRPairing()
        #expect(await eventually { model.state == .failed(.notFound(.noServiceSeen)) })
        #expect(PairingError.notFound(.noServiceSeen).explanation.contains("Guest networks"))
    }

    @Test func stopCancelsSilently() async throws {
        let model = PairingModel(pairing: FakePairing(result: .success(device), delay: .seconds(30)))
        model.startQRPairing()
        model.stop()
        try await Task.sleep(for: .milliseconds(50))
        #expect(model.state == .idle)
    }

    @Test func pairingCodeForm() async {
        let model = PairingModel(pairing: FakePairing(result: .success(device)))
        #expect(!model.canSubmitCode)
        model.codeHost = "192.168.1.20"
        model.codePort = "37099"
        model.code = "123456"
        model.connectPort = "41235"
        #expect(model.canSubmitCode)
        await model.pairWithCode()
        #expect(model.state == .paired(device))
        model.codePort = "x"
        await model.pairWithCode()
        #expect(model.state == .failed(.invalidInput))
    }

    @Test func legacyAndRememberedDevices() async {
        let model = PairingModel(pairing: FakePairing(result: .success(device)))
        await model.enableLegacy(usb: serial("R58"))
        #expect(model.state == .paired(device))
        await model.reconnectRemembered()
        #expect(model.remembered == [device])
        model.forget(device)
        #expect(model.remembered.isEmpty)
    }

    @Test(arguments: [
        PairingError.notFound(.macNotOnNetwork), .wrongCode, .unreachable, .pairedButNotConnected,
        .phoneNotOnWiFi, .invalidInput, .cancelled, .failed("x"),
    ])
    func everyErrorHasText(_ error: PairingError) {
        #expect(!error.explanation.isEmpty)
    }
}

@MainActor
@Suite("SettingsModel")
struct SettingsModelTests {
    @Test func savesAndRemovesTheKey() {
        let keys = FakeKeys()
        let model = SettingsModel(keys: keys)
        #expect(!model.hasKey)
        model.keyInput = "  "
        model.saveKey()
        #expect(model.message == "Paste your VirusTotal API key first.")
        model.keyInput = "abc"
        model.saveKey()
        #expect(model.hasKey)
        #expect(model.keyInput.isEmpty)
        #expect(keys.apiKey() == "abc")
        model.removeKey()
        #expect(!model.hasKey)
    }

    @Test func keychainFailureIsReported() {
        let keys = FakeKeys()
        keys.failSave = true
        let model = SettingsModel(keys: keys)
        model.keyInput = "abc"
        model.saveKey()
        #expect(model.message == "Could not save the key to your keychain.")
    }
}

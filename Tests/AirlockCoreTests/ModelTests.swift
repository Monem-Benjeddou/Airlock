// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation
import Testing

@Suite("DeviceSerial")
struct DeviceSerialTests {
    @Test(arguments: [
        "emulator-5554", "R58M123ABC", "192.168.1.20:5555", "[fe80::1]:5555",
        "adb-R58M123ABC-xYz12._adb-tls-connect._tcp",
    ])
    func acceptsRealSerials(_ raw: String) throws {
        #expect(try DeviceSerial(raw).rawValue == raw)
        #expect(DeviceSerial(rawValue: raw) != nil)
    }

    @Test(arguments: ["", "-s", "a b", "a;b", "a$b", "a\nb", "a/b", String(repeating: "x", count: 129)])
    func rejectsUnsafeSerials(_ raw: String) {
        #expect(throws: DeviceSerialError.invalid(raw)) { try DeviceSerial(raw) }
        #expect(DeviceSerial(rawValue: raw) == nil)
    }

    @Test func wirelessDetection() throws {
        #expect(try DeviceSerial("192.168.1.20:5555").isWireless)
        #expect(try DeviceSerial("adb-X._adb-tls-connect._tcp").isWireless)
        #expect(try !DeviceSerial("R58M123ABC").isWireless)
    }

    @Test func codableRoundTripAndRejection() throws {
        let serial = try DeviceSerial("emulator-5554")
        let data = try JSONEncoder().encode(serial)
        #expect(try JSONDecoder().decode(DeviceSerial.self, from: data) == serial)
        #expect(serial.description == "emulator-5554")
        #expect(throws: (any Error).self) { try JSONDecoder().decode(DeviceSerial.self, from: Data(#""a b""#.utf8)) }
    }
}

@Suite("Device models")
struct DeviceModelTests {
    @Test(arguments: [
        ("device", DeviceConnectionState.ready),
        ("unauthorized", .unauthorized),
        ("authorizing", .authorizing),
        ("offline", .offline),
        ("no permissions", .noPermissions),
        ("recovery", .other("recovery")),
    ])
    func mapsAdbStates(_ raw: String, _ expected: DeviceConnectionState) {
        #expect(DeviceConnectionState(adbState: raw) == expected)
    }

    @Test(arguments: [
        ("Google", "google", DeviceBrand.pixel),
        ("samsung", "samsung", .samsung),
        ("Xiaomi", "Redmi", .xiaomi),
        ("", "POCO", .xiaomi),
        ("OnePlus", "OnePlus", .oneplus),
        ("motorola", "motorola", .other),
    ])
    func mapsBrands(_ manufacturer: String, _ brand: String, _ expected: DeviceBrand) {
        #expect(DeviceBrand(manufacturer: manufacturer, brand: brand) == expected)
    }

    @Test func connectedDeviceIdentity() throws {
        let serial = try DeviceSerial("emulator-5554")
        let device = ConnectedDevice(serial: serial, state: .ready, model: "Pixel_9")
        #expect(device.id == serial)
        #expect(device.product == nil)
    }
}

@Suite("App models")
struct AppModelTests {
    private func app(installer: String?, system: Bool = false) throws -> InstalledApp {
        InstalledApp(
            packageName: try PackageName("com.example.app"), versionCode: 1, isSystem: system,
            state: .enabled, apkPaths: [], installerPackage: installer
        )
    }

    @Test(arguments: [
        ("com.android.vending", "Google Play"),
        ("com.sec.android.app.samsungapps", "Galaxy Store"),
        ("com.xiaomi.market", "Xiaomi GetApps"),
        ("com.amazon.venezia", "Amazon Appstore"),
        ("org.fdroid.fdroid", "F-Droid"),
        ("com.google.android.packageinstaller", "Installed from a file"),
        ("com.other.store", "com.other.store"),
    ])
    func installSource(_ installer: String, _ expected: String) throws {
        #expect(try app(installer: installer).installSource == expected)
    }

    @Test func installSourceWithoutInstaller() throws {
        #expect(try app(installer: nil).installSource == "Unknown (adb or sideload)")
        #expect(try app(installer: "null", system: true).installSource == "Preinstalled")
    }

    @Test func debloatRiskOrdering() {
        #expect(DebloatRisk.safe < .caution)
        #expect(DebloatRisk.caution < .expert)
        #expect(DebloatRisk.allCases.sorted() == [.safe, .caution, .expert])
    }

    @Test func presetIdentity() throws {
        let entry = DebloatEntry(packageName: try PackageName("com.a.b"), risk: .safe, description: "x")
        let preset = DebloatPreset(id: "p", name: "P", brand: .samsung, entries: [entry])
        #expect(entry.id.rawValue == "com.a.b")
        #expect(preset.entries.count == 1)
    }
}

@Suite("Safety and install models")
struct SafetyModelTests {
    @Test func riskLevelOrderingAndConfirmation() {
        #expect(RiskLevel.low < .medium && RiskLevel.medium < .high)
        #expect(!RiskLevel.low.requiresConfirmation)
        #expect(RiskLevel.medium.requiresConfirmation)
        #expect(RiskLevel.high.requiresConfirmation)
    }

    @Test(arguments: RiskLevel.allCases)
    func riskTitlesNeverSaySafe(_ level: RiskLevel) {
        #expect(!level.title.localizedCaseInsensitiveContains("safe"))
        #expect(level.title.hasSuffix("risk"))
    }

    @Test func identifiables() {
        let reason = RiskReason(ruleID: "r.1", category: .permissions, level: .medium, message: "m")
        let permission = PermissionFinding(permission: "android.permission.READ_SMS", plainLanguage: "Read texts", isDangerous: true)
        let tracker = TrackerFinding(name: "Ads", category: "Advertising", matchedPrefixes: ["com/ads/"])
        #expect(reason.id == "r.1")
        #expect(permission.id == "android.permission.READ_SMS")
        #expect(tracker.id == "Ads")
    }

    @Test func progressIsClamped() {
        let progress = InstallProgress(step: .installing, stepFraction: 1.5, totalFraction: -2, message: "")
        #expect(progress.stepFraction == 1)
        #expect(progress.totalFraction == 0)
    }

    @Test func inspectedPackageAggregates() throws {
        let package = Fixtures.package()
        #expect(package.packageName == "com.example.game")
        #expect(package.allAPKs.count == 2)
        #expect(package.totalSizeBytes == 100 + 20 + 500)
        #expect(package.splitAPKs == [SplitAPK(fileName: "split.apk", splitName: "config.arm64_v8a")])
    }

    @Test func splitWithoutManifestNameFallsBackToFileName() {
        let split = Fixtures.apk(name: "feature.apk", split: nil, size: 1)
        let package = Fixtures.package(splits: [split])
        #expect(package.splitAPKs.first?.splitName == "feature.apk")
    }

    @Test func planCopyReplacesSplitsOnly() throws {
        let plan = Fixtures.plan()
        let edited = plan.with(selectedSplits: [])
        #expect(edited.selectedSplits.isEmpty)
        #expect(edited.package == plan.package)
        #expect(edited.problems == plan.problems)
        #expect(edited.device == plan.device)
    }
}

@Suite("Journal models")
struct JournalModelTests {
    @Test func restorableOnlyWhenAppliedAndUndoable() throws {
        let name = try PackageName("com.example.app")
        var entry = JournalEntry(
            deviceID: "R58", packageName: name, kind: .operation(.disableForUser), restore: .enable
        )
        #expect(entry.status == .pending)
        #expect(!entry.isRestorable)
        entry.status = .applied
        #expect(entry.isRestorable)

        let update = JournalEntry(
            deviceID: "R58", packageName: name, kind: .install(versionCode: 2, wasUpdate: true),
            restore: .notRestorable, status: .applied
        )
        #expect(!update.isRestorable)
        #expect(update.updatedAt == update.createdAt)
    }

    @Test func confirmationCarriesOperation() throws {
        let name = try PackageName("com.example.app")
        let date = Date(timeIntervalSince1970: 1)
        let confirmed = ConfirmedOperation(userConfirmed: .uninstallForUser, on: name, at: date)
        #expect(confirmed.operation == .uninstallForUser)
        #expect(confirmed.package == name)
        #expect(confirmed.confirmedAt == date)
    }

    @Test func journalEntryCodableRoundTrip() throws {
        let entry = JournalEntry(
            deviceID: "R58", packageName: try PackageName("com.a.b"), kind: .operation(.uninstall),
            restore: .reinstallFromBackup(apkPaths: ["/tmp/a.apk"]), status: .applied, note: "n"
        )
        let decoded = try JSONDecoder().decode(JournalEntry.self, from: JSONEncoder().encode(entry))
        #expect(decoded == entry)
    }
}

/// Small builders shared by the model tests.
enum Fixtures {
    static func apk(name: String = "base.apk", split: String? = nil, size: Int64 = 100) -> InspectedAPK {
        InspectedAPK(
            fileName: name, sizeBytes: size, sha256: "00",
            manifest: ApkManifest(packageName: "com.example.game", versionCode: 7, splitName: split),
            signature: SignatureCheck(status: .verified, schemes: [2], certificates: [])
        )
    }

    static func package(splits: [InspectedAPK]? = nil) -> InspectedPackage {
        let url = URL(fileURLWithPath: "/tmp/game.xapk")
        return InspectedPackage(
            sourceFile: url, format: .xapk, sourceSHA256: "ff",
            base: apk(),
            splits: splits ?? [apk(name: "split.apk", split: "config.arm64_v8a", size: 20)],
            obbFiles: [OBBFile(fileName: "main.7.com.example.game.obb", sizeBytes: 500, sha256: "aa", localURL: url)],
            workDirectory: URL(fileURLWithPath: "/tmp/job")
        )
    }

    static func plan() -> InstallPlan {
        let package = package()
        // swiftlint:disable:next force_try
        let serial = try! DeviceSerial("emulator-5554")
        let device = DeviceInfo(
            serial: serial, stableID: "EMU", model: "Pixel 9", manufacturer: "Google", brand: .pixel,
            androidVersion: "15", properties: DeviceProperties(abis: ["arm64-v8a"], densityDPI: 420, locales: ["en"], sdkLevel: 35),
            batteryPercent: 80
        )
        let report = SafetyReport(
            packageName: package.packageName, sha256: "ff", level: .low, reasons: [],
            signer: package.base.signature, signerMatch: .notInstalled, permissions: [], trackers: [],
            reputation: .notConfigured, rulesVersion: "1"
        )
        return InstallPlan(
            package: package, device: device, selectedSplits: package.splits, existing: nil,
            report: report, problems: [.signerMismatch]
        )
    }
}

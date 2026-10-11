// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import AirlockPairing
import AirlockReputation
@testable import AirlockUI
import Foundation

func pkg(_ raw: String) -> PackageName { PackageName(rawValue: raw) ?? { preconditionFailure(raw) }() }
func serial(_ raw: String) -> DeviceSerial { DeviceSerial(rawValue: raw) ?? { preconditionFailure(raw) }() }

/// Thread-safe mutable box for fakes.
final class Locked<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value
    init(_ value: Value) { self.value = value }
    func get() -> Value { lock.withLock { value } }
    func set(_ newValue: Value) { lock.withLock { value = newValue } }
    func mutate(_ change: (inout Value) -> Void) { lock.withLock { change(&value) } }
}

enum Sample {
    static let properties = DeviceProperties(abis: ["arm64-v8a"], densityDPI: 560, locales: ["en-GB"], sdkLevel: 36)

    static func info(_ raw: String = "R58") -> DeviceInfo {
        DeviceInfo(serial: serial(raw), stableID: raw, model: "SM-S928B", manufacturer: "samsung", brand: .samsung,
                   androidVersion: "16", properties: properties, batteryPercent: 80)
    }

    static func package(_ name: String = "com.studio.game") -> InspectedPackage {
        let signature = SignatureCheck(status: .verified, schemes: [2], certificates: [])
        let base = InspectedAPK(fileName: "base.apk", sizeBytes: 10, sha256: "aa",
                                manifest: ApkManifest(packageName: name, versionCode: 7), signature: signature)
        let url = URL(fileURLWithPath: "/tmp/\(name).apk")
        return InspectedPackage(sourceFile: url, format: .apk, sourceSHA256: "aa", base: base, splits: [], obbFiles: [], workDirectory: url)
    }

    static func plan(_ package: InspectedPackage, level: RiskLevel = .low, problems: [PreCheckProblem] = []) -> InstallPlan {
        let report = SafetyReport(packageName: package.packageName, sha256: "aa", level: level, reasons: [], signer: package.base.signature,
                                  signerMatch: .notInstalled, permissions: [], trackers: [], reputation: .notConfigured, rulesVersion: "t")
        return InstallPlan(package: package, device: info(), selectedSplits: [], existing: nil, report: report, problems: problems)
    }

    static func app(_ name: String, system: Bool = false, state: InstalledApp.State = .enabled) -> InstalledApp {
        InstalledApp(packageName: pkg(name), versionCode: 1, isSystem: system, state: state, apkPaths: [])
    }
}

final class FakeDeviceService: DeviceService, @unchecked Sendable {
    let snapshots: [[ConnectedDevice]]
    let failingSerials: Set<String>
    init(snapshots: [[ConnectedDevice]], failing: Set<String> = []) {
        self.snapshots = snapshots
        failingSerials = failing
    }

    func deviceUpdates() -> AsyncStream<[ConnectedDevice]> {
        AsyncStream { continuation in
            for snapshot in snapshots { continuation.yield(snapshot) }
            continuation.finish()
        }
    }

    func info(for serial: DeviceSerial) async throws -> DeviceInfo {
        if failingSerials.contains(serial.rawValue) { throw InstallError.deviceDisconnected }
        return Sample.info(serial.rawValue)
    }
}

/// Plans by package name: names listed in `levels` get that risk, names in `problems` get a problem.
final class FakePipeline: InstallPipeline, @unchecked Sendable {
    let levels: [String: RiskLevel]
    let failures: [String: InstallError]
    let installDelay: Duration
    let installed = Locked<[String]>([])
    let discarded = Locked<[String]>([])

    init(levels: [String: RiskLevel] = [:], failures: [String: InstallError] = [:], installDelay: Duration = .zero) {
        self.levels = levels
        self.failures = failures
        self.installDelay = installDelay
    }

    func inspect(_ file: URL) async throws(InstallError) -> InspectedPackage {
        let name = file.deletingPathExtension().lastPathComponent
        if name == "notanapp" { throw .unsupportedFile("This file is not an Android app or app bundle.") }
        return Sample.package(name)
    }

    func plan(_ package: InspectedPackage, for serial: DeviceSerial) async throws(InstallError) -> InstallPlan {
        Sample.plan(package, level: levels[package.packageName] ?? .low)
    }

    func install(
        _ plan: InstallPlan,
        progress: @escaping @Sendable (InstallProgress) -> Void
    ) async throws(InstallError) -> InstallOutcome {
        progress(InstallProgress(step: .installing, stepFraction: 0.5, totalFraction: 0.5, message: "Installing"))
        if installDelay > .zero {
            do {
                try await Task.sleep(for: installDelay)
            } catch {
                throw .cancelled
            }
        }
        if let failure = failures[plan.package.packageName] { throw failure }
        installed.mutate { $0.append(plan.package.packageName) }
        return InstallOutcome(packageName: pkg(plan.package.packageName), versionCode: 7, journalEntryID: nil)
    }

    func discard(_ package: InspectedPackage) async {
        discarded.mutate { $0.append(package.packageName) }
    }
}

final class FakeAppManager: AppManager, @unchecked Sendable {
    let apps: Locked<[InstalledApp]>
    let performed = Locked<[ConfirmedOperation]>([])
    let restored = Locked<[(UUID, ConfirmedOperation?)]>([])
    let journal = Locked<[JournalEntry]>([])
    var blocked: Set<String> = []

    init(apps: [InstalledApp] = []) {
        self.apps = Locked(apps)
    }

    func listApps(on serial: DeviceSerial) async throws -> [InstalledApp] { apps.get() }

    func perform(_ operation: ConfirmedOperation, on serial: DeviceSerial) async throws -> JournalEntry {
        if blocked.contains(operation.package.rawValue) {
            throw AppManagerError.blockedByDenylist(operation.package, .criticalSystemComponent)
        }
        performed.mutate { $0.append(operation) }
        let entry = JournalEntry(deviceID: "R58", packageName: operation.package, kind: .operation(operation.operation),
                                 restore: .enable, status: .applied)
        journal.mutate { $0.insert(entry, at: 0) }
        apps.mutate { list in
            list = list.map { $0.packageName == operation.package ? Sample.app($0.packageName.rawValue, state: .disabled) : $0 }
        }
        return entry
    }

    func restore(_ entry: JournalEntry, on serial: DeviceSerial, confirmation: ConfirmedOperation?) async throws -> JournalEntry {
        if entry.restore == .uninstallInstalled, confirmation == nil { throw AppManagerError.confirmationRequired(entry.packageName) }
        restored.mutate { $0.append((entry.id, confirmation)) }
        var copy = entry
        copy.status = .restored
        return copy
    }

    func history(on serial: DeviceSerial) async throws -> [JournalEntry] { journal.get() }

    func exportAPKs(of package: PackageName, on serial: DeviceSerial, to folder: URL) async throws -> [URL] {
        [folder.appendingPathComponent("base.apk")]
    }

    func backupAccessibleData(of package: PackageName, on serial: DeviceSerial, to folder: URL) async throws -> [URL] { [] }

    func presets(for brand: DeviceBrand) -> [DebloatPreset] {
        [DebloatPreset(id: "samsung", name: "Samsung", brand: .samsung, entries: [
            DebloatEntry(packageName: pkg("com.samsung.bloat.safe"), risk: .safe, description: "s"),
            DebloatEntry(packageName: pkg("com.samsung.bloat.caution"), risk: .caution, description: "c"),
            DebloatEntry(packageName: pkg("com.samsung.bloat.expert"), risk: .expert, description: "e"),
            DebloatEntry(packageName: pkg("com.samsung.not.installed"), risk: .safe, description: "n"),
        ])]
    }
}

final class FakePairing: WirelessPairing, @unchecked Sendable {
    let result: Result<PairedDevice, PairingError>
    let delay: Duration
    let stored = Locked<[PairedDevice]>([])

    init(result: Result<PairedDevice, PairingError>, delay: Duration = .zero) {
        self.result = result
        self.delay = delay
    }

    private func outcome() async throws(PairingError) -> PairedDevice {
        if delay > .zero {
            do {
                try await Task.sleep(for: delay)
            } catch {
                throw .cancelled
            }
        }
        let device = try result.get()
        stored.mutate { $0 = $0.filter { $0.name != device.name } + [device] }
        return device
    }

    func pairWithQR(_ session: PairingSession) async throws(PairingError) -> PairedDevice { try await outcome() }
    func pairWithCode(host: String, pairingPort: Int, code: String, connectPort: Int) async throws(PairingError) -> PairedDevice {
        try await outcome()
    }
    func enableLegacyWireless(usb serial: DeviceSerial, port: Int) async throws(PairingError) -> PairedDevice { try await outcome() }
    func reconnectRemembered() async -> [PairedDevice] { stored.get() }
    func rememberedDevices() -> [PairedDevice] { stored.get() }
    func forget(_ device: PairedDevice) { stored.mutate { $0.removeAll { $0 == device } } }
    func diagnose(phoneAddress: String?) async -> NetworkDiagnosis { .noServiceSeen }
}

final class FakeKeys: APIKeyStoring, @unchecked Sendable {
    let key = Locked<String?>(nil)
    var failSave = false
    func apiKey() -> String? { key.get() }
    func save(_ value: String) throws(KeychainError) {
        if value.trimmingCharacters(in: .whitespaces).isEmpty { throw .emptyKey }
        if failSave { throw .unavailable }
        key.set(value)
    }
    func delete() throws(KeychainError) { key.set(nil) }
}

/// Polls a main-actor condition until it holds (UI models update asynchronously).
@MainActor
func eventually(timeout: Duration = .seconds(5), _ condition: @MainActor () -> Bool) async -> Bool {
    let deadline = ContinuousClock.now + timeout
    while !condition() {
        if ContinuousClock.now > deadline { return false }
        try? await Task.sleep(for: .milliseconds(5))
    }
    return true
}

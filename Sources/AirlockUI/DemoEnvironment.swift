// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import AirlockPairing
import AirlockReputation
import Foundation

/// In-memory services for UI tests and screenshots. Never touches adb or the network.
///
/// Launch the app with `--demo` (one ready phone) or `--demo-no-device`. `AIRLOCK_DEMO_QUEUE` lists file
/// names to enqueue at launch; names containing "risky" get a High risk report.
extension AppEnvironment {
    public static func demo(withDevice: Bool = true, queuedFiles: [String] = []) -> AppEnvironment {
        let manager = DemoAppManager()
        let queue = InstallQueueModel(pipeline: DemoPipeline(), appManager: manager)
        let environment = AppEnvironment(
            devices: DevicesModel(service: DemoDeviceService(withDevice: withDevice)),
            installQueue: queue,
            apps: AppsModel(manager: manager),
            pairing: PairingModel(pairing: DemoPairing()),
            settings: SettingsModel(keys: DemoKeys()),
            adbLocation: nil,
            startupProblem: nil
        )
        if !queuedFiles.isEmpty {
            // Enqueue once the window has seen the phone as ready, like a user dropping files would; adding
            // earlier races the window, which clears the install target until the phone is ready.
            let files = queuedFiles.map { URL(fileURLWithPath: "/demo/\($0)") }
            Task { @MainActor in
                while environment.devices.stage != .ready || queue.targetDevice == nil {
                    try? await Task.sleep(for: .milliseconds(50))
                }
                queue.add(files)
            }
        }
        return environment
    }

    /// Chooses live or demo services from the process arguments.
    public static func fromLaunchArguments(_ arguments: [String] = ProcessInfo.processInfo.arguments) -> AppEnvironment {
        let queued = ProcessInfo.processInfo.environment["AIRLOCK_DEMO_QUEUE"]?.split(separator: ",").map(String.init) ?? []
        if arguments.contains("--demo-no-device") { return .demo(withDevice: false) }
        if arguments.contains("--demo") { return .demo(queuedFiles: queued) }
        return .live()
    }
}

struct DemoDeviceService: DeviceService {
    static let serial = DeviceSerial(rawValue: "DEMO0001") ?? { preconditionFailure("demo serial") }()
    let withDevice: Bool

    func deviceUpdates() -> AsyncStream<[ConnectedDevice]> {
        AsyncStream { continuation in
            continuation.yield(withDevice ? [ConnectedDevice(serial: Self.serial, state: .ready, model: "Pixel_9")] : [])
            // Stays open like the real service.
        }
    }

    func info(for serial: DeviceSerial) async throws -> DeviceInfo {
        DeviceInfo(
            serial: serial, stableID: "DEMO0001", model: "Pixel 9 (demo)", manufacturer: "Google", brand: .pixel,
            androidVersion: "16", properties: DeviceProperties(abis: ["arm64-v8a"], densityDPI: 420, locales: ["en-US"], sdkLevel: 36),
            batteryPercent: 82
        )
    }
}

struct DemoPipeline: InstallPipeline {
    func inspect(_ file: URL) async throws(InstallError) -> InspectedPackage {
        let name = "com.demo." + file.deletingPathExtension().lastPathComponent.filter { $0.isLetter || $0.isNumber }.lowercased()
        let signature = SignatureCheck(
            status: .verified, schemes: [2, 3],
            certificates: [
                SignerCertificate(subject: "CN=Demo Studio", issuer: "CN=Demo Studio", sha256: String(repeating: "ab", count: 32)),
            ]
        )
        let manifest = ApkManifest(packageName: name, versionCode: 3, versionName: "1.0", minSdk: 24, targetSdk: 35,
                                   permissions: ["android.permission.INTERNET", "android.permission.CAMERA"])
        let base = InspectedAPK(fileName: "base.apk", sizeBytes: 12_000_000, sha256: String(repeating: "cd", count: 32),
                                manifest: manifest, signature: signature)
        return InspectedPackage(sourceFile: file, format: .apk, sourceSHA256: base.sha256, base: base, splits: [], obbFiles: [],
                                workDirectory: URL(fileURLWithPath: "/demo"))
    }

    func plan(_ package: InspectedPackage, for serial: DeviceSerial) async throws(InstallError) -> InstallPlan {
        let risky = package.sourceFile.lastPathComponent.contains("risky")
        let reasons = risky
            ? [RiskReason(ruleID: "perm.sms-and-overlay", category: .permissions, level: .high,
                          message: "It can read your text messages and draw over other apps, a combination common in banking malware.")]
            : []
        let report = SafetyReport(
            packageName: package.packageName, sha256: package.base.sha256, level: risky ? .high : .low, reasons: reasons,
            signer: package.base.signature, signerMatch: .notInstalled,
            permissions: [
                PermissionFinding(
                    permission: "android.permission.CAMERA", plainLanguage: "Take photos and record video", isDangerous: true
                ),
            ],
            trackers: [], reputation: .notConfigured, rulesVersion: "demo"
        )
        let device = try await info(serial)
        return InstallPlan(package: package, device: device, selectedSplits: [], existing: nil, report: report, problems: [])
    }

    func install(
        _ plan: InstallPlan,
        progress: @escaping @Sendable (InstallProgress) -> Void
    ) async throws(InstallError) -> InstallOutcome {
        for step in 1...4 {
            let fraction = Double(step) / 4
            progress(InstallProgress(step: .installing, stepFraction: fraction, totalFraction: fraction, message: "Installing"))
            do {
                try await Task.sleep(for: .milliseconds(150))
            } catch {
                throw .cancelled
            }
        }
        guard let name = PackageName(rawValue: plan.package.packageName) else { throw .unsupportedFile("demo") }
        return InstallOutcome(packageName: name, versionCode: 3, journalEntryID: nil)
    }

    func discard(_ package: InspectedPackage) async {}

    private func info(_ serial: DeviceSerial) async throws(InstallError) -> DeviceInfo {
        do {
            return try await DemoDeviceService(withDevice: true).info(for: serial)
        } catch {
            throw .deviceDisconnected
        }
    }
}

final class DemoAppManager: AppManager, @unchecked Sendable {
    private let lock = NSLock()
    private var apps: [InstalledApp]
    private var journal: [JournalEntry] = []

    init() {
        func app(_ name: String, system: Bool, installer: String?) -> InstalledApp {
            InstalledApp(packageName: PackageName(rawValue: name) ?? { preconditionFailure(name) }(), versionName: "1.0", versionCode: 1,
                         isSystem: system, state: .enabled, apkPaths: [], installerPackage: installer)
        }
        apps = [
            app("com.demo.notes", system: false, installer: "com.android.vending"),
            app("com.example.bloat", system: true, installer: nil),
            app("com.google.android.apps.tips", system: true, installer: nil),
            app("com.android.settings", system: true, installer: nil),
        ]
    }

    func listApps(on serial: DeviceSerial) async throws -> [InstalledApp] { lock.withLock { apps } }

    func perform(_ operation: ConfirmedOperation, on serial: DeviceSerial) async throws -> JournalEntry {
        let verdict = CriticalDenylist.standard.check(operation.package, operation: operation.operation, context: .init())
        if case .blocked(let reason) = verdict {
            throw AppManagerError.blockedByDenylist(operation.package, reason)
        }
        let restore: RestoreAction = operation.operation == .disableForUser ? .enable : .installExisting
        let entry = JournalEntry(deviceID: "DEMO0001", packageName: operation.package, kind: .operation(operation.operation),
                                 restore: restore, status: .applied)
        lock.withLock {
            journal.insert(entry, at: 0)
            apps = apps.map { app in
                guard app.packageName == operation.package else { return app }
                let state: InstalledApp.State = operation.operation == .disableForUser ? .disabled : .uninstalledForUser
                return InstalledApp(packageName: app.packageName, versionName: app.versionName, versionCode: app.versionCode,
                                    isSystem: app.isSystem, state: state, apkPaths: [], installerPackage: app.installerPackage)
            }
        }
        return entry
    }

    func restore(_ entry: JournalEntry, on serial: DeviceSerial, confirmation: ConfirmedOperation?) async throws -> JournalEntry {
        var restored = entry
        restored.status = .restored
        lock.withLock {
            journal = journal.map { $0.id == entry.id ? restored : $0 }
            apps = apps.map { app in
                guard app.packageName == entry.packageName else { return app }
                return InstalledApp(packageName: app.packageName, versionName: app.versionName, versionCode: app.versionCode,
                                    isSystem: app.isSystem, state: .enabled, apkPaths: [], installerPackage: app.installerPackage)
            }
        }
        return restored
    }

    func history(on serial: DeviceSerial) async throws -> [JournalEntry] { lock.withLock { journal } }
    func exportAPKs(of package: PackageName, on serial: DeviceSerial, to folder: URL) async throws -> [URL] { [] }
    func backupAccessibleData(of package: PackageName, on serial: DeviceSerial, to folder: URL) async throws -> [URL] { [] }

    func presets(for brand: DeviceBrand) -> [DebloatPreset] {
        let entry = DebloatEntry(packageName: PackageName(rawValue: "com.example.bloat") ?? { preconditionFailure("demo") }(),
                                 risk: .safe, description: "A demo app that is safe to remove.")
        return [DebloatPreset(id: "demo", name: "Demo preset", brand: .other, entries: [entry])]
    }
}

struct DemoPairing: WirelessPairing {
    func pairWithQR(_ session: PairingSession) async throws(PairingError) -> PairedDevice {
        do {
            try await Task.sleep(for: .seconds(600))
        } catch {
            throw .cancelled
        }
        throw .notFound(.noServiceSeen)
    }

    func pairWithCode(host: String, pairingPort: Int, code: String, connectPort: Int) async throws(PairingError) -> PairedDevice {
        PairedDevice(name: "adb-DEMO", host: host, port: connectPort)
    }

    func enableLegacyWireless(usb serial: DeviceSerial, port: Int) async throws(PairingError) -> PairedDevice {
        PairedDevice(name: serial.rawValue, host: "192.168.1.20", port: port)
    }

    func reconnectRemembered() async -> [PairedDevice] { [] }
    func rememberedDevices() -> [PairedDevice] { [] }
    func forget(_ device: PairedDevice) {}
    func diagnose(phoneAddress: String?) async -> NetworkDiagnosis { .noServiceSeen }
}

final class DemoKeys: APIKeyStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var key: String?
    func apiKey() -> String? { lock.withLock { key } }
    func save(_ value: String) throws(KeychainError) {
        guard !value.trimmingCharacters(in: .whitespaces).isEmpty else { throw .emptyKey }
        lock.withLock { key = value }
    }
    func delete() throws(KeychainError) { lock.withLock { key = nil } }
}

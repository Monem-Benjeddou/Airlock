// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockADB
import AirlockCore
import AirlockInspection
import AirlockJournal
import AirlockPairing
import AirlockReputation
import AirlockSafety
import AirlockServices
import Foundation

/// The composition root: builds the real services once and hands view models to the views.
@MainActor
public final class AppEnvironment {
    public let devices: DevicesModel
    public let installQueue: InstallQueueModel
    public let apps: AppsModel
    public let pairing: PairingModel
    public let settings: SettingsModel
    public let adbLocation: ADBLocator.Location?
    /// Set when a component could not start; the UI shows it instead of the main window content.
    public let startupProblem: String?

    public init(
        devices: DevicesModel,
        installQueue: InstallQueueModel,
        apps: AppsModel,
        pairing: PairingModel,
        settings: SettingsModel,
        adbLocation: ADBLocator.Location?,
        startupProblem: String?
    ) {
        self.devices = devices
        self.installQueue = installQueue
        self.apps = apps
        self.pairing = pairing
        self.settings = settings
        self.adbLocation = adbLocation
        self.startupProblem = startupProblem
    }

    /// Wires the production services. Without an adb binary the app still opens and explains what to do.
    public static func live(inspector: (any PackageInspector)? = nil) -> AppEnvironment {
        let location = ADBLocator().locate()
        let adb = ADBClient(configuration: ADBConfiguration(executable: location?.url ?? URL(fileURLWithPath: "/usr/bin/false")))
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Airlock", isDirectory: true)

        var problem: String?
        let journal: any JournalStore
        do {
            journal = try SQLiteJournalStore(url: support.appendingPathComponent("journal.sqlite"))
        } catch {
            problem = "Airlock could not open its change history in \(support.path)."
            journal = (try? SQLiteJournalStore.inMemory()) ?? EmptyJournal()
        }
        if location == nil {
            problem = "Airlock needs Android's adb tool. Install it with `brew install android-platform-tools`, then reopen Airlock."
        }

        let keys = KeychainKeyStore()
        let reputation = VirusTotalClient(keys: keys)
        let safety: any SafetyEngine = (try? SafetyCatalog.bundled()).map { DefaultSafetyEngine(catalog: $0, reputation: reputation) }
            ?? UnavailableSafetyEngine()
        let deviceService = DefaultDeviceService(adb: adb)
        let presets = (try? PresetLibrary.bundled()) ?? PresetLibrary(presets: [])
        let manager = DefaultAppManager(
            adb: adb, journal: journal, presets: presets, backupRoot: support.appendingPathComponent("Backups", isDirectory: true)
        )
        let pipeline = DefaultInstallPipeline(
            adb: adb, inspector: inspector ?? LocalPackageInspector(), safety: safety, devices: deviceService, journal: journal
        )

        return AppEnvironment(
            devices: DevicesModel(service: deviceService),
            installQueue: InstallQueueModel(pipeline: pipeline, appManager: manager),
            apps: AppsModel(manager: manager),
            pairing: PairingModel(pairing: PairingService(adb: adb)),
            settings: SettingsModel(keys: keys),
            adbLocation: location,
            startupProblem: problem
        )
    }
}

/// Used only if the bundled rules cannot be read; every package is then treated as High risk.
struct UnavailableSafetyEngine: SafetyEngine {
    func report(for package: InspectedPackage, installedSigners: [String]?) async -> SafetyReport {
        let reason = RiskReason(
            ruleID: "engine.unavailable", category: .manifest, level: .high,
            message: "Airlock's safety rules could not be loaded, so this app could not be checked."
        )
        return SafetyReport(
            packageName: package.packageName, sha256: package.base.sha256, level: .high, reasons: [reason],
            signer: package.base.signature, signerMatch: .notInstalled, permissions: [], trackers: [],
            reputation: .notConfigured, rulesVersion: "unavailable"
        )
    }
}

/// Last-resort journal when even an in-memory database cannot be created. Changes are refused.
struct EmptyJournal: JournalStore {
    struct Unavailable: Error {}
    func append(_ entry: JournalEntry) async throws { throw Unavailable() }
    func update(id: UUID, status: JournalEntry.Status, note: String?) async throws { throw Unavailable() }
    func entries(deviceID: String) async throws -> [JournalEntry] { [] }
    func pendingEntries() async throws -> [JournalEntry] { [] }
}

// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockADB
import AirlockCore
import AirlockJournal
@testable import AirlockServices
import AirlockTestSupport
import CryptoKit
import Foundation
import Testing

/// Returns a canned package whose files really exist on disk, so pushes and hashes are realistic.
struct StubInspector: PackageInspector {
    var package: InspectedPackage?
    var error: InstallError?
    var installedSigners: [String] = [String(repeating: "ab", count: 32)]

    func inspect(_ file: URL) async throws(InstallError) -> InspectedPackage {
        if let error { throw error }
        guard let package else { throw .unsupportedFile("none") }
        return package
    }

    func signerDigests(ofAPKAt url: URL) async throws(InstallError) -> [String] { installedSigners }
}

struct StubSafety: SafetyEngine {
    var level: RiskLevel = .low
    func report(for package: InspectedPackage, installedSigners: [String]?) async -> SafetyReport {
        let expected = String(repeating: "ab", count: 32)
        let match: SignerMatch = installedSigners.map { $0.contains(expected) ? .matchesInstalled : .differsFromInstalled } ?? .notInstalled
        return SafetyReport(
            packageName: package.packageName, sha256: package.base.sha256, level: level, reasons: [],
            signer: package.base.signature, signerMatch: match, permissions: [], trackers: [],
            reputation: .notConfigured, rulesVersion: "test"
        )
    }
}

/// Builds a realistic XAPK job folder: base + three config splits + one OBB file.
struct GameJob {
    let folder: URL
    let package: InspectedPackage
    let obbSHA: String

    init(versionCode: Int64 = 70, minSdk: Int = 24, obb: Bool = true, baseABIs: [String] = [], splitNames: [String]? = nil) throws {
        let jobFolder = FileManager.default.temporaryDirectory.appendingPathComponent("Airlock/jobs/\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: jobFolder, withIntermediateDirectories: true)
        let cert = SignerCertificate(subject: "CN=Studio", issuer: "CN=Studio", sha256: String(repeating: "ab", count: 32))
        let signature = SignatureCheck(status: .verified, schemes: [2, 3], certificates: [cert])

        let makeAPK = { (name: String, split: String?, size: Int) throws -> InspectedAPK in
            try Data(repeating: 7, count: size).write(to: jobFolder.appendingPathComponent(name))
            let manifest = ApkManifest(
                packageName: "com.studio.game", versionCode: versionCode, minSdk: minSdk, targetSdk: 34, splitName: split
            )
            return InspectedAPK(fileName: name, sizeBytes: Int64(size), sha256: String(repeating: "11", count: 32),
                                manifest: manifest, signature: signature, nativeABIs: split == nil ? baseABIs : [])
        }

        let base = try makeAPK("base.apk", nil, 1000)
        let names = splitNames ?? ["config.arm64_v8a", "config.x86_64", "config.xxhdpi", "config.en"]
        let splits = try names.enumerated().map { try makeAPK("split\($0.offset).apk", $0.element, 100) }

        let obbData = Data(repeating: 9, count: 5000)
        let obbURL = jobFolder.appendingPathComponent("main.70.com.studio.game.obb")
        try obbData.write(to: obbURL)
        let digest = SHA256.hash(data: obbData).map { String(format: "%02x", $0) }.joined()
        let obbFiles = obb ? [OBBFile(fileName: "main.70.com.studio.game.obb", sizeBytes: 5000, sha256: digest, localURL: obbURL)] : []

        folder = jobFolder
        obbSHA = digest
        package = InspectedPackage(
            sourceFile: jobFolder.appendingPathComponent("game.xapk"), format: .xapk, sourceSHA256: String(repeating: "33", count: 32),
            base: base, splits: splits, obbFiles: obbFiles, workDirectory: jobFolder
        )
    }
}

/// Scripts a device with the S24's properties and a working package manager.
struct PipelineHarness {
    let fake = FakeADB()
    let journal: SQLiteJournalStore
    let serial: DeviceSerial
    let job: GameJob
    let pipeline: DefaultInstallPipeline
    static let obbDir = "/sdcard/Android/obb/com.studio.game"
    static let obbFile = obbDir + "/main.70.com.studio.game.obb"

    init(job: GameJob? = nil, inspector: StubInspector? = nil, installed: String? = nil, freeKilobytes: Int = 75_032_496) throws {
        let job = try job ?? GameJob()
        self.job = job
        journal = try SQLiteJournalStore.inMemory()
        serial = try DeviceSerial(s24Serial)
        registerS24(fake)
        let adb = makeADB(fake)
        let df = "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/block/dm-65 232583388 1 \(freeKilobytes) 1% /data\n"
        fake.replace(shell("df", "/data"), .ok(df))
        fake.on(shell("getprop", "ro.serialno"), .ok("FIXTURESERIAL01\n"))
        if let installed {
            fake.on(shell("dumpsys", "package", "com.studio.game"), .ok(installed))
            fake.on(shell("pm", "path", "com.studio.game"), .ok("package:/data/app/~~x==/com.studio.game-y==/base.apk\n"))
            fake.onPrefix(["-s", s24Serial, "pull"], .ok("1 file pulled\n"))
        } else {
            fake.on(shell("dumpsys", "package", "com.studio.game"), .ok("Unable to find package: com.studio.game\n"))
        }
        // Package manager session
        fake.onPrefix(shell("mkdir", "-p"), .ok())
        fake.onPrefix(["-s", s24Serial, "push"], .ok("1 file pushed\n"))
        fake.onPrefix(shell("pm", "install-create"), .ok("Success: created install session [42]\n"))
        fake.onPrefix(shell("pm", "install-write"), .ok("Success: streamed\n"))
        fake.on(shell("pm", "install-commit", "42"), .ok("Success\n"))
        fake.on(shell("pm", "install-abandon", "42"), .ok("Success\n"))
        fake.onPrefix(shell("rm", "-rf"), .ok())
        fake.onPrefix(shell("rm", "-f"), .ok())
        // OBB verification
        fake.on(shell("stat", "-c", "%s", Self.obbFile), .ok("5000\n"))
        fake.on(shell("sha256sum", Self.obbFile), .ok("\(job.obbSHA)  \(Self.obbFile)\n"))

        pipeline = DefaultInstallPipeline(
            adb: adb,
            inspector: inspector ?? StubInspector(package: job.package),
            safety: StubSafety(),
            devices: DefaultDeviceService(adb: adb),
            journal: journal
        )
    }

    /// After a successful commit, `dumpsys` reports the new version.
    func reportInstalledAfterCommit(versionCode: Int64 = 70) {
        fake.replace(shell("dumpsys", "package", "com.studio.game"), .ok(Self.dumpsys(versionCode: versionCode)))
    }

    static func dumpsys(versionCode: Int64) -> String {
        """
        Packages:
          Package [com.studio.game] (1):
            versionCode=\(versionCode) minSdk=24 targetSdk=34
            versionName=1.0
            flags=[ HAS_CODE ]
            User 0: ceDataInode=1 installed=true hidden=false enabled=0

        """
    }

    func commands(_ word: String) -> [[String]] { fake.calls.filter { $0.contains(word) } }
}

final class ProgressLog: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [InstallProgress] = []
    func append(_ progress: InstallProgress) { lock.withLock { items.append(progress) } }
    var all: [InstallProgress] { lock.withLock { items } }
}

@Suite("InstallPipeline planning")
struct InstallPlanningTests {
    @Test func plansSplitsForTheS24AndFindsNoProblems() async throws {
        let harness = try PipelineHarness()
        let package = try await harness.pipeline.inspect(harness.job.folder)
        let plan = try await harness.pipeline.plan(package, for: harness.serial)
        #expect(plan.problems.isEmpty)
        #expect(plan.existing == nil)
        #expect(plan.device.model == "SM-S928B")
        // S24: arm64-v8a only; at 560 dpi no split is dense enough, so the densest (xxhdpi) is chosen.
        #expect(plan.selectedSplits.map(\.manifest.splitName) == ["config.arm64_v8a", "config.xxhdpi", "config.en"])
        #expect(plan.report.signerMatch == .notInstalled)
    }

    @Test func inspectErrorsPassThrough() async throws {
        let harness = try PipelineHarness(inspector: StubInspector(error: .unsafeArchive("zip slip")))
        await #expect(throws: InstallError.unsafeArchive("zip slip")) { try await harness.pipeline.inspect(harness.job.folder) }
    }

    @Test func tooNewForDeviceIsAProblem() async throws {
        let harness = try PipelineHarness(job: try GameJob(minSdk: 40))
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        #expect(plan.problems == [.deviceSDKTooOld(required: 40, device: 36)])
    }

    @Test func storageNeedsTwoAndAHalfTimesTheSize() async throws {
        // Package is 1000 + 4*100 + 5000 = 6400 bytes; 2.5x = 16000 bytes = 15.6 KiB.
        let harness = try PipelineHarness(freeKilobytes: 15)
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        #expect(plan.problems == [.insufficientStorage(requiredBytes: 16000, freeBytes: Int64(15 * 1024))])

        let enough = try PipelineHarness(freeKilobytes: 16)
        #expect(try await enough.pipeline.plan(enough.job.package, for: enough.serial).problems.isEmpty)
    }

    @Test func downgradeIsAProblem() async throws {
        let harness = try PipelineHarness(installed: PipelineHarness.dumpsys(versionCode: 99))
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        #expect(plan.problems == [.versionDowngrade(installed: 99, incoming: 70)])
        #expect(plan.existing?.versionCode == 99)
    }

    @Test func signerMismatchWithInstalledCopyIsAProblem() async throws {
        var inspector = StubInspector(package: try GameJob().package)
        inspector.installedSigners = [String(repeating: "ff", count: 32)]
        let harness = try PipelineHarness(inspector: inspector, installed: PipelineHarness.dumpsys(versionCode: 60))
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        #expect(plan.report.signerMatch == .differsFromInstalled)
        #expect(plan.problems == [.signerMismatch])
        #expect(harness.commands("pull").count == 1, "the installed base APK is copied to read its signer")
    }

    @Test func updateFromSameSignerHasNoProblems() async throws {
        let harness = try PipelineHarness(installed: PipelineHarness.dumpsys(versionCode: 60))
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        #expect(plan.problems.isEmpty)
        #expect(plan.report.signerMatch == .matchesInstalled)
    }

    @Test func noMatchingABISplitIsAProblem() async throws {
        let harness = try PipelineHarness(job: try GameJob(splitNames: ["config.x86", "config.x86_64"]))
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        #expect(plan.problems == [.noMatchingABI(available: ["x86", "x86_64"])])
    }

    @Test func baseWithForeignNativeCodeIsAProblem() async throws {
        let harness = try PipelineHarness(job: try GameJob(baseABIs: ["x86_64"], splitNames: []))
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        #expect(plan.problems == [.noMatchingABI(available: ["x86_64"])])
    }

    @Test func splitFromAnotherAppIsAProblem() async throws {
        let job = try GameJob(obb: false, splitNames: [])
        let foreign = InspectedAPK(
            fileName: "evil.apk", sizeBytes: 1, sha256: "00",
            manifest: ApkManifest(packageName: "com.other.app", versionCode: 70, splitName: "config.en"),
            signature: job.package.base.signature
        )
        let package = InspectedPackage(
            sourceFile: job.package.sourceFile, format: .apks, sourceSHA256: "x", base: job.package.base,
            splits: [foreign], obbFiles: [], workDirectory: job.folder
        )
        let harness = try PipelineHarness(job: job)
        let plan = try await harness.pipeline.plan(package, for: harness.serial)
        #expect(plan.problems.contains(.splitPackageMismatch("evil.apk")))
    }
}

@Suite("InstallPipeline install")
struct InstallExecutionTests {
    @Test func installsOBBFirstThenCommitsAndVerifies() async throws {
        let harness = try PipelineHarness()
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        harness.reportInstalledAfterCommit()
        let log = ProgressLog()
        let outcome = try await harness.pipeline.install(plan) { log.append($0) }

        #expect(outcome.packageName.rawValue == "com.studio.game")
        #expect(outcome.versionCode == 70)
        let calls = harness.fake.calls
        let obbPush = try #require(calls.firstIndex { $0.contains("push") && $0.last == PipelineHarness.obbFile })
        let commit = try #require(calls.firstIndex { $0.contains("install-commit") })
        #expect(obbPush < commit, "OBB is pushed and verified before the app is committed")
        #expect(harness.commands("install-write").count == 4, "base + 3 selected splits")
        #expect(harness.commands("sha256sum").count == 1)

        let steps = log.all.map(\.step)
        #expect(steps.first == .preparing)
        #expect(steps.contains(.pushingOBB) && steps.contains(.installing) && steps.contains(.verifying))
        #expect(log.all.last?.totalFraction == 1)
        let totals = log.all.map(\.totalFraction)
        #expect(totals == totals.sorted(), "overall progress never goes backwards")

        let history = try await harness.journal.entries(deviceID: "FIXTURESERIAL01")
        #expect(history.first?.status == .applied)
        #expect(history.first?.restore == .uninstallInstalled)
        #expect(history.first?.id == outcome.journalEntryID)
    }

    @Test func updateIsJournaledAsNotRestorable() async throws {
        let harness = try PipelineHarness(installed: PipelineHarness.dumpsys(versionCode: 60))
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        harness.fake.replace(shell("dumpsys", "package", "com.studio.game"), .ok(PipelineHarness.dumpsys(versionCode: 70)))
        _ = try await harness.pipeline.install(plan) { _ in }
        let entry = try #require(try await harness.journal.entries(deviceID: "FIXTURESERIAL01").first)
        #expect(entry.restore == .notRestorable)
        #expect(entry.kind == .install(versionCode: 70, wasUpdate: true))
    }

    @Test func refusesToInstallWithOpenProblems() async throws {
        let harness = try PipelineHarness(job: try GameJob(minSdk: 40))
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        await #expect(throws: InstallError.preCheckFailed([.deviceSDKTooOld(required: 40, device: 36)])) {
            try await harness.pipeline.install(plan) { _ in }
        }
        #expect(harness.commands("push").isEmpty)
    }

    @Test func packageManagerFailureIsExplainedAndOBBIsRemoved() async throws {
        let harness = try PipelineHarness()
        harness.fake.replace(shell("pm", "install-commit", "42"),
                             FakeADB.Response(stdout: "Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]\n", exitCode: 1))
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        await #expect {
            try await harness.pipeline.install(plan) { _ in }
        } throws: { error in
            guard case InstallError.packageManager(let explained) = error else { return false }
            return explained.code == "INSTALL_FAILED_INSUFFICIENT_STORAGE" && explained.fix == .freeUpSpace
        }
        #expect(harness.fake.calls.contains(shell("rm", "-f", PipelineHarness.obbFile)), "pushed OBB is cleaned up")
        #expect(harness.commands("install-abandon").isEmpty, "a committed session needs no abandon")
        #expect(try await harness.journal.entries(deviceID: "FIXTURESERIAL01").first?.status == .failed)
    }

    @Test func obbHashMismatchStopsBeforeTheAppIsInstalled() async throws {
        let harness = try PipelineHarness()
        harness.fake.replace(shell("sha256sum", PipelineHarness.obbFile), .ok(String(repeating: "0", count: 64) + "  x\n"))
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        await #expect(throws: InstallError.obbVerificationFailed(fileName: "main.70.com.studio.game.obb")) {
            try await harness.pipeline.install(plan) { _ in }
        }
        #expect(harness.commands("install-create").isEmpty)
        #expect(harness.fake.calls.contains(shell("rm", "-f", PipelineHarness.obbFile)))
    }

    @Test func obbSizeMismatchFails() async throws {
        let harness = try PipelineHarness()
        harness.fake.replace(shell("stat", "-c", "%s", PipelineHarness.obbFile), .ok("4999\n"))
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        await #expect(throws: InstallError.obbVerificationFailed(fileName: "main.70.com.studio.game.obb")) {
            try await harness.pipeline.install(plan) { _ in }
        }
    }

    @Test func missingSha256sumFallsBackToSizeCheck() async throws {
        let harness = try PipelineHarness()
        harness.fake.replace(shell("sha256sum", PipelineHarness.obbFile), FakeADB.Response(stderr: "sha256sum: not found", exitCode: 127))
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        harness.reportInstalledAfterCommit()
        _ = try await harness.pipeline.install(plan) { _ in }
    }

    @Test func versionCheckAfterInstallMustMatch() async throws {
        let harness = try PipelineHarness()
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        harness.reportInstalledAfterCommit(versionCode: 69)
        await #expect(throws: InstallError.self) { try await harness.pipeline.install(plan) { _ in } }
    }

    @Test func cancellingDuringOBBPushLeavesNothingBehind() async throws {
        let harness = try PipelineHarness()
        harness.fake.replace(["-s", s24Serial, "push", harness.job.package.obbFiles[0].localURL.path, PipelineHarness.obbFile],
                             FakeADB.Response(delay: .seconds(30)))
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        let task = Task { try await harness.pipeline.install(plan) { _ in } }
        try await harness.fake.waitForCall(containing: harness.job.package.obbFiles[0].localURL.path)
        task.cancel()
        let result = await task.result
        #expect(throws: InstallError.cancelled) { try result.get() }
        #expect(harness.commands("install-create").isEmpty)
        #expect(harness.commands("install-commit").isEmpty)
        #expect(harness.fake.calls.contains(shell("rm", "-f", PipelineHarness.obbFile)))
        #expect(try await harness.journal.entries(deviceID: "FIXTURESERIAL01").first?.status == .failed)
    }

    @Test func cancellingDuringAPKWriteAbandonsTheSession() async throws {
        let harness = try PipelineHarness(job: try GameJob(obb: false))
        harness.fake.onPrefix(shell("pm", "install-write"), FakeADB.Response(stdout: "Success\n", delay: .seconds(30)))
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        let task = Task { try await harness.pipeline.install(plan) { _ in } }
        try await harness.fake.waitForCall(containing: "install-write")
        task.cancel()
        let result = await task.result
        #expect(throws: InstallError.cancelled) { try result.get() }
        try await harness.fake.waitForCall(containing: "install-abandon")
        #expect(harness.commands("install-abandon").count == 1)
        #expect(harness.commands("install-commit").isEmpty)
        #expect(harness.commands("rm").contains { $0.last?.hasPrefix("/data/local/tmp/airlock-") == true })
    }

    @Test func deviceUnpluggedMidInstall() async throws {
        let harness = try PipelineHarness(job: try GameJob(obb: false))
        harness.fake.onPrefix(["-s", s24Serial, "push"], .failure("adb: device 'FIXTURESERIAL01' not found"))
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        await #expect(throws: InstallError.deviceDisconnected) { try await harness.pipeline.install(plan) { _ in } }
    }

    @Test func userEditedSplitSelectionIsRespected() async throws {
        let harness = try PipelineHarness(job: try GameJob(obb: false))
        let plan = try await harness.pipeline.plan(harness.job.package, for: harness.serial)
        harness.reportInstalledAfterCommit()
        _ = try await harness.pipeline.install(plan.with(selectedSplits: [])) { _ in }
        #expect(harness.commands("install-write").count == 1, "only the base APK")
    }

    @Test func discardDeletesOnlyJobFolders() async throws {
        let harness = try PipelineHarness()
        await harness.pipeline.discard(harness.job.package)
        #expect(!FileManager.default.fileExists(atPath: harness.job.folder.path))

        let outside = FileManager.default.temporaryDirectory.appendingPathComponent("not-a-job-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: outside) }
        let package = InspectedPackage(
            sourceFile: outside, format: .apk, sourceSHA256: "", base: harness.job.package.base,
            splits: [], obbFiles: [], workDirectory: outside
        )
        await harness.pipeline.discard(package)
        #expect(FileManager.default.fileExists(atPath: outside.path))
    }
}

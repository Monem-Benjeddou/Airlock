// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockArchive
import AirlockCore
import AirlockSafety
@testable import AirlockServices
import AirlockTestSupport
import Foundation
import Testing

/// End-to-end inspection of real, apksigner-signed fixture APKs and containers built from them.
@Suite("LocalPackageInspector")
struct LocalPackageInspectorTests {
    private let scratch: URL
    private let jobs: URL
    private let inspector: LocalPackageInspector

    init() throws {
        scratch = FileManager.default.temporaryDirectory.appendingPathComponent("airlock-inspect-\(UUID().uuidString)")
        jobs = scratch.appendingPathComponent("Airlock/jobs")
        try FileManager.default.createDirectory(at: jobs, withIntermediateDirectories: true)
        inspector = LocalPackageInspector(jobsRoot: jobs)
    }

    private func write(_ data: Data, _ name: String) throws -> URL {
        let url = scratch.appendingPathComponent(name)
        try data.write(to: url)
        return url
    }

    private func bytes(_ apk: FixtureAPKs.APK) throws -> [UInt8] { Array(try FixtureAPKs.data(apk)) }

    private var jobFolders: [String] { (try? FileManager.default.contentsOfDirectory(atPath: jobs.path)) ?? [] }

    @Test func singleSignedAPK() async throws {
        let url = try write(try FixtureAPKs.data(.v123RSA), "game.apk")
        let package = try await inspector.inspect(url)
        #expect(package.format == .apk)
        #expect(package.packageName == "org.airlock.fixture")
        #expect(package.base.manifest.versionCode == 42)
        #expect(package.base.manifest.versionName == "1.2.3")
        #expect(Set(package.base.manifest.permissions).isSuperset(of: ["android.permission.READ_SMS", "android.permission.CAMERA"]))
        #expect(package.base.signature.status == .verified)
        #expect(package.base.signature.schemes.contains(2))
        #expect(package.base.dexClassPrefixes.contains("com/facebook/ads/"))
        #expect(package.sourceSHA256 == package.base.sha256)
        #expect(package.base.sha256.count == 64)
        #expect(package.splits.isEmpty)
        #expect(FileManager.default.fileExists(atPath: package.workDirectory.appendingPathComponent("game.apk").path))
        #expect(package.workDirectory.path.hasPrefix(jobs.path))
    }

    @Test func tamperedAPKNeverPassesAsSigned() async throws {
        // The flipped byte breaks a zip CRC, so the reader rejects the file as damaged before the
        // signature is even checked. Either outcome is acceptable; "verified" is not.
        do {
            let package = try await inspector.inspect(try write(try FixtureAPKs.data(.tampered), "x.apk"))
            #expect(package.base.signature.status == .invalid)
        } catch {
            guard case InstallError.unsupportedFile(let message) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
            #expect(message.contains("damaged"))
        }
    }

    @Test func unsignedAPK() async throws {
        let package = try await inspector.inspect(try write(try FixtureAPKs.data(.unsigned), "x.apk"))
        #expect(package.base.signature.status == .unsigned)
    }

    @Test func apksBundleWithSplit() async throws {
        let container = ZipBuilder(files: [
            ("splits/base-master.apk", try bytes(.v2RSA)),
            ("splits/base-arm64_v8a.apk", try bytes(.splitArm64)),
            ("toc.pb", [0, 1, 2]),
        ])
        let url = try write(container.build(), "game.apks")
        let package = try await inspector.inspect(url)
        #expect(package.format == .apks)
        #expect(package.splits.count == 1)
        #expect(package.splits.first?.manifest.splitName == "config.arm64_v8a")
        #expect(package.splitAPKs.first?.kind == .abi("arm64-v8a"))
        #expect(package.sourceSHA256 != package.base.sha256)
    }

    @Test func manifestNotFileNameDecidesTheBase() async throws {
        // The split is named like a base and vice versa.
        let container = ZipBuilder(files: [
            ("base.apk", try bytes(.splitArm64)),
            ("split_config.arm64_v8a.apk", try bytes(.v2RSA)),
        ])
        let package = try await inspector.inspect(try write(container.build(), "swapped.apks"))
        #expect(package.base.manifest.splitName == nil)
        #expect(package.splits.first?.manifest.splitName == "config.arm64_v8a")
    }

    @Test func xapkWithOBB() async throws {
        let manifest = """
        {"xapk_version": 2, "package_name": "org.airlock.fixture", "version_code": "42", "name": "Fixture",
         "split_apks": [{"file": "org.airlock.fixture.apk", "id": "base"}, {"file": "config.arm64_v8a.apk", "id": "config.arm64_v8a"}],
         "expansions": [{"file": "Android/obb/org.airlock.fixture/main.42.org.airlock.fixture.obb",
                         "install_location": "EXTERNAL_STORAGE",
                         "install_path": "Android/obb/org.airlock.fixture/main.42.org.airlock.fixture.obb"}]}
        """
        let obb = [UInt8](repeating: 7, count: 4096)
        let container = ZipBuilder(files: [
            ("manifest.json", Array(manifest.utf8)),
            ("org.airlock.fixture.apk", try bytes(.v2RSA)),
            ("config.arm64_v8a.apk", try bytes(.splitArm64)),
            ("Android/obb/org.airlock.fixture/main.42.org.airlock.fixture.obb", obb),
        ])
        let package = try await inspector.inspect(try write(container.build(), "game.xapk"))
        #expect(package.format == .xapk)
        #expect(package.obbFiles.count == 1)
        let file = try #require(package.obbFiles.first)
        #expect(file.fileName == "main.42.org.airlock.fixture.obb")
        #expect(file.sizeBytes == 4096)
        #expect(file.sha256 == (try LocalPackageInspector.sha256(of: file.localURL)))
        #expect(package.totalSizeBytes > 4096)
    }

    @Test func zipSlipIsRejectedAndNothingIsLeftBehind() async throws {
        let container = ZipBuilder(files: [("../../evil.apk", try bytes(.v2RSA)), ("base.apk", try bytes(.v2RSA))])
        await #expect {
            try await inspector.inspect(try write(container.build(), "evil.apks"))
        } throws: { error in
            guard case InstallError.unsafeArchive = error else { return false }
            return true
        }
        #expect(jobFolders.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: scratch.deletingLastPathComponent().appendingPathComponent("evil.apk").path))
    }

    @Test func symlinkEntryIsRejected() async throws {
        let container = ZipBuilder(entries: [ZipBuilder.symlink("base.apk", target: "/etc/passwd")])
        await #expect(throws: InstallError.self) { try await inspector.inspect(try write(container.build(), "link.apks")) }
        #expect(jobFolders.isEmpty)
    }

    @Test func nonZipFileIsUnsupported() async throws {
        let url = try write(Data("just text".utf8), "readme.apk")
        await #expect {
            try await inspector.inspect(url)
        } throws: { error in
            guard case InstallError.unsupportedFile(let message) = error else { return false }
            return message.contains("not an Android app")
        }
    }

    @Test func zipWithoutAPKsIsUnsupported() async throws {
        let url = try write(ZipBuilder(files: [("photo.jpg", [1, 2, 3])]).build(), "photos.zip")
        await #expect(throws: InstallError.self) { try await inspector.inspect(url) }
        #expect(jobFolders.isEmpty)
    }

    @Test func twoBaseAPKsAreRejected() async throws {
        let container = ZipBuilder(files: [("a.apk", try bytes(.v2RSA)), ("b.apk", try bytes(.v2EC))])
        await #expect(throws: InstallError.self) { try await inspector.inspect(try write(container.build(), "two.apks")) }
        #expect(jobFolders.isEmpty)
    }

    @Test func folderOfSplitAPKs() async throws {
        let folder = scratch.appendingPathComponent("splits-folder")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try FixtureAPKs.data(.v2RSA).write(to: folder.appendingPathComponent("base.apk"))
        try FixtureAPKs.data(.splitArm64).write(to: folder.appendingPathComponent("split_config.arm64_v8a.apk"))
        let package = try await inspector.inspect(folder)
        #expect(package.format == .splitFolder)
        #expect(package.splits.count == 1)
        #expect(package.sourceSHA256 == package.base.sha256)
    }

    @Test func signerDigestsOfAnInstalledCopy() async throws {
        let url = try write(try FixtureAPKs.data(.v2RSA), "installed.apk")
        let digests = try await inspector.signerDigests(ofAPKAt: url)
        #expect(digests.count == 1)
        #expect(digests[0].count == 64)
    }

    @Test func endToEndReportOnRealFixtureFlagsSMS() async throws {
        let package = try await inspector.inspect(try write(try FixtureAPKs.data(.v123RSA), "fixture.apk"))
        let engine = DefaultSafetyEngine(catalog: try SafetyCatalog.bundled(), reputation: nil)
        let report = await engine.report(for: package, installedSigners: nil)
        #expect(report.reasons.contains { $0.ruleID == "perm.sms" })
        #expect(report.trackers.contains { $0.name == "Facebook Audience Network" })
        #expect(report.level >= .medium)
    }

    @Test(arguments: [
        (ArchiveError.cancelled, "cancelled"),
        (.notAnArchive, "unsupported"),
        (.noAPKs, "unsupported"),
        (.symlinkEntry("x"), "unsafe"),
        (.totalRatioLimitExceeded(bytes: 1, archiveBytes: 1, ratio: 10), "unsafe"),
    ])
    func archiveErrorMapping(_ error: ArchiveError, _ kind: String) {
        switch LocalPackageInspector.map(error) {
        case .cancelled: #expect(kind == "cancelled")
        case .unsupportedFile: #expect(kind == "unsupported")
        case .unsafeArchive: #expect(kind == "unsafe")
        default: Issue.record("unexpected mapping")
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockArchive
import AirlockCore
import AirlockTestSupport
import Foundation
import Testing

@Suite("FormatDetector")
struct FormatDetectorTests {
    let temp: TemporaryDirectory
    let detector = FormatDetector()

    init() throws {
        temp = try TemporaryDirectory()
    }

    private func detect(_ data: Data, as name: String = "dropped.bin") throws -> DetectedPackage {
        try detector.detect(at: temp.write(data, as: name))
    }

    private func detectionError(_ data: Data, as name: String = "dropped.bin") -> ArchiveError? {
        detectionError(at: try? temp.write(data, as: name))
    }

    private func detectionError(at url: URL?) -> ArchiveError? {
        guard let url else { return .unreadable("test setup failed") }
        do {
            _ = try detector.detect(at: url)
            return nil
        } catch {
            return error
        }
    }

    private func xapkManifest(_ body: String) -> (String, [UInt8]) {
        ("manifest.json", Array(body.utf8))
    }

    // MARK: Single APK

    @Test func detectsAPKByContentsNotExtension() throws {
        defer { temp.remove() }
        let package = try detect(ZipBuilder.apk(extraFiles: [("assets/plugin.apk", [UInt8](ZipBuilder.apk()))]), as: "app.zip")
        #expect(package.layout.format == .apk)
        #expect(package.layout.base.location == .sourceFile)
        #expect(package.layout.base.fileName == "app.zip")
        #expect(package.layout.splits.isEmpty)
        #expect(package.layout.entriesToExtract.isEmpty)
        #expect(package.archive != nil)
        #expect(try detector.format(at: temp.file("app.zip")) == .apk)
    }

    @Test func rejectsNonZipFilesAndMissingPaths() {
        defer { temp.remove() }
        #expect(detectionError(Data("<html>not an app</html>".utf8), as: "app.apk") == .notAnArchive)
        #expect(detectionError(Data(), as: "empty.apk") == .notAnArchive)
        guard case .unreadable? = detectionError(at: temp.file("missing.apk")) else {
            Issue.record("expected unreadable")
            return
        }
    }

    @Test func rejectsZipsWithoutAPKs() {
        defer { temp.remove() }
        #expect(detectionError(ZipBuilder().build()) == .noAPKs)
        #expect(detectionError(ZipBuilder(files: [("readme.txt", Array("hi".utf8))]).build()) == .noAPKs)
    }

    // MARK: APKS

    @Test func detectsBundletoolAPKS() throws {
        defer { temp.remove() }
        let builder = ZipBuilder.container(
            apks: [
                "splits/base-master.apk", "splits/base-arm64_v8a.apk", "splits/base-xxhdpi.apk",
                "splits/feature_ar-master.apk", "standalones/standalone-arm64_v8a_xxhdpi.apk",
            ],
            extraFiles: [("toc.pb", [1, 2, 3])]
        )
        let layout = try detect(builder.build(), as: "app.apks").layout
        #expect(layout.format == .apks)
        #expect(layout.base.path == "splits/base-master.apk")
        #expect(layout.splits.map(\.path) == ["splits/base-arm64_v8a.apk", "splits/base-xxhdpi.apk", "splits/feature_ar-master.apk"])
        #expect(layout.alternativeAPKs.map(\.path) == ["standalones/standalone-arm64_v8a_xxhdpi.apk"])
        #expect(layout.entriesToExtract.count == 4)
        #expect(layout.xapkManifest == nil)
    }

    @Test func detectsUniversalAPKS() throws {
        defer { temp.remove() }
        let layout = try detect(ZipBuilder.container(apks: ["universal.apk"], extraFiles: [("toc.pb", [1])]).build()).layout
        #expect(layout.format == .apks)
        #expect(layout.base.fileName == "universal.apk")
        if case .archiveEntry(let entry) = layout.base.location {
            #expect(entry.name == "universal.apk")
        } else {
            Issue.record("expected an archive entry")
        }
    }

    @Test func reportsAmbiguousAndMissingBases() {
        defer { temp.remove() }
        let standalones = ZipBuilder.container(apks: ["standalones/standalone-x86.apk", "standalones/standalone-arm64_v8a.apk"])
        #expect(detectionError(standalones.build())
            == .ambiguousBaseAPK(["standalones/standalone-arm64_v8a.apk", "standalones/standalone-x86.apk"]))
        let twoApps = ZipBuilder.container(apks: ["app1.apk", "app2.apk", "split_config.en.apk"])
        #expect(detectionError(twoApps.build()) == .ambiguousBaseAPK(["app1.apk", "app2.apk"]))
        let onlySplits = ZipBuilder.container(apks: ["split_config.en.apk", "config.arm64_v8a.apk"])
        #expect(detectionError(onlySplits.build()) == .noBaseAPK)
    }

    @Test func rejectsNestedContainers() {
        defer { temp.remove() }
        let inner = [UInt8](ZipBuilder.container(apks: ["base.apk"]).build())
        #expect(detectionError(ZipBuilder(files: [("inner.apks", inner)]).build()) == .nestingTooDeep(limit: 2))
        let mixed = ZipBuilder.container(apks: ["base.apk"], extraFiles: [("more.xapk", inner)])
        #expect(detectionError(mixed.build()) == .nestingTooDeep(limit: 2))
    }

    @Test func rejectsFilesNamedLikeAPKsThatAreNot() {
        defer { temp.remove() }
        let notZip = ZipBuilder(files: [("base.apk", Array("hello".utf8))])
        #expect(detectionError(notZip.build()) == .invalidAPK("base.apk"))
        let zipNoManifest = ZipBuilder(files: [("base.apk", [UInt8](ZipBuilder(files: [("a", [1])]).build()))])
        #expect(detectionError(zipNoManifest.build()) == .invalidAPK("base.apk"))
    }

    @Test func acceptsDeflatedInnerAPKsForLaterVerification() throws {
        defer { temp.remove() }
        var builder = ZipBuilder()
        builder.add("base.apk", [UInt8](ZipBuilder.apk()), method: .deflated)
        #expect(try detect(builder.build()).layout.base.path == "base.apk")
    }

    // MARK: APKM

    @Test func detectsAPKM() throws {
        defer { temp.remove() }
        let builder = ZipBuilder.container(
            apks: ["base.apk", "split_config.arm64_v8a.apk", "split_config.en.apk"],
            extraFiles: [("info.json", Array(#"{"pname":"com.example"}"#.utf8)), ("icon.png", [0x89])]
        )
        let layout = try detect(builder.build(), as: "app.apkm").layout
        #expect(layout.format == .apkm)
        #expect(layout.base.path == "base.apk")
        #expect(layout.splits.map(\.fileName) == ["split_config.arm64_v8a.apk", "split_config.en.apk"])
    }

    @Test func rejectsEncryptedAPKM() {
        defer { temp.remove() }
        var builder = ZipBuilder.container(apks: ["base.apk"], extraFiles: [("info.json", [1])])
        builder.entries[0].flags = 1
        #expect(detectionError(builder.build()) == .encryptedEntry("base.apk"))
    }

    // MARK: XAPK

    private let gameManifest = """
    {"xapk_version": 2, "package_name": "com.example.game", "name": "Game", "version_code": "412",
     "split_apks": [{"file": "com.example.game.apk", "id": "base"}, {"file": "config.arm64_v8a.apk", "id": "config.arm64_v8a"}],
     "expansions": [{"file": "Android/obb/com.example.game/main.412.com.example.game.obb",
                     "install_location": "EXTERNAL_STORAGE",
                     "install_path": "Android/obb/com.example.game/main.412.com.example.game.obb"}]}
    """

    private func gameXAPK(manifest: String? = nil, obbName: String = "Android/obb/com.example.game/main.412.com.example.game.obb") -> Data {
        ZipBuilder.container(
            apks: ["com.example.game.apk", "config.arm64_v8a.apk"],
            extraFiles: [xapkManifest(manifest ?? gameManifest), (obbName, randomBytes(4000)), ("icon.png", [1])]
        ).build()
    }

    @Test func detectsXAPKWithExpansions() throws {
        defer { temp.remove() }
        let package = try detect(gameXAPK(), as: "game.xapk")
        let layout = package.layout
        #expect(layout.format == .xapk)
        #expect(layout.base.path == "com.example.game.apk")
        #expect(layout.splits.map(\.path) == ["config.arm64_v8a.apk"])
        let manifest = try #require(layout.xapkManifest)
        #expect(manifest.packageName.rawValue == "com.example.game")
        #expect(manifest.versionCode == 412)
        #expect(manifest.splitAPKs.map(\.id) == ["base", "config.arm64_v8a"])
        #expect(manifest.expansions.first?.installLocation == "EXTERNAL_STORAGE")
        #expect(layout.obbFiles.map(\.installPath) == ["Android/obb/com.example.game/main.412.com.example.game.obb"])
        #expect(layout.obbFiles.first?.packageDirectory == "com.example.game")
        #expect(layout.obbFiles.first?.item.sizeBytes == 4000)
        #expect(layout.entriesToExtract.map(\.name) == [
            "com.example.game.apk", "config.arm64_v8a.apk", "Android/obb/com.example.game/main.412.com.example.game.obb",
        ])

        let extractor = SafeExtractor(jobsRoot: temp.url.appendingPathComponent("jobs"))
        let result = try extractor.extract(package)
        #expect(result.files.count == 3)
        #expect(FileManager.default.fileExists(atPath: result.files[2].url.path))
    }

    @Test func xapkWithoutSplitListUsesPackageNameAndListsLooseOBBs() throws {
        defer { temp.remove() }
        let manifest = #"{"package_name": "com.foo", "version_code": 7}"#
        let data = ZipBuilder.container(
            apks: ["com.foo.apk", "config.en.apk"],
            extraFiles: [xapkManifest(manifest), ("Android/obb/com.foo/patch.7.com.foo.obb", randomBytes(100))]
        ).build()
        let layout = try detect(data).layout
        #expect(layout.base.path == "com.foo.apk")
        #expect(layout.xapkManifest?.versionCode == 7)
        #expect(layout.obbFiles.map(\.installPath) == ["Android/obb/com.foo/patch.7.com.foo.obb"])
    }

    @Test(arguments: [
        "not json",
        #"{"version_code": 1}"#,
        #"{"package_name": "com.foo"}"#,
        #"{"package_name": "rm -rf /", "version_code": 1}"#,
        #"{"package_name": "com.foo", "version_code": "12a"}"#,
        #"{"package_name": "com.foo", "version_code": [1]}"#,
        #"{"package_name": "com.foo", "version_code": 1, "split_apks": [{"file": 3, "id": "base"}]}"#,
        "[1, 2, 3]",
    ])
    func rejectsInvalidXAPKManifests(_ manifest: String) {
        defer { temp.remove() }
        let data = ZipBuilder.container(apks: ["com.foo.apk"], extraFiles: [xapkManifest(manifest)]).build()
        guard case .invalidMetadata("manifest.json", _)? = detectionError(data) else {
            Issue.record("expected invalidMetadata for \(manifest)")
            return
        }
    }

    @Test func rejectsOversizedXAPKManifest() {
        defer { temp.remove() }
        let padding = String(repeating: " ", count: 1 << 20)
        let data = ZipBuilder.container(
            apks: ["com.foo.apk"], extraFiles: [xapkManifest(#"{"package_name": "com.foo", "version_code": 1}"# + padding)]
        ).build()
        guard case .invalidMetadata("manifest.json", _)? = detectionError(data) else {
            Issue.record("expected invalidMetadata")
            return
        }
    }

    @Test func rejectsManifestsReferencingMissingFiles() {
        defer { temp.remove() }
        let missingSplit = gameManifest.replacingOccurrences(of: "config.arm64_v8a.apk", with: "config.x86.apk")
        #expect(detectionError(gameXAPK(manifest: missingSplit)) == .missingEntry("config.x86.apk"))
        let missingOBB = ZipBuilder.container(apks: ["com.example.game.apk", "config.arm64_v8a.apk"], extraFiles: [xapkManifest(gameManifest)])
        #expect(detectionError(missingOBB.build()) == .missingEntry("Android/obb/com.example.game/main.412.com.example.game.obb"))
    }

    @Test(arguments: [
        "Android/obb/../../evil.obb",
        "/sdcard/Android/obb/com.example.game/x.obb",
        "Android/data/com.example.game/x.obb",
        "Android/obb/com.other/x.obb",
        "Android/obb/com.example.game/deeper/x.obb",
        "Android/obb/com.example.game",
    ])
    func rejectsUnsafeOBBInstallPaths(_ path: String) {
        defer { temp.remove() }
        let manifest = gameManifest.replacingOccurrences(
            of: #""install_path": "Android/obb/com.example.game/main.412.com.example.game.obb""#,
            with: #""install_path": "\#(path)""#
        )
        #expect(detectionError(gameXAPK(manifest: manifest)) == .unsafeOBBPath(path))
    }

    // MARK: Folder of splits

    @Test func detectsFolderOfSplitAPKs() throws {
        defer { temp.remove() }
        let folder = temp.url.appendingPathComponent("splits", isDirectory: true)
        try FileManager.default.createDirectory(at: folder.appendingPathComponent("subdir"), withIntermediateDirectories: true)
        try ZipBuilder.apk().write(to: folder.appendingPathComponent("base.apk"))
        try ZipBuilder.apk().write(to: folder.appendingPathComponent("split_config.arm64_v8a.apk"))
        try Data([0, 1]).write(to: folder.appendingPathComponent("._base.apk"))
        try Data([0, 1]).write(to: folder.appendingPathComponent(".DS_Store"))

        let package = try detector.detect(at: folder)
        #expect(package.archive == nil)
        #expect(package.layout.format == .splitFolder)
        #expect(package.layout.base.fileName == "base.apk")
        #expect(package.layout.base.location == .folderFile(folder.appendingPathComponent("base.apk")))
        #expect(package.layout.splits.map(\.fileName) == ["split_config.arm64_v8a.apk"])
        #expect(package.layout.entriesToExtract.isEmpty)

        let result = try SafeExtractor(jobsRoot: temp.url.appendingPathComponent("jobs")).extract(package)
        #expect(result.files.isEmpty)
    }

    @Test func rejectsBadFolders() throws {
        defer { temp.remove() }
        let empty = temp.url.appendingPathComponent("empty", isDirectory: true)
        try FileManager.default.createDirectory(at: empty, withIntermediateDirectories: true)
        #expect(detectionError(at: empty) == .noAPKs)

        let fake = temp.url.appendingPathComponent("fake", isDirectory: true)
        try FileManager.default.createDirectory(at: fake, withIntermediateDirectories: true)
        try Data("text".utf8).write(to: fake.appendingPathComponent("base.apk"))
        #expect(detectionError(at: fake) == .invalidAPK("base.apk"))

        let linked = temp.url.appendingPathComponent("linked", isDirectory: true)
        try FileManager.default.createDirectory(at: linked, withIntermediateDirectories: true)
        let real = try temp.write(ZipBuilder.apk(), as: "real.apk")
        try FileManager.default.createSymbolicLink(at: linked.appendingPathComponent("base.apk"), withDestinationURL: real)
        #expect(detectionError(at: linked) == .symlinkEntry("base.apk"))

        let crowded = temp.url.appendingPathComponent("crowded", isDirectory: true)
        try FileManager.default.createDirectory(at: crowded, withIntermediateDirectories: true)
        for index in 0..<3 {
            try ZipBuilder.apk().write(to: crowded.appendingPathComponent("split_\(index).apk"))
        }
        var limits = ExtractionLimits()
        limits.maxEntries = 2
        #expect(throws: ArchiveError.tooManyEntries(count: 3, limit: 2)) {
            try FormatDetector(limits: limits).detect(at: crowded)
        }
    }

    @Test func followsASymlinkToTheDroppedFileItself() throws {
        defer { temp.remove() }
        let real = try temp.write(ZipBuilder.apk(), as: "real.apk")
        let alias = temp.file("alias.apk")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: real)
        #expect(try detector.detect(at: alias).layout.format == .apk)
    }
}

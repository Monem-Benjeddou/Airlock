// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

@testable import AirlockArchive
import AirlockTestSupport
import Foundation
import Testing

@Suite("ArchiveError messages")
struct ArchiveErrorTests {
    static let allErrors: [ArchiveError] = [
        .notAnArchive, .unreadable("x"), .truncated("x"), .malformed("x"),
        .tooManyEntries(count: 20_000, limit: 10_000), .unsafeEntryName("../evil", .parentTraversal),
        .symlinkEntry("lib"), .specialFileEntry("fifo"), .duplicateEntry("a"), .encryptedEntry("a"),
        .unsupportedCompression("a", method: 12), .overlappingEntries("a"), .headerMismatch("a"),
        .totalSizeLimitExceeded(bytes: 2, limit: 1), .totalRatioLimitExceeded(bytes: 2, archiveBytes: 1, ratio: 10),
        .entryRatioLimitExceeded("a"), .sizeMismatch("a"), .checksumMismatch("a"), .corruptData("a"),
        .entryTooLarge("a", bytes: 2, limit: 1), .nestingTooDeep(limit: 2), .noAPKs, .invalidAPK("a.apk"),
        .noBaseAPK, .ambiguousBaseAPK(["a.apk", "b.apk"]), .invalidMetadata("manifest.json", reason: "bad"),
        .unsafeOBBPath("../x"), .missingEntry("a"), .pathEscapesJob("a"), .fileSystem("disk full"), .cancelled,
    ]

    @Test(arguments: allErrors)
    func everyErrorHasPlainEnglishAndTechnicalText(_ error: ArchiveError) {
        #expect(error.description.hasSuffix("."))
        #expect(!error.description.contains("zip64"))
        #expect(!error.technicalDetail.isEmpty)
    }

    @Test func keyMessagesMatchTheUICopy() {
        #expect(ArchiveError.notAnArchive.description == "This file is not an Android app or app bundle.")
        #expect(ArchiveError.unsafeEntryName("../x", .parentTraversal).description
            == "This archive contains a file that tries to escape its folder.")
        #expect(ArchiveError.pathEscapesJob("x").description == ArchiveError.unsafeEntryName("x", .absolutePath).description)
        #expect(ArchiveError.tooManyEntries(count: 1, limit: 10_000).description.contains("10000"))
        #expect(ArchiveError.ambiguousBaseAPK(["a.apk", "b.apk"]).technicalDetail.contains("a.apk, b.apk"))
        #expect(ArchiveError.unsafeEntryName("../x", .parentTraversal).technicalDetail.contains("parentTraversal"))
    }

    @Test func rejectsMoreRecordsThanDeclared() {
        var builder = ZipBuilder(files: [("a", [1]), ("b", [2])])
        builder.entryCountOverride = 1
        #expect(openError(builder) == .malformed("more central directory records than declared"))
    }

    @Test func singleNonSplitCandidateIsTheBase() throws {
        #expect(try BaseAPKHeuristic.chooseBase(paths: ["config.en.apk", "app.apk", "split_x.apk"], hint: nil) == 1)
        #expect(try BaseAPKHeuristic.chooseBase(paths: ["a.apk", "b.apk"], hint: "b.apk") == 1)
        #expect(BaseAPKHeuristic.isSplitLike("com.foo.config.xxhdpi.apk"))
        #expect(!BaseAPKHeuristic.isSplitLike("splits/base-master.apk"))
    }

    @Test func entriesKnowWhetherTheyAreAtTheRoot() throws {
        let archive = try ZipArchive(data: ZipBuilder(files: [("AndroidManifest.xml", [1]), ("res/AndroidManifest.xml", [2])]).build())
        #expect(archive.entries.map(\.isAtRoot) == [true, false])
        #expect(archive.entries.map(\.fileName) == ["AndroidManifest.xml", "AndroidManifest.xml"])
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

@testable import AirlockArchive
import AirlockTestSupport
import Foundation
import Testing

/// Lists every path under `url`, relative to it.
func tree(_ url: URL) -> [String] {
    guard let enumerator = FileManager.default.enumerator(atPath: url.path) else { return [] }
    return enumerator.compactMap { $0 as? String }.sorted()
}

func posixPermissions(_ url: URL) -> Int? {
    (try? FileManager.default.attributesOfItem(atPath: url.path))?[.posixPermissions] as? Int
}

@Suite("SafeExtractor")
struct SafeExtractorTests {
    let temp: TemporaryDirectory
    let extractor: SafeExtractor

    init() throws {
        temp = try TemporaryDirectory()
        extractor = SafeExtractor(jobsRoot: temp.url.appendingPathComponent("jobs"))
    }

    private func extractionError(_ body: () throws -> Void) -> ArchiveError? {
        do {
            try body()
            return nil
        } catch let error as ArchiveError {
            return error
        } catch {
            Issue.record("non-archive error: \(error)")
            return nil
        }
    }

    @Test func extractsSelectedEntriesIntoAFreshJob() throws {
        defer { temp.remove() }
        var builder = ZipBuilder(entries: [ZipBuilder.directory("Android/"), ZipBuilder.directory("Android/obb/")])
        builder.add("base.apk", randomBytes(5000))
        builder.add("Android/obb/com.game/main.1.com.game.obb", randomBytes(70_000, seed: 3), method: .deflated)
        builder.add("ignored.txt", "not selected")
        builder.entries[3].externalAttributes = 0o100755 << 16
        let archive = try ZipArchive(data: builder.build())
        let selected = archive.entries.filter { $0.name != "ignored.txt" }

        let result = try extractor.extract(selected, from: archive)
        #expect(result.job.directory.path.hasPrefix(temp.url.appendingPathComponent("jobs").path + "/"))
        #expect(tree(result.job.directory) == [
            "Android", "Android/obb", "Android/obb/com.game", "Android/obb/com.game/main.1.com.game.obb", "base.apk",
        ])
        #expect(result.files.map(\.entryName) == ["base.apk", "Android/obb/com.game/main.1.com.game.obb"])
        let obb = try #require(result.file(forEntry: "Android/obb/com.game/main.1.com.game.obb"))
        #expect(try Data(contentsOf: obb.url) == Data(randomBytes(70_000, seed: 3)))
        #expect(obb.sizeBytes == 70_000)
        #expect(posixPermissions(obb.url) == 0o644)
        #expect(posixPermissions(result.job.directory) == 0o700)
        #expect(result.file(forEntry: "nope") == nil)

        extractor.removeJob(result.job)
        #expect(!FileManager.default.fileExists(atPath: result.job.directory.path))
    }

    @Test func defaultJobsRootIsInCaches() {
        #expect(SafeExtractor.defaultJobsRoot.path.hasSuffix("Airlock/jobs"))
        #expect(SafeExtractor().jobsRoot == SafeExtractor.defaultJobsRoot)
    }

    @Test func refusesToFollowSymlinksPlantedInTheJob() throws {
        defer { temp.remove() }
        let outside = temp.url.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        let archive = try ZipArchive(data: ZipBuilder(files: [("lib/x.so", [1, 2, 3]), ("evil", [4])]).build())

        let job = try extractor.makeJob()
        try FileManager.default.createSymbolicLink(at: job.directory.appendingPathComponent("lib"), withDestinationURL: outside)
        let error = extractionError { _ = try extractor.extract([archive.entries[0]], from: archive, into: job) }
        #expect(error != nil)
        #expect(tree(outside).isEmpty)
        #expect(!FileManager.default.fileExists(atPath: job.directory.path))

        // A symlink at the file's own name is not followed either.
        let second = try extractor.makeJob()
        let target = outside.appendingPathComponent("target")
        try FileManager.default.createSymbolicLink(at: second.directory.appendingPathComponent("evil"), withDestinationURL: target)
        #expect(extractionError { _ = try extractor.extract([archive.entries[1]], from: archive, into: second) } != nil)
        #expect(!FileManager.default.fileExists(atPath: target.path))
    }

    @Test func cleansUpTheJobWhenAnEntryIsCorrupt() throws {
        defer { temp.remove() }
        var builder = ZipBuilder(files: [("good.apk", randomBytes(100)), ("bad.apk", randomBytes(100, seed: 9))])
        builder.entries[1].crcOverride = 1
        let archive = try ZipArchive(data: builder.build())
        let error = extractionError { _ = try extractor.extract(archive.entries, from: archive) }
        #expect(error == .checksumMismatch("bad.apk"))
        #expect(tree(extractor.jobsRoot).isEmpty)
    }

    @Test func enforcesLimitsOnActualBytes() throws {
        defer { temp.remove() }
        let data = ZipBuilder(files: [("a", [UInt8](repeating: 0, count: 50_000))], method: .deflated).build()
        let archive = try ZipArchive(data: data, limits: .lenient)

        var tight = ExtractionLimits.lenient
        tight.maxTotalUncompressedBytes = 10_000
        let capped = SafeExtractor(jobsRoot: extractor.jobsRoot, limits: tight)
        #expect(extractionError { _ = try capped.extract(archive.entries, from: archive) }
            == .totalSizeLimitExceeded(bytes: 50_000, limit: 10_000))

        var ratio = ExtractionLimits()
        ratio.maxTotalRatio = 2
        let ratioCapped = SafeExtractor(jobsRoot: extractor.jobsRoot, limits: ratio)
        #expect(extractionError { _ = try ratioCapped.extract(archive.entries, from: archive) }
            == .totalRatioLimitExceeded(bytes: 50_000, archiveBytes: UInt64(data.count), ratio: 2))
        #expect(tree(extractor.jobsRoot).isEmpty)
    }

    @Test func refusesEntriesFromAnotherArchive() throws {
        defer { temp.remove() }
        let first = try ZipArchive(data: ZipBuilder(files: [("a", [1])]).build())
        let second = try ZipArchive(data: ZipBuilder(files: [("a", [1, 2])]).build())
        #expect(extractionError { _ = try extractor.extract(first.entries, from: second) } == .missingEntry("a"))
    }

    @Test func refusesExistingFilesInTheJob() throws {
        defer { temp.remove() }
        let archive = try ZipArchive(data: ZipBuilder(files: [("a", [1])]).build())
        let job = try extractor.makeJob()
        try Data([9]).write(to: job.directory.appendingPathComponent("a"))
        guard case .fileSystem? = extractionError({ _ = try extractor.extract(archive.entries, from: archive, into: job) }) else {
            Issue.record("expected fileSystem error")
            return
        }
    }

    @Test func stopsWhenCancelled() async throws {
        defer { temp.remove() }
        let archive = try ZipArchive(data: ZipBuilder(files: [("a", randomBytes(300_000))]).build())
        let extractor = extractor
        let task = Task { () -> ArchiveError? in
            withUnsafeCurrentTask { $0?.cancel() }
            do throws(ArchiveError) {
                _ = try extractor.extract(archive.entries, from: archive)
                return nil
            } catch {
                return error
            }
        }
        #expect(await task.value == .cancelled)
        #expect(tree(extractor.jobsRoot).isEmpty)
    }

    @Test func reportsUnwritableJobsRoot() throws {
        defer { temp.remove() }
        let file = try temp.write(Data([1]), as: "not-a-directory")
        let broken = SafeExtractor(jobsRoot: file.appendingPathComponent("jobs"))
        guard case .fileSystem? = extractionError({ _ = try broken.makeJob() }) else {
            Issue.record("expected fileSystem error")
            return
        }
    }

    @Test(arguments: [
        (["a", "b"], true),
        (["..", "x"], false),
        (["a", "..", "..", "x"], false),
        (["."], false),
        ([], false),
        (["a/../../x"], false),
    ])
    func containmentCheck(_ components: [String], _ inside: Bool) {
        let job = URL(fileURLWithPath: "/tmp/airlock-jobs/1234", isDirectory: true)
        #expect(SafeExtractor.isContained(components, in: job) == inside)
    }
}

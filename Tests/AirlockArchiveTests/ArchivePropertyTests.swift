// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

@testable import AirlockArchive
import AirlockTestSupport
import Foundation
import Testing

/// Valid archives that mutations start from, covering every structure the reader parses.
private let corpus: [Data] = {
    var deflated = ZipBuilder(entries: [ZipBuilder.directory("res/")])
    deflated.add("res/a.xml", Array(String(repeating: "<a/>", count: 50).utf8), method: .deflated)
    deflated.add("classes.dex", randomBytes(600, seed: 4), method: .deflated)
    deflated.comment = Array("comment".utf8)

    var zip64 = ZipBuilder(files: [("a", randomBytes(100)), ("b/c", randomBytes(300, seed: 2))])
    zip64.entries[1].method = .deflated
    zip64.zip64 = true

    var withGap = ZipBuilder(files: [("AndroidManifest.xml", randomBytes(80, seed: 5))])
    withGap.gapBeforeCentralDirectory = randomBytes(64, seed: 6)

    return [
        ZipBuilder.apk(),
        deflated.build(),
        zip64.build(),
        withGap.build(),
        ZipBuilder.container(apks: ["base.apk", "split_config.en.apk"], extraFiles: [("toc.pb", [1])]).build(),
        ZipBuilder().build(),
    ]
}()

/// Field values that tend to hit edge cases when written over length, count and offset fields.
private let interestingValues: [UInt64] = [0, 1, 0x7F, 0xFF, 0xFFFF, 0xFFFE, 0x7FFF_FFFF, 0xFFFF_FFFF, 0x8000_0000, .max]

private func mutate(_ data: Data, using rng: inout SplitMix64) -> Data {
    var bytes = [UInt8](data)
    let rounds = Int.random(in: 1...4, using: &rng)
    for _ in 0..<rounds {
        guard !bytes.isEmpty else {
            bytes = [0x50, 0x4B, 0x05, 0x06]
            continue
        }
        let position = Int.random(in: 0..<bytes.count, using: &rng)
        switch Int.random(in: 0..<7, using: &rng) {
        case 0:
            bytes[position] ^= UInt8.random(in: 1...255, using: &rng)
        case 1:
            bytes.removeSubrange(position...)
        case 2:
            bytes.insert(contentsOf: randomBytes(Int.random(in: 1...16, using: &rng), seed: rng.next()), at: position)
        case 3:
            let value = interestingValues.randomElement(using: &rng) ?? 0
            let width = [2, 4, 8].randomElement(using: &rng) ?? 4
            for offset in 0..<width where position + offset < bytes.count {
                bytes[position + offset] = UInt8(truncatingIfNeeded: value >> UInt64(offset * 8))
            }
        case 4:
            let end = min(bytes.count, position + Int.random(in: 1...64, using: &rng))
            bytes.insert(contentsOf: bytes[position..<end], at: Int.random(in: 0...bytes.count, using: &rng))
        case 5:
            let end = min(bytes.count, position + Int.random(in: 1...64, using: &rng))
            bytes.removeSubrange(position..<end)
        default:
            // Plant a signature where a record might be expected.
            let signatures: [[UInt8]] = [[0x50, 0x4B, 0x01, 0x02], [0x50, 0x4B, 0x03, 0x04], [0x50, 0x4B, 0x05, 0x06],
                                         [0x50, 0x4B, 0x06, 0x06], [0x50, 0x4B, 0x06, 0x07]]
            let signature = signatures.randomElement(using: &rng) ?? []
            for (offset, byte) in signature.enumerated() where position + offset < bytes.count {
                bytes[position + offset] = byte
            }
        }
    }
    return Data(bytes)
}

/// Opens, reads and extracts `data`, checking the only outcomes are success or an `ArchiveError`, and
/// that nothing is ever written outside the job folder. Typed throws make any other error a compile error.
/// Returns whether the archive opened, so tests can check mutations reach past the first checks.
@discardableResult
private func exercise(_ data: Data, extractor: SafeExtractor, sandbox: URL) -> Bool {
    var limits = ExtractionLimits()
    limits.maxEntries = 500
    let archive: ZipArchive
    do {
        archive = try ZipArchive(data: data, limits: limits)
    } catch {
        return false
    }
    for entry in archive.entries {
        var produced: UInt64 = 0
        do {
            try archive.stream(entry, chunkSize: 512) { produced += UInt64($0.count) }
            #expect(produced == entry.uncompressedSize)
        } catch {
            #expect(produced <= entry.uncompressedSize)
        }
    }
    let result: ExtractionResult
    do {
        result = try extractor.extract(archive.entries, from: archive)
    } catch {
        #expect(tree(extractor.jobsRoot).isEmpty, "a failed extraction left files behind")
        return true
    }
    for file in result.files {
        #expect(file.url.standardizedFileURL.path.hasPrefix(result.job.directory.path + "/"))
    }
    #expect(tree(sandbox) == ["jobs"] + tree(extractor.jobsRoot).map { "jobs/" + $0 })
    extractor.removeJob(result.job)
    return true
}

@Suite("Archive Property: mutated archives never crash, hang or escape", .timeLimit(.minutes(2)))
struct ArchiveMutationPropertyTests {
    @Test(arguments: 0..<40)
    func mutatedArchivesFailCleanly(batch: Int) throws {
        let temp = try TemporaryDirectory()
        defer { temp.remove() }
        let extractor = SafeExtractor(jobsRoot: temp.url.appendingPathComponent("jobs"))
        var rng = SplitMix64(seed: 0xA1A1_0000 + UInt64(batch))
        var opened = 0
        for _ in 0..<100 {
            let original = corpus.randomElement(using: &rng) ?? Data()
            if exercise(mutate(original, using: &rng), extractor: extractor, sandbox: temp.url) {
                opened += 1
            }
        }
        #expect(opened >= 1, "mutations should not all be rejected up front")
    }

    @Test(arguments: 0..<4)
    func mutatedFilesThroughTheDetector(batch: Int) throws {
        let temp = try TemporaryDirectory()
        defer { temp.remove() }
        var rng = SplitMix64(seed: 0xD0D0_0000 + UInt64(batch))
        let detector = FormatDetector()
        for index in 0..<100 {
            let original = corpus.randomElement(using: &rng) ?? Data()
            let url = try temp.write(mutate(original, using: &rng), as: "case\(index).bin")
            // Success or a typed ArchiveError are the only outcomes; anything else fails to compile.
            _ = try? detector.detect(at: url)
        }
    }

    @Test(arguments: 0..<8)
    func everyTruncationOfAValidArchiveFailsCleanly(seed: Int) throws {
        let data = corpus[seed % corpus.count]
        let temp = try TemporaryDirectory()
        defer { temp.remove() }
        let extractor = SafeExtractor(jobsRoot: temp.url.appendingPathComponent("jobs"))
        for length in 0..<data.count {
            exercise(data.prefix(length), extractor: extractor, sandbox: temp.url)
        }
    }
}

@Suite("Archive Property: valid archives round-trip")
struct ArchiveRoundTripPropertyTests {
    @Test(arguments: 0..<25)
    func randomValidArchivesRoundTrip(seed: Int) throws {
        var rng = SplitMix64(seed: 0xBEEF_0000 + UInt64(seed))
        var builder = ZipBuilder()
        var expected: [String: [UInt8]] = [:]
        for index in 0..<Int.random(in: 1...20, using: &rng) {
            let depth = Int.random(in: 1...4, using: &rng)
            let name = (0..<depth).map { level in "d\(level)x\(Int.random(in: 0...3, using: &rng))" }.joined(separator: "/")
                + "-\(index).bin"
            // Random bytes do not compress, so the archive stays within the 10× ratio.
            let data = randomBytes(Int.random(in: 0...3000, using: &rng), seed: rng.next())
            builder.add(name, data, method: Bool.random(using: &rng) ? .deflated : .stored)
            expected[name] = data
        }
        builder.zip64 = Int.random(in: 0..<4, using: &rng) == 0
        let archive = try ZipArchive(data: builder.build())
        #expect(archive.entries.count == expected.count)
        for entry in archive.entries {
            #expect(try archive.data(for: entry, maxBytes: 1 << 20) == Data(expected[entry.name] ?? []))
        }
    }

    @Test(arguments: 0..<10)
    func acceptedNamesAlwaysStayInsideTheJob(seed: Int) {
        var rng = SplitMix64(seed: 0x4E41_0000 + UInt64(seed))
        let alphabet: [UInt8] = Array("a./\\:A..".utf8) + [0]
        let job = URL(fileURLWithPath: "/tmp/airlock/job", isDirectory: true)
        for _ in 0..<500 {
            let name = (0..<Int.random(in: 0...12, using: &rng)).map { _ in alphabet.randomElement(using: &rng) ?? 0x61 }
            guard let components = try? EntryName.validate(name, limits: .default).1 else { continue }
            #expect(!components.contains { $0.isEmpty || $0 == "." || $0 == ".." || $0.contains("/") })
            #expect(SafeExtractor.isContained(components, in: job))
        }
    }
}

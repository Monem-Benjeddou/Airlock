// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

@testable import AirlockArchive
import AirlockTestSupport
import Foundation
import Testing

/// Opens `builder`'s output and returns the error, failing the test if it opened.
func openError(_ builder: ZipBuilder, limits: ExtractionLimits = .default) -> ArchiveError? {
    openError(builder.build(), limits: limits)
}

func openError(_ data: Data, limits: ExtractionLimits = .default) -> ArchiveError? {
    do {
        _ = try ZipArchive(data: data, limits: limits)
        return nil
    } catch {
        return error
    }
}

extension ExtractionLimits {
    /// Ratio checks off, for tests whose tiny archives hold highly compressible data.
    static let lenient = ExtractionLimits(maxTotalRatio: 1_000_000, maxEntryRatio: 1_000_000)
}

func randomBytes(_ count: Int, seed: UInt64 = 1) -> [UInt8] {
    var rng = SplitMix64(seed: seed)
    return (0..<count).map { _ in UInt8.random(in: 0...255, using: &rng) }
}

/// Reads every entry fully, returning the first error.
func readAllError(_ archive: ZipArchive) -> ArchiveError? {
    do {
        for entry in archive.entries {
            try archive.stream(entry) { _ in }
        }
        return nil
    } catch {
        return error
    }
}

@Suite("ZipArchive reading")
struct ZipArchiveReadingTests {
    @Test func readsStoredAndDeflatedEntries() throws {
        var builder = ZipBuilder()
        builder.add("hello.txt", "Hello, world")
        let big = randomBytes(200_000)
        builder.add("dir/big.bin", big, method: .deflated)
        builder.add("empty.txt", [], method: .deflated)
        let archive = try ZipArchive(data: builder.build())

        #expect(archive.entries.map(\.name) == ["hello.txt", "dir/big.bin", "empty.txt"])
        let hello = try #require(archive.entry(named: "hello.txt"))
        #expect(hello.method == .stored)
        #expect(try archive.data(for: hello, maxBytes: 100) == Data("Hello, world".utf8))

        let bigEntry = try #require(archive.entry(named: "dir/big.bin"))
        #expect(bigEntry.method == .deflated)
        #expect(bigEntry.uncompressedSize == 200_000)
        #expect(bigEntry.pathComponents == ["dir", "big.bin"])
        #expect(try archive.data(for: bigEntry, maxBytes: 1 << 20) == Data(big))

        var chunks = 0
        var collected = Data()
        try archive.stream(bigEntry, chunkSize: 4096) { chunk in
            chunks += 1
            collected.append(chunk)
        }
        #expect(chunks > 10)
        #expect(collected == Data(big))

        let empty = try #require(archive.entry(named: "empty.txt"))
        #expect(try archive.data(for: empty, maxBytes: 0).isEmpty)
        #expect(archive.entry(named: "missing") == nil)
        #expect(archive.totalUncompressedBytes == 200_012)
    }

    @Test func readsFromFile() throws {
        let temp = try TemporaryDirectory()
        defer { temp.remove() }
        let url = try temp.write(ZipBuilder.apk(), as: "app.apk")
        let archive = try ZipArchive(contentsOf: url)
        #expect(archive.entry(named: "AndroidManifest.xml") != nil)
        #expect(readAllError(archive) == nil)
        #expect(archive.archiveSize == UInt64(try Data(contentsOf: url).count))
    }

    @Test func refusesMissingFileAndDirectories() throws {
        let temp = try TemporaryDirectory()
        defer { temp.remove() }
        #expect(throws: ArchiveError.self) { try ZipArchive(contentsOf: temp.file("nope.apk")) }
        #expect(throws: ArchiveError.self) { try ZipArchive(contentsOf: temp.url) }
    }

    @Test func dataRefusesEntriesOverTheCap() throws {
        let archive = try ZipArchive(data: ZipBuilder(files: [("a", [UInt8](repeating: 1, count: 100))]).build())
        let entry = try #require(archive.entries.first)
        #expect(throws: ArchiveError.entryTooLarge("a", bytes: 100, limit: 10)) {
            try archive.data(for: entry, maxBytes: 10)
        }
    }

    @Test func directoriesAndSigningBlockGapsAreAllowed() throws {
        var builder = ZipBuilder(entries: [ZipBuilder.directory("lib/"), .init(name: "lib/a.so", data: [1, 2, 3])])
        builder.gapBeforeCentralDirectory = [UInt8](repeating: 0xAB, count: 4096)
        let archive = try ZipArchive(data: builder.build())
        #expect(archive.entries.first?.isDirectory == true)
        #expect(archive.entries.last?.isDirectory == false)
    }

    @Test func emptyArchiveHasNoEntries() throws {
        let archive = try ZipArchive(data: ZipBuilder().build())
        #expect(archive.entries.isEmpty)
    }

    @Test func readsZip64Archives() throws {
        var builder = ZipBuilder(files: [("a.txt", Array("alpha".utf8)), ("b.bin", [UInt8](repeating: 9, count: 5000))])
        builder.entries[1].method = .deflated
        builder.zip64 = true
        let archive = try ZipArchive(data: builder.build(), limits: .lenient)
        #expect(archive.entries.map(\.name) == ["a.txt", "b.bin"])
        #expect(archive.entries[1].uncompressedSize == 5000)
        #expect(readAllError(archive) == nil)
    }

    @Test func ignoresUnknownExtraFields() throws {
        var builder = ZipBuilder(files: [("a", [1])])
        builder.entries[0].centralExtra = [0x55, 0x54, 0x05, 0x00, 1, 2, 3, 4, 5]
        #expect(openError(builder) == nil)
    }

    @Test func toleratesCommentsWithoutFakeRecords() throws {
        var builder = ZipBuilder(files: [("a", [1])])
        builder.comment = Array("signed by someone".utf8)
        #expect(openError(builder) == nil)
    }

    @Test func dataDescriptorFlagUsesCentralDirectoryValues() throws {
        var builder = ZipBuilder(files: [("a", [1, 2, 3])], method: .deflated)
        builder.entries[0].flags = 0x0008
        let archive = try ZipArchive(data: builder.build())
        #expect(readAllError(archive) == nil)
    }
}

@Suite("ZipArchive structural attacks")
struct ZipArchiveStructureTests {
    @Test func rejectsNonZipData() {
        #expect(openError(Data("not a zip at all, just text".utf8)) == .notAnArchive)
        #expect(openError(Data()) == .notAnArchive)
    }

    @Test func rejectsTruncatedCentralDirectory() throws {
        let data = ZipBuilder.apk()
        // Drop bytes from the middle of the central directory but keep the end record.
        var bytes = [UInt8](data)
        let eocd = bytes.count - 22
        bytes.removeSubrange((eocd - 20)..<eocd)
        #expect(openError(Data(bytes)) != nil)

        // Cut the file in the middle of the end record.
        #expect(openError(data.prefix(data.count - 5)) != nil)
    }

    @Test func rejectsCentralDirectoryOutsideFile() {
        var builder = ZipBuilder(files: [("a", [1])])
        builder.centralDirectoryOffsetOverride = 1 << 30
        #expect(openError(builder) != nil)

        var sized = ZipBuilder(files: [("a", [1])])
        sized.centralDirectorySizeOverride = 1 << 20
        #expect(openError(sized) != nil)
    }

    @Test func rejectsEntryCountMismatchAndExcess() {
        var builder = ZipBuilder(files: [("a", [1]), ("b", [2])])
        builder.entryCountOverride = 3
        #expect(openError(builder) != nil)

        let many = ZipBuilder(files: (0..<12).map { ("f\($0)", [UInt8($0)]) })
        var limits = ExtractionLimits()
        limits.maxEntries = 10
        #expect(openError(many, limits: limits) == .tooManyEntries(count: 12, limit: 10))
    }

    @Test func rejectsMultiDiskArchives() {
        var builder = ZipBuilder(files: [("a", [1])])
        builder.eocdDiskNumber = 1
        #expect(openError(builder) != nil)

        var entryDisk = ZipBuilder(files: [("a", [1])])
        entryDisk.entries[0].diskNumberStart = 2
        #expect(openError(entryDisk) != nil)
    }

    @Test func rejectsAmbiguousEndRecordsInComments() {
        // A comment that itself contains a valid-looking end record pointing at the same directory.
        var builder = ZipBuilder(files: [("a", [1])])
        let honest = [UInt8](builder.build())
        let realEOCD = Array(honest.suffix(22))
        var fake = realEOCD
        fake[20] = 0
        fake[21] = 0
        builder.comment = fake
        #expect(openError(builder) != nil)
    }

    @Test func rejectsCommentLengthPastEndOfFile() {
        var bytes = [UInt8](ZipBuilder(files: [("a", [1])]).build())
        bytes[bytes.count - 2] = 0x10
        #expect(openError(Data(bytes)) != nil)
    }

    @Test func rejectsOverlappingEntries() {
        let base = ZipBuilder()
        let hidden = ZipBuilder.Entry(name: "hidden.dex", data: [1, 2, 3, 4])
        var outer = ZipBuilder.Entry(name: "outer.bin", data: base.localRecord(hidden))
        outer.method = .stored
        var phantom = hidden
        phantom.writesLocalRecord = false
        phantom.localHeaderOffsetOverride = UInt64(30 + outer.nameBytes.count)
        let builder = ZipBuilder(entries: [outer, phantom])
        #expect(openError(builder) == .overlappingEntries("hidden.dex"))
    }

    @Test func rejectsTwoEntriesSharingOneLocalHeader() {
        var second = ZipBuilder.Entry(name: "a", data: [1])
        second.writesLocalRecord = false
        second.localHeaderOffsetOverride = 0
        let builder = ZipBuilder(entries: [.init(name: "a", data: [1]), second])
        #expect(openError(builder) != nil)
    }

    @Test func rejectsLocalHeaderMismatches() {
        var renamed = ZipBuilder(files: [("AndroidManifest.xml", [1])])
        renamed.entries[0].localNameOverride = Array("AndroidManifest.xmm".utf8)
        #expect(openError(renamed) == .headerMismatch("AndroidManifest.xml"))

        var method = ZipBuilder(files: [("a", [1])])
        method.entries[0].localMethodOverride = 8
        #expect(openError(method) == .headerMismatch("a"))

        var offset = ZipBuilder(files: [("a", [1]), ("b", [2])])
        offset.entries[1].localHeaderOffsetOverride = 3
        #expect(openError(offset) != nil)
    }

    @Test func rejectsCompressedSizeBeyondFile() {
        var builder = ZipBuilder(files: [("a", [1, 2, 3])])
        builder.entries[0].compressedSizeOverride = 1 << 32 - 2
        builder.entries[0].uncompressedSizeOverride = 1 << 32 - 2
        #expect(openError(builder) != nil)
    }

    @Test func rejectsStoredEntriesWithDifferentSizes() {
        var builder = ZipBuilder(files: [("a", [1, 2, 3])])
        builder.entries[0].uncompressedSizeOverride = 2
        #expect(openError(builder) != nil)
    }

    @Test func rejectsEncryptedEntries() {
        var builder = ZipBuilder(files: [("secret.dex", [1, 2, 3])])
        builder.entries[0].flags = 0x0001
        #expect(openError(builder) == .encryptedEntry("secret.dex"))
    }

    @Test(arguments: [UInt16(1), 9, 12, 14, 99])
    func rejectsUnsupportedMethods(_ method: UInt16) {
        let builder = ZipBuilder(entries: [.init(name: "x", data: [1, 2], method: .raw(method))])
        #expect(openError(builder) == .unsupportedCompression("x", method: method))
    }

    @Test func rejectsDirectoriesWithData() {
        let builder = ZipBuilder(files: [("dir/", [1, 2, 3])])
        #expect(openError(builder) != nil)
    }

    @Test func rejectsMalformedZip64Extra() {
        var builder = ZipBuilder(files: [("a", [1])])
        builder.zip64 = true
        var bytes = [UInt8](builder.build())
        // Shrink the declared ZIP64 extra in the central directory (tag 0x0001, size 24 → 4).
        if let index = findCentralZip64Extra(in: bytes) {
            bytes[index + 2] = 4
        }
        #expect(openError(Data(bytes)) != nil)
    }

    private func findCentralZip64Extra(in bytes: [UInt8]) -> Int? {
        let signature: [UInt8] = [0x50, 0x4B, 0x01, 0x02]
        guard let start = (0..<(bytes.count - 4)).first(where: { Array(bytes[$0..<($0 + 4)]) == signature }) else {
            return nil
        }
        let nameLength = Int(bytes[start + 28]) | Int(bytes[start + 29]) << 8
        return start + 46 + nameLength
    }
}

@Suite("ZipArchive entry names")
struct ZipArchiveNameTests {
    @Test(arguments: [
        ("../evil", UnsafeNameReason.parentTraversal),
        ("a/../../evil", .parentTraversal),
        ("a\\..\\..\\evil", .parentTraversal),
        ("..", .parentTraversal),
        ("/etc/passwd", .absolutePath),
        ("\\windows\\evil", .absolutePath),
        ("C:/evil", .driveLetter),
        ("c:evil", .driveLetter),
        ("a//b", .redundantComponent),
        ("./a", .redundantComponent),
        ("a/./b", .redundantComponent),
    ])
    func rejectsEscapingNames(_ name: String, _ reason: UnsafeNameReason) {
        let builder = ZipBuilder(files: [(name, [1])])
        #expect(openError(builder) == .unsafeEntryName(name, reason))
    }

    @Test func rejectsNULAndInvalidUTF8() {
        let nul = ZipBuilder(entries: [.init(nameBytes: Array("a\0.apk".utf8), data: [1])])
        #expect(openError(nul) == .unsafeEntryName("a\0.apk", .containsNUL))

        let invalid = ZipBuilder(entries: [.init(nameBytes: [0x61, 0xFF, 0xFE], data: [1])])
        if case .unsafeEntryName(_, .notUTF8)? = openError(invalid) {} else {
            Issue.record("expected notUTF8")
        }

        let empty = ZipBuilder(entries: [.init(nameBytes: [], data: [1])])
        #expect(openError(empty) == .unsafeEntryName("", .empty))
    }

    @Test func rejectsLongAndDeepNames() {
        let long = String(repeating: "a", count: 1025)
        #expect(openError(ZipBuilder(files: [(long, [1])])) == .unsafeEntryName(long, .tooLong))
        let okLong = String(repeating: "a", count: 1024)
        #expect(openError(ZipBuilder(files: [(okLong, [1])])) == nil)

        let deep = Array(repeating: "d", count: 33).joined(separator: "/")
        #expect(openError(ZipBuilder(files: [(deep, [1])])) == .unsafeEntryName(deep, .tooDeep))
        let okDeep = Array(repeating: "d", count: 32).joined(separator: "/")
        #expect(openError(ZipBuilder(files: [(okDeep, [1])])) == nil)
    }

    @Test func rejectsSymlinksAndSpecialFiles() {
        let link = ZipBuilder(entries: [ZipBuilder.symlink("lib/libevil.so", target: "/etc/passwd")])
        #expect(openError(link) == .symlinkEntry("lib/libevil.so"))

        var fifo = ZipBuilder.Entry(name: "fifo", data: [])
        fifo.externalAttributes = 0o010644 << 16
        #expect(openError(ZipBuilder(entries: [fifo])) == .specialFileEntry("fifo"))

        // DOS-made archives put attribute bits in the low byte; the Unix mode is ignored.
        var dos = ZipBuilder.Entry(name: "dos.txt", data: [1])
        dos.versionMadeBy = 0x0014
        dos.externalAttributes = 0o120777 << 16 | 0x20
        #expect(openError(ZipBuilder(entries: [dos])) == nil)
    }

    @Test(arguments: [
        ["classes.dex", "CLASSES.dex"],
        ["AndroidManifest.xml", "androidmanifest.XML"],
        ["a/b", "a/b"],
        ["lib/", "lib"],
        ["caf\u{E9}", "cafe\u{301}"],
    ])
    func rejectsDuplicateNames(_ names: [String]) {
        let builder = ZipBuilder(files: names.map { ($0, []) })
        guard case .duplicateEntry? = openError(builder) else {
            Issue.record("expected duplicateEntry for \(names)")
            return
        }
    }

    @Test func rejectsFilesUsedAsDirectories() {
        let builder = ZipBuilder(files: [("lib", [1]), ("lib/a.so", [2])])
        #expect(openError(builder) == .duplicateEntry("lib/a.so"))
        let reversed = ZipBuilder(files: [("lib/a.so", [2]), ("LIB", [1])])
        #expect(openError(reversed) == .duplicateEntry("LIB"))
    }

    @Test func backslashNamesAreSplitIntoComponents() throws {
        let archive = try ZipArchive(data: ZipBuilder(files: [("assets\\x.bin", [1])]).build())
        #expect(archive.entries.first?.pathComponents == ["assets", "x.bin"])
    }
}

@Suite("ZipArchive integrity")
struct ZipArchiveIntegrityTests {
    @Test func detectsBadCRC() throws {
        var builder = ZipBuilder(files: [("a", [1, 2, 3]), ("b", [UInt8](repeating: 4, count: 900))])
        builder.entries[0].crcOverride = 0xDEAD_BEEF
        builder.entries[1].method = .deflated
        builder.entries[1].crcOverride = 0xDEAD_BEEF
        let archive = try ZipArchive(data: builder.build(), limits: .lenient)
        #expect(readAllError(archive) == .checksumMismatch("a"))
        let second = try #require(archive.entry(named: "b"))
        #expect(throws: ArchiveError.checksumMismatch("b")) { try archive.stream(second) { _ in } }
    }

    @Test func detectsCorruptDeflateData() throws {
        var builder = ZipBuilder()
        builder.add("a", [UInt8](repeating: 5, count: 1000), method: .deflated)
        var bytes = [UInt8](builder.build())
        // The first deflate byte follows the 30-byte header and 1-byte name. Make it an invalid block type.
        bytes[31] = 0xFF
        let archive = try ZipArchive(data: Data(bytes), limits: .lenient)
        #expect(readAllError(archive) == .corruptData("a"))
    }

    @Test func detectsTruncatedDeflateStream() throws {
        let payload = ZipBuilder.deflate(randomBytes(5000))
        var entry = ZipBuilder.Entry(name: "a", data: Array(payload.prefix(payload.count / 2)), method: .raw(8))
        entry.uncompressedSizeOverride = 5000
        let archive = try ZipArchive(data: ZipBuilder(entries: [entry]).build(), limits: .lenient)
        #expect(readAllError(archive) == .corruptData("a"))
    }

    @Test func detectsTrailingBytesAfterDeflateStream() throws {
        let original = [UInt8](repeating: 1, count: 100)
        var entry = ZipBuilder.Entry(name: "a", data: ZipBuilder.deflate(original) + [0, 0, 0, 0], method: .raw(8))
        entry.uncompressedSizeOverride = 100
        entry.crcOverride = ZipBuilder.crc32(original)
        let archive = try ZipArchive(data: ZipBuilder(entries: [entry]).build(), limits: .lenient)
        #expect(readAllError(archive) == .corruptData("a"))
    }

    @Test func detectsLyingUncompressedSizes() throws {
        // Declares 1 KB but inflates to 1 MB: reading must stop at the declared size.
        let real = [UInt8](repeating: 0, count: 1 << 20)
        var entry = ZipBuilder.Entry(name: "liar.bin", data: real, method: .deflated)
        entry.uncompressedSizeOverride = 1024
        let archive = try ZipArchive(data: ZipBuilder(entries: [entry]).build())
        var seen = 0
        #expect(throws: ArchiveError.sizeMismatch("liar.bin")) {
            try archive.stream(archive.entries[0]) { seen += $0.count }
        }
        #expect(seen <= 1024)

        // And one that claims more than it holds.
        var short = ZipBuilder.Entry(name: "short.bin", data: [1, 2, 3], method: .deflated)
        short.uncompressedSizeOverride = 10
        let shortArchive = try ZipArchive(data: ZipBuilder(entries: [short]).build())
        #expect(readAllError(shortArchive) == .sizeMismatch("short.bin"))
    }

    @Test func consumerErrorsPropagate() throws {
        let archive = try ZipArchive(data: ZipBuilder(files: [("a", [1, 2, 3])]).build())
        #expect(throws: ArchiveError.cancelled) {
            try archive.stream(archive.entries[0]) { _ throws(ArchiveError) in throw .cancelled }
        }
    }

    @Test func detectsFileChangingUnderneath() throws {
        let temp = try TemporaryDirectory()
        defer { temp.remove() }
        let url = try temp.write(ZipBuilder.container(apks: ["base.apk"]).build(), as: "x.apks")
        let archive = try ZipArchive(contentsOf: url)
        try Data("PK".utf8).write(to: url)
        #expect(readAllError(archive) != nil)
    }
}

@Suite("ZipArchive nesting")
struct ZipArchiveNestingTests {
    @Test func opensStoredInnerArchivesInPlace() throws {
        let outer = try ZipArchive(data: ZipBuilder.container(apks: ["base.apk"]).build())
        let inner = try outer.openNested(outer.entries[0])
        #expect(inner.nestingDepth == 1)
        #expect(inner.entry(named: "AndroidManifest.xml") != nil)
        #expect(readAllError(inner) == nil)
    }

    @Test func refusesNestingPastTheLimit() throws {
        var level = ZipBuilder.apk()
        for index in 0..<3 {
            level = ZipBuilder(files: [("level\(index).zip", [UInt8](level))]).build()
        }
        let depth0 = try ZipArchive(data: level)
        let depth1 = try depth0.openNested(depth0.entries[0])
        let depth2 = try depth1.openNested(depth1.entries[0])
        #expect(depth2.nestingDepth == 2)
        #expect(throws: ArchiveError.nestingTooDeep(limit: 2)) { try depth2.openNested(depth2.entries[0]) }
    }

    @Test func refusesNestedDeflatedEntriesAndDirectories() throws {
        var builder = ZipBuilder(entries: [ZipBuilder.directory("d/")])
        builder.add("inner.apk", [UInt8](ZipBuilder.apk()), method: .deflated)
        let outer = try ZipArchive(data: builder.build())
        #expect(throws: ArchiveError.self) { try outer.openNested(outer.entries[0]) }
        #expect(throws: ArchiveError.self) { try outer.openNested(outer.entries[1]) }
    }

    @Test func nestedFileArchivesReadInPlace() throws {
        let temp = try TemporaryDirectory()
        defer { temp.remove() }
        let url = try temp.write(ZipBuilder.container(apks: ["a.apk", "b.apk"]).build(), as: "x.apks")
        let outer = try ZipArchive(contentsOf: url)
        let inner = try outer.openNested(outer.entries[1])
        #expect(readAllError(inner) == nil)
        #expect(inner.archiveSize == outer.entries[1].uncompressedSize)
    }
}

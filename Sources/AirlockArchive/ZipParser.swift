// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Parses and validates a zip's end records, central directory and local headers.
///
/// Everything an attacker controls is checked before an entry is handed out: record bounds, entry
/// counts, names, types, sizes, limits, local/central agreement and overlap. Structure follows
/// PKWARE APPNOTE 6.3.10, restricted to what Android tooling writes.
struct ZipParser {
    private enum Signature {
        static let local: UInt32 = 0x0403_4B50
        static let central: UInt32 = 0x0201_4B50
        static let end: UInt32 = 0x0605_4B50
        static let zip64End: UInt32 = 0x0606_4B50
        static let zip64Locator: UInt32 = 0x0706_4B50
    }

    private enum Size {
        static let endRecord = 22
        static let maxComment = 65_535
        static let zip64Locator = 20
        static let zip64EndMinimum = 56
        static let centralHeader = 46
        static let localHeader = 30
    }

    /// Where the central directory lives, from the (ZIP64) end records.
    private struct Directory {
        var entryCount: UInt64
        var offset: UInt64
        var size: UInt64
        /// The central directory must end exactly here.
        var end: UInt64
    }

    /// A central-directory record before its local header has been checked.
    private struct CentralRecord {
        var nameBytes: [UInt8]
        var name: String
        var components: [String]
        var flags: UInt16
        var method: ZipEntry.Method
        var crc32: UInt32
        var compressedSize: UInt64
        var uncompressedSize: UInt64
        var localHeaderOffset: UInt64
        var isDirectory: Bool
    }

    private let reader: ByteReader
    private let limits: ExtractionLimits

    init(reader: ByteReader, limits: ExtractionLimits) {
        self.reader = reader
        self.limits = limits
    }

    func parse() throws(ArchiveError) -> [ZipEntry] {
        try checkMagic()
        let directory = try locateDirectory()
        guard directory.entryCount <= UInt64(limits.maxEntries) else {
            throw .tooManyEntries(count: directory.entryCount, limit: limits.maxEntries)
        }
        let records = try readCentralDirectory(directory)
        try checkTotals(records)
        return try resolveLocalHeaders(records, dataLimit: directory.offset)
    }

    // MARK: End records

    private func checkMagic() throws(ArchiveError) {
        guard reader.length >= 4 else { throw .notAnArchive }
        var cursor = LittleEndianCursor(try reader.read(at: 0, count: 4))
        let magic = try cursor.uint32()
        guard magic == Signature.local || magic == Signature.end else { throw .notAnArchive }
    }

    private func locateDirectory() throws(ArchiveError) -> Directory {
        let endOffset = try findEndRecord()
        var cursor = LittleEndianCursor(try reader.read(at: endOffset, count: Size.endRecord), position: 4)
        let disk = try cursor.uint16()
        let directoryDisk = try cursor.uint16()
        let entriesOnDisk = try cursor.uint16()
        let entries = try cursor.uint16()
        let size = try cursor.uint32()
        let offset = try cursor.uint32()
        guard disk == 0, directoryDisk == 0, entriesOnDisk == entries else {
            throw .malformed("multi-disk archives are not supported")
        }

        if let zip64 = try readZip64Directory(endOffset: endOffset) {
            return zip64
        }
        guard entries != 0xFFFF, size != 0xFFFF_FFFF, offset != 0xFFFF_FFFF else {
            throw .malformed("ZIP64 values without a ZIP64 end record")
        }
        return Directory(entryCount: UInt64(entries), offset: UInt64(offset), size: UInt64(size), end: endOffset)
    }

    /// Finds the single end record whose comment runs exactly to the end of the file.
    ///
    /// A comment can contain bytes that look like another end record; if more than one candidate is
    /// self-consistent the archive is ambiguous and refused, because different tools would read it differently.
    private func findEndRecord() throws(ArchiveError) -> UInt64 {
        guard reader.length >= UInt64(Size.endRecord) else { throw .truncated("too short for an end record") }
        let tailLength = Int(min(reader.length, UInt64(Size.endRecord + Size.maxComment)))
        let tailStart = reader.length - UInt64(tailLength)
        let tail = try reader.read(at: tailStart, count: tailLength)
        var candidates: [UInt64] = []
        for index in stride(from: tailLength - Size.endRecord, through: 0, by: -1)
        where tail[index] == 0x50 && tail[index + 1] == 0x4B && tail[index + 2] == 0x05 && tail[index + 3] == 0x06 {
            let commentLength = Int(tail[index + 20]) | Int(tail[index + 21]) << 8
            if index + Size.endRecord + commentLength == tailLength {
                candidates.append(tailStart + UInt64(index))
            }
        }
        guard let endOffset = candidates.first else { throw .malformed("no valid end of central directory record") }
        guard candidates.count == 1 else { throw .malformed("ambiguous end of central directory records") }
        return endOffset
    }

    private func readZip64Directory(endOffset: UInt64) throws(ArchiveError) -> Directory? {
        guard endOffset >= UInt64(Size.zip64Locator) else { return nil }
        let locatorOffset = endOffset - UInt64(Size.zip64Locator)
        var locator = LittleEndianCursor(try reader.read(at: locatorOffset, count: Size.zip64Locator))
        guard try locator.uint32() == Signature.zip64Locator else { return nil }
        let recordDisk = try locator.uint32()
        let recordOffset = try locator.uint64()
        let totalDisks = try locator.uint32()
        guard recordDisk == 0, totalDisks <= 1 else { throw .malformed("multi-disk ZIP64 archives are not supported") }
        guard recordOffset <= locatorOffset, locatorOffset - recordOffset >= UInt64(Size.zip64EndMinimum) else {
            throw .malformed("ZIP64 end record out of place")
        }

        var record = LittleEndianCursor(try reader.read(at: recordOffset, count: Size.zip64EndMinimum))
        guard try record.uint32() == Signature.zip64End else { throw .malformed("missing ZIP64 end record") }
        let recordSize = try record.uint64()
        guard recordSize.addingReportingOverflow(12) == (locatorOffset - recordOffset, false) else {
            throw .malformed("ZIP64 end record size mismatch")
        }
        try record.skip(4)
        let disk = try record.uint32()
        let directoryDisk = try record.uint32()
        let entriesOnDisk = try record.uint64()
        let entries = try record.uint64()
        let size = try record.uint64()
        let offset = try record.uint64()
        guard disk == 0, directoryDisk == 0, entriesOnDisk == entries else {
            throw .malformed("multi-disk ZIP64 archives are not supported")
        }
        return Directory(entryCount: entries, offset: offset, size: size, end: recordOffset)
    }

    // MARK: Central directory

    private func readCentralDirectory(_ directory: Directory) throws(ArchiveError) -> [CentralRecord] {
        guard directory.offset.addingReportingOverflow(directory.size) == (directory.end, false) else {
            throw .malformed("central directory is not where the end record says")
        }
        var records: [CentralRecord] = []
        records.reserveCapacity(Int(directory.entryCount))
        var collisions = CollisionTracker()
        var position = directory.offset
        while position < directory.end {
            guard UInt64(records.count) < directory.entryCount else {
                throw .malformed("more central directory records than declared")
            }
            let (record, length) = try readCentralRecord(at: position, end: directory.end)
            try collisions.insert(name: record.name, components: record.components, isDirectory: record.isDirectory)
            records.append(record)
            position += length
        }
        guard UInt64(records.count) == directory.entryCount else {
            throw .malformed("fewer central directory records than declared")
        }
        return records
    }

    private func readCentralRecord(at position: UInt64, end: UInt64) throws(ArchiveError) -> (CentralRecord, UInt64) {
        guard end - position >= UInt64(Size.centralHeader) else { throw .truncated("central directory record cut short") }
        var header = LittleEndianCursor(try reader.read(at: position, count: Size.centralHeader))
        guard try header.uint32() == Signature.central else { throw .malformed("bad central directory signature") }
        let versionMadeBy = try header.uint16()
        try header.skip(2)
        let flags = try header.uint16()
        let methodID = try header.uint16()
        try header.skip(4)
        let crc = try header.uint32()
        let compressed32 = try header.uint32()
        let uncompressed32 = try header.uint32()
        let nameLength = Int(try header.uint16())
        let extraLength = Int(try header.uint16())
        let commentLength = Int(try header.uint16())
        let diskStart = try header.uint16()
        try header.skip(2)
        let externalAttributes = try header.uint32()
        let offset32 = try header.uint32()

        let variableLength = UInt64(nameLength + extraLength + commentLength)
        guard end - position - UInt64(Size.centralHeader) >= variableLength else {
            throw .truncated("central directory record cut short")
        }
        let nameBytes = try reader.read(at: position + UInt64(Size.centralHeader), count: nameLength)
        let extra = try reader.read(at: position + UInt64(Size.centralHeader + nameLength), count: extraLength)
        let (name, components) = try EntryName.validate(nameBytes, limits: limits)

        // Bit 0: traditional encryption. Bit 6: strong encryption. Bit 13: encrypted central directory.
        guard flags & 0x2041 == 0 else { throw .encryptedEntry(name) }
        guard let method = ZipEntry.Method(rawValue: methodID) else {
            throw .unsupportedCompression(name, method: methodID)
        }
        let sizes = try Zip64Fields.resolve(
            extra: extra, uncompressed: uncompressed32, compressed: compressed32, offset: offset32, disk: diskStart, name: name
        )
        guard sizes.disk == 0 else { throw .malformed("entry on another disk: \(name)") }
        let isDirectory = try Self.checkType(
            name: name, nameBytes: nameBytes, versionMadeBy: versionMadeBy, externalAttributes: externalAttributes
        )
        if isDirectory, sizes.uncompressed != 0 { throw .malformed("directory with contents: \(name)") }
        if method == .stored, sizes.compressed != sizes.uncompressed {
            throw .malformed("stored entry with differing sizes: \(name)")
        }
        try checkEntryRatio(name: name, compressed: sizes.compressed, uncompressed: sizes.uncompressed)

        let record = CentralRecord(
            nameBytes: nameBytes, name: name, components: components, flags: flags, method: method, crc32: crc,
            compressedSize: sizes.compressed, uncompressedSize: sizes.uncompressed,
            localHeaderOffset: sizes.offset, isDirectory: isDirectory
        )
        return (record, UInt64(Size.centralHeader) + variableLength)
    }

    /// Returns whether the entry is a directory; throws for links and special files.
    private static func checkType(
        name: String, nameBytes: [UInt8], versionMadeBy: UInt16, externalAttributes: UInt32
    ) throws(ArchiveError) -> Bool {
        let trailingSlash = nameBytes.last == UInt8(ascii: "/") || nameBytes.last == UInt8(ascii: "\\")
        // Only Unix (3) and macOS (19) hosts store a mode in the high 16 bits of the external attributes.
        let host = versionMadeBy >> 8
        guard host == 3 || host == 19 else { return trailingSlash }
        switch (externalAttributes >> 16) & 0o170000 {
        case 0o120000: throw .symlinkEntry(name)
        case 0o040000: return true
        case 0, 0o100000: return trailingSlash
        default: throw .specialFileEntry(name)
        }
    }

    // MARK: Limits

    private func checkEntryRatio(name: String, compressed: UInt64, uncompressed: UInt64) throws(ArchiveError) {
        guard uncompressed > limits.entryRatioExemptBytes else { return }
        let (allowed, overflow) = max(compressed, 1).multipliedReportingOverflow(by: limits.maxEntryRatio)
        if !overflow, uncompressed > allowed { throw .entryRatioLimitExceeded(name) }
    }

    private func checkTotals(_ records: [CentralRecord]) throws(ArchiveError) {
        var total: UInt64 = 0
        for record in records {
            let (sum, overflow) = total.addingReportingOverflow(record.uncompressedSize)
            guard !overflow else { throw .totalSizeLimitExceeded(bytes: .max, limit: limits.maxTotalUncompressedBytes) }
            total = sum
        }
        guard total <= limits.maxTotalUncompressedBytes else {
            throw .totalSizeLimitExceeded(bytes: total, limit: limits.maxTotalUncompressedBytes)
        }
        guard total <= limits.uncompressedBudget(forArchiveBytes: reader.length) else {
            throw .totalRatioLimitExceeded(bytes: total, archiveBytes: reader.length, ratio: limits.maxTotalRatio)
        }
    }

    // MARK: Local headers

    /// Checks each local header against its central record and that no two entries share bytes.
    private func resolveLocalHeaders(_ records: [CentralRecord], dataLimit: UInt64) throws(ArchiveError) -> [ZipEntry] {
        var entries: [ZipEntry] = []
        entries.reserveCapacity(records.count)
        for record in records {
            let dataOffset = try readLocalHeader(for: record, dataLimit: dataLimit)
            entries.append(ZipEntry(
                name: record.name, pathComponents: record.components, method: record.method,
                compressedSize: record.compressedSize, uncompressedSize: record.uncompressedSize,
                crc32: record.crc32, isDirectory: record.isDirectory,
                localHeaderOffset: record.localHeaderOffset, dataOffset: dataOffset
            ))
        }
        let ordered = entries.sorted { $0.localHeaderOffset < $1.localHeaderOffset }
        for (previous, next) in zip(ordered, ordered.dropFirst())
        where previous.dataOffset + previous.compressedSize > next.localHeaderOffset {
            throw .overlappingEntries(next.name)
        }
        return entries
    }

    /// Returns the data offset for `record` after checking its local header agrees with the central directory.
    private func readLocalHeader(for record: CentralRecord, dataLimit: UInt64) throws(ArchiveError) -> UInt64 {
        let offset = record.localHeaderOffset
        guard offset < dataLimit, dataLimit - offset >= UInt64(Size.localHeader) else {
            throw .malformed("local header outside the data area: \(record.name)")
        }
        var header = LittleEndianCursor(try reader.read(at: offset, count: Size.localHeader))
        guard try header.uint32() == Signature.local else { throw .headerMismatch(record.name) }
        try header.skip(2)
        let flags = try header.uint16()
        let method = try header.uint16()
        try header.skip(4)
        let crc = try header.uint32()
        let compressed = try header.uint32()
        let uncompressed = try header.uint32()
        let nameLength = UInt64(try header.uint16())
        let extraLength = UInt64(try header.uint16())

        let dataOffset = offset + UInt64(Size.localHeader) + nameLength + extraLength
        guard dataOffset <= dataLimit, record.compressedSize <= dataLimit - dataOffset else {
            throw .truncated("entry data runs past the central directory: \(record.name)")
        }
        let localName = try reader.read(at: offset + UInt64(Size.localHeader), count: Int(nameLength))
        guard localName == record.nameBytes, method == record.method.rawValue, flags & 0x2041 == 0 else {
            throw .headerMismatch(record.name)
        }
        // Without a data descriptor (bit 3) the local copy of CRC and sizes must agree too.
        if flags & 0x0008 == 0 {
            let sizesAgree = (compressed == 0xFFFF_FFFF || UInt64(compressed) == record.compressedSize)
                && (uncompressed == 0xFFFF_FFFF || UInt64(uncompressed) == record.uncompressedSize)
            guard crc == record.crc32, sizesAgree else { throw .headerMismatch(record.name) }
        }
        return dataOffset
    }
}

/// Values from the ZIP64 extended-information extra field (tag 0x0001), which replace any 32-bit
/// field set to all ones, in this fixed order.
private struct Zip64Fields {
    var uncompressed: UInt64
    var compressed: UInt64
    var offset: UInt64
    var disk: UInt32

    static func resolve(
        extra: [UInt8], uncompressed: UInt32, compressed: UInt32, offset: UInt32, disk: UInt16, name: String
    ) throws(ArchiveError) -> Zip64Fields {
        var fields = Zip64Fields(
            uncompressed: UInt64(uncompressed), compressed: UInt64(compressed), offset: UInt64(offset), disk: UInt32(disk)
        )
        let needsZip64 = uncompressed == 0xFFFF_FFFF || compressed == 0xFFFF_FFFF || offset == 0xFFFF_FFFF || disk == 0xFFFF
        guard needsZip64 else { return fields }
        guard var data = try zip64Data(in: extra) else { throw .malformed("missing ZIP64 extra field: \(name)") }
        do {
            if uncompressed == 0xFFFF_FFFF { fields.uncompressed = try data.uint64() }
            if compressed == 0xFFFF_FFFF { fields.compressed = try data.uint64() }
            if offset == 0xFFFF_FFFF { fields.offset = try data.uint64() }
            if disk == 0xFFFF { fields.disk = try data.uint32() }
        } catch {
            throw .malformed("short ZIP64 extra field: \(name)")
        }
        return fields
    }

    /// The body of the first ZIP64 extra field. Trailing bytes too short for a field header are ignored,
    /// as some tools pad extra fields.
    private static func zip64Data(in extra: [UInt8]) throws(ArchiveError) -> LittleEndianCursor? {
        var cursor = LittleEndianCursor(extra)
        while cursor.remaining >= 4 {
            let tag = try cursor.uint16()
            let size = Int(try cursor.uint16())
            let body = try cursor.bytes(size)
            if tag == 0x0001 { return LittleEndianCursor(body) }
        }
        return nil
    }
}

/// Detects names that would collide on a case-insensitive disk, including a file used as a directory.
private struct CollisionTracker {
    private var files: Set<String> = []
    private var explicitDirectories: Set<String> = []
    private var impliedDirectories: Set<String> = []

    mutating func insert(name: String, components: [String], isDirectory: Bool) throws(ArchiveError) {
        let key = EntryName.collisionKey(components)
        for depth in 1..<components.count {
            let parent = EntryName.collisionKey(components.prefix(depth))
            if files.contains(parent) { throw .duplicateEntry(name) }
            impliedDirectories.insert(parent)
        }
        if isDirectory {
            guard !files.contains(key), explicitDirectories.insert(key).inserted else { throw .duplicateEntry(name) }
        } else {
            guard !explicitDirectories.contains(key), !impliedDirectories.contains(key), files.insert(key).inserted else {
                throw .duplicateEntry(name)
            }
        }
    }
}

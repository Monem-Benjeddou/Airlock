// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation
#if canImport(zlib)
import zlib
#elseif canImport(CZlib)
import CZlib
#endif

/// A hardened, read-only zip reader for hostile input.
///
/// Opening an archive validates its whole structure and enforces ``ExtractionLimits`` on the declared
/// sizes. Reading an entry streams it in bounded chunks, never loading the archive into memory, stops as
/// soon as the inflated data exceeds the declared size, and verifies the CRC-32 at the end.
///
/// Only stored and deflated entries are supported, which is everything Android tooling writes.
public struct ZipArchive: Sendable {
    public static let defaultChunkSize = 64 * 1024

    /// Entries in central-directory order.
    public let entries: [ZipEntry]
    /// Size in bytes of the archive (for a nested archive, of its window in the outer file).
    public let archiveSize: UInt64
    /// 0 for a file opened directly, 1 for an archive inside it, and so on.
    public let nestingDepth: Int
    public let limits: ExtractionLimits
    /// Sum of the declared uncompressed sizes; already checked against `limits`.
    public let totalUncompressedBytes: UInt64

    let source: ByteSource
    private let indexByName: [String: Int]

    /// Opens a zip file on disk. Throws ``ArchiveError/notAnArchive`` if it is not a zip.
    public init(contentsOf url: URL, limits: ExtractionLimits = .default) throws(ArchiveError) {
        try self.init(source: .regularFile(at: url), limits: limits, nestingDepth: 0)
    }

    /// Opens a zip held in memory.
    public init(data: Data, limits: ExtractionLimits = .default) throws(ArchiveError) {
        try self.init(source: .memory(data, offset: 0, length: UInt64(data.count)), limits: limits, nestingDepth: 0)
    }

    init(source: ByteSource, limits: ExtractionLimits, nestingDepth: Int) throws(ArchiveError) {
        guard nestingDepth <= limits.maxNestingDepth else { throw .nestingTooDeep(limit: limits.maxNestingDepth) }
        let reader = try source.makeReader()
        defer { reader.close() }
        entries = try ZipParser(reader: reader, limits: limits).parse()
        self.source = source
        self.limits = limits
        self.nestingDepth = nestingDepth
        archiveSize = source.length
        totalUncompressedBytes = entries.reduce(0) { $0 + $1.uncompressedSize }
        var index: [String: Int] = [:]
        for (position, entry) in entries.enumerated() {
            index[entry.name] = position
        }
        indexByName = index
    }

    /// The entry with exactly this name, e.g. `AndroidManifest.xml`.
    public func entry(named name: String) -> ZipEntry? {
        indexByName[name].map { entries[$0] }
    }

    /// Opens a stored entry (such as an APK inside an APKS) as an archive in place, without extracting it.
    ///
    /// Deflated entries must be extracted first and opened from disk.
    public func openNested(_ entry: ZipEntry) throws(ArchiveError) -> ZipArchive {
        guard !entry.isDirectory, entry.method == .stored else {
            throw .malformed("only stored entries can be opened in place: \(entry.name)")
        }
        let window = source.window(offset: entry.dataOffset, length: entry.compressedSize)
        let nested = try ZipArchive(source: window, limits: limits, nestingDepth: nestingDepth + 1)
        // The inner bytes were never checksummed; do it now so a tampered APK is caught before use.
        try stream(entry) { _ in }
        return nested
    }

    /// Reads a whole entry into memory after checking it is at most `maxBytes` long.
    public func data(for entry: ZipEntry, maxBytes: Int) throws(ArchiveError) -> Data {
        guard entry.uncompressedSize <= UInt64(max(maxBytes, 0)) else {
            throw .entryTooLarge(entry.name, bytes: entry.uncompressedSize, limit: UInt64(max(maxBytes, 0)))
        }
        var result = Data()
        result.reserveCapacity(Int(entry.uncompressedSize))
        try stream(entry) { result.append($0) }
        return result
    }

    /// Streams an entry's uncompressed bytes to `consumer` in chunks of at most `chunkSize`.
    ///
    /// Throws ``ArchiveError/sizeMismatch(_:)`` as soon as more bytes are produced than declared (a lying
    /// zip bomb never inflates past its declared size), and ``ArchiveError/checksumMismatch(_:)`` at the end.
    /// Errors thrown by `consumer` propagate unchanged.
    public func stream(
        _ entry: ZipEntry,
        chunkSize: Int = defaultChunkSize,
        _ consumer: (Data) throws(ArchiveError) -> Void
    ) throws(ArchiveError) {
        let reader = try source.makeReader()
        defer { reader.close() }
        var sink = EntrySink(entry: entry)
        func deliver(_ bytes: UnsafeRawBufferPointer) throws(ArchiveError) {
            try sink.accept(bytes, to: consumer)
        }
        let chunk = max(chunkSize, 1)
        switch entry.method {
        case .stored:
            var offset: UInt64 = 0
            while offset < entry.compressedSize {
                let count = Int(min(UInt64(chunk), entry.compressedSize - offset))
                let bytes = try reader.read(at: entry.dataOffset + offset, count: count)
                var failure: ArchiveError?
                bytes.withUnsafeBytes { buffer in
                    do throws(ArchiveError) { try deliver(buffer) } catch { failure = error }
                }
                if let failure { throw failure }
                offset += UInt64(count)
            }
        case .deflated:
            try Inflater.run(entry: entry, reader: reader, chunkSize: chunk, output: deliver)
        }
        try sink.finish()
    }
}

/// Counts and checksums inflated bytes, enforcing the declared size as they arrive.
struct EntrySink {
    let entry: ZipEntry
    private var produced: UInt64 = 0
    private var crc: uLong = 0

    init(entry: ZipEntry) {
        self.entry = entry
    }

    mutating func accept(_ bytes: UnsafeRawBufferPointer, to consumer: (Data) throws(ArchiveError) -> Void) throws(ArchiveError) {
        guard let base = bytes.baseAddress, !bytes.isEmpty else { return }
        produced += UInt64(bytes.count)
        guard produced <= entry.uncompressedSize else { throw .sizeMismatch(entry.name) }
        crc = crc32(crc, base.assumingMemoryBound(to: Bytef.self), uInt(bytes.count))
        try consumer(Data(bytes))
        if Task.isCancelled { throw .cancelled }
    }

    func finish() throws(ArchiveError) {
        guard produced == entry.uncompressedSize else { throw .sizeMismatch(entry.name) }
        guard UInt32(truncatingIfNeeded: crc) == entry.crc32 else { throw .checksumMismatch(entry.name) }
    }
}

/// Streaming raw-deflate decoder over zlib (`inflateInit2` with negative window bits: no zlib header).
enum Inflater {
    static func run(
        entry: ZipEntry,
        reader: ByteReader,
        chunkSize: Int,
        output deliver: (UnsafeRawBufferPointer) throws(ArchiveError) -> Void
    ) throws(ArchiveError) {
        // zlib keeps a pointer back to the stream, so it must live at a fixed address.
        let stream = UnsafeMutablePointer<z_stream>.allocate(capacity: 1)
        stream.initialize(to: z_stream())
        let output = UnsafeMutablePointer<Bytef>.allocate(capacity: chunkSize)
        let input = UnsafeMutablePointer<Bytef>.allocate(capacity: chunkSize)
        defer {
            stream.deinitialize(count: 1)
            stream.deallocate()
            output.deallocate()
            input.deallocate()
        }
        guard inflateInit2_(stream, -MAX_WBITS, zlibVersion(), Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            throw .fileSystem("zlib could not initialise")
        }
        defer { inflateEnd(stream) }

        var nextOffset = entry.dataOffset
        var remaining = entry.compressedSize
        while true {
            if stream.pointee.avail_in == 0, remaining > 0 {
                let count = Int(min(UInt64(chunkSize), remaining))
                let bytes = try reader.read(at: nextOffset, count: count)
                bytes.withUnsafeBufferPointer { source in
                    if let base = source.baseAddress { input.update(from: base, count: count) }
                }
                stream.pointee.next_in = input
                stream.pointee.avail_in = uInt(count)
                nextOffset += UInt64(count)
                remaining -= UInt64(count)
            }
            stream.pointee.next_out = output
            stream.pointee.avail_out = uInt(chunkSize)
            let status = inflate(stream, Z_NO_FLUSH)
            let produced = chunkSize - Int(stream.pointee.avail_out)
            try deliver(UnsafeRawBufferPointer(start: output, count: produced))

            switch status {
            case Z_STREAM_END:
                // Bytes left after the end of the deflate stream mean the sizes were forged.
                guard stream.pointee.avail_in == 0, remaining == 0 else { throw .corruptData(entry.name) }
                return
            case Z_OK:
                continue
            case Z_BUF_ERROR where remaining > 0 && stream.pointee.avail_in == 0:
                continue
            default:
                // Z_DATA_ERROR, Z_NEED_DICT, Z_MEM_ERROR, or Z_BUF_ERROR with no input left: truncated stream.
                throw .corruptData(entry.name)
            }
        }
    }
}

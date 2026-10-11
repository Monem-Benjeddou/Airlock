// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation
import zlib

/// Writes zip files for tests, including deliberately malicious ones.
///
/// Independent of `AirlockArchive` so the reader is never tested against itself. Every field the reader
/// validates can be overridden to craft lies: sizes, CRCs, offsets, attributes, names in either header.
public struct ZipBuilder: Sendable {
    public enum Method: Sendable, Equatable {
        case stored
        case deflated
        /// Writes this method id with the data stored verbatim (for unsupported-method tests).
        case raw(UInt16)
    }

    public struct Entry: Sendable {
        public var nameBytes: [UInt8]
        public var data: [UInt8]
        public var method: Method
        public var flags: UInt16 = 0
        /// Host 3 (Unix) in the high byte, as Info-ZIP writes.
        public var versionMadeBy: UInt16 = 0x031E
        public var externalAttributes: UInt32 = 0o100644 << 16
        public var crcOverride: UInt32?
        public var compressedSizeOverride: UInt64?
        public var uncompressedSizeOverride: UInt64?
        /// Name written in the local header instead of `nameBytes`.
        public var localNameOverride: [UInt8]?
        /// Method written in the local header instead of `method`.
        public var localMethodOverride: UInt16?
        /// When false no local record is written; pair with `localHeaderOffsetOverride`.
        public var writesLocalRecord = true
        public var localHeaderOffsetOverride: UInt64?
        /// Extra field bytes appended to the central directory record.
        public var centralExtra: [UInt8] = []
        public var diskNumberStart: UInt16 = 0

        public init(name: String, data: [UInt8], method: Method = .stored) {
            nameBytes = Array(name.utf8)
            self.data = data
            self.method = method
        }

        public init(nameBytes: [UInt8], data: [UInt8], method: Method = .stored) {
            self.nameBytes = nameBytes
            self.data = data
            self.method = method
        }

        public var payload: [UInt8] {
            method == .deflated ? ZipBuilder.deflate(data) : data
        }

        var methodID: UInt16 {
            switch method {
            case .stored: 0
            case .deflated: 8
            case .raw(let id): id
            }
        }
    }

    public var entries: [Entry]
    public var comment: [UInt8] = []
    /// Always write sizes and offsets through ZIP64 extra fields and the ZIP64 end records.
    public var zip64 = false
    public var entryCountOverride: UInt64?
    public var centralDirectoryOffsetOverride: UInt64?
    public var centralDirectorySizeOverride: UInt64?
    public var eocdDiskNumber: UInt16 = 0
    /// Bytes inserted between the last local record and the central directory (like an APK signing block).
    public var gapBeforeCentralDirectory: [UInt8] = []
    public var prefix: [UInt8] = []

    public init(entries: [Entry] = []) {
        self.entries = entries
    }

    public init(files: [(String, [UInt8])], method: Method = .stored) {
        entries = files.map { Entry(name: $0.0, data: $0.1, method: method) }
    }

    public mutating func add(_ name: String, _ data: [UInt8], method: Method = .stored) {
        entries.append(Entry(name: name, data: data, method: method))
    }

    public mutating func add(_ name: String, _ text: String, method: Method = .stored) {
        add(name, Array(text.utf8), method: method)
    }

    // MARK: Building

    public func build() -> Data {
        var out = prefix
        var offsets: [UInt64] = []
        for entry in entries {
            offsets.append(entry.localHeaderOffsetOverride ?? UInt64(out.count))
            if entry.writesLocalRecord {
                out += localRecord(entry)
            }
        }
        out += gapBeforeCentralDirectory
        let cdOffset = UInt64(out.count)
        for (entry, offset) in zip(entries, offsets) {
            out += centralRecord(entry, offset: offset)
        }
        let cdSize = UInt64(out.count) - cdOffset
        out += endRecords(cdOffset: cdOffset, cdSize: cdSize, endOffset: UInt64(out.count))
        return Data(out)
    }

    public func write(to url: URL) throws {
        try build().write(to: url)
    }

    /// The local file header plus data for `entry`, for embedding inside another entry.
    public func localRecord(_ entry: Entry) -> [UInt8] {
        let payload = entry.payload
        var out: [UInt8] = []
        let name = entry.localNameOverride ?? entry.nameBytes
        out.le32(0x0403_4B50)
        out.le16(zip64 ? 45 : 20)
        out.le16(entry.flags)
        out.le16(entry.localMethodOverride ?? entry.methodID)
        out.le16(0)
        out.le16(0)
        out.le32(entry.crcOverride ?? Self.crc32(entry.data))
        let compressed = entry.compressedSizeOverride ?? UInt64(payload.count)
        let uncompressed = entry.uncompressedSizeOverride ?? UInt64(entry.data.count)
        var extra: [UInt8] = []
        if zip64 {
            out.le32(0xFFFF_FFFF)
            out.le32(0xFFFF_FFFF)
            extra.le16(0x0001)
            extra.le16(16)
            extra.le64(uncompressed)
            extra.le64(compressed)
        } else {
            out.le32(UInt32(truncatingIfNeeded: compressed))
            out.le32(UInt32(truncatingIfNeeded: uncompressed))
        }
        out.le16(UInt16(name.count))
        out.le16(UInt16(extra.count))
        out += name
        out += extra
        out += payload
        return out
    }

    private func centralRecord(_ entry: Entry, offset: UInt64) -> [UInt8] {
        let payload = entry.payload
        let compressed = entry.compressedSizeOverride ?? UInt64(payload.count)
        let uncompressed = entry.uncompressedSizeOverride ?? UInt64(entry.data.count)
        var extra: [UInt8] = []
        if zip64 {
            extra.le16(0x0001)
            extra.le16(24)
            extra.le64(uncompressed)
            extra.le64(compressed)
            extra.le64(offset)
        }
        extra += entry.centralExtra
        var out: [UInt8] = []
        out.le32(0x0201_4B50)
        out.le16(entry.versionMadeBy)
        out.le16(zip64 ? 45 : 20)
        out.le16(entry.flags)
        out.le16(entry.methodID)
        out.le16(0)
        out.le16(0)
        out.le32(entry.crcOverride ?? Self.crc32(entry.data))
        out.le32(zip64 ? 0xFFFF_FFFF : UInt32(truncatingIfNeeded: compressed))
        out.le32(zip64 ? 0xFFFF_FFFF : UInt32(truncatingIfNeeded: uncompressed))
        out.le16(UInt16(entry.nameBytes.count))
        out.le16(UInt16(extra.count))
        out.le16(0)
        out.le16(entry.diskNumberStart)
        out.le16(0)
        out.le32(entry.externalAttributes)
        out.le32(zip64 ? 0xFFFF_FFFF : UInt32(truncatingIfNeeded: offset))
        out += entry.nameBytes
        out += extra
        return out
    }

    private func endRecords(cdOffset realOffset: UInt64, cdSize realSize: UInt64, endOffset: UInt64) -> [UInt8] {
        let count = entryCountOverride ?? UInt64(entries.count)
        let cdOffset = centralDirectoryOffsetOverride ?? realOffset
        let cdSize = centralDirectorySizeOverride ?? realSize
        var out: [UInt8] = []
        if zip64 {
            out.le32(0x0606_4B50)
            out.le64(44)
            out.le16(45)
            out.le16(45)
            out.le32(0)
            out.le32(0)
            out.le64(count)
            out.le64(count)
            out.le64(cdSize)
            out.le64(cdOffset)
            out.le32(0x0706_4B50)
            out.le32(0)
            out.le64(endOffset)
            out.le32(1)
        }
        out.le32(0x0605_4B50)
        out.le16(eocdDiskNumber)
        out.le16(0)
        out.le16(zip64 ? 0xFFFF : UInt16(truncatingIfNeeded: count))
        out.le16(zip64 ? 0xFFFF : UInt16(truncatingIfNeeded: count))
        out.le32(zip64 ? 0xFFFF_FFFF : UInt32(truncatingIfNeeded: cdSize))
        out.le32(zip64 ? 0xFFFF_FFFF : UInt32(truncatingIfNeeded: cdOffset))
        out.le16(UInt16(comment.count))
        out += comment
        return out
    }

    // MARK: Crafted entries

    /// A Unix symlink entry pointing at `target`.
    public static func symlink(_ name: String, target: String) -> Entry {
        var entry = Entry(name: name, data: Array(target.utf8))
        entry.externalAttributes = 0o120777 << 16
        return entry
    }

    public static func directory(_ name: String) -> Entry {
        var entry = Entry(name: name, data: [])
        entry.externalAttributes = 0o040755 << 16
        return entry
    }

    // MARK: zlib helpers

    public static func crc32(_ bytes: [UInt8]) -> UInt32 {
        let value = bytes.withUnsafeBufferPointer { buffer in
            zlib.crc32(0, buffer.baseAddress, uInt(buffer.count))
        }
        return UInt32(truncatingIfNeeded: value)
    }

    /// Raw deflate (no zlib header), as zip uses.
    public static func deflate(_ bytes: [UInt8]) -> [UInt8] {
        var stream = z_stream()
        let initStatus = deflateInit2_(
            &stream, Z_BEST_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY,
            zlibVersion(), Int32(MemoryLayout<z_stream>.size)
        )
        precondition(initStatus == Z_OK, "deflateInit2 failed")
        defer { deflateEnd(&stream) }
        var output = [UInt8](repeating: 0, count: Int(deflateBound(&stream, uLong(bytes.count))) + 64)
        var input = bytes
        let produced = input.withUnsafeMutableBufferPointer { inBuffer in
            output.withUnsafeMutableBufferPointer { outBuffer in
                stream.next_in = inBuffer.baseAddress
                stream.avail_in = uInt(inBuffer.count)
                stream.next_out = outBuffer.baseAddress
                stream.avail_out = uInt(outBuffer.count)
                let status = zlib.deflate(&stream, Z_FINISH)
                precondition(status == Z_STREAM_END, "deflate did not finish")
                return outBuffer.count - Int(stream.avail_out)
            }
        }
        return Array(output.prefix(produced))
    }
}

// MARK: Ready-made packages

public extension ZipBuilder {
    /// A minimal APK: a placeholder manifest and dex. The manifest is not real binary XML.
    static func apk(extraFiles: [(String, [UInt8])] = []) -> Data {
        var builder = ZipBuilder()
        builder.add("AndroidManifest.xml", [UInt8](repeating: 0x03, count: 64), method: .deflated)
        builder.add("classes.dex", Array("dex\n035\0".utf8) + [UInt8](repeating: 7, count: 32), method: .deflated)
        builder.add("resources.arsc", [UInt8](repeating: 2, count: 16))
        for (name, data) in extraFiles {
            builder.add(name, data)
        }
        return builder.build()
    }

    /// A container zip holding the given APK names, each a stored minimal APK.
    static func container(apks: [String], extraFiles: [(String, [UInt8])] = []) -> ZipBuilder {
        let apkBytes = [UInt8](apk())
        var builder = ZipBuilder()
        for name in apks {
            builder.add(name, apkBytes)
        }
        for (name, data) in extraFiles {
            builder.add(name, data)
        }
        return builder
    }
}

/// Deterministic RNG for property tests (SplitMix64), so failures reproduce from the seed.
public struct SplitMix64: RandomNumberGenerator, Sendable {
    private var state: UInt64

    public init(seed: UInt64) {
        state = seed
    }

    public mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var value = state
        value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
        value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
        return value ^ (value >> 31)
    }
}

/// A fresh temporary directory, removed by `remove()`.
public struct TemporaryDirectory: Sendable {
    public let url: URL

    public init() throws {
        let base = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true).resolvingSymlinksInPath()
        url = base.appendingPathComponent("airlock-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }

    public func file(_ name: String) -> URL {
        url.appendingPathComponent(name)
    }

    public func write(_ data: Data, as name: String) throws -> URL {
        let target = file(name)
        try data.write(to: target)
        return target
    }

    public func remove() {
        try? FileManager.default.removeItem(at: url)
    }
}

extension [UInt8] {
    mutating func le16(_ value: UInt16) {
        append(UInt8(value & 0xFF))
        append(UInt8(value >> 8))
    }

    mutating func le32(_ value: UInt32) {
        for shift in stride(from: 0, to: 32, by: 8) {
            append(UInt8((value >> UInt32(shift)) & 0xFF))
        }
    }

    mutating func le64(_ value: UInt64) {
        for shift in stride(from: 0, to: 64, by: 8) {
            append(UInt8((value >> UInt64(shift)) & 0xFF))
        }
    }
}

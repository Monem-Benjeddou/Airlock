// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// A `ResStringPool` chunk, decoded lazily: only strings that elements and attributes refer to are read.
///
/// Decoding is cached per string offset and charged against a budget proportional to the document size,
/// so a pool whose offsets all point at one huge (or overlapping) string cannot cause quadratic work.
struct AXMLStringPool {
    private static let utf8Flag: UInt32 = 1 << 8

    private let reader: BoundedReader<AXMLError>
    private let offsetsStart: Int
    private let stringsStart: Int
    private let dataEnd: Int
    private let isUTF8: Bool
    let count: Int
    private var cache: [Int: String] = [:]
    private var budget: Int

    /// Parses the pool header at `chunk` (chunk size and header size already validated by the caller).
    init(reader: BoundedReader<AXMLError>, chunk: Int, headerSize: Int, size: Int, maxStrings: Int) throws(AXMLError) {
        guard headerSize >= 28 else { throw .invalidStringPool("header size \(headerSize)") }
        let stringCount = Int(try reader.u32(at: chunk + 8))
        let styleCount = Int(try reader.u32(at: chunk + 12))
        let flags = try reader.u32(at: chunk + 16)
        let stringsStart = Int(try reader.u32(at: chunk + 20))
        guard stringCount <= maxStrings, styleCount <= maxStrings else {
            throw .invalidStringPool("\(stringCount) strings, \(styleCount) styles")
        }
        guard (stringCount + styleCount) * 4 <= size - headerSize else {
            throw .invalidStringPool("offset table overruns the chunk")
        }
        if stringCount > 0, stringsStart < headerSize + stringCount * 4 || stringsStart >= size {
            throw .invalidStringPool("strings start \(stringsStart)")
        }
        self.reader = reader
        self.offsetsStart = chunk + headerSize
        self.stringsStart = chunk + stringsStart
        self.dataEnd = chunk + size
        self.isUTF8 = flags & Self.utf8Flag != 0
        self.count = stringCount
        self.budget = 4 * reader.count + 65_536
    }

    /// The string at `index`; throws for indices outside the pool or malformed string data.
    mutating func string(at index: UInt32) throws(AXMLError) -> String {
        guard Int(index) < count else { throw .stringIndexOutOfRange(index) }
        let relative = Int(try reader.u32(at: offsetsStart + Int(index) * 4))
        let offset = stringsStart + relative
        guard relative < dataEnd - stringsStart else { throw .invalidStringPool("string \(index) offset \(relative)") }
        if let cached = cache[offset] { return cached }
        let value = isUTF8 ? try utf8String(at: offset) : try utf16String(at: offset)
        cache[offset] = value
        return value
    }

    /// The string at `index`, or nil for the "no string" index `0xFFFFFFFF`.
    mutating func optionalString(at index: UInt32) throws(AXMLError) -> String? {
        index == UInt32.max ? nil : try string(at: index)
    }

    /// UTF-16: a `u16` length (two units with the high bit set for lengths ≥ 0x8000), then the code units.
    private mutating func utf16String(at offset: Int) throws(AXMLError) -> String {
        var length = Int(try reader.u16(at: offset))
        var start = offset + 2
        if length & 0x8000 != 0 {
            length = ((length & 0x7FFF) << 16) | Int(try reader.u16(at: start))
            start += 2
        }
        guard length <= (dataEnd - start) / 2 else { throw .invalidStringPool("string at \(offset) overruns the pool") }
        try charge(length * 2)
        let units = (0..<length).map { index in
            UInt16(littleEndian: reader.bytes.loadUnaligned(fromByteOffset: start + index * 2, as: UInt16.self))
        }
        return String(decoding: units, as: UTF16.self)
    }

    /// UTF-8: the UTF-16 length then the byte length, each one byte or two with the high bit set, then the bytes.
    private mutating func utf8String(at offset: Int) throws(AXMLError) -> String {
        var cursor = offset
        _ = try utf8Length(at: &cursor)
        let length = try utf8Length(at: &cursor)
        guard length <= dataEnd - cursor else { throw .invalidStringPool("string at \(offset) overruns the pool") }
        try charge(length)
        return String(decoding: try reader.slice(at: cursor, count: length), as: Unicode.UTF8.self)
    }

    private func utf8Length(at cursor: inout Int) throws(AXMLError) -> Int {
        guard cursor < dataEnd else { throw .truncated(offset: cursor) }
        let first = Int(try reader.u8(at: cursor))
        cursor += 1
        guard first & 0x80 != 0 else { return first }
        guard cursor < dataEnd else { throw .truncated(offset: cursor) }
        let second = Int(try reader.u8(at: cursor))
        cursor += 1
        return ((first & 0x7F) << 8) | second
    }

    private mutating func charge(_ bytes: Int) throws(AXMLError) {
        budget -= bytes + 16
        guard budget >= 0 else { throw .decodeBudgetExceeded }
    }
}

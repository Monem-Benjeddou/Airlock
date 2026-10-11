// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Why a `classes*.dex` file was rejected.
public enum DexError: Error, Hashable, Sendable {
    /// The input is larger than ``DexScanner/Limits/maxFileSize``.
    case tooLarge(Int)
    /// The magic is not `dex\n0NN\0`.
    case notDex
    /// The header is inconsistent: wrong size, byte order or an id table outside the file.
    case invalidHeader(String)
    /// An id table holds more entries than the limits allow.
    case tooManyEntries(table: String, count: Int)
    /// A read at this byte offset would run past the end of the file.
    case truncated(offset: Int)
    /// A type descriptor's string is malformed (bad index, no terminator, or too long).
    case invalidString(index: Int)
}

/// Reads class descriptors out of a DEX file without parsing code.
///
/// Only the header, `type_ids`, the `string_ids` entries they point at and those strings' MUTF-8 data are
/// touched, so a 100 MB file is scanned in a few milliseconds. Every index and offset is checked; the type
/// table is capped at the 65 536 entries the format can address.
public enum DexScanner {
    public enum Limits {
        public static let maxFileSize = 512 * 1024 * 1024
        /// `type_idx` is a `u16` in instructions, so a valid file never has more types.
        public static let maxTypeIDs = 65_536
        public static let maxStringIDs = 16 * 1024 * 1024
        public static let maxDescriptorLength = 4_096
        /// Package prefixes are reported at these depths (number of package segments): `com/facebook/` is
        /// depth 2, AdMob's `com/google/android/gms/ads/` is depth 5.
        public static let prefixDepths = 2...5
        /// At most this many prefixes are returned per call; once reached, further prefixes are dropped.
        public static let maxPrefixes = 50_000
    }

    /// Every class type descriptor (`Lcom/facebook/ads/AdView;`) referenced by the file. Array types are
    /// reported as their element class.
    public static func classDescriptors(in data: Data) throws(DexError) -> [String] {
        var descriptors: [String] = []
        try forEachClassDescriptor(in: data) { bytes in
            descriptors.append(String(decoding: bytes, as: Unicode.UTF8.self))
        }
        return descriptors
    }

    /// Package prefixes at depths 2…5 with a trailing slash (`com/facebook/`, `com/facebook/ads/`), for
    /// tracker matching by exact set membership. The class name itself is never included, and classes in
    /// packages shallower than two segments contribute nothing. The set holds at most
    /// ``Limits/maxPrefixes`` entries.
    public static func packagePrefixes(in data: Data) throws(DexError) -> Set<String> {
        var prefixes = Set<String>()
        var previousPackage: [UInt8] = []
        try forEachClassDescriptor(in: data) { descriptor in
            // Body without the leading `L` and trailing `;`: com/facebook/ads/AdView
            let body = UnsafeRawBufferPointer(rebasing: descriptor[1..<(descriptor.count - 1)])
            guard let lastSlash = body.lastIndex(of: UInt8(ascii: "/")) else { return }
            let package = UnsafeRawBufferPointer(rebasing: body[0...lastSlash])
            // Descriptors are sorted, so classes of one package arrive together; skip repeats cheaply.
            guard prefixes.count < Limits.maxPrefixes, !package.elementsEqual(previousPackage) else { return }
            previousPackage = Array(package)
            var depth = 0
            for (index, byte) in package.enumerated() where byte == UInt8(ascii: "/") {
                depth += 1
                if Limits.prefixDepths.contains(depth), prefixes.count < Limits.maxPrefixes {
                    prefixes.insert(String(decoding: UnsafeRawBufferPointer(rebasing: package[0...index]), as: Unicode.UTF8.self))
                }
                if depth >= Limits.prefixDepths.upperBound { break }
            }
        }
        return prefixes
    }

    /// The union of ``packagePrefixes(in:)`` over several files, also capped at ``Limits/maxPrefixes`` (`classes.dex`, `classes2.dex`, …).
    public static func packagePrefixes(in dexFiles: [Data]) throws(DexError) -> Set<String> {
        var combined = Set<String>()
        for file in dexFiles {
            for prefix in try packagePrefixes(in: file) where combined.count < Limits.maxPrefixes {
                combined.insert(prefix)
            }
        }
        return combined
    }

    // MARK: - Scanning

    private static let headerSize = 0x70
    private static let endianConstant: UInt32 = 0x1234_5678

    /// Calls `body` with the bytes of each class descriptor (`L…;`, array dimensions stripped).
    private static func forEachClassDescriptor(
        in data: Data, _ body: (UnsafeRawBufferPointer) -> Void
    ) throws(DexError) {
        guard data.count <= Limits.maxFileSize else { throw .tooLarge(data.count) }
        let result: Result<Void, DexError> = data.withUnsafeBytes { buffer in
            let reader = BoundedReader<DexError>(buffer) { .truncated(offset: $0) }
            return Result { () throws(DexError) in try scan(reader, body) }
        }
        try result.get()
    }

    private static func scan(_ reader: BoundedReader<DexError>, _ body: (UnsafeRawBufferPointer) -> Void) throws(DexError) {
        try checkMagic(reader)
        guard try reader.u32(at: 36) >= UInt32(headerSize) else { throw .invalidHeader("header size") }
        guard try reader.u32(at: 40) == endianConstant else { throw .invalidHeader("byte order") }
        let stringCount = Int(try reader.u32(at: 56))
        let stringsOffset = Int(try reader.u32(at: 60))
        let typeCount = Int(try reader.u32(at: 64))
        let typesOffset = Int(try reader.u32(at: 68))
        guard stringCount <= Limits.maxStringIDs else { throw .tooManyEntries(table: "string_ids", count: stringCount) }
        guard typeCount <= Limits.maxTypeIDs else { throw .tooManyEntries(table: "type_ids", count: typeCount) }
        do {
            try reader.check(stringsOffset, stringCount * 4)
            try reader.check(typesOffset, typeCount * 4)
        } catch {
            throw .invalidHeader("id table outside the file")
        }
        for type in 0..<typeCount {
            let stringIndex = Int(try reader.u32(at: typesOffset + type * 4))
            guard stringIndex < stringCount else { throw .invalidString(index: stringIndex) }
            let dataOffset = Int(try reader.u32(at: stringsOffset + stringIndex * 4))
            let descriptor = try descriptorBytes(reader, at: dataOffset, index: stringIndex)
            var start = 0
            while start < descriptor.count, descriptor[start] == UInt8(ascii: "[") { start += 1 }
            let element = UnsafeRawBufferPointer(rebasing: descriptor[start...])
            if element.count >= 3, element[0] == UInt8(ascii: "L"), element[element.count - 1] == UInt8(ascii: ";") {
                body(element)
            }
        }
    }

    /// `dex\n` + three ASCII digits + NUL.
    private static func checkMagic(_ reader: BoundedReader<DexError>) throws(DexError) {
        guard reader.count >= headerSize else { throw .notDex }
        let magic = Array(try reader.slice(at: 0, count: 8))
        guard magic[0..<4].elementsEqual("dex\n".utf8), magic[4...6].allSatisfy({ (0x30...0x39).contains($0) }), magic[7] == 0 else {
            throw .notDex
        }
    }

    /// `string_data_item`: ULEB128 UTF-16 length, then NUL-terminated MUTF-8 bytes (terminator excluded).
    private static func descriptorBytes(
        _ reader: BoundedReader<DexError>, at offset: Int, index: Int
    ) throws(DexError) -> UnsafeRawBufferPointer {
        var cursor = offset
        var shift = 0
        while true {
            let byte = try reader.u8(at: cursor)
            cursor += 1
            guard byte & 0x80 != 0 else { break }
            shift += 7
            guard shift < 35 else { throw .invalidString(index: index) }
        }
        let available = min(reader.count - cursor, Limits.maxDescriptorLength + 1)
        let window = try reader.slice(at: cursor, count: available)
        guard let end = window.firstIndex(of: 0) else { throw .invalidString(index: index) }
        return UnsafeRawBufferPointer(rebasing: window[0..<end])
    }
}

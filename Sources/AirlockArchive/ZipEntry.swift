// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// One validated entry from a zip central directory.
///
/// Every `ZipEntry` a ``ZipArchive`` hands out has already passed the name, type, size and overlap
/// checks, so callers can use ``pathComponents`` to build paths without re-validating.
public struct ZipEntry: Hashable, Sendable {
    public enum Method: UInt16, Hashable, Sendable {
        case stored = 0
        case deflated = 8
    }

    /// The name as stored in the archive (UTF-8).
    public let name: String
    /// `name` split on `/` and `\`, without empty components. Never contains `.` or `..`.
    public let pathComponents: [String]
    public let method: Method
    public let compressedSize: UInt64
    public let uncompressedSize: UInt64
    public let crc32: UInt32
    public let isDirectory: Bool
    /// Position of the local file header, relative to the start of the archive.
    public let localHeaderOffset: UInt64
    /// Position of the first data byte, relative to the start of the archive.
    let dataOffset: UInt64

    /// The last path component, e.g. `base.apk` for `splits/base.apk`.
    public var fileName: String { pathComponents.last ?? name }

    /// `true` when the entry sits at the archive root (`AndroidManifest.xml`, not `res/AndroidManifest.xml`).
    public var isAtRoot: Bool { pathComponents.count == 1 }
}

/// Entry-name safety rules, shared by the zip reader and the folder scanner.
enum EntryName {
    /// Validates raw name bytes and returns the decoded name and its components.
    static func validate(_ bytes: [UInt8], limits: ExtractionLimits) throws(ArchiveError) -> (String, [String]) {
        guard let name = String(bytes: bytes, encoding: .utf8) else {
            throw .unsafeEntryName(escaped(bytes), .notUTF8)
        }
        guard !bytes.isEmpty else { throw .unsafeEntryName(name, .empty) }
        guard !bytes.contains(0) else { throw .unsafeEntryName(name, .containsNUL) }
        guard bytes.count <= limits.maxNameBytes else { throw .unsafeEntryName(name, .tooLong) }

        // Work on bytes, not Characters: a combining mark after `/` would otherwise merge into one grapheme
        // and hide the separator. Backslashes count as separators, as Windows tools treat them that way.
        let unified = bytes.map { $0 == UInt8(ascii: "\\") ? UInt8(ascii: "/") : $0 }
        if unified[0] == UInt8(ascii: "/") { throw .unsafeEntryName(name, .absolutePath) }
        if unified.count >= 2, unified[1] == UInt8(ascii: ":"), isASCIILetter(unified[0]) {
            throw .unsafeEntryName(name, .driveLetter)
        }

        var parts = unified.split(separator: UInt8(ascii: "/"), omittingEmptySubsequences: false)
        if parts.count > 1, parts.last?.isEmpty == true {
            parts.removeLast()  // A trailing slash marks a directory.
        }
        var components: [String] = []
        for part in parts {
            if part.elementsEqual("..".utf8) { throw .unsafeEntryName(name, .parentTraversal) }
            if part.isEmpty || part.elementsEqual(".".utf8) { throw .unsafeEntryName(name, .redundantComponent) }
            // Splitting valid UTF-8 at an ASCII byte always leaves valid UTF-8.
            guard let component = String(bytes: part, encoding: .utf8) else { throw .unsafeEntryName(name, .notUTF8) }
            components.append(component)
        }
        guard components.count <= limits.maxPathDepth else { throw .unsafeEntryName(name, .tooDeep) }
        return (name, components)
    }

    /// The key two names collide on when written to a case- and normalization-insensitive disk (APFS, HFS+).
    static func collisionKey(_ components: some Sequence<String>) -> String {
        components.joined(separator: "/").decomposedStringWithCanonicalMapping.lowercased()
    }

    /// A printable form of a name that is not valid UTF-8, for errors and logs.
    private static func escaped(_ bytes: [UInt8]) -> String {
        bytes.map { byte in
            (0x20..<0x7F).contains(byte) ? String(UnicodeScalar(byte)) : "\\x" + String(byte, radix: 16)
        }.joined()
    }

    private static func isASCIILetter(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte) || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte)
    }
}

/// Little-endian reads over a byte array, throwing instead of trapping on short input.
struct LittleEndianCursor {
    private let bytes: [UInt8]
    private(set) var position: Int

    init(_ bytes: [UInt8], position: Int = 0) {
        self.bytes = bytes
        self.position = position
    }

    var remaining: Int { bytes.count - position }

    mutating func skip(_ count: Int) throws(ArchiveError) {
        guard count >= 0, count <= remaining else { throw .truncated("record shorter than declared") }
        position += count
    }

    mutating func bytes(_ count: Int) throws(ArchiveError) -> [UInt8] {
        let start = position
        try skip(count)
        return Array(bytes[start..<position])
    }

    mutating func uint16() throws(ArchiveError) -> UInt16 {
        UInt16(truncatingIfNeeded: try integer(width: 2))
    }

    mutating func uint32() throws(ArchiveError) -> UInt32 {
        UInt32(truncatingIfNeeded: try integer(width: 4))
    }

    mutating func uint64() throws(ArchiveError) -> UInt64 {
        try integer(width: 8)
    }

    private mutating func integer(width: Int) throws(ArchiveError) -> UInt64 {
        let start = position
        try skip(width)
        var value: UInt64 = 0
        for index in (start..<position).reversed() {
            value = value << 8 | UInt64(bytes[index])
        }
        return value
    }
}

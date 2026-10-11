// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Why a DER structure (certificate, public key or PKCS#7 block) was rejected.
public enum DERError: Error, Hashable, Sendable {
    /// The input ended inside a tag, length or value.
    case truncated
    /// Indefinite lengths, high tag numbers, oversized lengths or an unexpected tag.
    case malformed(String)
    /// The structure nests deeper or holds more elements than allowed.
    case limitExceeded
}

/// One DER TLV: tag byte, the value bytes and the whole encoding (tag + length + value).
struct DERElement: Hashable {
    let tag: UInt8
    let value: Data
    let encoded: Data

    var isConstructed: Bool { tag & 0x20 != 0 }

    static let integer: UInt8 = 0x02
    static let bitString: UInt8 = 0x03
    static let octetString: UInt8 = 0x04
    static let null: UInt8 = 0x05
    static let objectIdentifier: UInt8 = 0x06
    static let utcTime: UInt8 = 0x17
    static let generalizedTime: UInt8 = 0x18
    static let sequence: UInt8 = 0x30
    static let set: UInt8 = 0x31

    /// Context-specific tag `[number]`, constructed.
    static func context(_ number: UInt8) -> UInt8 { 0xA0 | number }

    /// Children of a constructed element.
    func children() throws(DERError) -> [DERElement] {
        guard isConstructed else { throw .malformed("tag \(tag) is not constructed") }
        return try DERParser.elements(in: value)
    }

    /// Children, requiring this element to carry `tag`.
    func children(expecting expected: UInt8) throws(DERError) -> [DERElement] {
        guard tag == expected else { throw .malformed("expected tag \(expected), found \(tag)") }
        return try children()
    }

    /// Dotted form of an OBJECT IDENTIFIER (`1.2.840.113549.1.1.1`).
    func objectIdentifier() throws(DERError) -> String {
        guard tag == Self.objectIdentifier, !value.isEmpty, value.count <= 64 else { throw .malformed("object identifier") }
        let bytes = [UInt8](value)
        var parts: [UInt64] = []
        var current: UInt64 = 0
        for byte in bytes {
            guard current <= UInt64.max >> 7 else { throw .malformed("object identifier arc") }
            current = (current << 7) | UInt64(byte & 0x7F)
            if byte & 0x80 == 0 {
                parts.append(current)
                current = 0
            }
        }
        guard bytes.last.map({ $0 & 0x80 == 0 }) == true, let first = parts.first else { throw .malformed("object identifier") }
        let head: [UInt64] = first < 80 ? [first / 40, first % 40] : [2, first - 80]
        return (head + parts.dropFirst()).map(String.init).joined(separator: ".")
    }
}

/// A minimal, bounded DER reader: definite lengths only, single-byte tags, at most 4-byte lengths.
enum DERParser {
    static let maxElements = 4_096

    /// Parses exactly one element spanning all of `data`.
    static func single(_ data: Data) throws(DERError) -> DERElement {
        let elements = try elements(in: data)
        guard elements.count == 1, let element = elements.first else { throw .malformed("expected one element") }
        return element
    }

    /// Parses the consecutive elements that make up `data`.
    static func elements(in data: Data) throws(DERError) -> [DERElement] {
        let bytes = [UInt8](data)
        var elements: [DERElement] = []
        var offset = 0
        while offset < bytes.count {
            guard elements.count < maxElements else { throw .limitExceeded }
            let (element, next) = try element(in: bytes, at: offset)
            elements.append(element)
            offset = next
        }
        return elements
    }

    private static func element(in bytes: [UInt8], at start: Int) throws(DERError) -> (DERElement, Int) {
        var offset = start
        guard offset + 2 <= bytes.count else { throw .truncated }
        let tag = bytes[offset]
        guard tag & 0x1F != 0x1F else { throw .malformed("high tag number") }
        var length = Int(bytes[offset + 1])
        offset += 2
        if length & 0x80 != 0 {
            let lengthBytes = length & 0x7F
            guard (1...4).contains(lengthBytes) else { throw .malformed("length of length \(lengthBytes)") }
            guard offset + lengthBytes <= bytes.count else { throw .truncated }
            length = 0
            for byte in bytes[offset..<(offset + lengthBytes)] {
                length = (length << 8) | Int(byte)
            }
            offset += lengthBytes
        }
        guard length <= bytes.count - offset else { throw .truncated }
        let end = offset + length
        let element = DERElement(tag: tag, value: Data(bytes[offset..<end]), encoded: Data(bytes[start..<end]))
        return (element, end)
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Writes binary XML by hand so tests can craft documents aapt2 would never emit (stripped names,
/// huge counts, broken offsets).
struct AXMLBuilder {
    struct Attribute {
        var namespace: String? = AXMLBuilder.android
        var name: String
        var type: UInt8
        var data: UInt32
        var raw: String?
    }

    static let android = "http://schemas.android.com/apk/res/android"

    var utf8: Bool
    private(set) var strings: [String] = []
    private(set) var resourceIDs: [UInt32] = []
    private(set) var nodes = Data()

    /// `idAttributes` are interned first so their string indices line up with the resource map.
    init(utf8: Bool = false, idAttributes: [(String, UInt32)] = []) {
        self.utf8 = utf8
        for (name, id) in idAttributes {
            strings.append(name)
            resourceIDs.append(id)
        }
    }

    mutating func intern(_ string: String) -> UInt32 {
        if let index = strings.firstIndex(of: string) { return UInt32(index) }
        strings.append(string)
        return UInt32(strings.count - 1)
    }

    mutating func string(_ name: String, _ value: String, namespace: String? = android) -> Attribute {
        Attribute(namespace: namespace, name: name, type: 0x03, data: intern(value), raw: value)
    }

    func int(_ name: String, _ value: Int32, hex: Bool = false) -> Attribute {
        Attribute(name: name, type: hex ? 0x11 : 0x10, data: UInt32(bitPattern: value))
    }

    func bool(_ name: String, _ value: Bool) -> Attribute {
        Attribute(name: name, type: 0x12, data: value ? 0xFFFF_FFFF : 0)
    }

    func typed(_ name: String, type: UInt8, data: UInt32) -> Attribute {
        Attribute(name: name, type: type, data: data)
    }

    mutating func startNamespace(prefix: String = "android", uri: String = android) {
        let body = Self.u32(intern(prefix)) + Self.u32(intern(uri))
        nodes += Self.node(type: 0x0100, body: body)
    }

    mutating func start(_ name: String, _ attributes: [Attribute] = []) {
        var attributeBytes = Data()
        for attribute in attributes {
            let namespace = attribute.namespace.map { intern($0) } ?? UInt32.max
            let raw = attribute.raw.map { intern($0) } ?? UInt32.max
            attributeBytes += Self.u32(namespace) + Self.u32(intern(attribute.name)) + Self.u32(raw)
            attributeBytes += Self.u16(8) + Data([0, attribute.type]) + Self.u32(attribute.data)
        }
        var body = Self.u32(UInt32.max) + Self.u32(intern(name))
        body += Self.u16(20) + Self.u16(20) + Self.u16(UInt16(attributes.count)) + Self.u16(0) + Self.u16(0) + Self.u16(0)
        nodes += Self.node(type: 0x0102, body: body + attributeBytes)
    }

    mutating func end(_ name: String) {
        nodes += Self.node(type: 0x0103, body: Self.u32(UInt32.max) + Self.u32(intern(name)))
    }

    /// Appends raw bytes (a hand-made chunk) to the node stream.
    mutating func appendRaw(_ data: Data) {
        nodes += data
    }

    func build() -> Data {
        var body = stringPool()
        if !resourceIDs.isEmpty {
            body += Self.chunk(type: 0x0180, headerSize: 8, body: resourceIDs.reduce(Data()) { $0 + Self.u32($1) })
        }
        body += nodes
        return Self.chunk(type: 0x0003, headerSize: 8, body: body)
    }

    func stringPool() -> Data {
        var offsets = Data()
        var data = Data()
        for string in strings {
            offsets += Self.u32(UInt32(data.count))
            data += utf8 ? Self.utf8Entry(string) : Self.utf16Entry(string)
        }
        while data.count % 4 != 0 { data.append(0) }
        let headerSize = 28
        var header = Self.u32(UInt32(strings.count)) + Self.u32(0) + Self.u32(utf8 ? 0x100 : 0)
        header += Self.u32(UInt32(headerSize + offsets.count)) + Self.u32(0)
        return Self.chunk(type: 0x0001, headerSize: UInt16(headerSize), body: header + offsets + data)
    }

    static func utf16Entry(_ string: String) -> Data {
        let units = Array(string.utf16)
        var out = Data()
        if units.count >= 0x8000 {
            out += u16(UInt16(0x8000 | (units.count >> 16))) + u16(UInt16(units.count & 0xFFFF))
        } else {
            out += u16(UInt16(units.count))
        }
        for unit in units { out += u16(unit) }
        return out + u16(0)
    }

    static func utf8Entry(_ string: String) -> Data {
        func length(_ value: Int) -> Data {
            value >= 0x80 ? Data([UInt8(0x80 | (value >> 8)), UInt8(value & 0xFF)]) : Data([UInt8(value)])
        }
        let bytes = Array(string.utf8)
        return length(string.utf16.count) + length(bytes.count) + Data(bytes) + Data([0])
    }

    /// A chunk: type, header size, total size, then the rest of the header and the body.
    static func chunk(type: UInt16, headerSize: UInt16, body: Data) -> Data {
        u16(type) + u16(headerSize) + u32(UInt32(8 + body.count)) + body
    }

    /// A tree node: chunk header, line number, comment index, then the extension.
    static func node(type: UInt16, body: Data) -> Data {
        chunk(type: type, headerSize: 16, body: u32(1) + u32(UInt32.max) + body)
    }

    static func u16(_ value: UInt16) -> Data { withUnsafeBytes(of: value.littleEndian) { Data($0) } }
    static func u32(_ value: UInt32) -> Data { withUnsafeBytes(of: value.littleEndian) { Data($0) } }
    static func u64(_ value: UInt64) -> Data { withUnsafeBytes(of: value.littleEndian) { Data($0) } }
}

/// Deterministic SplitMix64, so property tests replay exactly from their seed.
struct SeededGenerator: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var value = state
        value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
        value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
        return value ^ (value >> 31)
    }
}

/// Byte-level mutations used by the property suites.
enum Mutator {
    static func mutate(_ input: Data, using rng: inout SeededGenerator) -> Data {
        var bytes = [UInt8](input)
        guard !bytes.isEmpty else { return input }
        let rounds = Int.random(in: 1...8, using: &rng)
        for _ in 0..<rounds {
            let index = Int.random(in: 0..<bytes.count, using: &rng)
            switch Int.random(in: 0..<6, using: &rng) {
            case 0:
                bytes[index] ^= UInt8(1 << Int.random(in: 0..<8, using: &rng))
            case 1:
                bytes[index] = UInt8.random(in: 0...255, using: &rng)
            case 2:
                // Interesting values for length and offset fields.
                let values: [UInt32] = [0, 1, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x7FFF_FFFF, 0xFFFF_FFFF]
                let value = values[Int.random(in: 0..<values.count, using: &rng)]
                for offset in 0..<4 where index + offset < bytes.count {
                    bytes[index + offset] = UInt8(truncatingIfNeeded: value >> (8 * offset))
                }
            case 3:
                bytes.removeSubrange(index..<min(bytes.count, index + Int.random(in: 1...64, using: &rng)))
                if bytes.isEmpty { return Data() }
            case 4:
                bytes = Array(bytes.prefix(index))
                if bytes.isEmpty { return Data() }
            default:
                let length = min(Int.random(in: 1...32, using: &rng), bytes.count - index)
                bytes.insert(contentsOf: bytes[index..<(index + length)], at: index)
            }
        }
        return Data(bytes)
    }
}

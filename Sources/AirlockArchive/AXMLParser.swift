// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Parses Android binary XML (`AndroidManifest.xml` inside an APK) into an element tree.
///
/// The format is a sequence of `ResChunk_header`-prefixed chunks inside one `RES_XML_TYPE` chunk: a string
/// pool, an optional resource map (attribute name index → framework resource ID) and the XML tree nodes.
/// Input is hostile: every offset and size is bounds-checked, every chunk must advance by at least its
/// 8-byte header, and the limits in ``Limits`` cap the work any input can cause.
public enum AXMLParser {
    /// Hard caps on what one document may contain.
    public enum Limits {
        public static let maxFileSize = 8 * 1024 * 1024
        public static let maxStrings = 200_000
        public static let maxDepth = 64
        public static let maxAttributes = 512
    }

    enum ChunkType {
        static let stringPool: UInt16 = 0x0001
        static let xml: UInt16 = 0x0003
        static let startNamespace: UInt16 = 0x0100
        static let endNamespace: UInt16 = 0x0101
        static let startElement: UInt16 = 0x0102
        static let endElement: UInt16 = 0x0103
        static let resourceMap: UInt16 = 0x0180
    }

    /// Parses a whole binary XML document.
    public static func parse(_ data: Data) throws(AXMLError) -> AXMLDocument {
        guard data.count <= Limits.maxFileSize else { throw .tooLarge(data.count) }
        let result: Result<AXMLDocument, AXMLError> = data.withUnsafeBytes { buffer in
            let reader = BoundedReader<AXMLError>(buffer) { .truncated(offset: $0) }
            var state = AXMLTreeBuilder(reader: reader)
            return Result { () throws(AXMLError) in try state.run() }
        }
        return try result.get()
    }
}

/// Walks the chunks of one document and assembles the element tree with an explicit stack (no recursion).
private struct AXMLTreeBuilder {
    private struct OpenElement {
        let namespace: String?
        let name: String
        let attributes: [AXMLAttribute]
        var children: [AXMLElement] = []
    }

    private typealias Chunk = AXMLParser.ChunkType

    let reader: BoundedReader<AXMLError>
    private var pool: AXMLStringPool?
    private var resourceIDs: [UInt32] = []
    private var stack: [OpenElement] = []
    private var root: AXMLElement?

    init(reader: BoundedReader<AXMLError>) {
        self.reader = reader
    }

    mutating func run() throws(AXMLError) -> AXMLDocument {
        guard reader.count >= 8, try reader.u16(at: 0) == Chunk.xml else { throw .notBinaryXML }
        let headerSize = Int(try reader.u16(at: 2))
        let size = Int(try reader.u32(at: 4))
        guard headerSize >= 8, size >= headerSize, size <= reader.count else {
            throw .invalidChunk(type: Chunk.xml, offset: 0)
        }
        var offset = headerSize
        while offset < size {
            guard size - offset >= 8 else { throw .truncated(offset: offset) }
            let type = try reader.u16(at: offset)
            let chunkHeader = Int(try reader.u16(at: offset + 2))
            let chunkSize = Int(try reader.u32(at: offset + 4))
            guard chunkHeader >= 8, chunkSize >= chunkHeader, chunkSize <= size - offset else {
                throw .invalidChunk(type: type, offset: offset)
            }
            try handle(type: type, at: offset, headerSize: chunkHeader, size: chunkSize)
            offset += chunkSize
        }
        guard stack.isEmpty else { throw .unbalancedElements }
        guard let root else { throw .noRootElement }
        return AXMLDocument(root: root)
    }

    private mutating func handle(type: UInt16, at offset: Int, headerSize: Int, size: Int) throws(AXMLError) {
        switch type {
        case Chunk.stringPool:
            // Android uses the first pool; a second one is ignored rather than allowed to replace it.
            if pool == nil {
                pool = try AXMLStringPool(
                    reader: reader, chunk: offset, headerSize: headerSize, size: size, maxStrings: AXMLParser.Limits.maxStrings
                )
            }
        case Chunk.resourceMap:
            let count = min((size - headerSize) / 4, AXMLParser.Limits.maxStrings)
            resourceIDs = try (0..<count).map { index throws(AXMLError) in try reader.u32(at: offset + headerSize + index * 4) }
        case Chunk.startNamespace, Chunk.endNamespace:
            try requireNode(type: type, at: offset, headerSize: headerSize, size: size, extensionSize: 8)
        case Chunk.startElement:
            try startElement(at: offset, headerSize: headerSize, size: size)
        case Chunk.endElement:
            try requireNode(type: type, at: offset, headerSize: headerSize, size: size, extensionSize: 8)
            try endElement()
        default:
            break // CDATA and unknown chunks are skipped, as Android does.
        }
    }

    /// Tree nodes have a 16-byte header (chunk header, line number, comment) followed by a fixed extension.
    private func requireNode(type: UInt16, at offset: Int, headerSize: Int, size: Int, extensionSize: Int) throws(AXMLError) {
        guard headerSize >= 16, size - headerSize >= extensionSize else { throw .invalidChunk(type: type, offset: offset) }
    }

    private mutating func startElement(at offset: Int, headerSize: Int, size: Int) throws(AXMLError) {
        try requireNode(type: Chunk.startElement, at: offset, headerSize: headerSize, size: size, extensionSize: 20)
        guard stack.count < AXMLParser.Limits.maxDepth else { throw .nestingTooDeep }
        let ext = offset + headerSize
        let namespaceIndex = try reader.u32(at: ext)
        let nameIndex = try reader.u32(at: ext + 4)
        let attributeStart = Int(try reader.u16(at: ext + 8))
        let attributeSize = Int(try reader.u16(at: ext + 10))
        let attributeCount = Int(try reader.u16(at: ext + 12))
        guard attributeCount <= AXMLParser.Limits.maxAttributes else { throw .tooManyAttributes(attributeCount) }
        let first = ext + attributeStart
        if attributeCount > 0 {
            guard attributeSize >= 20, attributeStart >= 20,
                  attributeStart + attributeSize * attributeCount <= size - headerSize else {
                throw .invalidChunk(type: Chunk.startElement, offset: offset)
            }
        }
        let name = try string(nameIndex)
        let namespace = try optionalString(namespaceIndex)
        var attributes: [AXMLAttribute] = []
        attributes.reserveCapacity(attributeCount)
        for index in 0..<attributeCount {
            attributes.append(try attribute(at: first + index * attributeSize))
        }
        stack.append(OpenElement(namespace: namespace, name: name, attributes: attributes))
    }

    private mutating func endElement() throws(AXMLError) {
        guard let open = stack.popLast() else { throw .unbalancedElements }
        let element = AXMLElement(namespace: open.namespace, name: open.name, attributes: open.attributes, children: open.children)
        if stack.isEmpty {
            // Only the first top-level element counts; Android stops at the first root as well.
            if root == nil { root = element }
        } else {
            stack[stack.count - 1].children.append(element)
        }
    }

    /// `ResXMLTree_attribute`: namespace, name, raw value (string indices) and a `Res_value`.
    private mutating func attribute(at offset: Int) throws(AXMLError) -> AXMLAttribute {
        let namespaceIndex = try reader.u32(at: offset)
        let nameIndex = try reader.u32(at: offset + 4)
        let rawIndex = try reader.u32(at: offset + 8)
        let dataType = try reader.u8(at: offset + 15)
        let data = try reader.u32(at: offset + 16)
        let resourceID = Int(nameIndex) < resourceIDs.count ? resourceIDs[Int(nameIndex)] : 0
        // Names and namespaces of attributes are often garbage in obfuscated APKs; Android tolerates that.
        let name = try lenientString(nameIndex)
        let namespace = try lenientString(namespaceIndex)
        let raw = try lenientString(rawIndex)
        return AXMLAttribute(
            namespace: namespace,
            name: name ?? "",
            resourceID: resourceID == 0 ? nil : resourceID,
            rawValue: raw,
            value: try value(type: dataType, data: data, raw: raw)
        )
    }

    private mutating func value(type: UInt8, data: UInt32, raw: String?) throws(AXMLError) -> AXMLValue {
        switch type {
        case 0x00: .null
        case 0x01, 0x07: .reference(data)
        case 0x02: .attributeReference(data)
        case 0x03: (try lenientString(data) ?? raw).map(AXMLValue.string) ?? .other(type: type, data: data)
        case 0x04: .float(Float(bitPattern: data))
        case 0x10: .int(Int32(bitPattern: data))
        case 0x11: .hex(data)
        case 0x12: .bool(data != 0)
        default: .other(type: type, data: data)
        }
    }

    private mutating func string(_ index: UInt32) throws(AXMLError) -> String {
        guard pool != nil else { throw .stringIndexOutOfRange(index) }
        return try pool?.string(at: index) ?? ""
    }

    private mutating func optionalString(_ index: UInt32) throws(AXMLError) -> String? {
        index == UInt32.max ? nil : try string(index)
    }

    /// Like ``optionalString(_:)`` but maps bad indices and malformed strings to nil. Only an exhausted
    /// decode budget still throws, so a hostile pool cannot keep the parser busy.
    private mutating func lenientString(_ index: UInt32) throws(AXMLError) -> String? {
        do {
            return try optionalString(index)
        } catch .decodeBudgetExceeded {
            throw .decodeBudgetExceeded
        } catch {
            return nil
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Why a binary XML document was rejected. Every malformed input maps to one of these; the parser never traps.
public enum AXMLError: Error, Hashable, Sendable {
    /// The input is larger than ``AXMLParser/Limits/maxFileSize``.
    case tooLarge(Int)
    /// A read at this byte offset would run past the end of the document or chunk.
    case truncated(offset: Int)
    /// The first chunk is not `RES_XML_TYPE` (`0x0003`).
    case notBinaryXML
    /// A chunk header is inconsistent (header size, chunk size or a required field).
    case invalidChunk(type: UInt16, offset: Int)
    /// The string pool is malformed or declares more strings than allowed.
    case invalidStringPool(String)
    /// An element name or namespace refers to a string that does not exist.
    case stringIndexOutOfRange(UInt32)
    /// Elements nest deeper than ``AXMLParser/Limits/maxDepth``.
    case nestingTooDeep
    /// One element declares more attributes than ``AXMLParser/Limits/maxAttributes``.
    case tooManyAttributes(Int)
    /// An end tag without a start tag, or start tags that are never closed.
    case unbalancedElements
    /// The document has no element at all.
    case noRootElement
    /// String decoding exceeded its work budget (overlapping or repeated huge strings).
    case decodeBudgetExceeded
    /// The root element is not `<manifest>`.
    case notAManifest(String)
    /// `<manifest>` has no non-empty `package` attribute.
    case missingPackage
}

/// A typed attribute value (`Res_value`).
public enum AXMLValue: Hashable, Sendable {
    case null
    case string(String)
    /// `TYPE_INT_DEC`.
    case int(Int32)
    /// `TYPE_INT_HEX`.
    case hex(UInt32)
    case bool(Bool)
    /// `@resource` (`TYPE_REFERENCE` or `TYPE_DYNAMIC_REFERENCE`); not resolved, there is no resource table here.
    case reference(UInt32)
    /// `?attr` (`TYPE_ATTRIBUTE`).
    case attributeReference(UInt32)
    case float(Float)
    /// Dimensions, fractions, colours and unknown types, kept raw.
    case other(type: UInt8, data: UInt32)

    /// The literal string, or nil for any other type.
    public var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    /// Integer value of decimal, hex and boolean values, or a string holding a decimal number.
    public var integerValue: Int64? {
        switch self {
        case .int(let value): Int64(value)
        case .hex(let value): Int64(Int32(bitPattern: value))
        case .bool(let value): value ? 1 : 0
        case .string(let value): Int64(value.trimmingCharacters(in: .whitespaces))
        default: nil
        }
    }

    /// Boolean value of boolean and integer values, or the strings `true` / `false`.
    public var boolValue: Bool? {
        switch self {
        case .bool(let value): value
        case .int(let value): value != 0
        case .hex(let value): value != 0
        case .string(let value): Bool(value.lowercased())
        default: nil
        }
    }
}

/// One attribute of a start tag.
public struct AXMLAttribute: Hashable, Sendable {
    /// Namespace URI, e.g. `http://schemas.android.com/apk/res/android`.
    public let namespace: String?
    /// The attribute name. Obfuscators often blank it; match on ``resourceID`` instead.
    public let name: String
    /// The attribute's resource ID from the resource map (`0x0101021b` for `android:versionCode`), if any.
    public let resourceID: UInt32?
    /// The original string form, when the compiler kept one.
    public let rawValue: String?
    public let value: AXMLValue

    public init(namespace: String?, name: String, resourceID: UInt32?, rawValue: String?, value: AXMLValue) {
        self.namespace = namespace
        self.name = name
        self.resourceID = resourceID
        self.rawValue = rawValue
        self.value = value
    }
}

/// One element with its attributes and child elements. Text nodes are dropped.
public struct AXMLElement: Hashable, Sendable {
    public let namespace: String?
    public let name: String
    public let attributes: [AXMLAttribute]
    public let children: [AXMLElement]

    public init(namespace: String?, name: String, attributes: [AXMLAttribute], children: [AXMLElement]) {
        self.namespace = namespace
        self.name = name
        self.attributes = attributes
        self.children = children
    }

    /// Direct children with this tag name.
    public func children(named name: String) -> [AXMLElement] {
        children.filter { $0.name == name }
    }

    /// An `android:` attribute, matched by resource ID first and by name only for attributes without an ID.
    ///
    /// Android itself resolves framework attributes by ID, so an attribute whose ID points elsewhere is
    /// ignored even when its (possibly forged) name matches.
    public func attribute(_ key: AndroidAttribute) -> AXMLAttribute? {
        if let byID = attributes.first(where: { $0.resourceID.map(key.ids.contains) ?? false }) {
            return byID
        }
        return attributes.first {
            $0.resourceID == nil && $0.name == key.name && $0.namespace == AndroidAttribute.namespace
        }
    }

    /// An attribute without a namespace (`package`, `split`), matched by name.
    public func plainAttribute(_ name: String) -> AXMLAttribute? {
        attributes.first { $0.namespace == nil && $0.name == name }
    }
}

/// A parsed binary XML document.
public struct AXMLDocument: Hashable, Sendable {
    public let root: AXMLElement

    public init(root: AXMLElement) {
        self.root = root
    }
}

/// A framework attribute (`android:*`) known by its public resource ID.
public struct AndroidAttribute: Hashable, Sendable {
    public static let namespace = "http://schemas.android.com/apk/res/android"

    public let name: String
    /// The public ID plus, for attributes added recently, the staged ID used by preview SDKs.
    public let ids: [UInt32]

    public init(name: String, ids: [UInt32]) {
        self.name = name
        self.ids = ids
    }

    // IDs checked against `aapt2 dump resources android-36/android.jar` (frameworks/base public.xml).
    public static let label = Self(name: "label", ids: [0x0101_0001])
    public static let name = Self(name: "name", ids: [0x0101_0003])
    public static let debuggable = Self(name: "debuggable", ids: [0x0101_000f])
    public static let minSdkVersion = Self(name: "minSdkVersion", ids: [0x0101_020c])
    public static let versionCode = Self(name: "versionCode", ids: [0x0101_021b])
    public static let versionName = Self(name: "versionName", ids: [0x0101_021c])
    public static let targetSdkVersion = Self(name: "targetSdkVersion", ids: [0x0101_0270])
    public static let testOnly = Self(name: "testOnly", ids: [0x0101_0272])
    public static let required = Self(name: "required", ids: [0x0101_028e])
    public static let versionCodeMajor = Self(name: "versionCodeMajor", ids: [0x0101_0576])
    public static let isSplitRequired = Self(name: "isSplitRequired", ids: [0x0101_0591])
    public static let requiredSplitTypes = Self(name: "requiredSplitTypes", ids: [0x0101_064e, 0x01df_0001])
}

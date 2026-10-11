// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

public enum PackageNameError: Error, Equatable, Sendable {
    case empty
    case tooLong
    case malformed(String)
}

/// An Android application ID that has passed strict validation.
///
/// Every package name that reaches an adb command goes through this type, so a hostile manifest or
/// device output can never smuggle shell syntax into a command. The accepted grammar is
/// `^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z0-9_]+)+$`, ASCII only, at most ``maxLength`` characters.
public struct PackageName: RawRepresentable, Hashable, Comparable, Sendable, CustomStringConvertible, Codable {
    public static let maxLength = 255

    public let rawValue: String

    public init(_ raw: String) throws(PackageNameError) {
        try Self.validate(raw)
        rawValue = raw
    }

    /// Failable form required by `RawRepresentable`; prefer the throwing initialiser.
    public init?(rawValue: String) {
        guard Self.isValid(rawValue) else { return nil }
        self.rawValue = rawValue
    }

    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        do {
            try self.init(raw)
        } catch {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Invalid package name",
                underlyingError: error
            ))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    public var description: String { rawValue }

    public static func < (lhs: PackageName, rhs: PackageName) -> Bool { lhs.rawValue < rhs.rawValue }

    public static func isValid(_ raw: String) -> Bool {
        (try? validate(raw)) != nil
    }

    private static func validate(_ raw: String) throws(PackageNameError) {
        if raw.isEmpty { throw .empty }
        let bytes = Array(raw.utf8)
        if bytes.count > maxLength { throw .tooLong }

        var segmentCount = 1
        var segmentLength = 0
        for (index, byte) in bytes.enumerated() {
            if byte == UInt8(ascii: ".") {
                guard segmentLength > 0 else { throw .malformed(raw) }
                segmentCount += 1
                segmentLength = 0
                continue
            }
            let allowed = index == 0 ? isASCIILetter(byte) : isWordByte(byte)
            guard allowed else { throw .malformed(raw) }
            segmentLength += 1
        }
        guard segmentCount >= 2, segmentLength > 0 else { throw .malformed(raw) }
    }

    private static func isASCIILetter(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte) || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte)
    }

    private static func isWordByte(_ byte: UInt8) -> Bool {
        isASCIILetter(byte) || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte) || byte == UInt8(ascii: "_")
    }
}

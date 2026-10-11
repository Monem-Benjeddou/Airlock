// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// The parts of an X.509 certificate Airlock shows or checks, read with the bounded DER reader.
///
/// Only the structure is decoded; nothing here establishes trust. APK signing certificates are usually
/// self-signed, and Android does not check their validity dates.
public struct CertificateSummary: Hashable, Sendable {
    /// Distinguished name in RFC 4514 order (most specific first): `CN=Example, O=Org, C=US`.
    public let subject: String
    public let issuer: String
    public let notValidBefore: Date?
    public let notValidAfter: Date?
    /// The DER `SubjectPublicKeyInfo`, compared byte-for-byte with an APK signer's public key.
    public let subjectPublicKeyInfo: Data
    /// The whole DER certificate.
    public let der: Data

    /// Parses a DER certificate.
    public init(der: Data) throws(DERError) {
        let certificate = try DERParser.single(der).children(expecting: DERElement.sequence)
        guard let tbsElement = certificate.first else { throw .malformed("empty certificate") }
        var fields = try tbsElement.children(expecting: DERElement.sequence)
        if fields.first?.tag == DERElement.context(0) { fields.removeFirst() } // explicit version
        // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, …
        guard fields.count >= 6 else { throw .malformed("tbsCertificate has \(fields.count) fields") }
        let validity = try fields[3].children(expecting: DERElement.sequence)
        guard validity.count == 2 else { throw .malformed("validity") }
        guard fields[5].tag == DERElement.sequence else { throw .malformed("subjectPublicKeyInfo") }
        self.issuer = try Self.distinguishedName(fields[2])
        self.subject = try Self.distinguishedName(fields[4])
        self.notValidBefore = Self.time(validity[0])
        self.notValidAfter = Self.time(validity[1])
        self.subjectPublicKeyInfo = fields[5].encoded
        self.der = der
    }

    private static let attributeNames: [String: String] = [
        "2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "SERIALNUMBER", "2.5.4.6": "C", "2.5.4.7": "L",
        "2.5.4.8": "ST", "2.5.4.9": "STREET", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "T",
        "2.5.4.42": "GN", "1.2.840.113549.1.9.1": "E", "0.9.2342.19200300.100.1.25": "DC",
        "0.9.2342.19200300.100.1.1": "UID",
    ]

    /// `Name ::= SEQUENCE OF RelativeDistinguishedName`, printed most specific first.
    static func distinguishedName(_ element: DERElement) throws(DERError) -> String {
        var parts: [String] = []
        for rdn in try element.children(expecting: DERElement.sequence) {
            var values: [String] = []
            for attribute in try rdn.children(expecting: DERElement.set) {
                let pair = try attribute.children(expecting: DERElement.sequence)
                guard pair.count == 2 else { throw .malformed("attribute type and value") }
                let oid = try pair[0].objectIdentifier()
                values.append("\(attributeNames[oid] ?? oid)=\(stringValue(pair[1]))")
            }
            parts.append(values.joined(separator: "+"))
        }
        return parts.reversed().joined(separator: ", ")
    }

    /// Text of a directory string: UTF-8, printable, IA5 and T61 are read as UTF-8/Latin-1, BMP as UTF-16BE.
    static func stringValue(_ element: DERElement) -> String {
        switch element.tag {
        case 0x1E:
            let bytes = [UInt8](element.value)
            let units = stride(from: 0, to: bytes.count - 1, by: 2).map { UInt16(bytes[$0]) << 8 | UInt16(bytes[$0 + 1]) }
            return String(decoding: units, as: UTF16.self)
        case 0x0C, 0x13, 0x16:
            return String(decoding: element.value, as: Unicode.UTF8.self)
        case 0x14:
            return String(element.value.map { Character(Unicode.Scalar($0)) })
        default:
            return "#" + element.encoded.map { String(format: "%02x", $0) }.joined()
        }
    }

    /// `UTCTime` (`YYMMDDHHMMSSZ`, years 1950–2049) or `GeneralizedTime` (`YYYYMMDDHHMMSSZ`); nil otherwise.
    static func time(_ element: DERElement) -> Date? {
        let text = String(decoding: element.value, as: Unicode.UTF8.self)
        let digits: Substring
        var year: Int
        switch element.tag {
        case DERElement.utcTime:
            guard text.count == 13, text.hasSuffix("Z"), let yy = Int(text.prefix(2)) else { return nil }
            year = yy < 50 ? 2000 + yy : 1900 + yy
            digits = text.dropFirst(2).dropLast()
        case DERElement.generalizedTime:
            guard text.count == 15, text.hasSuffix("Z"), let yyyy = Int(text.prefix(4)) else { return nil }
            year = yyyy
            digits = text.dropFirst(4).dropLast()
        default:
            return nil
        }
        guard digits.count == 10, digits.allSatisfy(\.isASCII), digits.allSatisfy(\.isNumber) else { return nil }
        let numbers = stride(from: 0, to: 10, by: 2).compactMap { offset -> Int? in
            let start = digits.index(digits.startIndex, offsetBy: offset)
            return Int(digits[start..<digits.index(start, offsetBy: 2)])
        }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0) ?? calendar.timeZone
        let components = DateComponents(
            year: year, month: numbers[0], day: numbers[1], hour: numbers[2], minute: numbers[3], second: numbers[4]
        )
        guard components.isValidDate(in: calendar) else { return nil }
        return calendar.date(from: components)
    }
}

/// The algorithm and raw key bits of a DER `SubjectPublicKeyInfo`.
public struct PublicKeyInfo: Hashable, Sendable {
    public enum Algorithm: Hashable, Sendable {
        case rsa
        /// Elliptic curve key on the named curve (`1.2.840.10045.3.1.7` is P-256).
        case ec(curve: String)
        case dsa
        case other(String)
    }

    public let algorithm: Algorithm
    /// The BIT STRING contents: a PKCS#1 `RSAPublicKey` for RSA, an X9.63 point for EC.
    public let keyBytes: Data

    public init(subjectPublicKeyInfo: Data) throws(DERError) {
        let parts = try DERParser.single(subjectPublicKeyInfo).children(expecting: DERElement.sequence)
        guard parts.count == 2, parts[1].tag == DERElement.bitString, parts[1].value.first == 0 else {
            throw .malformed("subjectPublicKeyInfo")
        }
        let algorithmParts = try parts[0].children(expecting: DERElement.sequence)
        guard let oidElement = algorithmParts.first else { throw .malformed("algorithm identifier") }
        switch try oidElement.objectIdentifier() {
        case "1.2.840.113549.1.1.1":
            algorithm = .rsa
        case "1.2.840.10045.2.1":
            guard algorithmParts.count == 2 else { throw .malformed("EC key without a named curve") }
            algorithm = .ec(curve: try algorithmParts[1].objectIdentifier())
        case "1.2.840.10040.4.1":
            algorithm = .dsa
        case let oid:
            algorithm = .other(oid)
        }
        keyBytes = Data(parts[1].value.dropFirst())
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// A JAR (v1) signature: the signature file and its PKCS#7 signature block, both under `META-INF/`.
public struct JARSignatureEntries: Hashable, Sendable {
    /// `META-INF/CERT.SF`
    public let signatureFile: String
    /// `META-INF/CERT.RSA`, `.DSA` or `.EC`
    public let signatureBlock: String

    public init(signatureFile: String, signatureBlock: String) {
        self.signatureFile = signatureFile
        self.signatureBlock = signatureBlock
    }
}

/// Evidence of a v1 signature that the caller (which owns the zip reader) collected from the APK.
public struct JARSignatureEvidence: Hashable, Sendable {
    public let entries: [JARSignatureEntries]
    /// Raw bytes of each `signatureBlock`, in the same order as `entries`.
    public let signatureBlocks: [Data]

    public init(entries: [JARSignatureEntries], signatureBlocks: [Data]) {
        self.entries = entries
        self.signatureBlocks = signatureBlocks
    }
}

/// Detects JAR signatures and pulls certificates out of their PKCS#7 blocks.
///
/// This does not verify v1 signatures (that needs every entry's digest from the zip); it only shows who
/// claims to have signed.
public enum JARSignature {
    public static let maxSigners = 16
    private static let blockExtensions = ["RSA", "DSA", "EC"]
    private static let signedDataOID = "1.2.840.113549.1.7.2"

    /// Signature-file / signature-block pairs directly under `META-INF/`, as Android's verifier looks for them.
    /// Extensions are matched case-insensitively; at most ``maxSigners`` pairs are returned.
    public static func signatureEntries(in entryNames: [String]) -> [JARSignatureEntries] {
        let sorted = Set(entryNames).sorted()
        var blocks: [String: String] = [:]
        for name in sorted {
            for ext in blockExtensions {
                if let base = metaInfBase(name, extension: ext), blocks[base] == nil { blocks[base] = name }
            }
        }
        var result: [JARSignatureEntries] = []
        for name in sorted where result.count < maxSigners {
            if let base = metaInfBase(name, extension: "SF"), let block = blocks[base] {
                result.append(JARSignatureEntries(signatureFile: name, signatureBlock: block))
            }
        }
        return result
    }

    /// DER certificates from a PKCS#7 `SignedData` block (`ContentInfo` → `[0] certificates`).
    public static func certificates(fromPKCS7 data: Data) throws(DERError) -> [Data] {
        let contentInfo = try DERParser.single(data).children(expecting: DERElement.sequence)
        guard contentInfo.count == 2, try contentInfo[0].objectIdentifier() == signedDataOID else {
            throw .malformed("not PKCS#7 signedData")
        }
        let explicit = try contentInfo[1].children(expecting: DERElement.context(0))
        guard explicit.count == 1 else { throw .malformed("signedData wrapper") }
        let signedData = try explicit[0].children(expecting: DERElement.sequence)
        guard let certificateSet = signedData.first(where: { $0.tag == DERElement.context(0) }) else { return [] }
        return try certificateSet.children().map { certificate throws(DERError) in
            guard certificate.tag == DERElement.sequence else { throw .malformed("certificate choice \(certificate.tag)") }
            return certificate.encoded
        }
    }

    /// `META-INF/NAME.EXT` → `NAME` (exactly one level under META-INF, extension case-insensitive).
    private static func metaInfBase(_ name: String, extension ext: String) -> String? {
        let prefix = "META-INF/"
        guard name.hasPrefix(prefix) else { return nil }
        let file = name.dropFirst(prefix.count)
        guard !file.contains("/"), let dot = file.lastIndex(of: "."), file[file.index(after: dot)...].uppercased() == ext else {
            return nil
        }
        let base = file[..<dot]
        return base.isEmpty ? nil : String(base)
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockArchive
import Foundation
import Security

/// Signature algorithm IDs used in v2/v3 signer blocks.
enum APKSignatureAlgorithm: UInt32, CaseIterable {
    case rsaPSSSHA256 = 0x0101
    case rsaPSSSHA512 = 0x0102
    case rsaPKCS1SHA256 = 0x0103
    case rsaPKCS1SHA512 = 0x0104
    case ecdsaSHA256 = 0x0201
    case ecdsaSHA512 = 0x0202
    case dsaSHA256 = 0x0301
    case verityRSAPKCS1SHA256 = 0x0421
    case verityECDSASHA256 = 0x0423
    case verityDSASHA256 = 0x0425

    /// The content digest the algorithm's digest entry holds, or nil when Airlock cannot compute it (verity).
    var contentDigest: APKContentDigest? {
        switch self {
        case .rsaPSSSHA256, .rsaPKCS1SHA256, .ecdsaSHA256, .dsaSHA256: .sha256
        case .rsaPSSSHA512, .rsaPKCS1SHA512, .ecdsaSHA512: .sha512
        case .verityRSAPKCS1SHA256, .verityECDSASHA256, .verityDSASHA256: nil
        }
    }

    /// Security.framework algorithm, or nil for DSA and verity (reported as unverifiable).
    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        case .rsaPSSSHA256: .rsaSignatureMessagePSSSHA256
        case .rsaPSSSHA512: .rsaSignatureMessagePSSSHA512
        case .rsaPKCS1SHA256: .rsaSignatureMessagePKCS1v15SHA256
        case .rsaPKCS1SHA512: .rsaSignatureMessagePKCS1v15SHA512
        case .ecdsaSHA256: .ecdsaSignatureMessageX962SHA256
        case .ecdsaSHA512: .ecdsaSignatureMessageX962SHA512
        case .dsaSHA256, .verityRSAPKCS1SHA256, .verityECDSASHA256, .verityDSASHA256: nil
        }
    }

    var isRSA: Bool { [.rsaPSSSHA256, .rsaPSSSHA512, .rsaPKCS1SHA256, .rsaPKCS1SHA512].contains(self) }

    /// Higher is preferred: SHA-512 over SHA-256, then the order apksigner uses (RSA-PSS, PKCS#1, ECDSA).
    var strength: Int {
        switch self {
        case .rsaPSSSHA512, .rsaPKCS1SHA512, .ecdsaSHA512: 2
        default: 1
        }
    }

    /// The strongest algorithm Airlock can verify among `signatures`.
    static func strongestVerifiable(in signatures: [APKAlgorithmValue]) -> (Self, Data)? {
        signatures
            .compactMap { signature in Self(rawValue: signature.algorithm).map { ($0, signature.value) } }
            .filter { $0.0.secKeyAlgorithm != nil }
            .max { $0.0.strength < $1.0.strength }
    }

    /// Builds a Security public key from a DER `SubjectPublicKeyInfo` for this algorithm's key type.
    func publicKey(from subjectPublicKeyInfo: Data) -> SecKey? {
        guard let info = try? PublicKeyInfo(subjectPublicKeyInfo: subjectPublicKeyInfo) else { return nil }
        let keyType: CFString
        switch info.algorithm {
        case .rsa where isRSA:
            keyType = kSecAttrKeyTypeRSA
        case .ec(let curve) where !isRSA && Self.curves.contains(curve):
            keyType = kSecAttrKeyTypeECSECPrimeRandom
        default:
            return nil
        }
        let attributes: [CFString: Any] = [kSecAttrKeyType: keyType, kSecAttrKeyClass: kSecAttrKeyClassPublic]
        return SecKeyCreateWithData(info.keyBytes as CFData, attributes as CFDictionary, nil)
    }

    /// P-256, P-384 and P-521.
    private static let curves: Set<String> = ["1.2.840.10045.3.1.7", "1.3.132.0.34", "1.3.132.0.35"]
}

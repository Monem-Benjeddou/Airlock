// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import CryptoKit
import Foundation
import Security

/// Builds small "APKs" signed with throwaway in-memory keys, so tests can produce every kind of broken
/// signer that apksigner never would. The content digest is computed here independently of production code.
struct SignedAPKCraft {
    enum Key {
        case p256(P256.Signing.PrivateKey)
        case rsa(SecKey)

        var subjectPublicKeyInfo: Data {
            switch self {
            case .p256(let key):
                return key.publicKey.derRepresentation
            case .rsa(let key):
                let publicKey = SecKeyCopyPublicKey(key).flatMap { SecKeyCopyExternalRepresentation($0, nil) as Data? } ?? Data()
                let algorithm = DER.sequence(DER.oid([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]) + Data([0x05, 0x00]))
                return DER.sequence(algorithm + DER.tlv(0x03, Data([0]) + publicKey))
            }
        }

        func sign(_ data: Data, algorithm: UInt32) -> Data {
            switch self {
            case .p256(let key):
                let signature = algorithm == 0x0202
                    ? try? key.signature(for: SHA512.hash(data: data))
                    : try? key.signature(for: data)
                return signature?.derRepresentation ?? Data()
            case .rsa(let key):
                let secAlgorithm: SecKeyAlgorithm = switch algorithm {
                case 0x0101: .rsaSignatureMessagePSSSHA256
                case 0x0102: .rsaSignatureMessagePSSSHA512
                case 0x0104: .rsaSignatureMessagePKCS1v15SHA512
                default: .rsaSignatureMessagePKCS1v15SHA256
                }
                return SecKeyCreateSignature(key, secAlgorithm, data as CFData, nil) as Data? ?? Data()
            }
        }

        static func newRSA() -> Key? {
            let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
            return SecKeyCreateRandomKey(attributes as CFDictionary, nil).map(Key.rsa)
        }
    }

    /// One signer and the ways a test may break it.
    struct Signer {
        var key: Key
        var algorithm: UInt32 = 0x0201
        /// Signature algorithm list; defaults to `[algorithm]`.
        var signatureAlgorithms: [UInt32]?
        var digestAlgorithms: [UInt32]?
        var certificateKey: Data?
        var minSDK: UInt32 = 24
        var maxSDK: UInt32 = 0x7FFF_FFFF
        var signedMaxSDK: UInt32?
        var attributes: [(UInt32, Data)] = []
        var wrongDigest = false
        var publicKeyOverride: Data?
    }

    var contents = Data(repeating: 0x41, count: 3_000)
    var centralDirectory = Data("PK\u{01}\u{02}central-directory".utf8)
    var trailingGap = Data()

    /// The finished file: contents ‖ signing block ‖ central directory ‖ [gap the EOCD does not count] ‖ EOCD.
    func build(v2: [Signer] = [], v3: [Signer] = []) -> Data {
        var pairs: [(UInt32, Data)] = []
        if !v2.isEmpty { pairs.append((0x7109_871a, signerBlock(v2, isV3: false))) }
        if !v3.isEmpty { pairs.append((0xf053_68c0, signerBlock(v3, isV3: true))) }
        let block = Self.block(pairs)
        return contents + block + centralDirectory + trailingGap + eocd(cdOffset: contents.count + block.count)
    }

    private func eocd(cdOffset: Int) -> Data {
        var record = u32(0x0605_4b50) + u16(0) + u16(0) + u16(1) + u16(1)
        record += u32(UInt32(centralDirectory.count)) + u32(UInt32(cdOffset)) + u16(0)
        return record
    }

    /// Sections cut into 1 MiB chunks: contents, central directory, EOCD with the CD offset pointing at the block.
    func contentDigest(sha512: Bool) -> Data {
        let sections = [contents, centralDirectory, eocd(cdOffset: contents.count)]
        func hash(_ data: Data) -> Data { sha512 ? Data(SHA512.hash(data: data)) : Data(SHA256.hash(data: data)) }
        var chunks: [Data] = []
        for section in sections {
            var start = 0
            while start < section.count {
                let end = min(start + 1_048_576, section.count)
                chunks.append(section.subdata(in: start..<end))
                start = end
            }
        }
        var top = Data([0x5a]) + u32(UInt32(chunks.count))
        for chunk in chunks { top += hash(Data([0xa5]) + u32(UInt32(chunk.count)) + chunk) }
        return hash(top)
    }

    private func signerBlock(_ signers: [Signer], isV3: Bool) -> Data {
        lp(seq(signers.map { signerBytes($0, isV3: isV3) }))
    }

    private func signerBytes(_ signer: Signer, isV3: Bool) -> Data {
        let publicKey = signer.publicKeyOverride ?? signer.key.subjectPublicKeyInfo
        let certificate = DER.certificate(subjectPublicKeyInfo: signer.certificateKey ?? publicKey)
        let digests = (signer.digestAlgorithms ?? [signer.algorithm]).map { algorithm -> Data in
            var digest = contentDigest(sha512: [0x0102, 0x0104, 0x0202].contains(algorithm))
            if signer.wrongDigest { digest[0] ^= 0xFF }
            return u32(algorithm) + lp(digest)
        }
        var signedData = lp(seq(digests)) + lp(seq([certificate]))
        if isV3 { signedData += u32(signer.minSDK) + u32(signer.signedMaxSDK ?? signer.maxSDK) }
        signedData += lp(seq(signer.attributes.map { u32($0.0) + $0.1 }))
        let signatures = (signer.signatureAlgorithms ?? [signer.algorithm]).map { algorithm in
            u32(algorithm) + lp(signer.key.sign(signedData, algorithm: algorithm))
        }
        var out = lp(signedData)
        if isV3 { out += u32(signer.minSDK) + u32(signer.maxSDK) }
        return out + lp(seq(signatures)) + lp(publicKey)
    }

    static func block(_ pairs: [(UInt32, Data)]) -> Data {
        var body = Data()
        for (id, value) in pairs { body += u64(UInt64(value.count + 4)) + u32(id) + value }
        let size = UInt64(body.count + 24)
        return u64(size) + body + u64(size) + Data("APK Sig Block 42".utf8)
    }
}

/// Just enough DER to wrap a public key in a certificate-shaped structure.
enum DER {
    static func tlv(_ tag: UInt8, _ value: Data) -> Data {
        var out = Data([tag])
        if value.count < 0x80 {
            out.append(UInt8(value.count))
        } else if value.count < 0x100 {
            out += Data([0x81, UInt8(value.count)])
        } else {
            out += Data([0x82, UInt8(value.count >> 8), UInt8(value.count & 0xFF)])
        }
        return out + value
    }

    static func sequence(_ value: Data) -> Data { tlv(0x30, value) }
    static func oid(_ bytes: [UInt8]) -> Data { tlv(0x06, Data(bytes)) }

    static func name(_ commonName: String) -> Data {
        let attribute = sequence(oid([0x55, 0x04, 0x03]) + tlv(0x0C, Data(commonName.utf8)))
        return sequence(tlv(0x31, attribute))
    }

    static func certificate(subjectPublicKeyInfo: Data) -> Data {
        let algorithm = sequence(oid([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]))
        let validity = sequence(tlv(0x17, Data("260101000000Z".utf8)) + tlv(0x17, Data("360101000000Z".utf8)))
        let tbs = sequence(
            tlv(0xA0, tlv(0x02, Data([2]))) + tlv(0x02, Data([1])) + algorithm + name("Crafted") + validity + name("Crafted")
                + subjectPublicKeyInfo
        )
        return sequence(tbs + algorithm + tlv(0x03, Data([0, 0])))
    }
}

func u16(_ value: UInt16) -> Data { withUnsafeBytes(of: value.littleEndian) { Data($0) } }
func u32(_ value: UInt32) -> Data { withUnsafeBytes(of: value.littleEndian) { Data($0) } }
func u64(_ value: UInt64) -> Data { withUnsafeBytes(of: value.littleEndian) { Data($0) } }
func lp(_ data: Data) -> Data { u32(UInt32(data.count)) + data }
func seq(_ items: [Data]) -> Data { items.reduce(Data()) { $0 + lp($1) } }

/// Writes bytes to a unique temporary file and removes it afterwards.
func withTemporaryFile<T>(_ data: Data, name: String = "x.apk", _ body: (URL) throws -> T) throws -> T {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("airlock-safety-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent(name)
    try data.write(to: url)
    return try body(url)
}

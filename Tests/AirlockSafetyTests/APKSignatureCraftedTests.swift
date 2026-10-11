// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockArchive
import AirlockCore
@testable import AirlockSafety
import CryptoKit
import Foundation
import Testing

@Suite("APKSignatureVerifier on crafted signers")
struct APKSignatureCraftedTests {
    private let ec = SignedAPKCraft.Key.p256(P256.Signing.PrivateKey())

    private func check(_ data: Data) throws -> SignatureCheck {
        try withTemporaryFile(data) { APKSignatureVerifier().verify(apkAt: $0) }
    }

    private func signer(_ change: (inout SignedAPKCraft.Signer) -> Void = { _ in }) -> SignedAPKCraft.Signer {
        var signer = SignedAPKCraft.Signer(key: ec)
        change(&signer)
        return signer
    }

    @Test func craftedSignersVerify() throws {
        let craft = SignedAPKCraft()
        #expect(try check(craft.build(v2: [signer()])).status == .verified)
        #expect(try check(craft.build(v3: [signer()])).status == .verified)
        let sha512 = try check(craft.build(v2: [signer { $0.algorithm = 0x0202 }]))
        #expect(sha512.status == .verified, "\(sha512.problem ?? "")")
        let rsa = try #require(SignedAPKCraft.Key.newRSA())
        for algorithm: UInt32 in [0x0101, 0x0102, 0x0103, 0x0104] {
            let result = try check(craft.build(v2: [SignedAPKCraft.Signer(key: rsa, algorithm: algorithm)]))
            #expect(result.status == .verified, "algorithm \(algorithm): \(result.problem ?? "")")
        }
        // Several chunks per section: contents over 1 MiB.
        var big = SignedAPKCraft()
        big.contents = Data(repeating: 0x42, count: APKContentDigest.chunkSize + 10)
        let bigResult = try check(big.build(v2: [signer()]))
        #expect(bigResult.status == .verified, "\(bigResult.problem ?? "")")
    }

    @Test func picksTheStrongestSupportedSignature() throws {
        // Unknown and DSA entries are skipped; SHA-512 beats SHA-256.
        let craft = SignedAPKCraft()
        let mixed = signer {
            $0.signatureAlgorithms = [0x0301, 0x0201, 0x0202, 0x9999]
            $0.digestAlgorithms = [0x0301, 0x0201, 0x0202, 0x9999]
        }
        #expect(try check(craft.build(v2: [mixed])).status == .verified)
    }

    @Test(arguments: [
        ([UInt32(0x0301)], "cannot verify (0x0301)"),
        ([0x0421, 0x0423], "cannot verify (0x0421, 0x0423)"),
    ])
    func unsupportedAlgorithmsAreUnverifiable(_ algorithms: [UInt32], _ problem: String) throws {
        let unsupported = signer { $0.signatureAlgorithms = algorithms; $0.digestAlgorithms = algorithms }
        let result = try check(SignedAPKCraft().build(v2: [unsupported]))
        #expect(result.status == .unverifiable)
        #expect(result.problem?.contains(problem) == true)
        #expect(result.certificates.first?.subject == "CN=Crafted")
    }

    @Test(arguments: [
        ("wrongDigest", "do not match its v2 signature"),
        ("digestList", "digest and signature lists differ"),
        ("certificate", "certificate does not match the signing key"),
        ("badKey", "public key is malformed"),
        ("rsaKeyForEC", "public key is malformed"),
        ("signature", "signature does not verify"),
    ])
    func brokenV2Signers(_ breakage: String, _ problem: String) throws {
        let other = P256.Signing.PrivateKey().publicKey.derRepresentation
        let broken = signer { signer in
            switch breakage {
            case "wrongDigest": signer.wrongDigest = true
            case "digestList": signer.digestAlgorithms = [0x0201, 0x0202]
            case "certificate": signer.certificateKey = other
            case "badKey": signer.publicKeyOverride = Data([0x30, 0x00])
            case "rsaKeyForEC": signer.algorithm = 0x0103
            default: signer.publicKeyOverride = other
            }
        }
        let result = try check(SignedAPKCraft().build(v2: [broken]))
        #expect(result.status == .invalid)
        #expect(result.problem?.contains(problem) == true, "\(result.problem ?? "nil")")
    }

    @Test func v3RangeMismatchAndStripping() throws {
        let craft = SignedAPKCraft()
        let range = try check(craft.build(v3: [signer { $0.signedMaxSDK = 30 }]))
        #expect(range.status == .invalid && range.problem?.contains("SDK range") == true)

        let stripped = signer { $0.attributes = [(0xbeef_f00d, u32(3))] }
        let result = try check(craft.build(v2: [stripped]))
        #expect(result.status == .invalid && result.problem?.contains("stripping") == true)
        #expect(try check(craft.build(v2: [stripped], v3: [signer()])).status == .verified)
        let otherAttribute = signer { $0.attributes = [(0xbeef_f00d, u32(2)), (0x1234, Data([1]))] }
        #expect(try check(craft.build(v2: [otherAttribute])).status == .verified)
    }

    @Test func unverifiableSignerDoesNotHideAnInvalidOne() throws {
        let craft = SignedAPKCraft()
        let dsaOnly = signer { $0.signatureAlgorithms = [0x0301]; $0.digestAlgorithms = [0x0301] }
        let mixed = try check(craft.build(v2: [dsaOnly, signer()]))
        #expect(mixed.status == .unverifiable)
        let invalid = try check(craft.build(v2: [dsaOnly, signer { $0.wrongDigest = true }]))
        #expect(invalid.status == .invalid)
    }

    @Test func layoutAndBlockProblems() throws {
        var gap = SignedAPKCraft()
        gap.trailingGap = Data(count: 5)
        let result = try check(gap.build(v2: [signer()]))
        #expect(result.status == .invalid && result.problem?.contains("zip layout") == true)

        var data = SignedAPKCraft().build(v2: [signer()])
        let eocd = data.count - 22
        data.replaceSubrange((eocd + 16)..<(eocd + 20), with: u32(.max))
        #expect(try check(data).status == .unverifiable, "Zip64 cannot carry APK signatures")

        var malformed = SignedAPKCraft().build(v2: [signer()])
        malformed.replaceSubrange(3_000..<3_008, with: u64(5)) // first block size field
        let bad = try check(malformed)
        #expect(bad.status == .invalid && bad.problem?.contains("malformed") == true)
    }

    @Test func digestRejectsBadLayouts() throws {
        let layout = APKFileLayout(fileSize: 100, centralDirectoryOffset: 10, centralDirectorySize: 5,
                                   endOfCentralDirectoryOffset: 20, endOfCentralDirectory: Data(count: 22))
        try withTemporaryFile(Data(count: 100)) { url in
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            #expect(throws: APKContentDigest.Failure.self) {
                try APKContentDigest.compute([.sha256], handle: handle, layout: layout, signingBlockOffset: 0)
            }
            let short = APKFileLayout(fileSize: 100, centralDirectoryOffset: 10, centralDirectorySize: 10,
                                      endOfCentralDirectoryOffset: 20, endOfCentralDirectory: Data(count: 4))
            #expect(throws: APKContentDigest.Failure.layout("signing block offset")) {
                try APKContentDigest.compute([.sha256], handle: handle, layout: short, signingBlockOffset: 0)
            }
            let beyond = APKFileLayout(fileSize: 100, centralDirectoryOffset: 500, centralDirectorySize: 10,
                                       endOfCentralDirectoryOffset: 510, endOfCentralDirectory: Data(count: 22))
            #expect(throws: APKContentDigest.Failure.self) {
                try APKContentDigest.compute([.sha512], handle: handle, layout: beyond, signingBlockOffset: 0)
            }
        }
    }
}

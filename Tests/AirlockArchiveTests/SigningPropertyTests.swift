// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

@testable import AirlockArchive
import AirlockTestSupport
import Foundation
import Testing

@Suite("Signing Property: mutated signing data only ever produces typed errors")
struct SigningPropertyTests {
    /// Mutates only the signed tail (signing block, central directory, EOCD), where the parser reads.
    @Test(.timeLimit(.minutes(2)), arguments: [FixtureAPKs.APK.v123RSA, .rotated, .v2EC])
    func mutatedApkTails(_ apk: FixtureAPKs.APK) throws {
        let original = try FixtureAPKs.data(apk)
        let block = try #require(try SigningBlockParser.inspect(fileAt: FixtureAPKs.url(apk)).signingBlock)
        let head = original.prefix(Int(block.offset))
        let tail = original.suffix(from: Int(block.offset))
        var rng = SeededGenerator(seed: UInt64(apk.rawValue.count))
        try withTemporaryFile(Data()) { url in
            for _ in 0..<700 {
                try (head + Mutator.mutate(Data(tail), using: &rng)).write(to: url)
                do {
                    _ = try SigningBlockParser.inspect(fileAt: url)
                } catch {
                    #expect(error is SigningBlockError)
                }
            }
        }
    }

    @Test(.timeLimit(.minutes(2)))
    func mutatedSignerValues() throws {
        let inspection = try SigningBlockParser.inspect(fileAt: FixtureAPKs.url(.v123RSA))
        let signer = try #require(inspection.signingBlock?.v3Signers.first)
        // Re-serialise the v3 signer so it can be mutated in memory.
        let lp = SigningCraft.lp
        let signatures = SigningCraft.seq(signer.signatures.map { SigningCraft.algorithmValue($0.algorithm, $0.value) })
        let signerBytes = lp(signer.signedData) + AXMLBuilder.u32(signer.minSDK ?? 0) + AXMLBuilder.u32(signer.maxSDK ?? 0)
            + lp(signatures) + lp(signer.publicKey)
        let value = SigningCraft.signerBlockValue([signerBytes])
        #expect(try SigningBlockParser.parseSigners(value, scheme: .v3).first?.digests.count == signer.digests.count)
        var rng = SeededGenerator(seed: 0x51_6E)
        for _ in 0..<5_000 {
            _ = try? SigningBlockParser.parseSigners(Mutator.mutate(value, using: &rng), scheme: .v3)
        }
    }

    @Test(.timeLimit(.minutes(2)))
    func mutatedCertificatesAndPKCS7() throws {
        let pkcs7 = try FixtureAPKs.raw("app-v1-rsa.RSA")
        let certificate = try #require(try JARSignature.certificates(fromPKCS7: pkcs7).first)
        let ecBlock = try FixtureAPKs.raw("app-v1-ec.EC")
        var rng = SeededGenerator(seed: 0xCE27)
        var parsed = 0
        for _ in 0..<3_000 {
            if let summary = try? CertificateSummary(der: Mutator.mutate(certificate, using: &rng)) {
                _ = try? PublicKeyInfo(subjectPublicKeyInfo: summary.subjectPublicKeyInfo)
                parsed += 1
            }
            _ = try? JARSignature.certificates(fromPKCS7: Mutator.mutate(pkcs7, using: &rng))
            _ = try? JARSignature.certificates(fromPKCS7: Mutator.mutate(ecBlock, using: &rng))
        }
        #expect(parsed > 0, "some mutations only touch values, so the structure still parses")
    }
}

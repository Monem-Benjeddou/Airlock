// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

@testable import AirlockArchive
import AirlockTestSupport
import Foundation
import Testing

/// Writes bytes to a unique temporary file and removes it afterwards.
func withTemporaryFile<T>(_ data: Data, name: String = "x.apk", _ body: (URL) throws -> T) throws -> T {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("airlock-tests-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent(name)
    try data.write(to: url)
    return try body(url)
}

private func inspect(_ apk: FixtureAPKs.APK) throws -> APKSigningInspection {
    try SigningBlockParser.inspect(fileAt: FixtureAPKs.url(apk))
}

@Suite("SigningBlockParser on apksigner output")
struct SigningFixtureTests {
    @Test(arguments: [
        (FixtureAPKs.APK.unsigned, [APKSignatureScheme]()),
        (.flagsUnsigned, []),
        (.v1RSA, []),
        (.v1EC, []),
        (.v2RSA, [.v2]),
        (.v2EC, [.v2]),
        (.v3RSA, [.v3]),
        (.v123RSA, [.v2, .v3]),
        (.v123EC, [.v2, .v3]),
        (.v24RSA, [.v2]),
        (.rotated, [.v2, .v3, .v31]),
        (.tampered, [.v2, .v3]),
        (.splitArm64, [.v2]),
    ])
    func schemesPerFixture(_ apk: FixtureAPKs.APK, _ expected: [APKSignatureScheme]) throws {
        let inspection = try inspect(apk)
        #expect(inspection.blockSchemes == expected)
        let layout = inspection.layout
        #expect(layout.centralDirectoryOffset + layout.centralDirectorySize == layout.endOfCentralDirectoryOffset)
        #expect(layout.endOfCentralDirectoryOffset + Int64(layout.endOfCentralDirectory.count) == layout.fileSize)
        if let block = inspection.signingBlock {
            #expect(block.offset + block.size == layout.centralDirectoryOffset)
        }
    }

    @Test func rsaSignerDetails() throws {
        let block = try #require(try inspect(.v123RSA).signingBlock)
        let v2 = try #require(block.v2Signers.first)
        #expect(v2.signatures.map(\.algorithm) == [0x0103])
        #expect(v2.digests.map(\.algorithm) == [0x0103])
        #expect(v2.minSDK == nil)
        let certificate = try CertificateSummary(der: try #require(v2.certificates.first))
        #expect(certificate.subject == "CN=Airlock Test RSA, OU=Fixtures, O=Airlock, C=US")
        #expect(certificate.issuer == certificate.subject)
        #expect(certificate.notValidBefore == Date(timeIntervalSince1970: 1_767_225_600)) // 2026-01-01T00:00:00Z
        #expect(certificate.notValidAfter.map { $0 > Date(timeIntervalSince1970: 2_400_000_000) } == true)
        #expect(certificate.subjectPublicKeyInfo == v2.publicKey)
        #expect(try PublicKeyInfo(subjectPublicKeyInfo: v2.publicKey).algorithm == .rsa)

        let v3 = try #require(block.v3Signers.first)
        #expect(v3.minSDK == v3.signedMinSDK && v3.maxSDK == v3.signedMaxSDK)
        #expect(v3.minSDK != nil && v3.certificates == v2.certificates)
    }

    @Test func ecSignerAndRotation() throws {
        let ec = try #require(try inspect(.v2EC).signingBlock?.v2Signers.first)
        #expect(ec.signatures.map(\.algorithm) == [0x0201])
        let key = try PublicKeyInfo(subjectPublicKeyInfo: ec.publicKey)
        #expect(key.algorithm == .ec(curve: "1.2.840.10045.3.1.7"))
        #expect(key.keyBytes.count == 65 && key.keyBytes.first == 4)
        #expect(try CertificateSummary(der: ec.certificates[0]).subject == "CN=Airlock Test EC, O=Airlock, C=DE")

        let rotated = try #require(try inspect(.rotated).signingBlock)
        let old = try CertificateSummary(der: rotated.v3Signers[0].certificates[0])
        let new = try CertificateSummary(der: rotated.v31Signers[0].certificates[0])
        #expect(old.subject.contains("RSA") && new.subject.contains("EC"))
        #expect(rotated.v3Signers[0].maxSDK.map { $0 < 33 } == true)
        #expect(rotated.v31Signers[0].minSDK == 33)
    }

    @Test func v4IsDetectedByItsDetachedFile() throws {
        #expect(SigningBlockParser.hasV4Signature(apkAt: try FixtureAPKs.url(.v24RSA)))
        #expect(!SigningBlockParser.hasV4Signature(apkAt: try FixtureAPKs.url(.v2RSA)))
    }

    @Test func inspectThroughHandle() throws {
        let handle = try FileHandle(forReadingFrom: FixtureAPKs.url(.v2RSA))
        defer { try? handle.close() }
        #expect(try SigningBlockParser.inspect(handle: handle).blockSchemes == [.v2])
    }
}

@Suite("JARSignature")
struct JARSignatureTests {
    @Test func findsPairsAndCertificates() throws {
        for (stem, ext, subject) in [
            ("app-v1-rsa", "RSA", "CN=Airlock Test RSA, OU=Fixtures, O=Airlock, C=US"),
            ("app-v1-ec", "EC", "CN=Airlock Test EC, O=Airlock, C=DE"),
        ] {
            let entries = JARSignature.signatureEntries(in: try FixtureAPKs.entryNames(stem))
            #expect(entries == [JARSignatureEntries(signatureFile: "META-INF/\(ext).SF", signatureBlock: "META-INF/\(ext).\(ext)")])
            let certificates = try JARSignature.certificates(fromPKCS7: FixtureAPKs.raw("\(stem).\(ext)"))
            #expect(certificates.count == 1)
            #expect(try CertificateSummary(der: certificates[0]).subject == subject)
        }
    }

    @Test func entryMatchingRules() {
        let names = [
            "META-INF/A.SF", "META-INF/A.rsa", "META-INF/B.SF", "META-INF/sub/C.SF", "META-INF/sub/C.RSA",
            "META-INF/.SF", "META-INF/.RSA", "META-INF/D.SF", "META-INF/D.DSA", "META-INF/D.EC", "other/E.SF", "META-INF/MANIFEST.MF",
        ]
        #expect(JARSignature.signatureEntries(in: names) == [
            JARSignatureEntries(signatureFile: "META-INF/A.SF", signatureBlock: "META-INF/A.rsa"),
            JARSignatureEntries(signatureFile: "META-INF/D.SF", signatureBlock: "META-INF/D.DSA"),
        ])
        let many = (0..<40).flatMap { ["META-INF/S\($0).SF", "META-INF/S\($0).RSA"] }
        #expect(JARSignature.signatureEntries(in: many).count == JARSignature.maxSigners)
    }

    @Test func rejectsNonPKCS7() throws {
        #expect(throws: DERError.self) { try JARSignature.certificates(fromPKCS7: Data([0x30, 0x03, 0x02, 0x01, 0x01])) }
        let oidData = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01]) // 1.2.840.113549.1.7.1 (data)
        let wrapped = Data([0x30, UInt8(oidData.count + 2)]) + oidData + Data([0xA0, 0x00])
        #expect(throws: DERError.malformed("not PKCS#7 signedData")) { try JARSignature.certificates(fromPKCS7: wrapped) }
        // signedData without a certificates field.
        let signedOID = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])
        let inner = Data([0x30, 0x03, 0x02, 0x01, 0x01])
        let explicit = Data([0xA0, UInt8(inner.count)]) + inner
        let noCerts = Data([0x30, UInt8(signedOID.count + explicit.count)]) + signedOID + explicit
        #expect(try JARSignature.certificates(fromPKCS7: noCerts).isEmpty)
        let twoWrapped = Data([0xA0, UInt8(inner.count * 2)]) + inner + inner
        let bad = Data([0x30, UInt8(signedOID.count + twoWrapped.count)]) + signedOID + twoWrapped
        #expect(throws: DERError.malformed("signedData wrapper")) { try JARSignature.certificates(fromPKCS7: bad) }
        let certSet = Data([0xA0, 0x03, 0x02, 0x01, 0x05])
        let signedBody = Data([0x30, UInt8(3 + certSet.count), 0x02, 0x01, 0x01]) + certSet
        let explicitBody = Data([0xA0, UInt8(signedBody.count)]) + signedBody
        let badCert = Data([0x30, UInt8(signedOID.count + explicitBody.count)]) + signedOID + explicitBody
        #expect(throws: DERError.malformed("certificate choice 2")) { try JARSignature.certificates(fromPKCS7: badCert) }
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockArchive
import AirlockCore
@testable import AirlockSafety
import AirlockTestSupport
import CryptoKit
import Foundation
import Testing

private let rsaSHA256 = "fb23ba0dbc4c158f0b229e0f7ec101ee79a786b779816ea42579fd906a219c2d"
private let ecSHA256 = "fe1c97593b63ad71a1d3df738d04762f0de615c189b4f410e1ece7a8f3fea10b"

/// v1 evidence for a fixture, collected the way the install pipeline will (entry names + block bytes).
private func jarEvidence(_ stem: String, _ ext: String) throws -> JARSignatureEvidence {
    let entries = JARSignature.signatureEntries(in: try FixtureAPKs.entryNames(stem))
    return JARSignatureEvidence(entries: entries, signatureBlocks: [try FixtureAPKs.raw("\(stem).\(ext)")])
}

private func verify(_ apk: FixtureAPKs.APK, jar: JARSignatureEvidence? = nil) throws -> SignatureCheck {
    APKSignatureVerifier().verify(apkAt: try FixtureAPKs.url(apk), jarSignature: jar)
}

@Suite("APKSignatureVerifier on apksigner output")
struct APKSignatureVerifierFixtureTests {
    @Test(arguments: [
        (FixtureAPKs.APK.v2RSA, [2], rsaSHA256),
        (.v3RSA, [3], rsaSHA256),
        (.v2EC, [2], ecSHA256),
        (.v24RSA, [2, 4], rsaSHA256),
        (.splitArm64, [2], rsaSHA256),
        (.rotated, [2, 3], ecSHA256),
    ])
    func verifies(_ apk: FixtureAPKs.APK, _ schemes: [Int], _ certificate: String) throws {
        let check = try verify(apk)
        #expect(check.status == .verified, "\(check.problem ?? "")")
        #expect(check.schemes == schemes)
        #expect(check.certificates.map(\.sha256) == [certificate])
        #expect(check.problem == nil)
    }

    @Test func allSchemesWithV1Evidence() throws {
        let rsa = try verify(.v123RSA, jar: jarEvidence("app-v1-rsa", "RSA"))
        #expect(rsa.status == .verified && rsa.schemes == [1, 2, 3])
        let certificate = try #require(rsa.certificates.first)
        #expect(certificate.subject == "CN=Airlock Test RSA, OU=Fixtures, O=Airlock, C=US")
        #expect(certificate.issuer == certificate.subject)
        #expect(certificate.notValidBefore == Date(timeIntervalSince1970: 1_767_225_600))
        #expect(certificate.notValidAfter != nil)
        let ec = try verify(.v123EC)
        #expect(ec.status == .verified && ec.schemes == [2, 3] && ec.certificates.first?.sha256 == ecSHA256)
    }

    @Test func v1OnlyIsUnverifiableButShowsTheSigner() throws {
        for (apk, stem, ext, hash) in [(FixtureAPKs.APK.v1RSA, "app-v1-rsa", "RSA", rsaSHA256), (.v1EC, "app-v1-ec", "EC", ecSHA256)] {
            let check = try verify(apk, jar: jarEvidence(stem, ext))
            #expect(check.status == .unverifiable)
            #expect(check.schemes == [1])
            #expect(check.certificates.map(\.sha256) == [hash])
            #expect(check.problem?.contains("v1") == true)
        }
        let unreadable = JARSignatureEvidence(
            entries: [JARSignatureEntries(signatureFile: "META-INF/A.SF", signatureBlock: "META-INF/A.RSA")],
            signatureBlocks: [Data([1, 2])]
        )
        let check = try verify(.v1RSA, jar: unreadable)
        #expect(check.status == .unverifiable && check.certificates.isEmpty)
        #expect(check.problem?.contains("could not be read") == true)
    }

    @Test func unsignedAndTampered() throws {
        #expect(try verify(.unsigned) == SignatureCheck(status: .unsigned, schemes: [], certificates: []))
        #expect(try verify(.v1RSA).status == .unsigned, "without v1 evidence nothing marks the APK as signed")
        let tampered = try verify(.tampered)
        #expect(tampered.status == .invalid)
        #expect(tampered.schemes == [2, 3])
        #expect(tampered.problem?.contains("do not match") == true)
        #expect(tampered.certificates.first?.sha256 == rsaSHA256)
    }

    @Test func unreadableAndNonZipFiles() throws {
        let missing = APKSignatureVerifier().verify(apkAt: URL(fileURLWithPath: "/nonexistent/airlock.apk"))
        #expect(missing.status == .unverifiable)
        let notZip = try withTemporaryFile(Data(repeating: 7, count: 100)) { APKSignatureVerifier().verify(apkAt: $0) }
        #expect(notZip.status == .invalid && notZip.problem == "The file is not a valid zip archive.")
    }

    @Test func certificateFallbacks() {
        let unreadable = APKSignatureVerifier.signerCertificate(Data([0x30, 0x00]))
        #expect(unreadable.subject == "Unreadable certificate" && unreadable.issuer == "Unknown")
        #expect(unreadable.sha256 == SHA256.hash(data: Data([0x30, 0x00])).map { String(format: "%02x", $0) }.joined())
        #expect(APKSignatureVerifier.certificates([Data([1]), Data([1]), Data([2])]).count == 2)
    }
}

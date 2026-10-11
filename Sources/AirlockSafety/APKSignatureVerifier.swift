// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockArchive
import AirlockCore
import CryptoKit
import Foundation
import Security

/// Verifies APK signatures the way Android's package installer does for schemes v2, v3 and v3.1.
///
/// For every signer of every block present: the strongest supported signature over `signed data` is
/// checked with the signer's public key (RSA PKCS#1 v1.5, RSA-PSS or ECDSA on P-256/384/521); the digest and
/// signature algorithm lists must match; the first certificate's public key must equal the signer key; v3
/// SDK ranges must match their signed copies; and the chunked content digest recomputed from the file must
/// equal the signed one. A v2 block that announces a v3 block which is missing counts as stripping.
///
/// Not verified, by design or for now:
/// - v1 (JAR) signatures: certificates from the PKCS#7 block are reported, but the per-entry digests are not
///   checked, so a v1-only APK is `unverifiable`.
/// - v4 (`.idsig`): only its presence is reported.
/// - DSA and verity-only signers (`0x0301`, `0x042x`): `unverifiable`.
/// - Certificate trust and validity dates: Android ignores both for APK signing.
public struct APKSignatureVerifier: Sendable {
    public init() {}

    /// Checks the APK at `url`. `jarSignature` is the v1 evidence the caller pulled from the zip, if any.
    public func verify(apkAt url: URL, jarSignature: JARSignatureEvidence? = nil) -> SignatureCheck {
        let jar = JARResult(jarSignature)
        let hasV4 = SigningBlockParser.hasV4Signature(apkAt: url)
        let handle: FileHandle
        do {
            handle = try FileHandle(forReadingFrom: url)
        } catch {
            return SignatureCheck(status: .unverifiable, schemes: jar.schemes, certificates: jar.certificates,
                                  problem: "The APK could not be read: \(error.localizedDescription)")
        }
        defer { try? handle.close() }

        let inspection: APKSigningInspection
        do {
            inspection = try SigningBlockParser.inspect(handle: handle)
        } catch {
            return failure(for: error, jar: jar)
        }
        let blockSchemes = inspection.blockSchemes
        var schemes = Set(jar.schemes)
        for scheme in blockSchemes { schemes.insert(scheme == .v31 ? 3 : scheme.rawValue) }
        if hasV4, !blockSchemes.isEmpty { schemes.insert(4) }
        let sortedSchemes = schemes.sorted()

        guard let block = inspection.signingBlock, !blockSchemes.isEmpty else {
            if jar.isPresent {
                return SignatureCheck(status: .unverifiable, schemes: sortedSchemes, certificates: jar.certificates,
                                      problem: jar.problem ?? Self.v1Only)
            }
            return SignatureCheck(status: .unsigned, schemes: [], certificates: [])
        }

        let primary = [APKSignatureScheme.v31, .v3, .v2].first { blockSchemes.contains($0) } ?? .v2
        let certificates = Self.certificates(block.signers(for: primary).flatMap(\.certificates))
        let outcome = verifyBlock(block, schemes: blockSchemes, handle: handle, layout: inspection.layout)
        switch outcome {
        case .verified:
            return SignatureCheck(status: .verified, schemes: sortedSchemes, certificates: certificates)
        case .invalid(let problem):
            return SignatureCheck(status: .invalid, schemes: sortedSchemes, certificates: certificates, problem: problem)
        case .unverifiable(let problem):
            return SignatureCheck(status: .unverifiable, schemes: sortedSchemes, certificates: certificates, problem: problem)
        }
    }

    // MARK: - Blocks and signers

    enum Outcome: Equatable {
        case verified
        case invalid(String)
        case unverifiable(String)
    }

    /// A signer whose signature checked out, waiting for the content digest comparison.
    private struct PendingDigest {
        let scheme: APKSignatureScheme
        let kind: APKContentDigest
        let expected: Data
    }

    private static let strippingProtectionID: UInt32 = 0xbeef_f00d

    private static let v1Only = "Only a JAR (v1) signature is present; Airlock does not verify v1 signatures."

    private func verifyBlock(
        _ block: APKSigningBlock, schemes: [APKSignatureScheme], handle: FileHandle, layout: APKFileLayout
    ) -> Outcome {
        var pending: [PendingDigest] = []
        var unverifiable: String?
        for scheme in schemes {
            for signer in block.signers(for: scheme) {
                switch checkSigner(signer, scheme: scheme) {
                case .pending(let digest):
                    pending.append(digest)
                case .invalid(let problem):
                    return .invalid(problem)
                case .unverifiable(let problem):
                    unverifiable = unverifiable ?? problem
                }
            }
        }
        if !schemes.contains(.v3), block.v2Signers.contains(where: Self.announcesV3) {
            return .invalid("The v2 signature says a v3 signature was removed (signature stripping).")
        }
        if !pending.isEmpty {
            let kinds = Set(pending.map(\.kind))
            let digests: [APKContentDigest: Data]
            do {
                digests = try APKContentDigest.compute(kinds, handle: handle, layout: layout, signingBlockOffset: block.offset)
            } catch .layout(let reason) {
                return .invalid("The zip layout does not allow signature verification: \(reason).")
            } catch {
                return .unverifiable("The APK could not be read while verifying: \(error).")
            }
            if let mismatch = pending.first(where: { digests[$0.kind] != $0.expected }) {
                return .invalid("The APK contents do not match its \(Self.name(mismatch.scheme)) signature (modified or corrupt).")
            }
        }
        return unverifiable.map(Outcome.unverifiable) ?? .verified
    }

    private enum SignerCheck {
        case pending(PendingDigest)
        case invalid(String)
        case unverifiable(String)
    }

    private func checkSigner(_ signer: APKSigner, scheme: APKSignatureScheme) -> SignerCheck {
        let name = Self.name(scheme)
        guard let (algorithm, signature) = APKSignatureAlgorithm.strongestVerifiable(in: signer.signatures),
              let kind = algorithm.contentDigest, let secAlgorithm = algorithm.secKeyAlgorithm else {
            let ids = signer.signatures.map { String(format: "0x%04x", $0.algorithm) }.joined(separator: ", ")
            return .unverifiable("The \(name) signature uses algorithms Airlock cannot verify (\(ids)).")
        }
        guard let key = algorithm.publicKey(from: signer.publicKey) else {
            return .invalid("The \(name) signer's public key is malformed or does not fit its algorithm.")
        }
        guard SecKeyVerifySignature(key, secAlgorithm, signer.signedData as CFData, signature as CFData, nil) else {
            return .invalid("The \(name) signature does not verify.")
        }
        guard signer.signatures.map(\.algorithm) == signer.digests.map(\.algorithm),
              let digest = signer.digests.first(where: { $0.algorithm == algorithm.rawValue }) else {
            return .invalid("The \(name) signer's digest and signature lists differ.")
        }
        guard let certificate = signer.certificates.first,
              (try? CertificateSummary(der: certificate))?.subjectPublicKeyInfo == signer.publicKey else {
            return .invalid("The \(name) certificate does not match the signing key.")
        }
        guard signer.minSDK == signer.signedMinSDK, signer.maxSDK == signer.signedMaxSDK else {
            return .invalid("The \(name) signer's SDK range differs from the signed one.")
        }
        return .pending(PendingDigest(scheme: scheme, kind: kind, expected: digest.value))
    }

    /// Stripping protection: a v2 additional attribute listing scheme 3.
    private static func announcesV3(_ signer: APKSigner) -> Bool {
        signer.additionalAttributes.contains { attribute in
            guard attribute.algorithm == strippingProtectionID, attribute.value.count >= 4 else { return false }
            return attribute.value.prefix(4).enumerated().reduce(UInt32(0)) { $0 | UInt32($1.element) << (8 * $1.offset) } == 3
        }
    }

    private static func name(_ scheme: APKSignatureScheme) -> String {
        scheme == .v31 ? "v3.1" : "v\(scheme.rawValue)"
    }

    // MARK: - Results

    private func failure(for error: SigningBlockError, jar: JARResult) -> SignatureCheck {
        switch error {
        case .io(let reason):
            return SignatureCheck(status: .unverifiable, schemes: jar.schemes, certificates: jar.certificates,
                                  problem: "The APK could not be read: \(reason)")
        case .zip64Unsupported:
            return SignatureCheck(status: .unverifiable, schemes: jar.schemes, certificates: jar.certificates,
                                  problem: "The APK uses Zip64, which APK signature schemes do not support.")
        case .notAZip:
            return SignatureCheck(status: .invalid, schemes: jar.schemes, certificates: jar.certificates,
                                  problem: "The file is not a valid zip archive.")
        case .invalidLayout(let reason), .invalidSigningBlock(let reason), .invalidSigner(_, let reason):
            return SignatureCheck(status: .invalid, schemes: jar.schemes, certificates: jar.certificates,
                                  problem: "The APK signature data is malformed: \(reason).")
        }
    }

    /// Converts DER certificates to `SignerCertificate`, dropping duplicates.
    static func certificates(_ ders: [Data]) -> [SignerCertificate] {
        var seen = Set<Data>()
        return ders.filter { seen.insert($0).inserted }.map(signerCertificate)
    }

    static func signerCertificate(_ der: Data) -> SignerCertificate {
        let sha256 = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
        if let summary = try? CertificateSummary(der: der) {
            return SignerCertificate(subject: summary.subject, issuer: summary.issuer, sha256: sha256,
                                     notValidBefore: summary.notValidBefore, notValidAfter: summary.notValidAfter)
        }
        let fallback = SecCertificateCreateWithData(nil, der as CFData).flatMap { SecCertificateCopySubjectSummary($0) as String? }
        return SignerCertificate(subject: fallback ?? "Unreadable certificate", issuer: "Unknown", sha256: sha256)
    }
}

/// The v1 evidence turned into schemes and certificates.
private struct JARResult {
    let isPresent: Bool
    let certificates: [SignerCertificate]
    let problem: String?

    var schemes: [Int] { isPresent ? [1] : [] }

    init(_ evidence: JARSignatureEvidence?) {
        guard let evidence, !evidence.entries.isEmpty else {
            isPresent = false
            certificates = []
            problem = nil
            return
        }
        isPresent = true
        var ders: [Data] = []
        var failed = false
        for block in evidence.signatureBlocks {
            if let found = try? JARSignature.certificates(fromPKCS7: block) {
                ders += found
            } else {
                failed = true
            }
        }
        certificates = APKSignatureVerifier.certificates(ders)
        problem = failed ? "A JAR (v1) signature block could not be read; Airlock does not verify v1 signatures." : nil
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

@testable import AirlockArchive
import AirlockTestSupport
import Foundation
import Testing

/// Hand-built APK trailers and signing blocks.
enum SigningCraft {
    static func lp(_ data: Data) -> Data { AXMLBuilder.u32(UInt32(data.count)) + data }
    static func seq(_ items: [Data]) -> Data { items.reduce(Data()) { $0 + lp($1) } }
    static func algorithmValue(_ id: UInt32, _ value: Data) -> Data { AXMLBuilder.u32(id) + lp(value) }

    static func v2Signer(certificates: [Data] = [Data([1])], signatures: [Data]? = nil, publicKey: Data = Data([2])) -> Data {
        let signedData = lp(seq([algorithmValue(0x0103, Data(count: 32))])) + lp(seq(certificates)) + lp(Data())
        let sigs = signatures ?? [algorithmValue(0x0103, Data([9]))]
        return lp(signedData) + lp(seq(sigs)) + lp(publicKey)
    }

    static func signerBlockValue(_ signers: [Data]) -> Data { lp(seq(signers)) }

    static func block(_ pairs: [(UInt32, Data)]) -> Data {
        var body = Data()
        for (id, value) in pairs { body += AXMLBuilder.u64(UInt64(value.count + 4)) + AXMLBuilder.u32(id) + value }
        let size = UInt64(body.count + 24)
        return AXMLBuilder.u64(size) + body + AXMLBuilder.u64(size) + Data("APK Sig Block 42".utf8)
    }

    /// contents ‖ block ‖ central directory ‖ EOCD (with optional comment).
    static func apk(block: Data?, contents: Data = Data(repeating: 0x41, count: 64), comment: Data = Data()) -> Data {
        let centralDirectory = Data("PK\u{01}\u{02}fake-central-directory".utf8)
        let cdOffset = contents.count + (block?.count ?? 0)
        var eocd = AXMLBuilder.u32(0x0605_4b50) + AXMLBuilder.u16(0) + AXMLBuilder.u16(0) + AXMLBuilder.u16(1) + AXMLBuilder.u16(1)
        eocd += AXMLBuilder.u32(UInt32(centralDirectory.count)) + AXMLBuilder.u32(UInt32(cdOffset)) + AXMLBuilder.u16(UInt16(comment.count))
        return contents + (block ?? Data()) + centralDirectory + eocd + comment
    }

    static func patch(_ data: Data, at offset: Int, _ bytes: Data) -> Data {
        var copy = data
        copy.replaceSubrange(offset..<(offset + bytes.count), with: bytes)
        return copy
    }
}

private func inspect(_ data: Data) throws -> APKSigningInspection {
    try withTemporaryFile(data) { try SigningBlockParser.inspect(fileAt: $0) }
}

@Suite("SigningBlockParser rejects malformed input")
struct SigningMalformedTests {
    private let v2 = APKSignatureScheme.v2

    @Test func craftedBlockParses() throws {
        let value = SigningCraft.signerBlockValue([SigningCraft.v2Signer()])
        let apk = SigningCraft.apk(block: SigningCraft.block([(0x4272_6577, Data(count: 8)), (0x7109_871a, value), (0x7109_871a, Data())]),
                                   comment: Data("hello".utf8))
        let inspection = try inspect(apk)
        #expect(inspection.blockSchemes == [.v2])
        #expect(inspection.signingBlock?.pairIDs == [0x4272_6577, 0x7109_871a, 0x7109_871a], "only the first v2 pair is parsed")
        #expect(inspection.signingBlock?.signers(for: .v1).isEmpty == true)
        #expect(try inspect(SigningCraft.apk(block: nil)).signingBlock == nil)
        #expect(APKSignatureScheme.v1.blockID == nil && APKSignatureScheme.v31.blockID == 0x1b93_ad61)
    }

    @Test func trailerErrors() throws {
        #expect(throws: SigningBlockError.notAZip) { try inspect(Data(count: 10)) }
        #expect(throws: SigningBlockError.notAZip) { try inspect(Data(repeating: 0x50, count: 70_000)) }
        let good = SigningCraft.apk(block: nil)
        let eocd = good.count - 22
        #expect(throws: SigningBlockError.zip64Unsupported) { try inspect(SigningCraft.patch(good, at: eocd + 16, AXMLBuilder.u32(.max))) }
        #expect(throws: SigningBlockError.invalidLayout("multi-disk archive")) {
            try inspect(SigningCraft.patch(good, at: eocd + 4, AXMLBuilder.u16(1)))
        }
        #expect(throws: SigningBlockError.invalidLayout("central directory overlaps the end record")) {
            try inspect(SigningCraft.patch(good, at: eocd + 12, AXMLBuilder.u32(5_000)))
        }
        #expect(throws: SigningBlockError.self) {
            try SigningBlockParser.inspect(fileAt: URL(fileURLWithPath: "/nonexistent/airlock.apk"))
        }
    }

    @Test func blockFramingErrors() throws {
        let block = SigningCraft.block([(0x7109_871a, SigningCraft.signerBlockValue([SigningCraft.v2Signer()]))])
        let apk = SigningCraft.apk(block: block)
        let blockStart = 64
        let footer = blockStart + block.count - 24
        #expect(throws: SigningBlockError.invalidSigningBlock("block size 8")) {
            try inspect(SigningCraft.patch(apk, at: footer, AXMLBuilder.u64(8)))
        }
        #expect(throws: SigningBlockError.invalidSigningBlock("block size 1000000")) {
            try inspect(SigningCraft.patch(apk, at: footer, AXMLBuilder.u64(1_000_000)))
        }
        #expect(throws: SigningBlockError.invalidSigningBlock("size fields differ")) {
            try inspect(SigningCraft.patch(apk, at: blockStart, AXMLBuilder.u64(7)))
        }
        #expect(throws: SigningBlockError.invalidSigningBlock("pair length 2")) {
            try inspect(SigningCraft.patch(apk, at: blockStart + 8, AXMLBuilder.u64(2)))
        }
        #expect(throws: SigningBlockError.invalidSigningBlock("pair length 4294967295")) {
            try inspect(SigningCraft.patch(apk, at: blockStart + 8, AXMLBuilder.u64(UInt64(UInt32.max))))
        }
        let manyPairs = SigningCraft.block((0...SigningBlockParser.Limits.maxPairs).map { _ in (UInt32(1), Data()) })
        #expect(throws: SigningBlockError.invalidSigningBlock("more than 1024 pairs")) { try inspect(SigningCraft.apk(block: manyPairs)) }
        // A truncated pair header inside the block.
        let shortPair = SigningCraft.block([]) // then splice 3 garbage bytes into the pair area
        var spliced = shortPair
        spliced.insert(contentsOf: [1, 2, 3], at: 8)
        spliced.replaceSubrange(0..<8, with: AXMLBuilder.u64(27))
        spliced.replaceSubrange((spliced.count - 24)..<(spliced.count - 16), with: AXMLBuilder.u64(27))
        #expect(throws: SigningBlockError.self) { try inspect(SigningCraft.apk(block: spliced)) }
    }

    @Test func signerErrors() {
        func parse(_ value: Data) throws(SigningBlockError) -> [APKSigner] {
            try SigningBlockParser.parseSigners(value, scheme: v2)
        }
        func reason(_ text: String) -> SigningBlockError { .invalidSigner(scheme: v2, reason: text) }
        #expect(throws: reason("no signers")) { try parse(SigningCraft.signerBlockValue([])) }
        #expect(throws: reason("trailing bytes after the signer list")) { try parse(SigningCraft.signerBlockValue([]) + Data([0])) }
        #expect(throws: reason("no signatures")) { try parse(SigningCraft.signerBlockValue([SigningCraft.v2Signer(signatures: [])])) }
        #expect(throws: reason("no public key")) { try parse(SigningCraft.signerBlockValue([SigningCraft.v2Signer(publicKey: Data())])) }
        #expect(throws: reason("no certificates")) { try parse(SigningCraft.signerBlockValue([SigningCraft.v2Signer(certificates: [])])) }
        #expect(throws: reason("more than 16 items")) {
            try parse(SigningCraft.signerBlockValue(Array(repeating: SigningCraft.v2Signer(), count: 17)))
        }
        #expect(throws: reason("length 4294967295")) { try parse(AXMLBuilder.u32(.max)) }
        #expect(throws: reason("length 4 at 0 overruns 2")) { try parse(AXMLBuilder.u32(2) + Data([0, 0])) }
        #expect(throws: SigningBlockError.invalidSigningBlock("x")) { throw SigningBlockError.notAZip.with("x") }
    }
}

@Suite("DER and X.509 edge cases")
struct DERTests {
    @Test func lengthsAndTags() throws {
        #expect(throws: DERError.truncated) { try DERParser.single(Data([0x30])) }
        #expect(throws: DERError.truncated) { try DERParser.single(Data([0x30, 0x05, 0x00])) }
        #expect(throws: DERError.truncated) { try DERParser.single(Data([0x30, 0x82, 0x01])) }
        #expect(throws: DERError.malformed("high tag number")) { try DERParser.single(Data([0x1F, 0x00])) }
        #expect(throws: DERError.malformed("length of length 0")) { try DERParser.single(Data([0x30, 0x80])) }
        #expect(throws: DERError.malformed("length of length 5")) { try DERParser.single(Data([0x30, 0x85, 0, 0, 0, 0, 1])) }
        #expect(throws: DERError.malformed("expected one element")) { try DERParser.single(Data([0x05, 0x00, 0x05, 0x00])) }
        let long = Data([0x04, 0x81, 0x80]) + Data(count: 128)
        #expect(try DERParser.single(long).value.count == 128)
        #expect(throws: DERError.malformed("tag 4 is not constructed")) { try DERParser.single(long).children() }
        #expect(throws: DERError.limitExceeded) { try DERParser.elements(in: Data(repeating: 0, count: 2 * 4_097)) }
    }

    @Test func objectIdentifiers() throws {
        func oid(_ bytes: [UInt8]) throws -> String { try DERElement(tag: 0x06, value: Data(bytes), encoded: Data()).objectIdentifier() }
        #expect(try oid([0x2A, 0x86, 0x48]) == "1.2.840")
        #expect(try oid([0x88, 0x37]) == "2.999")
        #expect(throws: DERError.malformed("object identifier")) { try oid([0x86]) }
        #expect(throws: DERError.malformed("object identifier")) { try oid([]) }
        #expect(throws: DERError.malformed("object identifier arc")) { try oid(Array(repeating: 0xFF, count: 12) + [0x01]) }
    }

    @Test func directoryStringsAndTimes() {
        #expect(CertificateSummary.stringValue(DERElement(tag: 0x1E, value: Data([0x00, 0x41, 0x00, 0xE9]), encoded: Data())) == "Aé")
        #expect(CertificateSummary.stringValue(DERElement(tag: 0x14, value: Data([0x41, 0xE9]), encoded: Data())) == "Aé")
        #expect(CertificateSummary.stringValue(DERElement(tag: 0x02, value: Data([1]), encoded: Data([2, 1, 1]))) == "#020101")
        func time(_ tag: UInt8, _ text: String) -> Date? {
            CertificateSummary.time(DERElement(tag: tag, value: Data(text.utf8), encoded: Data()))
        }
        #expect(time(0x17, "491231235959Z") == Date(timeIntervalSince1970: 2_524_607_999))
        #expect(time(0x17, "700101000000Z") == Date(timeIntervalSince1970: 0))
        #expect(time(0x18, "20260101000000Z") == Date(timeIntervalSince1970: 1_767_225_600))
        #expect(time(0x17, "701301000000Z") == nil, "month 13")
        #expect(time(0x17, "7001010000Z") == nil)
        #expect(time(0x18, "2026010100000+Z") == nil)
        #expect(time(0x18, "20260101000000+0100") == nil)
        #expect(time(0x02, "700101000000Z") == nil)
    }

    @Test func certificateStructureErrors() throws {
        #expect(throws: DERError.malformed("empty certificate")) { try CertificateSummary(der: Data([0x30, 0x00])) }
        #expect(throws: DERError.malformed("tbsCertificate has 1 fields")) {
            try CertificateSummary(der: Data([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01]))
        }
        #expect(throws: DERError.self) { try PublicKeyInfo(subjectPublicKeyInfo: Data([0x30, 0x00])) }
        // AlgorithmIdentifier { ecPublicKey } without curve, and an unknown algorithm.
        let ecOID = Data([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
        let bits = Data([0x03, 0x02, 0x00, 0x04])
        let ecNoCurve = Data([0x30, UInt8(2 + ecOID.count + bits.count), 0x30, UInt8(ecOID.count)]) + ecOID + bits
        #expect(throws: DERError.malformed("EC key without a named curve")) { try PublicKeyInfo(subjectPublicKeyInfo: ecNoCurve) }
        let dsaOID = Data([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01])
        let dsa = Data([0x30, UInt8(2 + dsaOID.count + bits.count), 0x30, UInt8(dsaOID.count)]) + dsaOID + bits
        #expect(try PublicKeyInfo(subjectPublicKeyInfo: dsa).algorithm == .dsa)
        let otherOID = Data([0x06, 0x03, 0x2B, 0x65, 0x70]) // 1.3.101.112 (Ed25519)
        let other = Data([0x30, UInt8(2 + otherOID.count + bits.count), 0x30, UInt8(otherOID.count)]) + otherOID + bits
        #expect(try PublicKeyInfo(subjectPublicKeyInfo: other).algorithm == .other("1.3.101.112"))
        let emptyAlg = Data([0x30, UInt8(2 + bits.count), 0x30, 0x00]) + bits
        #expect(throws: DERError.malformed("algorithm identifier")) { try PublicKeyInfo(subjectPublicKeyInfo: emptyAlg) }
    }
}

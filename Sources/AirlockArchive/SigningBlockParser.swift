// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Locates and parses the APK Signing Block (schemes v2, v3 and v3.1).
///
/// Layout, from the end of the file backwards: the End of Central Directory record gives the central
/// directory's offset; the 24 bytes before the central directory hold the block size and the magic
/// `APK Sig Block 42`; the block itself is a list of `(u64 length, u32 id, value)` pairs. All lengths are
/// checked against their container, and only the block (at most ``Limits/maxBlockSize``) and the zip trailer
/// are read, never the whole APK.
public enum SigningBlockParser {
    public enum Limits {
        public static let maxBlockSize = 32 * 1024 * 1024
        public static let maxPairs = 1_024
        public static let maxSigners = 16
        /// Items in any length-prefixed sequence (digests, certificates, signatures, attributes).
        public static let maxSequenceItems = 256
    }

    private static let magic = Data("APK Sig Block 42".utf8)

    /// Inspects the APK at `url`.
    public static func inspect(fileAt url: URL) throws(SigningBlockError) -> APKSigningInspection {
        let handle: FileHandle
        do {
            handle = try FileHandle(forReadingFrom: url)
        } catch {
            throw .io(error.localizedDescription)
        }
        defer { try? handle.close() }
        return try inspect(handle: handle)
    }

    /// Inspects an APK through an open handle. The handle's position is changed.
    public static func inspect(handle: FileHandle) throws(SigningBlockError) -> APKSigningInspection {
        let file = try SigningFileReader(handle: handle)
        let layout = try SigningEOCDLocator.layout(of: file)
        return APKSigningInspection(layout: layout, signingBlock: try signingBlock(in: file, layout: layout))
    }

    /// True when a detached v4 signature (`<apk>.idsig`) sits next to the APK. It is never verified.
    public static func hasV4Signature(apkAt url: URL) -> Bool {
        FileManager.default.fileExists(atPath: url.path + ".idsig")
    }

    // MARK: - Block

    private static func signingBlock(in file: SigningFileReader, layout: APKFileLayout) throws(SigningBlockError) -> APKSigningBlock? {
        let cdOffset = layout.centralDirectoryOffset
        guard cdOffset >= 32 else { return nil }
        let footer = try file.read(at: cdOffset - 24, count: 24)
        guard footer.suffix(16) == magic else { return nil }
        let size = footer.withUnsafeBytes { UInt64(littleEndian: $0.loadUnaligned(as: UInt64.self)) }
        guard size >= 24, size <= UInt64(Limits.maxBlockSize), Int64(size) + 8 <= cdOffset else {
            throw .invalidSigningBlock("block size \(size)")
        }
        let offset = cdOffset - Int64(size) - 8
        let block = try file.read(at: offset, count: Int(size) + 8)
        var cursor = SigningCursor(block, context: .invalidSigningBlock(""))
        guard try cursor.u64() == size else { throw .invalidSigningBlock("size fields differ") }

        var pairs = SigningCursor(Data(block[8..<(block.count - 24)]), context: .invalidSigningBlock(""))
        var ids: [UInt32] = []
        var signers: [APKSignatureScheme: [APKSigner]] = [:]
        while !pairs.isAtEnd {
            guard ids.count < Limits.maxPairs else { throw .invalidSigningBlock("more than \(Limits.maxPairs) pairs") }
            let length = try pairs.u64()
            guard length >= 4, length <= UInt64(pairs.remaining) else { throw .invalidSigningBlock("pair length \(length)") }
            let id = try pairs.u32()
            let value = try pairs.bytes(Int(length) - 4)
            ids.append(id)
            if let scheme = [APKSignatureScheme.v2, .v3, .v31].first(where: { $0.blockID == id }), signers[scheme] == nil {
                signers[scheme] = try parseSigners(value, scheme: scheme)
            }
        }
        return APKSigningBlock(
            offset: offset, size: Int64(size) + 8, pairIDs: ids,
            v2Signers: signers[.v2] ?? [], v3Signers: signers[.v3] ?? [], v31Signers: signers[.v31] ?? []
        )
    }

    // MARK: - Signers

    /// `length-prefixed sequence of length-prefixed signer`.
    static func parseSigners(_ value: Data, scheme: APKSignatureScheme) throws(SigningBlockError) -> [APKSigner] {
        let context = SigningBlockError.invalidSigner(scheme: scheme, reason: "")
        var outer = SigningCursor(value, context: context)
        let list = try outer.lengthPrefixed()
        guard outer.isAtEnd else { throw context.with("trailing bytes after the signer list") }
        let items = try SigningCursor.sequence(list, context: context, maxItems: Limits.maxSigners)
        guard !items.isEmpty else { throw context.with("no signers") }
        return try items.map { item throws(SigningBlockError) in try parseSigner(item, scheme: scheme, context: context) }
    }

    private static func parseSigner(
        _ data: Data, scheme: APKSignatureScheme, context: SigningBlockError
    ) throws(SigningBlockError) -> APKSigner {
        let isV3 = scheme != .v2
        var cursor = SigningCursor(data, context: context)
        let signedData = try cursor.lengthPrefixed()
        let minSDK = isV3 ? try cursor.u32() : nil
        let maxSDK = isV3 ? try cursor.u32() : nil
        let signatures = try algorithmValues(try cursor.lengthPrefixed(), context: context)
        let publicKey = try cursor.lengthPrefixed()
        guard !signatures.isEmpty else { throw context.with("no signatures") }
        guard !publicKey.isEmpty else { throw context.with("no public key") }

        var signed = SigningCursor(signedData, context: context)
        let digests = try algorithmValues(try signed.lengthPrefixed(), context: context)
        let certificates = try SigningCursor.sequence(try signed.lengthPrefixed(), context: context, maxItems: Limits.maxSequenceItems)
        let signedMinSDK = isV3 ? try signed.u32() : nil
        let signedMaxSDK = isV3 ? try signed.u32() : nil
        let attributes = try attributes(try signed.lengthPrefixed(), context: context)
        guard !certificates.isEmpty else { throw context.with("no certificates") }
        return APKSigner(
            signedData: signedData, digests: digests, certificates: certificates, additionalAttributes: attributes,
            signatures: signatures, publicKey: publicKey,
            minSDK: minSDK, maxSDK: maxSDK, signedMinSDK: signedMinSDK, signedMaxSDK: signedMaxSDK
        )
    }

    /// Sequence of `(u32 algorithm, length-prefixed bytes)`, as used for digests and signatures.
    private static func algorithmValues(_ data: Data, context: SigningBlockError) throws(SigningBlockError) -> [APKAlgorithmValue] {
        try SigningCursor.sequence(data, context: context, maxItems: Limits.maxSequenceItems).map { item throws(SigningBlockError) in
            var cursor = SigningCursor(item, context: context)
            let algorithm = try cursor.u32()
            let value = try cursor.lengthPrefixed()
            return APKAlgorithmValue(algorithm: algorithm, value: value)
        }
    }

    /// Sequence of `(u32 id, rest of the item)`.
    private static func attributes(_ data: Data, context: SigningBlockError) throws(SigningBlockError) -> [APKAlgorithmValue] {
        try SigningCursor.sequence(data, context: context, maxItems: Limits.maxSequenceItems).map { item throws(SigningBlockError) in
            var cursor = SigningCursor(item, context: context)
            let id = try cursor.u32()
            return APKAlgorithmValue(algorithm: id, value: try cursor.bytes(cursor.remaining))
        }
    }
}

extension SigningBlockError {
    /// The same error kind with a specific reason.
    func with(_ reason: String) -> SigningBlockError {
        switch self {
        case .invalidSigner(let scheme, _): .invalidSigner(scheme: scheme, reason: reason)
        default: .invalidSigningBlock(reason)
        }
    }
}

/// Little-endian cursor over a zero-based `Data` with length-prefixed helpers.
struct SigningCursor {
    private let data: Data
    private let context: SigningBlockError
    private(set) var offset = 0

    init(_ data: Data, context: SigningBlockError) {
        self.data = Data(data) // re-base to index 0
        self.context = context
    }

    var remaining: Int { data.count - offset }
    var isAtEnd: Bool { offset >= data.count }

    mutating func bytes(_ count: Int) throws(SigningBlockError) -> Data {
        guard count >= 0, count <= remaining else { throw context.with("length \(count) at \(offset) overruns \(data.count)") }
        defer { offset += count }
        return data.subdata(in: offset..<(offset + count))
    }

    mutating func u32() throws(SigningBlockError) -> UInt32 {
        try bytes(4).withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) }
    }

    mutating func u64() throws(SigningBlockError) -> UInt64 {
        try bytes(8).withUnsafeBytes { UInt64(littleEndian: $0.loadUnaligned(as: UInt64.self)) }
    }

    /// `u32 length` followed by that many bytes.
    mutating func lengthPrefixed() throws(SigningBlockError) -> Data {
        let length = try u32()
        guard length <= UInt32(Int32.max) else { throw context.with("length \(length)") }
        return try bytes(Int(length))
    }

    /// Splits `data` into its length-prefixed items.
    static func sequence(_ data: Data, context: SigningBlockError, maxItems: Int) throws(SigningBlockError) -> [Data] {
        var cursor = SigningCursor(data, context: context)
        var items: [Data] = []
        while !cursor.isAtEnd {
            guard items.count < maxItems else { throw context.with("more than \(maxItems) items") }
            items.append(try cursor.lengthPrefixed())
        }
        return items
    }
}

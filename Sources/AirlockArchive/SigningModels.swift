// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Why an APK's zip trailer or APK Signing Block could not be read.
public enum SigningBlockError: Error, Hashable, Sendable {
    /// Reading the file failed.
    case io(String)
    /// No End of Central Directory record in the last 64 KiB: not a zip.
    case notAZip
    /// The central directory is described by Zip64 records, which APK signing does not support.
    case zip64Unsupported
    /// Central directory offsets and sizes contradict each other or the file size.
    case invalidLayout(String)
    /// The APK Signing Block is malformed or exceeds the limits.
    case invalidSigningBlock(String)
    /// A v2/v3 signer inside the block is malformed.
    case invalidSigner(scheme: APKSignatureScheme, reason: String)
}

/// APK signature schemes, numbered as `SignatureCheck.schemes` reports them.
public enum APKSignatureScheme: Int, Hashable, Sendable, Codable, CaseIterable {
    /// JAR signing (`META-INF/*.SF` + `*.RSA|DSA|EC`).
    case v1 = 1
    case v2 = 2
    case v3 = 3
    /// v3.1, the rotation-targeted block (Android 13+). Reported as scheme 3 in `SignatureCheck.schemes`.
    case v31 = 31
    /// Detached `<apk>.idsig` file; detected, never verified.
    case v4 = 4

    /// ID of the block in the APK Signing Block, for the schemes that live there.
    public var blockID: UInt32? {
        switch self {
        case .v2: 0x7109_871a
        case .v3: 0xf053_68c0
        case .v31: 0x1b93_ad61
        case .v1, .v4: nil
        }
    }
}

/// Where the parts of the zip that APK signing covers lie in the file.
public struct APKFileLayout: Hashable, Sendable {
    public let fileSize: Int64
    public let centralDirectoryOffset: Int64
    public let centralDirectorySize: Int64
    public let endOfCentralDirectoryOffset: Int64
    /// The End of Central Directory record including its comment.
    public let endOfCentralDirectory: Data

    public init(
        fileSize: Int64, centralDirectoryOffset: Int64, centralDirectorySize: Int64,
        endOfCentralDirectoryOffset: Int64, endOfCentralDirectory: Data
    ) {
        self.fileSize = fileSize
        self.centralDirectoryOffset = centralDirectoryOffset
        self.centralDirectorySize = centralDirectorySize
        self.endOfCentralDirectoryOffset = endOfCentralDirectoryOffset
        self.endOfCentralDirectory = endOfCentralDirectory
    }
}

/// A `(algorithm ID, bytes)` pair: a digest or a signature.
public struct APKAlgorithmValue: Hashable, Sendable {
    /// Signature algorithm ID, e.g. `0x0103` (RSASSA-PKCS1-v1_5 with SHA-256).
    public let algorithm: UInt32
    public let value: Data

    public init(algorithm: UInt32, value: Data) {
        self.algorithm = algorithm
        self.value = value
    }
}

/// One signer of a v2, v3 or v3.1 block.
public struct APKSigner: Hashable, Sendable {
    /// The exact `signed data` bytes the signatures cover.
    public let signedData: Data
    public let digests: [APKAlgorithmValue]
    /// DER X.509 certificates; the first one is the signer's.
    public let certificates: [Data]
    public let additionalAttributes: [APKAlgorithmValue]
    public let signatures: [APKAlgorithmValue]
    /// DER `SubjectPublicKeyInfo`.
    public let publicKey: Data
    /// v3/v3.1: the SDK range on the signer, and the copy inside the signed data (they must match).
    public let minSDK: UInt32?
    public let maxSDK: UInt32?
    public let signedMinSDK: UInt32?
    public let signedMaxSDK: UInt32?

    public init(
        signedData: Data, digests: [APKAlgorithmValue], certificates: [Data], additionalAttributes: [APKAlgorithmValue],
        signatures: [APKAlgorithmValue], publicKey: Data,
        minSDK: UInt32? = nil, maxSDK: UInt32? = nil, signedMinSDK: UInt32? = nil, signedMaxSDK: UInt32? = nil
    ) {
        self.signedData = signedData
        self.digests = digests
        self.certificates = certificates
        self.additionalAttributes = additionalAttributes
        self.signatures = signatures
        self.publicKey = publicKey
        self.minSDK = minSDK
        self.maxSDK = maxSDK
        self.signedMinSDK = signedMinSDK
        self.signedMaxSDK = signedMaxSDK
    }
}

/// The APK Signing Block that sits between the zip entries and the central directory.
public struct APKSigningBlock: Hashable, Sendable {
    /// Offset of the block's first byte; everything before it is the "contents" section.
    public let offset: Int64
    /// Total size including both size fields and the magic.
    public let size: Int64
    /// IDs of every ID-value pair, in file order (padding and unknown blocks included).
    public let pairIDs: [UInt32]
    public let v2Signers: [APKSigner]
    public let v3Signers: [APKSigner]
    public let v31Signers: [APKSigner]

    public init(offset: Int64, size: Int64, pairIDs: [UInt32], v2Signers: [APKSigner], v3Signers: [APKSigner], v31Signers: [APKSigner]) {
        self.offset = offset
        self.size = size
        self.pairIDs = pairIDs
        self.v2Signers = v2Signers
        self.v3Signers = v3Signers
        self.v31Signers = v31Signers
    }

    public func signers(for scheme: APKSignatureScheme) -> [APKSigner] {
        switch scheme {
        case .v2: v2Signers
        case .v3: v3Signers
        case .v31: v31Signers
        case .v1, .v4: []
        }
    }
}

/// What ``SigningBlockParser`` found in one APK.
public struct APKSigningInspection: Hashable, Sendable {
    public let layout: APKFileLayout
    /// Nil when there is no APK Signing Block (unsigned or v1-only).
    public let signingBlock: APKSigningBlock?

    public init(layout: APKFileLayout, signingBlock: APKSigningBlock?) {
        self.layout = layout
        self.signingBlock = signingBlock
    }

    /// v2/v3/v3.1 schemes with at least one signer, in ascending order.
    public var blockSchemes: [APKSignatureScheme] {
        guard let signingBlock else { return [] }
        return [.v2, .v3, .v31].filter { !signingBlock.signers(for: $0).isEmpty }
    }
}

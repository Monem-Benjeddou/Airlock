// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockArchive
import CryptoKit
import Foundation

/// The chunked content digests of APK Signature Scheme v2/v3.
///
/// The APK is viewed as three sections: the zip entries before the signing block, the central directory,
/// and the End of Central Directory record with its central-directory offset replaced by the signing
/// block's offset. Each section is cut into 1 MiB chunks; every chunk is hashed as
/// `H(0xa5 ‖ u32le(length) ‖ chunk)` and the result is `H(0x5a ‖ u32le(chunkCount) ‖ chunk digests…)`.
/// The file is streamed one chunk at a time, so memory use does not grow with the APK size.
enum APKContentDigest: Hashable, Sendable {
    case sha256
    case sha512

    static let chunkSize = 1024 * 1024

    enum Failure: Error, Equatable {
        case layout(String)
        case io(String)
    }

    /// Computes the requested digests in a single pass over the file.
    static func compute(
        _ kinds: Set<APKContentDigest>, handle: FileHandle, layout: APKFileLayout, signingBlockOffset: Int64
    ) throws(Failure) -> [APKContentDigest: Data] {
        guard layout.centralDirectoryOffset + layout.centralDirectorySize == layout.endOfCentralDirectoryOffset else {
            throw .layout("the central directory is not immediately followed by the end record")
        }
        guard layout.endOfCentralDirectory.count >= 22, signingBlockOffset >= 0, signingBlockOffset <= UInt32.max else {
            throw .layout("signing block offset")
        }
        var eocd = layout.endOfCentralDirectory
        eocd.replaceSubrange(16..<20, with: withUnsafeBytes(of: UInt32(signingBlockOffset).littleEndian) { Data($0) })

        var chunkDigests: [APKContentDigest: Data] = [:]
        var chunkCount: UInt32 = 0
        func absorb(_ chunk: Data) {
            chunkCount += 1
            for kind in kinds {
                chunkDigests[kind, default: Data()] += kind.chunkDigest(chunk)
            }
        }
        try stream(handle: handle, from: 0, length: signingBlockOffset, into: absorb)
        try stream(handle: handle, from: layout.centralDirectoryOffset, length: layout.centralDirectorySize, into: absorb)
        var start = 0
        while start < eocd.count {
            let end = min(start + chunkSize, eocd.count)
            absorb(eocd.subdata(in: start..<end))
            start = end
        }

        var result: [APKContentDigest: Data] = [:]
        for kind in kinds {
            var top = Data([0x5a])
            top += withUnsafeBytes(of: chunkCount.littleEndian) { Data($0) }
            top += chunkDigests[kind] ?? Data()
            result[kind] = kind.hash(top)
        }
        return result
    }

    private static func stream(handle: FileHandle, from offset: Int64, length: Int64, into body: (Data) -> Void) throws(Failure) {
        do {
            try handle.seek(toOffset: UInt64(offset))
            var remaining = length
            while remaining > 0 {
                let wanted = Int(min(Int64(chunkSize), remaining))
                let chunk: Data = try autoreleasepool { try handle.read(upToCount: wanted) ?? Data() }
                guard chunk.count == wanted else { throw Failure.io("file shrank while reading at \(offset + length - remaining)") }
                body(chunk)
                remaining -= Int64(wanted)
            }
        } catch let failure as Failure {
            throw failure
        } catch {
            throw .io(error.localizedDescription)
        }
    }

    private func chunkDigest(_ chunk: Data) -> Data {
        var prefix = Data([0xa5])
        prefix += withUnsafeBytes(of: UInt32(chunk.count).littleEndian) { Data($0) }
        switch self {
        case .sha256:
            var hasher = SHA256()
            hasher.update(data: prefix)
            hasher.update(data: chunk)
            return Data(hasher.finalize())
        case .sha512:
            var hasher = SHA512()
            hasher.update(data: prefix)
            hasher.update(data: chunk)
            return Data(hasher.finalize())
        }
    }

    private func hash(_ data: Data) -> Data {
        switch self {
        case .sha256: Data(SHA256.hash(data: data))
        case .sha512: Data(SHA512.hash(data: data))
        }
    }
}

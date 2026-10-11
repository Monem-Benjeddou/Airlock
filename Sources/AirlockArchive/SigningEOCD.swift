// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Bounded random access to a file through `FileHandle`.
struct SigningFileReader {
    let handle: FileHandle
    let size: Int64

    init(handle: FileHandle) throws(SigningBlockError) {
        self.handle = handle
        do {
            size = Int64(try handle.seekToEnd())
        } catch {
            throw .io(error.localizedDescription)
        }
    }

    /// Exactly `count` bytes at `offset`; throws if the range leaves the file.
    func read(at offset: Int64, count: Int) throws(SigningBlockError) -> Data {
        guard offset >= 0, count >= 0, offset <= size, Int64(count) <= size - offset else {
            throw .invalidLayout("read of \(count) bytes at \(offset) leaves the file")
        }
        do {
            try handle.seek(toOffset: UInt64(offset))
            let data = try handle.read(upToCount: count) ?? Data()
            guard data.count == count else { throw SigningBlockError.io("short read at \(offset)") }
            return data
        } catch let error as SigningBlockError {
            throw error
        } catch {
            throw .io(error.localizedDescription)
        }
    }
}

/// Finds the End of Central Directory record, which APK signing needs to find the central directory and
/// the signing block before it. Kept private to the signing parser and bounded to the last 64 KiB + 22 bytes.
enum SigningEOCDLocator {
    static let recordSize = 22
    static let maxCommentSize = 0xFFFF
    private static let signature: UInt32 = 0x0605_4b50

    static func layout(of file: SigningFileReader) throws(SigningBlockError) -> APKFileLayout {
        guard file.size >= Int64(recordSize) else { throw .notAZip }
        let tailSize = Int(min(file.size, Int64(recordSize + maxCommentSize)))
        let tailStart = file.size - Int64(tailSize)
        let tail = [UInt8](try file.read(at: tailStart, count: tailSize))
        // Scan backwards for a signature whose comment length reaches exactly to the end of the file.
        var position = tail.count - recordSize
        while position >= 0 {
            if u32(tail, position) == signature, Int(u16(tail, position + 20)) == tail.count - position - recordSize {
                return try layout(record: Array(tail[position...]), at: tailStart + Int64(position), fileSize: file.size)
            }
            position -= 1
        }
        throw .notAZip
    }

    private static func layout(record: [UInt8], at offset: Int64, fileSize: Int64) throws(SigningBlockError) -> APKFileLayout {
        let entriesOnDisk = u16(record, 8)
        let entries = u16(record, 10)
        let cdSize = u32(record, 12)
        let cdOffset = u32(record, 16)
        if cdSize == UInt32.max || cdOffset == UInt32.max || entries == UInt16.max || entriesOnDisk == UInt16.max {
            throw .zip64Unsupported
        }
        guard u16(record, 4) == 0, u16(record, 6) == 0, entriesOnDisk == entries else {
            throw .invalidLayout("multi-disk archive")
        }
        guard Int64(cdOffset) + Int64(cdSize) <= offset else {
            throw .invalidLayout("central directory overlaps the end record")
        }
        return APKFileLayout(
            fileSize: fileSize,
            centralDirectoryOffset: Int64(cdOffset),
            centralDirectorySize: Int64(cdSize),
            endOfCentralDirectoryOffset: offset,
            endOfCentralDirectory: Data(record)
        )
    }

    private static func u16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) | UInt16(bytes[offset + 1]) << 8
    }

    private static func u32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(u16(bytes, offset)) | UInt32(u16(bytes, offset + 2)) << 16
    }
}

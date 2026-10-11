// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Little-endian reads over a borrowed byte buffer where every access is bounds-checked.
///
/// Used by the binary XML, DEX and signing-block parsers on hostile input. The reader borrows the buffer
/// handed to a `withUnsafeBytes` closure and must not escape it. Offsets are `Int` and checked without
/// overflow; a failed check throws the caller's typed error built from the offending offset.
struct BoundedReader<Failure: Error> {
    let bytes: UnsafeRawBufferPointer
    let failure: (Int) -> Failure

    init(_ bytes: UnsafeRawBufferPointer, failure: @escaping (Int) -> Failure) {
        self.bytes = bytes
        self.failure = failure
    }

    var count: Int { bytes.count }

    /// Throws unless `size` bytes starting at `offset` lie inside the buffer.
    func check(_ offset: Int, _ size: Int) throws(Failure) {
        guard offset >= 0, size >= 0, offset <= bytes.count, size <= bytes.count - offset else {
            throw failure(offset)
        }
    }

    func u8(at offset: Int) throws(Failure) -> UInt8 {
        try check(offset, 1)
        return bytes[offset]
    }

    func u16(at offset: Int) throws(Failure) -> UInt16 {
        try check(offset, 2)
        return UInt16(littleEndian: bytes.loadUnaligned(fromByteOffset: offset, as: UInt16.self))
    }

    func u32(at offset: Int) throws(Failure) -> UInt32 {
        try check(offset, 4)
        return UInt32(littleEndian: bytes.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
    }

    func u64(at offset: Int) throws(Failure) -> UInt64 {
        try check(offset, 8)
        return UInt64(littleEndian: bytes.loadUnaligned(fromByteOffset: offset, as: UInt64.self))
    }

    /// A copy of `size` bytes at `offset`.
    func data(at offset: Int, count size: Int) throws(Failure) -> Data {
        try check(offset, size)
        return Data(UnsafeRawBufferPointer(rebasing: bytes[offset..<(offset + size)]))
    }

    /// A borrowed view of `size` bytes at `offset`, valid as long as the underlying buffer.
    func slice(at offset: Int, count size: Int) throws(Failure) -> UnsafeRawBufferPointer {
        try check(offset, size)
        return UnsafeRawBufferPointer(rebasing: bytes[offset..<(offset + size)])
    }
}

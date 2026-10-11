// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Where an archive's bytes live: a window of a file on disk, or of an in-memory buffer.
///
/// A window lets a stored APK inside a bundle be read in place without extracting it first.
enum ByteSource: Sendable {
    case file(URL, offset: UInt64, length: UInt64)
    case memory(Data, offset: UInt64, length: UInt64)

    var length: UInt64 {
        switch self {
        case .file(_, _, let length), .memory(_, _, let length): length
        }
    }

    /// A sub-window, relative to this one. The caller has already bounds-checked it.
    func window(offset: UInt64, length: UInt64) -> ByteSource {
        switch self {
        case let .file(url, base, _): .file(url, offset: base + offset, length: length)
        case let .memory(data, base, _): .memory(data, offset: base + offset, length: length)
        }
    }

    func makeReader() throws(ArchiveError) -> ByteReader {
        switch self {
        case let .file(url, offset, length):
            do {
                return ByteReader(handle: try FileHandle(forReadingFrom: url), base: offset, length: length)
            } catch {
                throw .unreadable("cannot open \(url.lastPathComponent)")
            }
        case let .memory(data, offset, length):
            return ByteReader(data: data, base: offset, length: length)
        }
    }

    /// Opens a regular file (never a FIFO or device, which could block forever) as a whole-file source.
    static func regularFile(at url: URL) throws(ArchiveError) -> ByteSource {
        let attributes: [FileAttributeKey: Any]
        do {
            attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        } catch {
            throw .unreadable("cannot stat \(url.lastPathComponent)")
        }
        guard attributes[.type] as? FileAttributeType == .typeRegular else {
            throw .unreadable("\(url.lastPathComponent) is not a regular file")
        }
        let reader = try ByteSource.file(url, offset: 0, length: 0).makeReader()
        defer { reader.close() }
        return .file(url, offset: 0, length: try reader.fileLength())
    }
}

/// Bounded random-access reads over a ``ByteSource``. Not thread-safe; make one per operation.
final class ByteReader {
    private let handle: FileHandle?
    private let data: Data?
    private let base: UInt64
    let length: UInt64

    init(handle: FileHandle, base: UInt64, length: UInt64) {
        self.handle = handle
        data = nil
        self.base = base
        self.length = length
    }

    init(data: Data, base: UInt64, length: UInt64) {
        handle = nil
        self.data = data
        self.base = base
        self.length = length
    }

    deinit {
        close()
    }

    func close() {
        try? handle?.close()
    }

    /// Reads exactly `count` bytes at `offset` within the window, or throws `.truncated`.
    func read(at offset: UInt64, count: Int) throws(ArchiveError) -> [UInt8] {
        guard count >= 0, offset <= length, UInt64(count) <= length - offset else {
            throw .truncated("read of \(count) bytes at \(offset) past end (\(length))")
        }
        if count == 0 { return [] }
        let absolute = base + offset
        if let handle {
            let chunk: Data?
            do {
                try handle.seek(toOffset: absolute)
                chunk = try handle.read(upToCount: count)
            } catch {
                throw .unreadable("read failed at \(absolute)")
            }
            guard let chunk, chunk.count == count else {
                throw .truncated("file shorter than expected at \(absolute)")
            }
            return [UInt8](chunk)
        }
        guard let data, absolute + UInt64(count) <= UInt64(data.count) else {
            throw .truncated("buffer shorter than expected at \(absolute)")
        }
        let start = data.startIndex + Int(absolute)
        return [UInt8](data[start..<(start + count)])
    }

    fileprivate func fileLength() throws(ArchiveError) -> UInt64 {
        guard let handle else { return length }
        do {
            return try handle.seekToEnd()
        } catch {
            throw .unreadable("cannot determine file size")
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Why an entry name was refused.
public enum UnsafeNameReason: String, Hashable, Sendable, Codable {
    case empty
    case notUTF8
    case containsNUL
    case absolutePath
    case driveLetter
    case parentTraversal
    /// Empty (`a//b`) or `.` components, which make two names refer to the same file.
    case redundantComponent
    case tooLong
    case tooDeep
}

/// Every way reading or extracting a hostile archive can fail.
///
/// `description` is plain English for the UI; `technicalDetail` is for logs and bug reports.
public enum ArchiveError: Error, Hashable, Sendable, CustomStringConvertible {
    /// Not a zip at all (wrong magic bytes).
    case notAnArchive
    /// The file or folder could not be read.
    case unreadable(String)
    /// The file ends before a structure it declares.
    case truncated(String)
    /// Structurally invalid zip data.
    case malformed(String)
    case tooManyEntries(count: UInt64, limit: Int)
    case unsafeEntryName(String, UnsafeNameReason)
    case symlinkEntry(String)
    /// A device file, FIFO or other non-regular entry.
    case specialFileEntry(String)
    /// Two entries that would land on the same file on a case-insensitive disk.
    case duplicateEntry(String)
    case encryptedEntry(String)
    case unsupportedCompression(String, method: UInt16)
    /// Two entries share bytes, a trick used to hide content from some unzip tools.
    case overlappingEntries(String)
    /// The local header disagrees with the central directory about this entry.
    case headerMismatch(String)
    /// Declared total size exceeds the configured cap.
    case totalSizeLimitExceeded(bytes: UInt64, limit: UInt64)
    /// Declared total size is too large relative to the archive (zip bomb).
    case totalRatioLimitExceeded(bytes: UInt64, archiveBytes: UInt64, ratio: UInt64)
    /// One entry expands too far relative to its compressed size (zip bomb).
    case entryRatioLimitExceeded(String)
    /// The inflated data does not match the declared size.
    case sizeMismatch(String)
    case checksumMismatch(String)
    /// The compressed data is corrupt.
    case corruptData(String)
    case entryTooLarge(String, bytes: UInt64, limit: UInt64)
    case nestingTooDeep(limit: Int)
    case noAPKs
    case noBaseAPK
    case ambiguousBaseAPK([String])
    case invalidMetadata(String, reason: String)
    case unsafeOBBPath(String)
    case missingEntry(String)
    /// An extracted path resolved outside the job folder.
    case pathEscapesJob(String)
    /// Writing extracted files failed.
    case fileSystem(String)
    case cancelled

    public var description: String {
        switch self {
        case .notAnArchive:
            "This file is not an Android app or app bundle."
        case .unreadable:
            "Airlock couldn't read this file. Check that it still exists and that you have permission to open it."
        case .truncated, .malformed, .corruptData, .checksumMismatch, .sizeMismatch, .headerMismatch:
            "This file is damaged or incomplete. Download it again from a source you trust."
        case .tooManyEntries(_, let limit):
            "This archive contains more than \(limit) files, far more than any real app."
        case .unsafeEntryName, .pathEscapesJob:
            "This archive contains a file that tries to escape its folder."
        case .symlinkEntry:
            "This archive contains a link to another location on your Mac. Airlock never extracts links."
        case .specialFileEntry:
            "This archive contains a special system file, which no real app needs."
        case .duplicateEntry:
            "This archive contains two files with the same name, a trick used to hide content."
        case .encryptedEntry:
            "This archive is encrypted or password-protected, so Airlock can't check what's inside."
        case .unsupportedCompression:
            "This archive uses a compression method Android apps don't use."
        case .overlappingEntries:
            "This archive has been built to show different contents to different tools."
        case .totalSizeLimitExceeded, .totalRatioLimitExceeded, .entryRatioLimitExceeded, .entryTooLarge:
            "This archive expands to far more data than its size suggests (a \u{201C}zip bomb\u{201D}). Airlock refused to unpack it."
        case .nestingTooDeep:
            "This archive contains archives inside archives, deeper than any real app bundle."
        case .noAPKs:
            "This file doesn't contain any Android apps."
        case .noBaseAPK:
            "This bundle contains only add-on parts (splits) and no main app."
        case .ambiguousBaseAPK:
            "This bundle contains more than one main app, so Airlock can't tell which one to install."
        case .invalidMetadata, .missingEntry:
            "This app bundle's description file is invalid or refers to files that aren't there."
        case .unsafeOBBPath:
            "This bundle tries to copy game data outside the folder Android reserves for it."
        case .fileSystem:
            "Airlock couldn't unpack this file. Check that your Mac has enough free space."
        case .cancelled:
            "Cancelled."
        }
    }

    /// Precise cause for logs; may contain entry names from the archive.
    public var technicalDetail: String {
        switch self {
        case .notAnArchive: "missing zip signature"
        case .unreadable(let detail), .truncated(let detail), .malformed(let detail), .fileSystem(let detail):
            detail
        case let .tooManyEntries(count, limit): "\(count) entries, limit \(limit)"
        case let .unsafeEntryName(name, reason): "unsafe name (\(reason.rawValue)): \(name)"
        case .symlinkEntry(let name): "symlink: \(name)"
        case .specialFileEntry(let name): "special file: \(name)"
        case .duplicateEntry(let name): "duplicate: \(name)"
        case .encryptedEntry(let name): "encrypted: \(name)"
        case let .unsupportedCompression(name, method): "method \(method): \(name)"
        case .overlappingEntries(let name): "overlapping data: \(name)"
        case .headerMismatch(let name): "local header mismatch: \(name)"
        case let .totalSizeLimitExceeded(bytes, limit): "\(bytes) bytes declared, limit \(limit)"
        case let .totalRatioLimitExceeded(bytes, archive, ratio): "\(bytes) bytes from \(archive)-byte archive, max \(ratio)x"
        case .entryRatioLimitExceeded(let name): "entry ratio too high: \(name)"
        case .sizeMismatch(let name): "size mismatch: \(name)"
        case .checksumMismatch(let name): "CRC mismatch: \(name)"
        case .corruptData(let name): "corrupt deflate data: \(name)"
        case let .entryTooLarge(name, bytes, limit): "\(name) is \(bytes) bytes, limit \(limit)"
        case .nestingTooDeep(let limit): "nesting deeper than \(limit)"
        case .noAPKs: "no APK entries"
        case .noBaseAPK: "no base APK candidate"
        case .ambiguousBaseAPK(let names): "base APK candidates: \(names.joined(separator: ", "))"
        case let .invalidMetadata(file, reason): "\(file): \(reason)"
        case .unsafeOBBPath(let path): "unsafe OBB path: \(path)"
        case .missingEntry(let name): "missing entry: \(name)"
        case .pathEscapesJob(let name): "escapes job directory: \(name)"
        case .cancelled: "cancelled"
        }
    }
}

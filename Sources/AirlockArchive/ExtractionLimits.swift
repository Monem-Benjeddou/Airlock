// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Caps that stop hostile archives from exhausting disk, memory or time.
///
/// Totals are checked twice: against the sizes the central directory declares when an archive is opened,
/// and against the bytes actually inflated while extracting, because declared sizes can lie.
public struct ExtractionLimits: Hashable, Sendable {
    public static let gibibyte: UInt64 = 1 << 30
    public static let mebibyte: UInt64 = 1 << 20

    /// Refuse an archive whose entries add up to more than this many bytes. Default 8 GiB.
    public var maxTotalUncompressedBytes: UInt64
    /// Refuse an archive whose entries add up to more than this multiple of the archive's own size. Default 10×.
    ///
    /// Real APKs inflate to well under 3× and stored APKs inside XAPKs to about 1×.
    public var maxTotalRatio: UInt64
    /// Refuse a single entry that inflates to more than this multiple of its compressed size…
    public var maxEntryRatio: UInt64
    /// …unless it inflates to at most this many bytes, since small, highly compressible files are harmless.
    public var entryRatioExemptBytes: UInt64
    public var maxEntries: Int
    /// How many archives deep we will open: a bundle (0) holding APKs (1) is normal.
    public var maxNestingDepth: Int
    public var maxNameBytes: Int
    public var maxPathDepth: Int
    /// Cap for metadata entries read into memory, such as XAPK `manifest.json`.
    public var maxMetadataBytes: UInt64

    public init(
        maxTotalUncompressedBytes: UInt64 = 8 * gibibyte,
        maxTotalRatio: UInt64 = 10,
        maxEntryRatio: UInt64 = 100,
        entryRatioExemptBytes: UInt64 = 16 * mebibyte,
        maxEntries: Int = 10_000,
        maxNestingDepth: Int = 2,
        maxNameBytes: Int = 1024,
        maxPathDepth: Int = 32,
        maxMetadataBytes: UInt64 = mebibyte
    ) {
        self.maxTotalUncompressedBytes = maxTotalUncompressedBytes
        self.maxTotalRatio = maxTotalRatio
        self.maxEntryRatio = maxEntryRatio
        self.entryRatioExemptBytes = entryRatioExemptBytes
        self.maxEntries = maxEntries
        self.maxNestingDepth = maxNestingDepth
        self.maxNameBytes = maxNameBytes
        self.maxPathDepth = maxPathDepth
        self.maxMetadataBytes = maxMetadataBytes
    }

    public static let `default` = ExtractionLimits()

    /// The most bytes an archive of `archiveBytes` may expand to: the smaller of the absolute and ratio caps.
    public func uncompressedBudget(forArchiveBytes archiveBytes: UInt64) -> UInt64 {
        let (byRatio, overflow) = archiveBytes.multipliedReportingOverflow(by: maxTotalRatio)
        return overflow ? maxTotalUncompressedBytes : min(byRatio, maxTotalUncompressedBytes)
    }
}

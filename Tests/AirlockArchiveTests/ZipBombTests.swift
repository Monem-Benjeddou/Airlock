// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

@testable import AirlockArchive
import AirlockTestSupport
import Foundation
import Testing

@Suite("Zip bomb limits")
struct ZipBombTests {
    @Test func budgetIsTheSmallerOfRatioAndAbsoluteCaps() {
        let limits = ExtractionLimits()
        #expect(limits.maxTotalUncompressedBytes == 8 << 30)
        #expect(limits.maxTotalRatio == 10)
        #expect(limits.maxEntries == 10_000)
        #expect(limits.maxNestingDepth == 2)
        #expect(limits.uncompressedBudget(forArchiveBytes: 100) == 1000)
        #expect(limits.uncompressedBudget(forArchiveBytes: 1 << 40) == 8 << 30)
        #expect(limits.uncompressedBudget(forArchiveBytes: .max) == 8 << 30)
    }

    @Test func refusesDeclaredTotalAboveTenTimesTheArchive() throws {
        let builder = ZipBuilder(files: [("zeros.bin", [UInt8](repeating: 0, count: 100_000))], method: .deflated)
        let data = builder.build()
        let error = openError(data)
        #expect(error == .totalRatioLimitExceeded(bytes: 100_000, archiveBytes: UInt64(data.count), ratio: 10))
        // Exactly at 10× is allowed.
        var limits = ExtractionLimits()
        limits.maxTotalRatio = UInt64((100_000 + data.count - 1) / data.count)
        #expect(openError(data, limits: limits) == nil)
    }

    @Test func refusesDeclaredTotalAboveTheAbsoluteCap() {
        let builder = ZipBuilder(files: [("a", randomBytes(600)), ("b", randomBytes(600, seed: 2))])
        var limits = ExtractionLimits()
        limits.maxTotalUncompressedBytes = 1000
        #expect(openError(builder, limits: limits) == .totalSizeLimitExceeded(bytes: 1200, limit: 1000))
        limits.maxTotalUncompressedBytes = 1200
        #expect(openError(builder, limits: limits) == nil)
    }

    @Test func refusesSizesThatOverflowWhenAdded() {
        var builder = ZipBuilder(files: [("a", [1]), ("b", [2])], method: .deflated)
        builder.zip64 = true
        builder.entries[0].uncompressedSizeOverride = UInt64.max / 2 + 1
        builder.entries[1].uncompressedSizeOverride = UInt64.max / 2 + 1
        var limits = ExtractionLimits.lenient
        limits.maxEntryRatio = .max
        guard case .totalSizeLimitExceeded? = openError(builder, limits: limits) else {
            Issue.record("expected totalSizeLimitExceeded")
            return
        }
    }

    @Test func refusesSingleEntriesWithExtremeRatios() {
        var limits = ExtractionLimits.lenient
        limits.maxEntryRatio = 10
        limits.entryRatioExemptBytes = 1000
        let bomb = ZipBuilder(files: [("x", [UInt8](repeating: 0, count: 10_000))], method: .deflated)
        #expect(openError(bomb, limits: limits) == .entryRatioLimitExceeded("x"))
        // Small entries are exempt however compressible they are.
        let small = ZipBuilder(files: [("x", [UInt8](repeating: 0, count: 1000))], method: .deflated)
        #expect(openError(small, limits: limits) == nil)
    }

    @Test func refusesARealFiftyMegabyteBomb() throws {
        let zeros = [UInt8](repeating: 0, count: 50 << 20)
        let honest = ZipBuilder(files: [("bomb.bin", zeros)], method: .deflated).build()
        #expect(honest.count < 200_000)
        #expect(openError(honest) == .entryRatioLimitExceeded("bomb.bin"))

        // The same payload declaring a tiny size opens, but inflation stops at the declared size.
        var entry = ZipBuilder.Entry(name: "bomb.bin", data: zeros, method: .deflated)
        entry.uncompressedSizeOverride = 40_000
        let liar = try ZipArchive(data: ZipBuilder(entries: [entry]).build())
        var inflated = 0
        #expect(throws: ArchiveError.sizeMismatch("bomb.bin")) {
            try liar.stream(liar.entries[0]) { inflated += $0.count }
        }
        #expect(inflated <= 40_000)
    }

    @Test func errorsHaveUserFacingDescriptions() {
        let bomb = ArchiveError.totalRatioLimitExceeded(bytes: 1, archiveBytes: 1, ratio: 10)
        #expect(bomb.description.contains("zip bomb"))
        #expect(bomb.technicalDetail.contains("10x"))
    }
}

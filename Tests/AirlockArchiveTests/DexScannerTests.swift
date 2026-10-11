// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockArchive
import AirlockTestSupport
import Foundation
import Testing

/// Builds a minimal DEX: header, string_ids, type_ids (one per string) and the string data.
enum DexBuilder {
    static func build(_ descriptors: [String], padTo size: Int = 0, typeOrder: [UInt32]? = nil) -> Data {
        let sorted = descriptors.sorted()
        let stringIDs = 0x70
        let typeIDs = stringIDs + sorted.count * 4
        var stringData = Data()
        var offsets: [UInt32] = []
        let dataStart = typeIDs + sorted.count * 4
        for descriptor in sorted {
            offsets.append(UInt32(dataStart + stringData.count))
            stringData += uleb(descriptor.utf16.count) + Data(descriptor.utf8) + Data([0])
        }
        var header = Data("dex\n039\0".utf8) + Data(count: 24)
        header += AXMLBuilder.u32(0) + AXMLBuilder.u32(0x70) + AXMLBuilder.u32(0x1234_5678) + Data(count: 12)
        header += AXMLBuilder.u32(UInt32(sorted.count)) + AXMLBuilder.u32(UInt32(stringIDs))
        header += AXMLBuilder.u32(UInt32(sorted.count)) + AXMLBuilder.u32(UInt32(typeIDs))
        header += Data(count: 0x70 - header.count)
        var out = header
        for offset in offsets { out += AXMLBuilder.u32(offset) }
        for index in typeOrder ?? Array(0..<UInt32(sorted.count)) { out += AXMLBuilder.u32(index) }
        out += stringData
        if out.count < size { out += Data(count: size - out.count) }
        out.replaceSubrange(32..<36, with: AXMLBuilder.u32(UInt32(out.count)))
        return out
    }

    static func uleb(_ value: Int) -> Data {
        var value = value
        var out = Data()
        repeat {
            var byte = UInt8(value & 0x7F)
            value >>= 7
            if value != 0 { byte |= 0x80 }
            out.append(byte)
        } while value != 0
        return out
    }

    static func patch(_ data: Data, at offset: Int, _ value: UInt32) -> Data {
        var copy = data
        copy.replaceSubrange(offset..<(offset + 4), with: AXMLBuilder.u32(value))
        return copy
    }
}

@Suite("DexScanner")
struct DexScannerTests {
    @Test func fixtureDexPrefixes() throws {
        let dex = try FixtureAPKs.classesDex()
        let descriptors = try DexScanner.classDescriptors(in: dex)
        #expect(descriptors.contains("Lcom/facebook/ads/AdView;"))
        #expect(descriptors.contains("Lcom/google/firebase/analytics/FirebaseAnalytics;"))
        let prefixes = try DexScanner.packagePrefixes(in: dex)
        let expected: Set<String> = [
            "com/facebook/", "com/facebook/ads/", "com/google/", "com/google/firebase/",
            "com/google/firebase/analytics/", "com/google/android/", "com/google/android/gms/",
            "com/google/android/gms/ads/", "org/airlock/", "org/airlock/fixture/", "org/airlock/fixture/deep/",
            "org/airlock/fixture/deep/inner/",
        ]
        #expect(expected.isSubset(of: prefixes))
        #expect(!prefixes.contains("org/airlock/fixture/deep/inner/most/"), "depth is capped at 5")
        #expect(!prefixes.contains("com/"), "depth 1 is too coarse to match trackers")
        #expect(prefixes.allSatisfy { $0.hasSuffix("/") && !$0.hasPrefix("L") })
    }

    @Test func multipleFilesAreUnioned() throws {
        let first = DexBuilder.build(["Lio/sentry/Sentry;"])
        let second = DexBuilder.build(["[[Lcom/appsflyer/AppsFlyerLib;", "I", "[I", "LTopLevel;", "Lsingle/Level;"])
        #expect(try DexScanner.packagePrefixes(in: [first, second]) == ["io/sentry/", "com/appsflyer/"])
        #expect(try DexScanner.classDescriptors(in: second) == [
            "LTopLevel;", "Lsingle/Level;", "Lcom/appsflyer/AppsFlyerLib;",
        ])
    }

    @Test func rejectsBadHeaders() {
        let good = DexBuilder.build(["La/b/C;"])
        #expect(throws: DexError.notDex) { try DexScanner.packagePrefixes(in: Data(count: 10)) }
        #expect(throws: DexError.notDex) { try DexScanner.packagePrefixes(in: Data("dey\n035\0".utf8) + good.dropFirst(8)) }
        #expect(throws: DexError.notDex) { try DexScanner.packagePrefixes(in: Data("dex\n0a5\0".utf8) + good.dropFirst(8)) }
        #expect(throws: DexError.notDex) { try DexScanner.packagePrefixes(in: Data("dex\n035x".utf8) + good.dropFirst(8)) }
        #expect(throws: DexError.invalidHeader("header size")) { try DexScanner.packagePrefixes(in: DexBuilder.patch(good, at: 36, 0x20)) }
        #expect(throws: DexError.invalidHeader("byte order")) {
            try DexScanner.packagePrefixes(in: DexBuilder.patch(good, at: 40, 0x7856_3412))
        }
        #expect(throws: DexError.tooManyEntries(table: "type_ids", count: 70_000)) {
            try DexScanner.packagePrefixes(in: DexBuilder.patch(good, at: 64, 70_000))
        }
        #expect(throws: DexError.tooManyEntries(table: "string_ids", count: 0x0200_0000)) {
            try DexScanner.packagePrefixes(in: DexBuilder.patch(good, at: 56, 0x0200_0000))
        }
        #expect(throws: DexError.invalidHeader("id table outside the file")) {
            try DexScanner.packagePrefixes(in: DexBuilder.patch(good, at: 60, 0xFFFF_FFF0))
        }
        #expect(throws: DexError.invalidHeader("id table outside the file")) {
            try DexScanner.packagePrefixes(in: DexBuilder.patch(good, at: 64, 60_000))
        }
    }

    @Test func rejectsBadStrings() {
        let good = DexBuilder.build(["La/b/C;"])
        // type_ids[0] points past the string table.
        #expect(throws: DexError.invalidString(index: 5)) { try DexScanner.packagePrefixes(in: DexBuilder.patch(good, at: 0x74, 5)) }
        // string_ids[0] points outside the file.
        #expect(throws: DexError.truncated(offset: 0x00FF_FFFF)) {
            try DexScanner.packagePrefixes(in: DexBuilder.patch(good, at: 0x70, 0x00FF_FFFF))
        }
        // No NUL terminator before the end of the file.
        var unterminated = good
        unterminated.removeLast()
        #expect(throws: DexError.invalidString(index: 0)) { try DexScanner.packagePrefixes(in: unterminated) }
        // A ULEB128 that never ends.
        var endless = good
        endless.replaceSubrange((good.count - 9)..<good.count, with: Data(repeating: 0xFF, count: 9))
        #expect(throws: DexError.invalidString(index: 0)) { try DexScanner.packagePrefixes(in: endless) }
        // A descriptor longer than the cap.
        let long = DexBuilder.build(["L" + String(repeating: "a/", count: 3_000) + "X;"])
        #expect(throws: DexError.invalidString(index: 0)) { try DexScanner.packagePrefixes(in: long) }
        #expect(throws: DexError.tooLarge(DexScanner.Limits.maxFileSize + 1)) {
            try DexScanner.packagePrefixes(in: Data(count: DexScanner.Limits.maxFileSize + 1))
        }
    }

    @Test func prefixSetIsCapped() throws {
        let descriptors = (0..<60_000).map { "Lv\($0)/k/C;" }
        let dex = DexBuilder.build(descriptors)
        #expect(try DexScanner.packagePrefixes(in: dex).count == DexScanner.Limits.maxPrefixes)
        let small = DexBuilder.build(["Lz/z/Z;"])
        #expect(try DexScanner.packagePrefixes(in: [dex, small]).count == DexScanner.Limits.maxPrefixes)
    }

    /// 65 535 types padded to 100 MB: only the tables and type strings are read, so this stays fast.
    @Test(.timeLimit(.minutes(1))) func largeFileIsFast() throws {
        let descriptors = (0..<65_535).map { "Lcom/vendor\($0 % 300)/pkg\($0 % 7)/Class\($0);" }
        let dex = DexBuilder.build(descriptors, padTo: 100 * 1024 * 1024)
        let clock = ContinuousClock()
        var prefixes = Set<String>()
        let elapsed = try clock.measure { prefixes = try DexScanner.packagePrefixes(in: dex) }
        #expect(prefixes.count == 300 + 300 * 7)
        #expect(elapsed < .seconds(1), "scan took \(elapsed)")
    }
}

@Suite("DEX Property: mutated files only ever produce typed errors")
struct DexPropertyTests {
    @Test(.timeLimit(.minutes(2)), arguments: [UInt64(3), 0xC0FFEE, 99])
    func mutationsNeverCrash(seed: UInt64) throws {
        var rng = SeededGenerator(seed: seed)
        let corpus = [try FixtureAPKs.classesDex(), DexBuilder.build(["La/b/C;", "[Lx/y/z/W;", "J"])]
        var outcomes = 0
        for base in corpus {
            for _ in 0..<2_000 {
                let input = Mutator.mutate(base, using: &rng)
                do {
                    _ = try DexScanner.packagePrefixes(in: input)
                } catch {
                    _ = error as DexError
                }
                outcomes += 1
            }
        }
        #expect(outcomes == 4_000)
    }

    @Test(.timeLimit(.minutes(1)))
    func randomHeaderFields() {
        var rng = SeededGenerator(seed: 11)
        let base = DexBuilder.build(["La/b/C;", "Ld/e/F;"])
        for _ in 0..<3_000 {
            let field = [56, 60, 64, 68].randomElement(using: &rng) ?? 56
            let value = UInt32.random(in: 0...UInt32.max, using: &rng) >> UInt32.random(in: 0..<32, using: &rng)
            _ = try? DexScanner.packagePrefixes(in: DexBuilder.patch(base, at: field, value))
        }
    }
}

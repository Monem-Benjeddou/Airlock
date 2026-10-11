// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

@testable import AirlockArchive
import AirlockCore
import AirlockTestSupport
import Foundation
import Testing

@Suite("AXMLParser on aapt2 output")
struct AXMLFixtureTests {
    @Test func plainAppManifest() throws {
        let manifest = try AXMLParser.manifest(from: FixtureAPKs.appManifest())
        #expect(manifest == ApkManifest(
            packageName: "org.airlock.fixture",
            versionCode: 42,
            versionName: "1.2.3",
            minSdk: 24,
            targetSdk: 34,
            label: "Airlock Fixture",
            permissions: ["android.permission.READ_SMS", "android.permission.CAMERA", "android.permission.INTERNET"],
            features: ["android.hardware.camera"]
        ))
    }

    @Test func flagsManifest() throws {
        let manifest = try AXMLParser.manifest(from: FixtureAPKs.flagsManifest())
        #expect(manifest.packageName == "org.airlock.flags")
        #expect(manifest.versionCode == (2 << 32) | 7)
        #expect(manifest.versionName == nil)
        #expect(manifest.minSdk == 26)
        #expect(manifest.targetSdk == 26, "targetSdk defaults to minSdk")
        #expect(manifest.isSplitRequired)
        #expect(manifest.label == nil, "@string/app_name is a reference, not a literal")
        #expect(manifest.permissions == ["android.permission.ACCESS_FINE_LOCATION", "android.permission.RECORD_AUDIO"])
        #expect(manifest.features == ["android.hardware.microphone"])
        #expect(manifest.isDebuggable)
        #expect(manifest.isTestOnly)
    }

    @Test func splitManifest() throws {
        let manifest = try AXMLParser.manifest(from: FixtureAPKs.splitManifest())
        #expect(manifest.splitName == "config.arm64_v8a")
        #expect(manifest.packageName == "org.airlock.fixture")
        #expect(manifest.minSdk == nil && manifest.targetSdk == nil)
    }

    @Test func documentTreeKeepsNamespacesAndResourceIDs() throws {
        let document = try AXMLParser.parse(FixtureAPKs.appManifest())
        #expect(document.root.name == "manifest")
        let versionCode = try #require(document.root.attribute(.versionCode))
        #expect(versionCode.resourceID == 0x0101_021b)
        #expect(versionCode.namespace == AndroidAttribute.namespace)
        #expect(versionCode.value == .int(42))
        #expect(document.root.children(named: "uses-permission").count == 3)
    }
}

@Suite("AXMLParser on crafted documents")
struct AXMLCraftedTests {
    private static let ids: [(String, UInt32)] = [
        ("versionCode", 0x0101_021b), ("name", 0x0101_0003), ("minSdkVersion", 0x0101_020c),
        ("label", 0x0101_0001), ("debuggable", 0x0101_000f),
    ]

    private func manifest(utf8: Bool = false, strippedNames: Bool = false) -> Data {
        var names = Self.ids
        // Obfuscators replace names with junk (or nothing); only the resource map still says what they are.
        if strippedNames { names = names.enumerated().map { ($0.offset == 0 ? "" : "o\($0.offset)", $0.element.1) } }
        var builder = AXMLBuilder(utf8: utf8, idAttributes: names)
        let attr = { (index: Int) in names[index].0 }
        builder.startNamespace()
        builder.start("manifest", [
            builder.string("package", "com.example.obf", namespace: nil),
            builder.int(attr(0), 0x10, hex: true),
        ])
        builder.start("uses-sdk", [builder.string(attr(2), "Tiramisu")])
        builder.end("uses-sdk")
        builder.start("uses-permission", [builder.string(attr(1), "android.permission.SEND_SMS")])
        builder.end("uses-permission")
        builder.start("uses-permission", [builder.string(attr(1), "android.permission.SEND_SMS")])
        builder.end("uses-permission")
        builder.start("application", [builder.string(attr(3), "Ünïcødé ✓"), builder.int(attr(4), 1)])
        builder.start("uses-permission", [builder.string(attr(1), "android.permission.NESTED_IGNORED")])
        builder.end("uses-permission")
        builder.end("application")
        builder.end("manifest")
        return builder.build()
    }

    @Test(arguments: [false, true])
    func resolvesByResourceIDWhenNamesAreStripped(_ utf8: Bool) throws {
        for stripped in [false, true] {
            let result = try AXMLParser.manifest(from: manifest(utf8: utf8, strippedNames: stripped))
            #expect(result.packageName == "com.example.obf")
            #expect(result.versionCode == 16)
            #expect(result.minSdk == nil, "a codename minSdk is not a number")
            #expect(result.permissions == ["android.permission.SEND_SMS"])
            #expect(result.label == "Ünïcødé ✓")
            #expect(result.isDebuggable, "integer 1 counts as true")
        }
    }

    @Test func forgedNameWithOtherResourceIDIsIgnored() throws {
        // The attribute is *named* versionCode but its ID is android:label, so Android would not read it.
        var builder = AXMLBuilder(idAttributes: [("versionCode", 0x0101_0001)])
        builder.start("manifest", [builder.string("package", "a.b", namespace: nil), builder.int("versionCode", 99)])
        builder.end("manifest")
        #expect(try AXMLParser.manifest(from: builder.build()).versionCode == 0)
    }

    @Test func fallsBackToNameWithoutResourceMap() throws {
        var builder = AXMLBuilder()
        builder.start("manifest", [
            builder.string("package", "a.b", namespace: nil),
            builder.string("versionCode", "77"),
            builder.int("versionCodeMajor", 1),
            builder.string("requiredSplitTypes", "base__abi"),
        ])
        builder.start("uses-sdk", [builder.int("minSdkVersion", 21), builder.int("targetSdkVersion", 99_999)])
        builder.end("uses-sdk")
        builder.start("uses-feature", [builder.string("name", "android.hardware.nfc"), builder.bool("required", true)])
        builder.end("uses-feature")
        builder.start("uses-feature", [builder.string("name", "x"), builder.string("required", "false")])
        builder.end("uses-feature")
        builder.start("application", [builder.typed("label", type: 0x01, data: 0x7f01_0000), builder.bool("testOnly", false)])
        builder.end("application")
        builder.end("manifest")
        let result = try AXMLParser.manifest(from: builder.build())
        #expect(result.versionCode == (1 << 32) | 77)
        #expect(result.isSplitRequired)
        #expect(result.minSdk == 21)
        #expect(result.targetSdk == nil, "out-of-range SDK levels are dropped")
        #expect(result.features == ["android.hardware.nfc"])
        #expect(result.label == nil)
        #expect(!result.isTestOnly)
    }

    @Test func longStringsUseTwoUnitLengths() throws {
        let long = String(repeating: "a", count: 0x8001)
        for utf8 in [false, true] {
            var builder = AXMLBuilder(utf8: utf8)
            let value = utf8 ? String(repeating: "é", count: 200) : long
            builder.start("manifest", [builder.string("package", "a.b", namespace: nil), builder.string("versionName", value)])
            builder.end("manifest")
            #expect(try AXMLParser.manifest(from: builder.build()).versionName == value)
        }
    }

    @Test func typedValues() throws {
        var builder = AXMLBuilder()
        builder.start("root", [
            builder.typed("n", type: 0x00, data: 0),
            builder.typed("r", type: 0x07, data: 5),
            builder.typed("a", type: 0x02, data: 6),
            builder.typed("f", type: 0x04, data: Float(1.5).bitPattern),
            builder.typed("d", type: 0x05, data: 9),
            builder.int("h", -1, hex: true),
            builder.typed("s", type: 0x03, data: 9999),
        ])
        builder.end("root")
        let attributes = try AXMLParser.parse(builder.build()).root.attributes
        #expect(attributes.map(\.value) == [
            .null, .reference(5), .attributeReference(6), .float(1.5), .other(type: 5, data: 9), .hex(0xFFFF_FFFF),
            .other(type: 3, data: 9999),
        ])
        #expect(attributes[5].value.integerValue == -1)
        #expect(attributes[5].value.boolValue == true)
        #expect(attributes[0].value.integerValue == nil && attributes[0].value.boolValue == nil)
        #expect(AXMLValue.string("TRUE").boolValue == true)
        #expect(AXMLValue.bool(true).integerValue == 1 && AXMLValue.bool(false).integerValue == 0)
    }

    @Test func secondRootAndSecondPoolAreIgnored() throws {
        var builder = AXMLBuilder()
        builder.start("manifest", [builder.string("package", "first.one", namespace: nil)])
        builder.end("manifest")
        builder.appendRaw(AXMLBuilder(utf8: true).stringPool())
        builder.start("other")
        builder.end("other")
        builder.appendRaw(AXMLBuilder.chunk(type: 0x0104, headerSize: 8, body: Data(count: 12)))
        #expect(try AXMLParser.manifest(from: builder.build()).packageName == "first.one")
    }

    @Test func rejectsNonManifestsAndMissingPackage() throws {
        var other = AXMLBuilder()
        other.start("resources")
        other.end("resources")
        #expect(throws: AXMLError.notAManifest("resources")) { try AXMLParser.manifest(from: other.build()) }
        var empty = AXMLBuilder()
        empty.start("manifest", [empty.string("package", "", namespace: nil)])
        empty.end("manifest")
        #expect(throws: AXMLError.missingPackage) { try AXMLParser.manifest(from: empty.build()) }
    }
}

@Suite("AXMLParser rejects malformed input")
struct AXMLMalformedTests {
    private func simple() -> AXMLBuilder {
        var builder = AXMLBuilder()
        builder.start("manifest", [builder.string("package", "a.b", namespace: nil)])
        builder.end("manifest")
        return builder
    }

    private func patch(_ data: Data, at offset: Int, _ bytes: Data) -> Data {
        var copy = data
        copy.replaceSubrange(offset..<(offset + bytes.count), with: bytes)
        return copy
    }

    @Test func sizeAndHeaderChecks() {
        #expect(throws: AXMLError.tooLarge(AXMLParser.Limits.maxFileSize + 1)) {
            try AXMLParser.parse(Data(count: AXMLParser.Limits.maxFileSize + 1))
        }
        #expect(throws: AXMLError.notBinaryXML) { try AXMLParser.parse(Data()) }
        #expect(throws: AXMLError.notBinaryXML) { try AXMLParser.parse(Data("<manifest/>".utf8)) }
        let good = simple().build()
        #expect(throws: AXMLError.invalidChunk(type: 3, offset: 0)) { try AXMLParser.parse(patch(good, at: 4, AXMLBuilder.u32(99_999))) }
        #expect(throws: AXMLError.invalidChunk(type: 3, offset: 0)) { try AXMLParser.parse(patch(good, at: 2, AXMLBuilder.u16(4))) }
        #expect(throws: AXMLError.noRootElement) { try AXMLParser.parse(AXMLBuilder().build()) }
    }

    @Test func zeroSizeAndOverlongChunksAreRejected() {
        var zero = AXMLBuilder()
        zero.appendRaw(AXMLBuilder.u16(0x0102) + AXMLBuilder.u16(0) + AXMLBuilder.u32(0))
        #expect(throws: AXMLError.invalidChunk(type: 0x0102, offset: 8 + zero.stringPool().count)) { try AXMLParser.parse(zero.build()) }
        var long = AXMLBuilder()
        long.appendRaw(AXMLBuilder.u16(0x7777) + AXMLBuilder.u16(8) + AXMLBuilder.u32(0xFFFF_FFF0))
        #expect(throws: AXMLError.self) { try AXMLParser.parse(long.build()) }
        var trailing = AXMLBuilder()
        trailing.appendRaw(Data([1, 2, 3]))
        #expect(throws: AXMLError.self) { try AXMLParser.parse(trailing.build()) }
        var shortNode = AXMLBuilder()
        shortNode.appendRaw(AXMLBuilder.chunk(type: 0x0103, headerSize: 16, body: Data(count: 8)))
        #expect(throws: AXMLError.self) { try AXMLParser.parse(shortNode.build()) }
    }

    @Test func unbalancedElements() {
        var unclosed = AXMLBuilder()
        unclosed.start("manifest")
        #expect(throws: AXMLError.unbalancedElements) { try AXMLParser.parse(unclosed.build()) }
        var extraEnd = AXMLBuilder()
        extraEnd.end("manifest")
        #expect(throws: AXMLError.unbalancedElements) { try AXMLParser.parse(extraEnd.build()) }
    }

    @Test func depthAndAttributeLimits() {
        var deep = AXMLBuilder()
        for _ in 0...AXMLParser.Limits.maxDepth { deep.start("a") }
        #expect(throws: AXMLError.nestingTooDeep) { try AXMLParser.parse(deep.build()) }
        var ok = AXMLBuilder()
        for _ in 0..<AXMLParser.Limits.maxDepth { ok.start("a") }
        for _ in 0..<AXMLParser.Limits.maxDepth { ok.end("a") }
        #expect(throws: Never.self) { try AXMLParser.parse(ok.build()) }
        var wide = AXMLBuilder()
        let many = (0...AXMLParser.Limits.maxAttributes).map { _ in wide.int("x", 1) }
        wide.start("a", many)
        #expect(throws: AXMLError.tooManyAttributes(AXMLParser.Limits.maxAttributes + 1)) { try AXMLParser.parse(wide.build()) }
    }

    @Test func attributeTableOutsideTheChunk() {
        var builder = AXMLBuilder()
        builder.start("a", [builder.int("x", 1)])
        builder.end("a")
        var data = builder.build()
        let poolEnd = 8 + builder.stringPool().count
        // attributeCount lives at node + 16 (header) + 12.
        data = patch(data, at: poolEnd + 16 + 12, AXMLBuilder.u16(400))
        #expect(throws: AXMLError.invalidChunk(type: 0x0102, offset: poolEnd)) { try AXMLParser.parse(data) }
        var small = builder.build()
        small = patch(small, at: poolEnd + 16 + 10, AXMLBuilder.u16(4))
        #expect(throws: AXMLError.invalidChunk(type: 0x0102, offset: poolEnd)) { try AXMLParser.parse(small) }
    }

    @Test func elementNameIndexOutOfRange() {
        var builder = AXMLBuilder()
        builder.appendRaw(AXMLBuilder.node(type: 0x0102, body: AXMLBuilder.u32(UInt32.max) + AXMLBuilder.u32(500) + Data(count: 12)))
        #expect(throws: AXMLError.stringIndexOutOfRange(500)) { try AXMLParser.parse(builder.build()) }
        var noPool = Data()
        noPool += AXMLBuilder.node(type: 0x0102, body: AXMLBuilder.u32(UInt32.max) + AXMLBuilder.u32(0) + Data(count: 12))
        #expect(throws: AXMLError.stringIndexOutOfRange(0)) {
            try AXMLParser.parse(AXMLBuilder.chunk(type: 3, headerSize: 8, body: noPool))
        }
    }

    @Test func stringPoolChecks() {
        func pool(count: UInt32, styles: UInt32 = 0, stringsStart: UInt32, headerSize: UInt16 = 28, payload: Data = Data()) -> Data {
            let header = AXMLBuilder.u32(count) + AXMLBuilder.u32(styles) + AXMLBuilder.u32(0) + AXMLBuilder.u32(stringsStart)
                + AXMLBuilder.u32(0)
            let poolChunk = AXMLBuilder.chunk(type: 1, headerSize: headerSize, body: header + payload)
            return AXMLBuilder.chunk(type: 3, headerSize: 8, body: poolChunk)
        }
        #expect(throws: AXMLError.invalidStringPool("200001 strings, 0 styles")) {
            try AXMLParser.parse(pool(count: 200_001, stringsStart: 0))
        }
        #expect(throws: AXMLError.invalidStringPool("offset table overruns the chunk")) {
            try AXMLParser.parse(pool(count: 1000, stringsStart: 0))
        }
        #expect(throws: AXMLError.invalidStringPool("strings start 0")) {
            try AXMLParser.parse(pool(count: 1, stringsStart: 0, payload: Data(count: 8)))
        }
        #expect(throws: AXMLError.invalidStringPool("header size 20")) {
            try AXMLParser.parse(pool(count: 0, stringsStart: 0, headerSize: 20))
        }
    }

    /// A pool whose single string claims a length far beyond the chunk.
    @Test func overlongStrings() {
        for utf8 in [false, true] {
            var builder = AXMLBuilder(utf8: utf8)
            builder.start("x")
            builder.end("x")
            var data = builder.build()
            // First string data sits right after the 28-byte header and one offset: 8 + 28 + 4 * count.
            let stringData = 8 + 28 + 4 * builder.strings.count
            data = patch(data, at: stringData, utf8 ? Data([0x7F, 0xFF, 0xFF]) : AXMLBuilder.u16(0x7FFF))
            #expect(throws: AXMLError.self) { try AXMLParser.parse(data) }
        }
        var offsets = AXMLBuilder()
        offsets.start("x")
        offsets.end("x")
        let data = patch(offsets.build(), at: 8 + 28, AXMLBuilder.u32(0x00FF_FFFF))
        #expect(throws: AXMLError.invalidStringPool("string 0 offset 16777215")) { try AXMLParser.parse(data) }
    }

    /// Thousands of offsets pointing at one large string must hit the decode budget, not burn CPU.
    @Test func decodeBudget() throws {
        let big = String(repeating: "x", count: 30_000)
        let count = 1_000
        var offsets = Data()
        for _ in 0..<count { offsets += AXMLBuilder.u32(0) }
        var strings = AXMLBuilder.utf8Entry(big)
        while strings.count % 4 != 0 { strings.append(0) }
        let header = AXMLBuilder.u32(UInt32(count)) + AXMLBuilder.u32(0) + AXMLBuilder.u32(0x100)
            + AXMLBuilder.u32(UInt32(28 + offsets.count)) + AXMLBuilder.u32(0)
        var body = AXMLBuilder.chunk(type: 1, headerSize: 28, body: header + offsets + strings)
        // One element whose 500 attributes each use a different string index (all aliasing the same bytes).
        var attributes = Data()
        for index in 0..<500 {
            attributes += AXMLBuilder.u32(UInt32.max) + AXMLBuilder.u32(UInt32(index)) + AXMLBuilder.u32(UInt32(index))
            attributes += AXMLBuilder.u16(8) + Data([0, 0x03]) + AXMLBuilder.u32(UInt32(index + 500))
        }
        let ext = AXMLBuilder.u32(UInt32.max) + AXMLBuilder.u32(0) + AXMLBuilder.u16(20) + AXMLBuilder.u16(20)
            + AXMLBuilder.u16(500) + Data(count: 6)
        body += AXMLBuilder.node(type: 0x0102, body: ext + attributes)
        body += AXMLBuilder.node(type: 0x0103, body: AXMLBuilder.u32(UInt32.max) + AXMLBuilder.u32(0))
        // Same offset for every index is served from the cache, so this parses fine and quickly.
        let document = try AXMLParser.parse(AXMLBuilder.chunk(type: 3, headerSize: 8, body: body))
        #expect(document.root.attributes.count == 500)

        // Now give every index a distinct offset into a run of 0xFF bytes: each reads as a 32 KiB string.
        var distinct = Data()
        for index in 0..<count { distinct += AXMLBuilder.u32(UInt32(index)) }
        var run = Data(repeating: 0xFF, count: count + 0x8010)
        run[run.count - 1] = 0
        let header2 = AXMLBuilder.u32(UInt32(count)) + AXMLBuilder.u32(0) + AXMLBuilder.u32(0x100)
            + AXMLBuilder.u32(UInt32(28 + distinct.count)) + AXMLBuilder.u32(0)
        var body2 = AXMLBuilder.chunk(type: 1, headerSize: 28, body: header2 + distinct + run)
        body2 += AXMLBuilder.node(type: 0x0102, body: ext + attributes)
        body2 += AXMLBuilder.node(type: 0x0103, body: AXMLBuilder.u32(UInt32.max) + AXMLBuilder.u32(0))
        #expect(throws: AXMLError.decodeBudgetExceeded) { try AXMLParser.parse(AXMLBuilder.chunk(type: 3, headerSize: 8, body: body2)) }
    }
}

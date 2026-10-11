// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockArchive
import AirlockTestSupport
import Foundation
import Testing

@Suite("AXML Property: mutated manifests only ever produce typed errors")
struct AXMLPropertyTests {
    static let seeds: [UInt64] = [1, 0xA1B2, 0xDEAD_BEEF, 42_424_242]

    private func corpus() throws -> [Data] {
        var utf8 = AXMLBuilder(utf8: true, idAttributes: [("versionCode", 0x0101_021b), ("name", 0x0101_0003)])
        utf8.startNamespace()
        utf8.start("manifest", [utf8.string("package", "p.q", namespace: nil), utf8.int("versionCode", 3)])
        utf8.start("uses-permission", [utf8.string("name", "android.permission.CAMERA")])
        utf8.end("uses-permission")
        utf8.end("manifest")
        return [try FixtureAPKs.appManifest(), try FixtureAPKs.flagsManifest(), try FixtureAPKs.splitManifest(), utf8.build()]
    }

    @Test(.timeLimit(.minutes(2)), arguments: seeds)
    func mutationsNeverCrash(seed: UInt64) throws {
        var rng = SeededGenerator(seed: seed)
        var parsed = 0
        var rejected = 0
        for base in try corpus() {
            for _ in 0..<1_500 {
                let input = Mutator.mutate(base, using: &rng)
                do {
                    _ = try AXMLParser.manifest(from: input)
                    parsed += 1
                } catch {
                    rejected += 1
                }
            }
        }
        #expect(parsed + rejected == 6_000)
        #expect(rejected > 0)
    }

    @Test(.timeLimit(.minutes(1)))
    func randomBytesBehindAValidHeader() {
        var rng = SeededGenerator(seed: 7)
        for _ in 0..<2_000 {
            let length = Int.random(in: 0..<512, using: &rng)
            var body = Data((0..<length).map { _ in UInt8.random(in: 0...255, using: &rng) })
            if Bool.random(using: &rng) {
                // Make a plausible chunk stream more likely.
                body = AXMLBuilder.chunk(type: 0x0001, headerSize: 28, body: body)
            }
            let document = AXMLBuilder.chunk(type: 0x0003, headerSize: 8, body: body)
            #expect(throws: AXMLError.self) { try AXMLParser.manifest(from: document) }
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation
import Testing

@Suite("PackageName")
struct PackageNameTests {
    @Test(arguments: [
        "com.example",
        "com.example.app",
        "com.Example.App_2",
        "a.b",
        "org.mozilla.firefox",
        "com.google.android.gms",
        "com.example.1numeric", // allowed by the plan's regex after the first segment
        "com.example._underscore",
    ])
    func acceptsValidNames(_ raw: String) throws {
        let name = try PackageName(raw)
        #expect(name.rawValue == raw)
        #expect(name.description == raw)
    }

    @Test(arguments: [
        "",
        "com",                       // needs at least two segments
        "1com.example",              // must start with a letter
        "_com.example",
        "com..example",
        "com.example.",
        ".com.example",
        "com.example app",
        "com.example;rm -rf /",
        "com.example && reboot",
        "com.example$(id)",
        "com.example`id`",
        "com.example\nreboot",
        "com.example\u{0}x",
        "com/example",
        "com-example.app",
        "com.exämple",               // non-ASCII
        "-com.example",
        "com.example|sh",
        "com.example'",
        "com.example\"",
        "com.example*",
    ])
    func rejectsInvalidNames(_ raw: String) {
        #expect(throws: PackageNameError.self) { try PackageName(raw) }
        #expect(PackageName.isValid(raw) == false)
    }

    @Test func rejectsOverlongNames() {
        let raw = "com." + String(repeating: "a", count: PackageName.maxLength)
        #expect(throws: PackageNameError.tooLong) { try PackageName(raw) }
    }

    @Test func acceptsNameAtMaxLength() throws {
        let raw = "com." + String(repeating: "a", count: PackageName.maxLength - 4)
        #expect(raw.count == PackageName.maxLength)
        _ = try PackageName(raw)
    }

    @Test func errorDistinguishesEmptyFromMalformed() {
        #expect(throws: PackageNameError.empty) { try PackageName("") }
        #expect(throws: PackageNameError.malformed("x y")) { try PackageName("x y") }
    }

    @Test func isCodableAndComparable() throws {
        let a = try PackageName("com.a.app")
        let b = try PackageName("com.b.app")
        #expect(a < b)
        let data = try JSONEncoder().encode([a, b])
        let decoded = try JSONDecoder().decode([PackageName].self, from: data)
        #expect(decoded == [a, b])
    }

    @Test func failableInitialiser() {
        #expect(PackageName(rawValue: "com.example")?.rawValue == "com.example")
        #expect(PackageName(rawValue: "bad name") == nil)
    }

    @Test func decodingRejectsInvalidName() {
        let data = Data(#"["com.example;reboot"]"#.utf8)
        #expect(throws: (any Error).self) { try JSONDecoder().decode([PackageName].self, from: data) }
    }
}

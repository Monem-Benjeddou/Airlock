// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
@testable import AirlockUI
import Foundation
import Testing

@Suite("App naming")
struct AppNamingTests {
    @Test(arguments: [
        ("com.demo.notes", "Notes"), ("com.google.android.apps.tips", "Tips"), ("org.airlock.fixture", "Fixture"),
        ("com.whatsapp", "Whatsapp"), ("com.example.myCoolApp", "My Cool App"), ("com.foo.android", "Foo"),
        ("single", "Single"),
    ])
    func packageNamesBecomeReadable(_ package: String, _ expected: String) {
        #expect(AppNaming.name(forPackage: package) == expected)
    }

    @Test(arguments: [
        ("/x/Signal-Android-7.1.apk", "Signal Android 7.1"), ("/x/my_game.xapk", "My Game"),
        ("/x/Split Folder", "Split Folder"), ("/x/notes.APKS", "Notes"),
    ])
    func fileNamesBecomeReadable(_ path: String, _ expected: String) {
        #expect(AppNaming.name(forFile: URL(fileURLWithPath: path)) == expected)
    }
}

@MainActor
@Suite("App tile")
struct AppTileTests {
    @Test func theColourIsStableForAPackage() {
        #expect(AppTile.color(for: "com.demo.notes") == AppTile.color(for: "com.demo.notes"))
    }

    @Test func packagesSpreadOverTheColours() {
        let used = Set((0..<64).map { AppTile.colors.firstIndex(of: AppTile.color(for: "com.app\($0)")) })
        #expect(used.count >= 6)
    }

    @Test func theMonogramIsTheFirstLetterOrDigit() {
        #expect(AppTile.monogram(for: "notes") == "N")
        #expect(AppTile.monogram(for: "  9gag") == "9")
        #expect(AppTile.monogram(for: "…") == "?")
    }
}

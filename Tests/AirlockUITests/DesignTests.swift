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

@MainActor
@Suite("Safety report text")
struct ReportTextTests {
    private func signature(_ subject: String?) -> SignatureCheck {
        SignatureCheck(status: .verified, schemes: [2], certificates: subject.map {
            [SignerCertificate(subject: $0, issuer: $0, sha256: "00")]
        } ?? [])
    }

    @Test func theSignerIsItsCommonName() {
        #expect(ReportSections.signerName(signature("CN=Demo Studio, O=Demo, C=GB")) == "Demo Studio")
        #expect(ReportSections.signerName(signature("O=No Common Name")) == "O=No Common Name")
        #expect(ReportSections.signerName(signature(nil)) == "Unknown")
    }

    @Test func sensitivePermissionsComeFirst() {
        let permissions = [
            PermissionFinding(permission: "a", plainLanguage: "Use the internet", isDangerous: false),
            PermissionFinding(permission: "b", plainLanguage: "Read your text messages", isDangerous: true),
            PermissionFinding(permission: "c", plainLanguage: "Access your location", isDangerous: true),
        ]
        #expect(ReportSections.sorted(permissions).map(\.permission) == ["c", "b", "a"])
    }

    @Test func aVerifiedSignatureSaysSoWithoutJargon() {
        #expect(SignerText.status(signature("CN=x")) == "Verified")
        #expect(SignerText.match(.notInstalled) == "Not installed yet")
    }
}

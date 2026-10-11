// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

@testable import AirlockADB
import Foundation
import Testing

@Suite("ADBLocator")
struct ADBLocatorTests {
    @Test func prefersCustomThenBundledThenSDKThenHomebrew() {
        let bundled = URL(fileURLWithPath: "/App/Contents/Resources/platform-tools/adb")
        let all = ADBLocator(bundledURL: bundled, customPath: "/custom/adb", homeDirectory: "/Users/u") { _ in true }
        #expect(all.locate() == .init(url: URL(fileURLWithPath: "/custom/adb"), source: .custom))

        let noCustom = ADBLocator(bundledURL: bundled, homeDirectory: "/Users/u") { _ in true }
        #expect(noCustom.locate()?.source == .bundled)

        let sdk = ADBLocator(bundledURL: nil, homeDirectory: "/Users/u") { $0.contains("Android/sdk") || $0.hasPrefix("/opt") }
        #expect(sdk.locate() == .init(url: URL(fileURLWithPath: "/Users/u/Library/Android/sdk/platform-tools/adb"), source: .androidSDK))

        let brew = ADBLocator(bundledURL: nil, homeDirectory: "/Users/u") { $0 == "/usr/local/bin/adb" }
        #expect(brew.locate()?.source == .homebrew)
    }

    @Test func nothingFound() {
        #expect(ADBLocator(bundledURL: nil, homeDirectory: "/x") { _ in false }.locate() == nil)
    }

    @Test func versionCheck() {
        #expect(ADBLocator.isTested("37.0.1"))
        #expect(ADBLocator.isTested("37.0.4"))
        #expect(!ADBLocator.isTested("36.0.0"))
        #expect(!ADBLocator.isTested(""))
    }

    @Test func defaultInitialiserUsesRealFileSystem() {
        // Must not crash; result depends on the machine.
        _ = ADBLocator().locate()
    }
}

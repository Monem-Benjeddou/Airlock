// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Testing

@Suite("SplitKind classification")
struct SplitKindTests {
    @Test(arguments: [
        ("config.arm64_v8a", SplitKind.abi("arm64-v8a")),
        ("config.armeabi_v7a", .abi("armeabi-v7a")),
        ("config.armeabi", .abi("armeabi")),
        ("config.x86", .abi("x86")),
        ("config.x86_64", .abi("x86_64")),
        ("config.xxhdpi", .density(480)),
        ("config.mdpi", .density(160)),
        ("config.ldpi", .density(120)),
        ("config.tvdpi", .density(213)),
        ("config.hdpi", .density(240)),
        ("config.xhdpi", .density(320)),
        ("config.xxxhdpi", .density(640)),
        ("config.en", .language("en")),
        ("config.fil", .language("fil")),
        ("config.zh_TW", .language("zh")),
        ("config.pt_rBR", .language("pt")),
        ("feature_ar", .feature),
        ("base_assets", .feature),
        ("config.something_odd", .feature),
    ])
    func classifiesBundletoolNames(_ name: String, _ expected: SplitKind) {
        #expect(SplitKind(splitName: name) == expected)
    }
}

@Suite("SplitResolver")
struct SplitResolverTests {
    private let pixel = DeviceProperties(
        abis: ["arm64-v8a", "armeabi-v7a", "armeabi"], densityDPI: 420, locales: ["fr-FR", "en-US"], sdkLevel: 35
    )

    private func split(_ name: String) -> SplitAPK {
        SplitAPK(fileName: "split_\(name).apk", splitName: name)
    }

    private var gameSplits: [SplitAPK] {
        [
            split("config.arm64_v8a"), split("config.armeabi_v7a"), split("config.x86_64"),
            split("config.mdpi"), split("config.xhdpi"), split("config.xxhdpi"), split("config.xxxhdpi"),
            split("config.en"), split("config.fr"), split("config.de"),
            split("feature_levels"),
        ]
    }

    @Test func picksBestABIDensityAndLanguages() throws {
        let selection = try SplitResolver.resolve(splits: gameSplits, for: pixel)
        #expect(selection.map(\.splitName) == [
            "config.arm64_v8a", "config.xxhdpi", "config.en", "config.fr", "feature_levels",
        ])
    }

    @Test func prefersFirstListedABI() throws {
        let device = DeviceProperties(abis: ["armeabi-v7a", "armeabi"], densityDPI: 320, locales: ["en"], sdkLevel: 28)
        let selection = try SplitResolver.resolve(splits: gameSplits, for: device)
        #expect(selection.contains { $0.splitName == "config.armeabi_v7a" })
        #expect(!selection.contains { $0.splitName == "config.arm64_v8a" })
    }

    @Test func throwsWhenNoABIMatches() {
        let device = DeviceProperties(abis: ["mips"], densityDPI: 320, locales: ["en"], sdkLevel: 28)
        #expect(throws: SplitResolutionError.noMatchingABI(available: ["arm64-v8a", "armeabi-v7a", "x86_64"])) {
            try SplitResolver.resolve(splits: gameSplits, for: device)
        }
    }

    @Test func noABISplitsIsFine() throws {
        let selection = try SplitResolver.resolve(splits: [split("config.en")], for: pixel)
        #expect(selection.map(\.splitName) == ["config.en"])
    }

    @Test func picksExactDensityWhenAvailable() throws {
        let device = DeviceProperties(abis: ["arm64-v8a"], densityDPI: 320, locales: ["en"], sdkLevel: 30)
        let selection = try SplitResolver.resolve(splits: gameSplits, for: device)
        #expect(selection.contains { $0.splitName == "config.xhdpi" })
    }

    @Test func picksLargestDensityWhenDeviceExceedsAll() throws {
        let device = DeviceProperties(abis: ["arm64-v8a"], densityDPI: 700, locales: ["en"], sdkLevel: 30)
        let splits = [split("config.mdpi"), split("config.xhdpi")]
        let selection = try SplitResolver.resolve(splits: splits, for: device)
        #expect(selection.map(\.splitName) == ["config.xhdpi"])
    }

    @Test func picksSmallestDensityAboveDevice() throws {
        let device = DeviceProperties(abis: ["arm64-v8a"], densityDPI: 100, locales: ["en"], sdkLevel: 30)
        let splits = [split("config.xhdpi"), split("config.mdpi"), split("config.hdpi")]
        let selection = try SplitResolver.resolve(splits: splits, for: device)
        #expect(selection.map(\.splitName) == ["config.mdpi"])
    }

    @Test func includesEnglishFallbackOnlyWhenNoLocaleMatches() throws {
        let device = DeviceProperties(abis: ["arm64-v8a"], densityDPI: 420, locales: ["ja-JP"], sdkLevel: 30)
        let selection = try SplitResolver.resolve(splits: [split("config.en"), split("config.de")], for: device)
        #expect(selection.map(\.splitName) == ["config.en"])
    }

    @Test func noLanguageSplitWhenNothingMatchesAndNoEnglish() throws {
        let device = DeviceProperties(abis: ["arm64-v8a"], densityDPI: 420, locales: ["ja-JP"], sdkLevel: 30)
        let selection = try SplitResolver.resolve(splits: [split("config.de")], for: device)
        #expect(selection.isEmpty)
    }

    @Test func localeMatchingIgnoresRegionAndCase() throws {
        let device = DeviceProperties(abis: ["arm64-v8a"], densityDPI: 420, locales: ["PT_br"], sdkLevel: 30)
        let selection = try SplitResolver.resolve(splits: [split("config.pt_rBR"), split("config.en")], for: device)
        #expect(selection.map(\.splitName) == ["config.pt_rBR"])
    }

    @Test func keepsFeatureAndUnknownSplits() throws {
        let splits = [split("dynamic_feature"), split("config.weird_thing")]
        let selection = try SplitResolver.resolve(splits: splits, for: pixel)
        #expect(selection.count == 2)
    }

    @Test func emptyInputYieldsEmptySelection() throws {
        #expect(try SplitResolver.resolve(splits: [], for: pixel).isEmpty)
    }

    @Test func densityBucketsCoverAllNames() {
        for (name, dpi) in SplitKind.densityBuckets {
            #expect(SplitKind(splitName: "config.\(name)") == .density(dpi))
        }
    }
}

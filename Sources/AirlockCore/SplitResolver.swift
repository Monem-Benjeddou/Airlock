// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// What a configuration split targets, derived from its bundletool split name (`config.arm64_v8a`).
public enum SplitKind: Hashable, Sendable, Codable {
    case abi(String)
    case density(Int)
    case language(String)
    /// Dynamic-feature or asset splits, and anything unrecognised. Always installed.
    case feature

    public static let densityBuckets: [String: Int] = [
        "ldpi": 120, "mdpi": 160, "tvdpi": 213, "hdpi": 240,
        "xhdpi": 320, "xxhdpi": 480, "xxxhdpi": 640,
    ]

    /// bundletool split-name suffix → Android ABI name. Only some ABIs swap `_` for `-`.
    private static let abis: [String: String] = [
        "armeabi": "armeabi", "armeabi_v7a": "armeabi-v7a", "arm64_v8a": "arm64-v8a",
        "x86": "x86", "x86_64": "x86_64", "mips": "mips", "mips64": "mips64", "riscv64": "riscv64",
    ]

    public init(splitName: String) {
        guard splitName.hasPrefix("config.") else {
            self = .feature
            return
        }
        let value = String(splitName.dropFirst("config.".count))
        if let abi = Self.abis[value] {
            self = .abi(abi)
        } else if let dpi = Self.densityBuckets[value] {
            self = .density(dpi)
        } else if let language = Self.language(in: value) {
            self = .language(language)
        } else {
            self = .feature
        }
    }

    /// Accepts `en`, `fil`, `zh_TW`, `pt_rBR`, `zh-TW`; returns the lowercase language code.
    private static func language(in value: String) -> String? {
        let parts = value.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "_" || $0 == "-" })
        guard let first = parts.first, (2...3).contains(first.count), first.allSatisfy(\.isLowercase),
              first.allSatisfy(\.isASCII) else { return nil }
        switch parts.count {
        case 1:
            return String(first)
        case 2:
            var region = parts[1]
            if region.count == 3, region.first == "r" { region = region.dropFirst() }
            guard region.count == 2, region.allSatisfy({ $0.isUppercase && $0.isASCII }) else { return nil }
            return String(first)
        default:
            return nil
        }
    }
}

/// One non-base APK inside a split bundle.
public struct SplitAPK: Hashable, Sendable, Codable {
    public let fileName: String
    /// The manifest's `split` attribute (or the bundletool name when the manifest has none).
    public let splitName: String
    public var kind: SplitKind { SplitKind(splitName: splitName) }

    public init(fileName: String, splitName: String) {
        self.fileName = fileName
        self.splitName = splitName
    }
}

public enum SplitResolutionError: Error, Hashable, Sendable {
    /// The bundle has ABI splits but none for the device's ABIs.
    case noMatchingABI(available: [String])
}

/// Chooses the configuration splits a device needs, matching what Play would deliver.
public enum SplitResolver {
    /// Returns the selected splits in input order. The base APK is not part of `splits` and always installs.
    public static func resolve(splits: [SplitAPK], for device: DeviceProperties) throws(SplitResolutionError) -> [SplitAPK] {
        let chosenABI = try chooseABI(splits: splits, device: device)
        let chosenDensity = chooseDensity(splits: splits, device: device)
        let chosenLanguages = chooseLanguages(splits: splits, device: device)

        return splits.filter { split in
            switch split.kind {
            case .abi(let abi): abi == chosenABI
            case .density(let dpi): dpi == chosenDensity
            case .language(let language): chosenLanguages.contains(language)
            case .feature: true
            }
        }
    }

    private static func chooseABI(splits: [SplitAPK], device: DeviceProperties) throws(SplitResolutionError) -> String? {
        let available = splits.compactMap { split -> String? in
            if case .abi(let abi) = split.kind { return abi }
            return nil
        }
        guard !available.isEmpty else { return nil }
        guard let match = device.abis.first(where: available.contains) else {
            throw .noMatchingABI(available: available)
        }
        return match
    }

    /// The smallest bucket at or above the device density, else the largest bucket below it.
    private static func chooseDensity(splits: [SplitAPK], device: DeviceProperties) -> Int? {
        let available = splits.compactMap { split -> Int? in
            if case .density(let dpi) = split.kind { return dpi }
            return nil
        }
        return available.filter { $0 >= device.densityDPI }.min() ?? available.max()
    }

    private static func chooseLanguages(splits: [SplitAPK], device: DeviceProperties) -> Set<String> {
        let available = Set(splits.compactMap { split -> String? in
            if case .language(let language) = split.kind { return language }
            return nil
        })
        let wanted = Set(device.locales.compactMap { locale in
            locale.split(whereSeparator: { $0 == "-" || $0 == "_" }).first.map { $0.lowercased() }
        })
        let matched = available.intersection(wanted)
        if matched.isEmpty, available.contains("en") { return ["en"] }
        return matched
    }
}

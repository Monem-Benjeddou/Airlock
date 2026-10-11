// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation

/// Debloat presets shipped with the app, built from the UAD-ng lists by `scripts/import_uad_presets.py`.
///
/// Every entry is filtered through the critical-package denylist at load time, so even a bad preset
/// file can never offer a package that must not be removed.
public struct PresetLibrary: Sendable {
    public let presets: [DebloatPreset]

    public init(presets: [DebloatPreset], denylist: CriticalDenylist = .standard) {
        self.presets = presets.map { preset in
            DebloatPreset(
                id: preset.id,
                name: preset.name,
                brand: preset.brand,
                entries: preset.entries.filter {
                    denylist.check(rawPackage: $0.packageName.rawValue, operation: .uninstallForUser) == .allowed
                }
            )
        }
    }

    public static func bundled(denylist: CriticalDenylist = .standard) throws -> PresetLibrary {
        let urls = Bundle.module.urls(forResourcesWithExtension: "json", subdirectory: "presets") ?? []
        let decoder = JSONDecoder()
        let presets = try urls.map { try decoder.decode(DebloatPreset.self, from: Data(contentsOf: $0)) }
        return PresetLibrary(presets: presets.sorted { $0.id < $1.id }, denylist: denylist)
    }

    /// The device brand's presets first, then presets that apply to every phone.
    public func presets(for brand: DeviceBrand) -> [DebloatPreset] {
        presets.filter { $0.brand == brand && brand != .other } + presets.filter { $0.brand == .other }
    }
}

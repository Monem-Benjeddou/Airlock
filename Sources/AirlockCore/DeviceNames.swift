// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Picks the name people know their phone by ("Galaxy S24 Ultra") instead of the model code adb reports
/// ("SM-S928B").
///
/// The name the owner gave the phone can contain their own name, so it is only ever shown on screen: callers
/// must not log it, store it or send it anywhere.
public enum DeviceNames {
    /// Longest name kept; a longer one is cut so a pasted paragraph cannot break the sidebar.
    public static let maxLength = 48

    /// The first usable name, in order: the name set on the phone, the maker's marketing name, a bundled
    /// model list, then the model code itself. A candidate that only repeats the model code is skipped.
    public static func friendlyName(ownerName: String?, marketName: String?, model: String) -> String {
        for candidate in [ownerName, marketName, knownName(forModel: model)] {
            if let name = cleaned(candidate), name.caseInsensitiveCompare(model) != .orderedSame {
                return name
            }
        }
        return model
    }

    /// The marketing name for a model code Airlock knows, such as `SM-S928B` → `Galaxy S24 Ultra`.
    public static func knownName(forModel model: String) -> String? {
        if model.hasPrefix("sdk_gphone") || model.hasPrefix("Android SDK built for") {
            return "Android Emulator"
        }
        // Samsung codes end in a region suffix (B, U, N, 0, W, DS...) after the four-character family.
        guard model.hasPrefix("SM-"), model.count >= 7 else { return nil }
        return samsung[String(model.prefix(7))]
    }

    /// Trims a value read from the device; nil for an empty value or the literal `null` that `settings get`
    /// prints when nothing is set. Control characters are dropped.
    static func cleaned(_ value: String?) -> String? {
        guard let value else { return nil }
        let printable = String(String.UnicodeScalarView(value.unicodeScalars.filter {
            !CharacterSet.controlCharacters.contains($0)
        }))
        let trimmed = printable.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, trimmed != "null" else { return nil }
        return trimmed.count > maxLength ? String(trimmed.prefix(maxLength - 1)) + "…" : trimmed
    }

    /// Samsung phones from the last few years. Samsung does not set `ro.product.marketname`, and a phone that
    /// was never renamed is the case this list is for. Codes are the family part, without the region suffix.
    static let samsung: [String: String] = [
        "SM-G990": "Galaxy S21 FE", "SM-G991": "Galaxy S21", "SM-G996": "Galaxy S21+", "SM-G998": "Galaxy S21 Ultra",
        "SM-S901": "Galaxy S22", "SM-S906": "Galaxy S22+", "SM-S908": "Galaxy S22 Ultra",
        "SM-S711": "Galaxy S23 FE", "SM-S911": "Galaxy S23", "SM-S916": "Galaxy S23+", "SM-S918": "Galaxy S23 Ultra",
        "SM-S721": "Galaxy S24 FE", "SM-S921": "Galaxy S24", "SM-S926": "Galaxy S24+", "SM-S928": "Galaxy S24 Ultra",
        "SM-S931": "Galaxy S25", "SM-S936": "Galaxy S25+", "SM-S937": "Galaxy S25 Edge", "SM-S938": "Galaxy S25 Ultra",
        "SM-N981": "Galaxy Note20", "SM-N986": "Galaxy Note20 Ultra",
        "SM-F711": "Galaxy Z Flip3", "SM-F721": "Galaxy Z Flip4", "SM-F731": "Galaxy Z Flip5",
        "SM-F741": "Galaxy Z Flip6", "SM-F766": "Galaxy Z Flip7",
        "SM-F926": "Galaxy Z Fold3", "SM-F936": "Galaxy Z Fold4", "SM-F946": "Galaxy Z Fold5",
        "SM-F956": "Galaxy Z Fold6", "SM-F966": "Galaxy Z Fold7",
        "SM-A145": "Galaxy A14", "SM-A146": "Galaxy A14 5G", "SM-A155": "Galaxy A15", "SM-A156": "Galaxy A15 5G",
        "SM-A256": "Galaxy A25", "SM-A346": "Galaxy A34", "SM-A356": "Galaxy A35",
        "SM-A525": "Galaxy A52", "SM-A528": "Galaxy A52s", "SM-A536": "Galaxy A53",
        "SM-A546": "Galaxy A54", "SM-A556": "Galaxy A55",
    ]
}

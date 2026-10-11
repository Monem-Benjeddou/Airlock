// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import SwiftUI

/// Semantic colours and symbols, so risk and status look the same on every screen.
///
/// Colour is never the only signal: every use sits next to text or a symbol that says the same thing.
enum Palette {
    static let success = Color.green
    static let warning = Color.orange
    static let danger = Color.red

    /// The verdict badge: green, orange or red for Low, Medium or High.
    static func verdict(_ level: RiskLevel) -> Color {
        switch level {
        case .low: success
        case .medium: warning
        case .high: danger
        }
    }

    /// One reason in the report. A Low reason is information, not good news, so it stays neutral.
    static func reason(_ level: RiskLevel) -> Color {
        level == .low ? .secondary : verdict(level)
    }

    /// The verdict itself: a shield that is checked, marked or crossed.
    static func verdictSymbol(_ level: RiskLevel) -> String {
        switch level {
        case .low: "checkmark.shield.fill"
        case .medium: "exclamationmark.shield.fill"
        case .high: "xmark.shield.fill"
        }
    }

    static func reasonSymbol(_ level: RiskLevel) -> String {
        switch level {
        case .low: "info.circle"
        case .medium: "exclamationmark.triangle"
        case .high: "exclamationmark.octagon"
        }
    }

    /// Debloat risk uses the same scale: safe to remove, remove with care, experts only.
    static func debloat(_ risk: DebloatRisk) -> Color {
        switch risk {
        case .safe: success
        case .caution: warning
        case .expert: danger
        }
    }
}

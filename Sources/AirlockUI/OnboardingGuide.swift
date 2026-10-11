// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore

/// One instruction in the "turn on USB debugging" walkthrough.
public struct GuideStep: Hashable, Sendable, Identifiable {
    public var id: String { title }
    public let title: String
    public let detail: String
    /// SF Symbol shown next to the step.
    public let symbol: String
}

/// Brand-specific steps for enabling USB debugging. Menu names follow each brand's 2025–26 software.
public enum OnboardingGuide {
    public static func steps(for brand: DeviceBrand) -> [GuideStep] {
        developerOptions(brand) + usbDebugging(brand) + extras(brand) + [connect]
    }

    public static func title(for brand: DeviceBrand) -> String {
        switch brand {
        case .pixel: "Google Pixel"
        case .samsung: "Samsung Galaxy"
        case .xiaomi: "Xiaomi, Redmi or POCO"
        case .oneplus: "OnePlus"
        case .other: "Android phone"
        }
    }

    private static func developerOptions(_ brand: DeviceBrand) -> [GuideStep] {
        let path: String
        switch brand {
        case .pixel: path = "Open Settings › About phone and tap Build number seven times."
        case .samsung: path = "Open Settings › About phone › Software information and tap Build number seven times."
        case .xiaomi: path = "Open Settings › About phone and tap OS version (or MIUI version) seven times."
        case .oneplus: path = "Open Settings › About device › Version and tap Build number seven times."
        case .other: path = "Open Settings › About phone and tap Build number seven times. It may be under Software information."
        }
        return [GuideStep(title: "Turn on Developer options", detail: path + " Enter your PIN if asked.", symbol: "hand.tap")]
    }

    private static func usbDebugging(_ brand: DeviceBrand) -> [GuideStep] {
        let path: String
        switch brand {
        case .pixel, .oneplus: path = "Open Settings › System › Developer options and turn on USB debugging."
        case .samsung: path = "Open Settings › Developer options (at the bottom of Settings) and turn on USB debugging."
        case .xiaomi: path = "Open Settings › Additional settings › Developer options and turn on USB debugging."
        case .other: path = "Open Developer options (often under Settings › System) and turn on USB debugging."
        }
        return [GuideStep(title: "Turn on USB debugging", detail: path, symbol: "switch.2")]
    }

    private static func extras(_ brand: DeviceBrand) -> [GuideStep] {
        switch brand {
        case .samsung:
            [GuideStep(
                title: "Turn off Auto Blocker",
                detail: "On One UI 6 and later, Auto Blocker blocks USB commands. Open Settings › Security and privacy › "
                    + "Auto Blocker and turn it off while you use Airlock.",
                symbol: "lock.shield"
            )]
        case .xiaomi:
            [GuideStep(
                title: "Turn on Install via USB",
                detail: "In Developer options, also turn on Install via USB and USB debugging (Security settings). "
                    + "Xiaomi asks you to sign in to a Mi account and insert a SIM card for this.",
                symbol: "simcard"
            )]
        case .pixel, .oneplus, .other:
            []
        }
    }

    private static let connect = GuideStep(
        title: "Connect and allow",
        detail: "Connect the phone with a USB cable that carries data, unlock it, and tap Allow on the "
            + "\"Allow USB debugging?\" prompt. Tick \"Always allow from this computer\" to skip this next time.",
        symbol: "cable.connector"
    )

    /// Plain explanations for each connection state.
    public static func explanation(for stage: OnboardingStage) -> (title: String, detail: String) {
        switch stage {
        case .noDevice:
            ("Connect your Android phone",
             "Use a USB cable that carries data. If nothing happens, follow the steps below to turn on USB debugging.")
        case .tapAllow:
            ("Tap Allow on your phone",
             "Unlock your phone and tap Allow on the \"Allow USB debugging?\" prompt. "
                + "If you see no prompt, unplug and reconnect the cable.")
        case .offline:
            ("Your phone is not responding",
             "Unplug and reconnect the cable. If that does not help, turn USB debugging off and on again in Developer options.")
        case .noPermission:
            ("Your Mac cannot open the phone",
             "Try another USB port or cable, and make sure no other Android tool is using the phone.")
        case .unsupportedMode(let mode):
            ("Your phone is in \(mode) mode",
             "Restart the phone normally, then connect it again.")
        case .ready:
            ("Ready", "Your phone is connected.")
        }
    }
}

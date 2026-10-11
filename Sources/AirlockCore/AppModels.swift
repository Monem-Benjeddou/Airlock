// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// A package as listed by the app manager.
public struct InstalledApp: Hashable, Sendable, Codable, Identifiable {
    public enum State: String, Hashable, Sendable, Codable {
        case enabled
        case disabled
        /// Removed for user 0 but still on the system partition (restorable with install-existing).
        case uninstalledForUser
    }

    public var id: PackageName { packageName }
    public let packageName: PackageName
    public let label: String?
    public let versionName: String?
    public let versionCode: Int64
    public let isSystem: Bool
    public let state: State
    /// Paths of the base and split APKs on the device.
    public let apkPaths: [String]
    public let installerPackage: String?
    public let sizeBytes: Int64?
    public let uid: Int?

    public init(
        packageName: PackageName,
        label: String? = nil,
        versionName: String? = nil,
        versionCode: Int64,
        isSystem: Bool,
        state: State,
        apkPaths: [String],
        installerPackage: String? = nil,
        sizeBytes: Int64? = nil,
        uid: Int? = nil
    ) {
        self.packageName = packageName
        self.label = label
        self.versionName = versionName
        self.versionCode = versionCode
        self.isSystem = isSystem
        self.state = state
        self.apkPaths = apkPaths
        self.installerPackage = installerPackage
        self.sizeBytes = sizeBytes
        self.uid = uid
    }

    /// Plain-language install source, e.g. "Google Play".
    public var installSource: String {
        switch installerPackage {
        case "com.android.vending": "Google Play"
        case "com.sec.android.app.samsungapps": "Galaxy Store"
        case "com.xiaomi.market", "com.xiaomi.mipicks": "Xiaomi GetApps"
        case "com.amazon.venezia": "Amazon Appstore"
        case "org.fdroid.fdroid": "F-Droid"
        case "com.google.android.packageinstaller", "com.android.packageinstaller": "Installed from a file"
        case .none, "null": isSystem ? "Preinstalled" : "Unknown (adb or sideload)"
        case .some(let other): other
        }
    }
}

/// Risk tag on a debloat preset entry, following UAD-ng's removal levels.
public enum DebloatRisk: String, Hashable, Sendable, Codable, CaseIterable, Comparable {
    /// Removing it has no known side effects.
    case safe
    /// May break a feature the user might want.
    case caution
    /// Can break important functions; for people who know what they are removing.
    case expert

    private var order: Int {
        switch self {
        case .safe: 0
        case .caution: 1
        case .expert: 2
        }
    }

    public static func < (lhs: DebloatRisk, rhs: DebloatRisk) -> Bool { lhs.order < rhs.order }
}

public struct DebloatEntry: Hashable, Sendable, Codable, Identifiable {
    public var id: PackageName { packageName }
    public let packageName: PackageName
    public let risk: DebloatRisk
    public let description: String

    public init(packageName: PackageName, risk: DebloatRisk, description: String) {
        self.packageName = packageName
        self.risk = risk
        self.description = description
    }
}

public struct DebloatPreset: Hashable, Sendable, Codable, Identifiable {
    public let id: String
    public let name: String
    public let brand: DeviceBrand
    public let entries: [DebloatEntry]

    public init(id: String, name: String, brand: DeviceBrand, entries: [DebloatEntry]) {
        self.id = id
        self.name = name
        self.brand = brand
        self.entries = entries
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation

/// A permission and what it lets an app do, in plain language.
public struct PermissionInfo: Hashable, Sendable, Decodable {
    public let name: String
    public let text: String
    public let dangerous: Bool
}

/// A tracker or advertising SDK, identified by DEX class-name prefixes.
public struct TrackerSignature: Hashable, Sendable, Decodable {
    public let name: String
    public let category: String
    public let prefixes: [String]
}

/// The official signing certificate(s) of a well-known app.
public struct KnownSigner: Hashable, Sendable, Decodable {
    public let package: String
    public let name: String
    public let sha256: [String]

    public init(package: String, name: String, sha256: [String]) {
        self.package = package
        self.name = name
        self.sha256 = sha256
    }
}

/// All data the safety engine uses: rules, permission texts, tracker signatures and known signers.
/// Shipped as versioned JSON in the app bundle and updated with the app.
public struct SafetyCatalog: Sendable {
    public var rules: RiskRuleSet
    public var permissions: [PermissionInfo]
    public var trackers: [TrackerSignature]
    public var knownSigners: [KnownSigner]

    public init(rules: RiskRuleSet, permissions: [PermissionInfo], trackers: [TrackerSignature], knownSigners: [KnownSigner]) {
        self.rules = rules
        self.permissions = permissions
        self.trackers = trackers
        self.knownSigners = knownSigners
    }

    public static func bundled() throws -> SafetyCatalog {
        struct Permissions: Decodable { let permissions: [PermissionInfo] }
        struct Trackers: Decodable { let trackers: [TrackerSignature] }
        struct Signers: Decodable { let signers: [KnownSigner] }
        return SafetyCatalog(
            rules: try load("risk-rules", as: RiskRuleSet.self),
            permissions: try load("permissions", as: Permissions.self).permissions,
            trackers: try load("trackers", as: Trackers.self).trackers,
            knownSigners: try load("known-signers", as: Signers.self).signers
        )
    }

    private static func load<T: Decodable>(_ name: String, as type: T.Type) throws -> T {
        guard let url = Bundle.module.url(forResource: name, withExtension: "json") else {
            throw CocoaError(.fileNoSuchFile, userInfo: [NSFilePathErrorKey: name + ".json"])
        }
        return try JSONDecoder().decode(type, from: Data(contentsOf: url))
    }
}

/// A rough guess at what kind of app this is, used to spot permissions that do not fit.
public enum AppCategory: String, Hashable, Sendable, Decodable, CaseIterable {
    case game, communication, media, utility, other

    private static let keywords: [(AppCategory, [String])] = [
        (.game, ["game", "games"]),
        (.communication, ["messag", "messeng", "sms", "chat", "mail", "dialer", "phone", "contacts"]),
        (.media, ["music", "player", "video", "radio", "podcast"]),
        (.utility, ["flashlight", "torch", "calculator", "cleaner", "battery", "compass", "qrcode", "scanner", "wallpaper"]),
    ]
    private static let gameEngines = ["com/unity3d/player/", "org/cocos2dx/", "com/epicgames/", "com/badlogic/gdx/"]

    public static func guess(packageName: String, label: String?, features: [String], dexPrefixes: Set<String>) -> AppCategory {
        if features.contains("android.hardware.gamepad") || gameEngines.contains(where: dexPrefixes.contains) { return .game }
        let haystack = (packageName + " " + (label ?? "")).lowercased()
        return keywords.first { $0.1.contains(where: haystack.contains) }?.0 ?? .other
    }
}

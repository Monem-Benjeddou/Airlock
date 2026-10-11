// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// The only verdicts Airlock gives. There is deliberately no "safe".
public enum RiskLevel: Int, Hashable, Sendable, Codable, Comparable, CaseIterable {
    case low = 0
    case medium = 1
    case high = 2

    public static func < (lhs: RiskLevel, rhs: RiskLevel) -> Bool { lhs.rawValue < rhs.rawValue }

    public var title: String {
        switch self {
        case .low: "Low risk"
        case .medium: "Medium risk"
        case .high: "High risk"
        }
    }

    /// Whether the install flow must ask the user to confirm before continuing.
    public var requiresConfirmation: Bool { self >= .medium }
}

/// One reason contributing to a verdict, shown to the user as a sentence.
public struct RiskReason: Hashable, Sendable, Codable, Identifiable {
    public enum Category: String, Hashable, Sendable, Codable {
        case signature, permissions, trackers, reputation, manifest
    }

    public var id: String { ruleID }
    /// Stable rule identifier from the rules file, e.g. `sig.mismatch-installed`.
    public let ruleID: String
    public let category: Category
    public let level: RiskLevel
    public let message: String

    public init(ruleID: String, category: Category, level: RiskLevel, message: String) {
        self.ruleID = ruleID
        self.category = category
        self.level = level
        self.message = message
    }
}

/// A dangerous permission explained in plain language.
public struct PermissionFinding: Hashable, Sendable, Codable, Identifiable {
    public var id: String { permission }
    public let permission: String
    public let plainLanguage: String
    public let isDangerous: Bool

    public init(permission: String, plainLanguage: String, isDangerous: Bool) {
        self.permission = permission
        self.plainLanguage = plainLanguage
        self.isDangerous = isDangerous
    }
}

public struct TrackerFinding: Hashable, Sendable, Codable, Identifiable {
    public var id: String { name }
    public let name: String
    public let category: String
    public let matchedPrefixes: [String]

    public init(name: String, category: String, matchedPrefixes: [String]) {
        self.name = name
        self.category = category
        self.matchedPrefixes = matchedPrefixes
    }
}

/// Outcome of the hash-only reputation lookup.
public enum ReputationResult: Hashable, Sendable, Codable {
    /// The service knows the file. `malicious` and `suspicious` are engine counts out of `total`.
    case found(malicious: Int, suspicious: Int, total: Int, permalink: URL?)
    /// The hash is not in the service's database.
    case unknown
    /// The user has not configured a lookup key or turned lookups off.
    case notConfigured
    /// Network or service error; the report still completes offline.
    case unavailable(String)
}

/// How the APK's signer relates to what is already known.
public enum SignerMatch: Hashable, Sendable, Codable {
    case matchesInstalled
    case differsFromInstalled
    case notInstalled
    case matchesKnownOfficial(String)
    case differsFromKnownOfficial(String)
}

public struct SafetyReport: Hashable, Sendable, Codable {
    public let packageName: String
    public let sha256: String
    public let level: RiskLevel
    /// Sorted most severe first.
    public let reasons: [RiskReason]
    public let signer: SignatureCheck
    public let signerMatch: SignerMatch
    public let permissions: [PermissionFinding]
    public let trackers: [TrackerFinding]
    public let reputation: ReputationResult
    public let rulesVersion: String

    public init(
        packageName: String,
        sha256: String,
        level: RiskLevel,
        reasons: [RiskReason],
        signer: SignatureCheck,
        signerMatch: SignerMatch,
        permissions: [PermissionFinding],
        trackers: [TrackerFinding],
        reputation: ReputationResult,
        rulesVersion: String
    ) {
        self.packageName = packageName
        self.sha256 = sha256
        self.level = level
        self.reasons = reasons
        self.signer = signer
        self.signerMatch = signerMatch
        self.permissions = permissions
        self.trackers = trackers
        self.reputation = reputation
        self.rulesVersion = rulesVersion
    }
}

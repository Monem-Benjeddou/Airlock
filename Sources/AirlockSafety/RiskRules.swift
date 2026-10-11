// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation

/// The versioned rule file (`risk-rules.json`).
public struct RiskRuleSet: Hashable, Sendable, Decodable {
    public let version: String
    public let rules: [RiskRule]
}

/// One declarative rule: every present condition must hold for it to fire.
public struct RiskRule: Hashable, Sendable, Decodable {
    public let id: String
    /// Rules sharing a group report only their most severe match.
    public let group: String?
    public let category: RiskReason.Category
    public let level: RiskLevel
    public let when: RiskCondition
    /// May contain `{category}`, `{count}`, `{malicious}`, `{suspicious}`, `{trackers}`.
    public let message: String

    private enum CodingKeys: String, CodingKey { case id, group, category, level, when, message }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        group = try container.decodeIfPresent(String.self, forKey: .group)
        category = try container.decode(RiskReason.Category.self, forKey: .category)
        when = try container.decode(RiskCondition.self, forKey: .when)
        message = try container.decode(String.self, forKey: .message)
        switch try container.decode(String.self, forKey: .level) {
        case "low": level = .low
        case "medium": level = .medium
        case "high": level = .high
        case let other:
            throw DecodingError.dataCorruptedError(forKey: .level, in: container, debugDescription: "Unknown level \(other)")
        }
    }
}

/// Facts about a package that rules are evaluated against.
struct RiskFacts {
    var signatureStatus: SignatureCheck.Status
    var signerMatch: SignerMatch
    var debugCertificate: Bool
    var permissions: Set<String>
    var dangerousPermissionCount: Int
    var category: AppCategory
    var malicious: Int
    var suspicious: Int
    var trackerCount: Int
    var debuggable: Bool
    var testOnly: Bool
    var targetSdk: Int?
}

public struct RiskCondition: Hashable, Sendable, Decodable {
    var signatureStatus: [String]?
    var signerMatch: [String]?
    var debugCertificate: Bool?
    var anyPermission: [String]?
    var allPermissions: [String]?
    var appCategory: [AppCategory]?
    var dangerousPermissionCountAtLeast: Int?
    var maliciousAtLeast: Int?
    var maliciousBelow: Int?
    var suspiciousAtLeast: Int?
    var trackerCountAtLeast: Int?
    var trackerCountBelow: Int?
    var debuggable: Bool?
    var testOnly: Bool?
    var targetSdkBelow: Int?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case signatureStatus, signerMatch, debugCertificate, anyPermission, allPermissions, appCategory
        case dangerousPermissionCountAtLeast, maliciousAtLeast, maliciousBelow, suspiciousAtLeast
        case trackerCountAtLeast, trackerCountBelow, debuggable, testOnly, targetSdkBelow
    }

    /// Rejects unknown keys so a typo in the rule file fails loudly instead of matching everything.
    private struct AnyKey: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }
        init(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }
    }

    public init(from decoder: any Decoder) throws {
        let raw = try decoder.container(keyedBy: AnyKey.self)
        let known = Set(CodingKeys.allCases.map(\.rawValue))
        if let unknown = raw.allKeys.first(where: { !known.contains($0.stringValue) }) {
            throw DecodingError.dataCorruptedError(forKey: unknown, in: raw, debugDescription: "Unknown condition \(unknown.stringValue)")
        }
        guard !raw.allKeys.isEmpty else {
            let context = DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "A rule needs at least one condition")
            throw DecodingError.dataCorrupted(context)
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        signatureStatus = try container.decodeIfPresent([String].self, forKey: .signatureStatus)
        signerMatch = try container.decodeIfPresent([String].self, forKey: .signerMatch)
        debugCertificate = try container.decodeIfPresent(Bool.self, forKey: .debugCertificate)
        anyPermission = try container.decodeIfPresent([String].self, forKey: .anyPermission)
        allPermissions = try container.decodeIfPresent([String].self, forKey: .allPermissions)
        appCategory = try container.decodeIfPresent([AppCategory].self, forKey: .appCategory)
        dangerousPermissionCountAtLeast = try container.decodeIfPresent(Int.self, forKey: .dangerousPermissionCountAtLeast)
        maliciousAtLeast = try container.decodeIfPresent(Int.self, forKey: .maliciousAtLeast)
        maliciousBelow = try container.decodeIfPresent(Int.self, forKey: .maliciousBelow)
        suspiciousAtLeast = try container.decodeIfPresent(Int.self, forKey: .suspiciousAtLeast)
        trackerCountAtLeast = try container.decodeIfPresent(Int.self, forKey: .trackerCountAtLeast)
        trackerCountBelow = try container.decodeIfPresent(Int.self, forKey: .trackerCountBelow)
        debuggable = try container.decodeIfPresent(Bool.self, forKey: .debuggable)
        testOnly = try container.decodeIfPresent(Bool.self, forKey: .testOnly)
        targetSdkBelow = try container.decodeIfPresent(Int.self, forKey: .targetSdkBelow)
    }

    func matches(_ facts: RiskFacts) -> Bool {
        var checks: [Bool] = []
        if let signatureStatus { checks.append(signatureStatus.contains(facts.signatureStatus.rawValue)) }
        if let signerMatch { checks.append(signerMatch.contains(facts.signerMatch.ruleName)) }
        if let debugCertificate { checks.append(facts.debugCertificate == debugCertificate) }
        if let anyPermission { checks.append(anyPermission.contains(where: facts.permissions.contains)) }
        if let allPermissions { checks.append(allPermissions.allSatisfy(facts.permissions.contains)) }
        if let appCategory { checks.append(appCategory.contains(facts.category)) }
        if let minimum = dangerousPermissionCountAtLeast { checks.append(facts.dangerousPermissionCount >= minimum) }
        if let maliciousAtLeast { checks.append(facts.malicious >= maliciousAtLeast) }
        if let maliciousBelow { checks.append(facts.malicious < maliciousBelow) }
        if let suspiciousAtLeast { checks.append(facts.suspicious >= suspiciousAtLeast) }
        if let trackerCountAtLeast { checks.append(facts.trackerCount >= trackerCountAtLeast) }
        if let trackerCountBelow { checks.append(facts.trackerCount < trackerCountBelow) }
        if let debuggable { checks.append(facts.debuggable == debuggable) }
        if let testOnly { checks.append(facts.testOnly == testOnly) }
        if let targetSdkBelow { checks.append((facts.targetSdk ?? Int.max) < targetSdkBelow) }
        return !checks.isEmpty && checks.allSatisfy { $0 }
    }
}

extension SignerMatch {
    /// The name used for this case in the rule file.
    var ruleName: String {
        switch self {
        case .matchesInstalled: "matchesInstalled"
        case .differsFromInstalled: "differsFromInstalled"
        case .notInstalled: "notInstalled"
        case .matchesKnownOfficial: "matchesKnownOfficial"
        case .differsFromKnownOfficial: "differsFromKnownOfficial"
        }
    }
}

enum RiskEvaluator {
    /// Fires every matching rule, keeps the most severe per group, and sorts most severe first.
    static func evaluate(_ rules: RiskRuleSet, facts: RiskFacts) -> [RiskReason] {
        var seenGroups = Set<String>()
        var reasons: [RiskReason] = []
        let ordered = rules.rules.enumerated().sorted { lhs, rhs in
            lhs.element.level != rhs.element.level ? lhs.element.level > rhs.element.level : lhs.offset < rhs.offset
        }
        for (_, rule) in ordered where rule.when.matches(facts) {
            if let group = rule.group, !seenGroups.insert(group).inserted { continue }
            reasons.append(RiskReason(ruleID: rule.id, category: rule.category, level: rule.level, message: render(rule.message, facts)))
        }
        return reasons
    }

    private static func render(_ template: String, _ facts: RiskFacts) -> String {
        template
            .replacingOccurrences(of: "{category}", with: facts.category.rawValue)
            .replacingOccurrences(of: "{count}", with: String(facts.dangerousPermissionCount))
            .replacingOccurrences(of: "{malicious}", with: String(facts.malicious))
            .replacingOccurrences(of: "{suspicious}", with: String(facts.suspicious))
            .replacingOccurrences(of: "{trackers}", with: String(facts.trackerCount))
    }
}

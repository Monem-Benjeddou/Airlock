// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation

/// Builds the safety report from already-inspected package facts plus an optional hash lookup.
///
/// The verdict is the most severe matching rule; with no matching rule it is "Low risk", never "safe".
public struct DefaultSafetyEngine: SafetyEngine {
    private let catalog: SafetyCatalog
    private let reputation: (any ReputationLookup)?
    private let permissionInfo: [String: PermissionInfo]

    public init(catalog: SafetyCatalog, reputation: (any ReputationLookup)?) {
        self.catalog = catalog
        self.reputation = reputation
        permissionInfo = Dictionary(catalog.permissions.map { ($0.name, $0) }, uniquingKeysWith: { first, _ in first })
    }

    public func report(for package: InspectedPackage, installedSigners: [String]?) async -> SafetyReport {
        let base = package.base
        let reputationResult = await reputation?.lookup(sha256: base.sha256) ?? .notConfigured

        let requested = Set(package.allAPKs.flatMap(\.manifest.permissions))
        let permissions = findings(for: requested)
        let prefixes = package.allAPKs.reduce(into: Set<String>()) { $0.formUnion($1.dexClassPrefixes) }
        let trackers = matchTrackers(prefixes)
        let signerMatch = matchSigner(package: package.packageName, certificates: base.signature.certificates, installed: installedSigners)

        var malicious = 0
        var suspicious = 0
        if case .found(let flagged, let questionable, _, _) = reputationResult {
            malicious = flagged
            suspicious = questionable
        }

        let facts = RiskFacts(
            signatureStatus: base.signature.status,
            signerMatch: signerMatch,
            debugCertificate: base.signature.certificates.contains { $0.subject.contains("CN=Android Debug") },
            permissions: requested,
            dangerousPermissionCount: permissions.filter(\.isDangerous).count,
            category: AppCategory.guess(
                packageName: package.packageName, label: base.manifest.label, features: base.manifest.features, dexPrefixes: prefixes
            ),
            malicious: malicious,
            suspicious: suspicious,
            trackerCount: trackers.count,
            debuggable: base.manifest.isDebuggable,
            testOnly: base.manifest.isTestOnly,
            targetSdk: base.manifest.targetSdk
        )
        let reasons = RiskEvaluator.evaluate(catalog.rules, facts: facts)

        return SafetyReport(
            packageName: package.packageName,
            sha256: base.sha256,
            level: reasons.map(\.level).max() ?? .low,
            reasons: reasons,
            signer: base.signature,
            signerMatch: signerMatch,
            permissions: permissions,
            trackers: trackers,
            reputation: reputationResult,
            rulesVersion: catalog.rules.version
        )
    }

    /// Dangerous permissions first, then alphabetical.
    private func findings(for permissions: Set<String>) -> [PermissionFinding] {
        permissions.map { name in
            let info = permissionInfo[name]
            return PermissionFinding(permission: name, plainLanguage: info?.text ?? name, isDangerous: info?.dangerous ?? false)
        }
        .sorted { lhs, rhs in lhs.isDangerous != rhs.isDangerous ? lhs.isDangerous : lhs.permission < rhs.permission }
    }

    private func matchTrackers(_ prefixes: Set<String>) -> [TrackerFinding] {
        catalog.trackers.compactMap { tracker in
            let matched = tracker.prefixes.filter(prefixes.contains)
            return matched.isEmpty ? nil : TrackerFinding(name: tracker.name, category: tracker.category, matchedPrefixes: matched)
        }
        .sorted { $0.name < $1.name }
    }

    private func matchSigner(package: String, certificates: [SignerCertificate], installed: [String]?) -> SignerMatch {
        let incoming = Set(certificates.map(\.sha256))
        if let installed {
            return incoming.isDisjoint(with: installed) ? .differsFromInstalled : .matchesInstalled
        }
        if let official = catalog.knownSigners.first(where: { $0.package == package }) {
            return incoming.isDisjoint(with: official.sha256)
                ? .differsFromKnownOfficial(official.name)
                : .matchesKnownOfficial(official.name)
        }
        return .notInstalled
    }
}

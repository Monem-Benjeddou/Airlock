// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
@testable import AirlockSafety
import Foundation
import Testing

/// Builders for inspected packages with just the facts each test cares about.
enum Make {
    static let cert = SignerCertificate(subject: "CN=Example Corp", issuer: "CN=Example Corp", sha256: String(repeating: "ab", count: 32))
    static let debugCert = SignerCertificate(
        subject: "C=US, O=Android, CN=Android Debug", issuer: "CN=Android Debug", sha256: String(repeating: "cd", count: 32)
    )

    static func package(
        name: String = "com.example.app",
        permissions: [String] = [],
        status: SignatureCheck.Status = .verified,
        certificates: [SignerCertificate] = [cert],
        prefixes: Set<String> = [],
        targetSdk: Int? = 34,
        debuggable: Bool = false,
        testOnly: Bool = false,
        label: String? = nil,
        features: [String] = [],
        splitPermissions: [String] = []
    ) -> InspectedPackage {
        let manifest = ApkManifest(
            packageName: name, versionCode: 1, targetSdk: targetSdk, label: label,
            permissions: permissions, features: features, isTestOnly: testOnly, isDebuggable: debuggable
        )
        let signature = SignatureCheck(status: status, schemes: status == .unsigned ? [] : [2], certificates: certificates)
        let base = InspectedAPK(fileName: "base.apk", sizeBytes: 10, sha256: String(repeating: "11", count: 32),
                                manifest: manifest, signature: signature, dexClassPrefixes: prefixes)
        let splitManifest = ApkManifest(packageName: name, versionCode: 1, splitName: "config.en", permissions: splitPermissions)
        let split = InspectedAPK(fileName: "split.apk", sizeBytes: 1, sha256: String(repeating: "22", count: 32),
                                 manifest: splitManifest, signature: signature)
        let url = URL(fileURLWithPath: "/tmp/x.apk")
        return InspectedPackage(sourceFile: url, format: .apks, sourceSHA256: String(repeating: "33", count: 32),
                                base: base, splits: [split], obbFiles: [], workDirectory: url)
    }
}

struct StubReputation: ReputationLookup {
    let result: ReputationResult
    func lookup(sha256: String) async -> ReputationResult { result }
}

@Suite("Safety catalog resources")
struct SafetyCatalogTests {
    @Test func bundledCatalogLoadsAndIsConsistent() throws {
        let catalog = try SafetyCatalog.bundled()
        #expect(catalog.rules.rules.count >= 20)
        #expect(catalog.permissions.count >= 40)
        #expect(catalog.trackers.count >= 30)
        #expect(!catalog.rules.version.isEmpty)
        #expect(Set(catalog.rules.rules.map(\.id)).count == catalog.rules.rules.count, "rule IDs must be unique")
    }

    @Test func noRuleOrPermissionTextEverSaysSafe() throws {
        let catalog = try SafetyCatalog.bundled()
        for rule in catalog.rules.rules {
            #expect(!rule.message.localizedCaseInsensitiveContains("safe"), "\(rule.id)")
            #expect(rule.message.hasSuffix("."), "\(rule.id)")
        }
    }

    @Test func trackerPrefixesAreWellFormed() throws {
        for tracker in try SafetyCatalog.bundled().trackers {
            for prefix in tracker.prefixes {
                #expect(prefix.hasSuffix("/") && !prefix.hasPrefix("/") && !prefix.contains("."), "\(tracker.name): \(prefix)")
                let depth = prefix.split(separator: "/").count
                #expect((2...5).contains(depth), "\(prefix) must be 2-5 segments to match DexScanner output")
            }
        }
    }

    @Test func unknownConditionKeyIsRejected() {
        let json = #"""
        {"version": "1", "rules": [{"id": "x", "category": "manifest", "level": "low", "when": {"debugable": true}, "message": "m."}]}
        """#
        #expect(throws: (any Error).self) { try JSONDecoder().decode(RiskRuleSet.self, from: Data(json.utf8)) }
    }

    @Test func ruleWithoutConditionsIsRejected() {
        let json = #"{"version": "1", "rules": [{"id": "x", "category": "manifest", "level": "low", "when": {}, "message": "m."}]}"#
        #expect(throws: (any Error).self) { try JSONDecoder().decode(RiskRuleSet.self, from: Data(json.utf8)) }
    }
}

@Suite("DefaultSafetyEngine")
struct SafetyEngineTests {
    private func report(
        _ package: InspectedPackage,
        installed: [String]? = nil,
        reputation: ReputationResult = .notConfigured
    ) async throws -> SafetyReport {
        let engine = DefaultSafetyEngine(catalog: try SafetyCatalog.bundled(), reputation: StubReputation(result: reputation))
        return await engine.report(for: package, installedSigners: installed)
    }

    @Test func cleanAppIsLowRiskWithNoReasons() async throws {
        let result = try await report(Make.package(permissions: ["android.permission.INTERNET"]))
        #expect(result.level == .low)
        #expect(result.reasons.isEmpty)
        #expect(result.signerMatch == .notInstalled)
        #expect(result.permissions.map(\.permission) == ["android.permission.INTERNET"])
        #expect(result.permissions.first?.isDangerous == false)
    }

    @Test func unsignedIsHigh() async throws {
        let result = try await report(Make.package(status: .unsigned, certificates: []))
        #expect(result.level == .high)
        #expect(result.reasons.map(\.ruleID) == ["sig.unsigned"])
    }

    @Test func tamperedIsHigh() async throws {
        #expect(try await report(Make.package(status: .invalid)).reasons.first?.ruleID == "sig.invalid")
    }

    @Test func unverifiableIsMedium() async throws {
        #expect(try await report(Make.package(status: .unverifiable)).level == .medium)
    }

    @Test func signerMatchingInstalledCopy() async throws {
        let same = try await report(Make.package(), installed: [Make.cert.sha256])
        #expect(same.signerMatch == .matchesInstalled)
        #expect(same.level == .low)

        let different = try await report(Make.package(), installed: [String(repeating: "ff", count: 32)])
        #expect(different.signerMatch == .differsFromInstalled)
        #expect(different.level == .high)
        #expect(different.reasons.first?.ruleID == "sig.differs-installed")
    }

    @Test func knownOfficialSigner() async throws {
        let official = KnownSigner(package: "com.example.app", name: "Example Corp", sha256: [Make.cert.sha256])
        var catalog = try SafetyCatalog.bundled()
        catalog.knownSigners = [official]
        let engine = DefaultSafetyEngine(catalog: catalog, reputation: nil)
        let genuine = await engine.report(for: Make.package(), installedSigners: nil)
        #expect(genuine.signerMatch == .matchesKnownOfficial("Example Corp"))

        let fake = await engine.report(for: Make.package(certificates: [Make.debugCert]), installedSigners: nil)
        #expect(fake.signerMatch == .differsFromKnownOfficial("Example Corp"))
        #expect(fake.level == .high)
        #expect(fake.reasons.map(\.ruleID).contains("sig.differs-official"))
    }

    @Test func installedSignerTakesPrecedenceOverOfficialList() async throws {
        var catalog = try SafetyCatalog.bundled()
        catalog.knownSigners = [KnownSigner(package: "com.example.app", name: "Example", sha256: [Make.cert.sha256])]
        let engine = DefaultSafetyEngine(catalog: catalog, reputation: nil)
        let result = await engine.report(for: Make.package(), installedSigners: [Make.cert.sha256])
        #expect(result.signerMatch == .matchesInstalled)
    }

    @Test func debugCertificateIsMedium() async throws {
        let result = try await report(Make.package(certificates: [Make.debugCert]))
        #expect(result.level == .medium)
        #expect(result.reasons.map(\.ruleID) == ["sig.debug-certificate"])
    }

    @Test func smsAloneIsMediumAndExplained() async throws {
        let result = try await report(Make.package(permissions: ["android.permission.READ_SMS"]))
        #expect(result.level == .medium)
        #expect(result.reasons.map(\.ruleID) == ["perm.sms"])
        #expect(result.permissions.first?.plainLanguage.contains("text messages") == true)
    }

    @Test func gameAskingForSMSIsHighAndOnlyMostSevereSMSReasonShows() async throws {
        let result = try await report(Make.package(name: "com.studio.supergame", permissions: ["android.permission.SEND_SMS"]))
        #expect(result.level == .high)
        #expect(result.reasons.map(\.ruleID) == ["perm.sms-unexpected"])
        #expect(result.reasons.first?.message == "A game app asking to read or send text messages is unusual.")
    }

    @Test func bankingTrojanPatternIsHigh() async throws {
        let result = try await report(Make.package(permissions: [
            "android.permission.RECEIVE_SMS", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.INTERNET",
        ]))
        #expect(result.level == .high)
        #expect(result.reasons.map(\.ruleID) == ["perm.sms-and-overlay"])
    }

    @Test func permissionsFromSplitsCount() async throws {
        let result = try await report(Make.package(splitPermissions: ["android.permission.READ_CALL_LOG"]))
        #expect(result.reasons.map(\.ruleID) == ["perm.call-log"])
    }

    @Test func manyDangerousPermissions() async throws {
        let catalog = try SafetyCatalog.bundled()
        let dangerous = catalog.permissions.filter(\.dangerous).map(\.name)
            .filter { !$0.contains("SMS") && !$0.contains("CALL_LOG") && !$0.contains("OUTGOING") && !$0.contains("BACKGROUND_LOCATION")
                && !$0.contains("INSTALL_PACKAGES") && !$0.contains("MANAGE_EXTERNAL") && !$0.contains("ACCESSIBILITY")
                && !$0.contains("SYSTEM_ALERT") && !$0.contains("MMS") && !$0.contains("WAP") }
            .prefix(12)
        let result = try await report(Make.package(permissions: Array(dangerous)))
        #expect(result.reasons.map(\.ruleID) == ["perm.many-dangerous"])
        #expect(result.reasons.first?.message == "It asks for 12 sensitive permissions, more than most apps need.")
    }

    @Test func unknownPermissionsAreListedAsNotDangerous() async throws {
        let result = try await report(Make.package(permissions: ["com.vendor.permission.CUSTOM"]))
        #expect(result.permissions.first?.isDangerous == false)
        #expect(result.permissions.first?.plainLanguage == "com.vendor.permission.CUSTOM")
    }

    @Test func dangerousPermissionsAreListedFirst() async throws {
        let result = try await report(Make.package(permissions: ["android.permission.INTERNET", "android.permission.CAMERA"]))
        #expect(result.permissions.map(\.permission) == ["android.permission.CAMERA", "android.permission.INTERNET"])
    }

    @Test func trackersAreDetectedByPrefix() async throws {
        let result = try await report(Make.package(prefixes: ["com/facebook/ads/", "com/facebook/", "com/appsflyer/", "com/example/"]))
        #expect(result.trackers.map(\.name) == ["AppsFlyer", "Facebook Audience Network"])
        #expect(result.level == .low)
        #expect(result.reasons.map(\.ruleID) == ["trk.some"])
        #expect(result.reasons.first?.message == "It contains 2 tracking or advertising library(ies).")
    }

    @Test func manyTrackersIsMedium() async throws {
        let prefixes: Set<String> = ["com/appsflyer/", "com/adjust/sdk/", "io/branch/", "com/applovin/", "com/vungle/", "com/inmobi/"]
        let result = try await report(Make.package(prefixes: prefixes))
        #expect(result.trackers.count == 6)
        #expect(result.level == .medium)
        #expect(result.reasons.map(\.ruleID) == ["trk.many"])
    }

    @Test func reputationRules() async throws {
        let cases: [(ReputationResult, RiskLevel, String)] = [
            (.found(malicious: 5, suspicious: 0, total: 70, permalink: nil), .high, "rep.malicious-many"),
            (.found(malicious: 1, suspicious: 0, total: 70, permalink: nil), .medium, "rep.malicious-few"),
            (.found(malicious: 0, suspicious: 2, total: 70, permalink: nil), .medium, "rep.suspicious"),
        ]
        for (reputation, level, rule) in cases {
            let result = try await report(Make.package(), reputation: reputation)
            #expect(result.level == level)
            #expect(result.reasons.map(\.ruleID) == [rule])
            #expect(result.reputation == reputation)
        }
    }

    @Test(arguments: [
        ReputationResult.unknown, .notConfigured, .unavailable("x"), .found(malicious: 0, suspicious: 0, total: 70, permalink: nil),
    ])
    func cleanOrMissingReputationAddsNoReason(_ reputation: ReputationResult) async throws {
        #expect(try await report(Make.package(), reputation: reputation).reasons.isEmpty)
    }

    @Test func reputationIsLookedUpByBaseAPKHash() async throws {
        final class Spy: ReputationLookup, @unchecked Sendable {
            var hashes: [String] = []
            func lookup(sha256: String) async -> ReputationResult { hashes.append(sha256); return .unknown }
        }
        let spy = Spy()
        let engine = DefaultSafetyEngine(catalog: try SafetyCatalog.bundled(), reputation: spy)
        _ = await engine.report(for: Make.package(), installedSigners: nil)
        #expect(spy.hashes == [String(repeating: "11", count: 32)])
    }

    @Test func withoutReputationServiceReportsNotConfigured() async throws {
        let engine = DefaultSafetyEngine(catalog: try SafetyCatalog.bundled(), reputation: nil)
        #expect(await engine.report(for: Make.package(), installedSigners: nil).reputation == .notConfigured)
    }

    @Test func manifestRules() async throws {
        #expect(try await report(Make.package(debuggable: true)).reasons.map(\.ruleID) == ["man.debuggable"])
        #expect(try await report(Make.package(testOnly: true)).reasons.map(\.ruleID) == ["man.test-only"])
        #expect(try await report(Make.package(targetSdk: 22)).reasons.map(\.ruleID) == ["man.old-target"])
        #expect(try await report(Make.package(targetSdk: nil)).reasons.isEmpty)
    }

    @Test func reasonsAreSortedMostSevereFirstAndVerdictIsTheMaximum() async throws {
        let result = try await report(
            Make.package(permissions: ["android.permission.READ_CALL_LOG"], prefixes: ["com/appsflyer/"], debuggable: true),
            installed: [String(repeating: "ff", count: 32)]
        )
        #expect(result.level == .high)
        let levels = result.reasons.map(\.level)
        #expect(levels == levels.sorted(by: >))
        #expect(result.reasons.first?.ruleID == "sig.differs-installed")
    }

    @Test func reportCarriesRulesVersionAndHash() async throws {
        let result = try await report(Make.package())
        #expect(result.rulesVersion == "2026.10.1")
        #expect(result.sha256 == String(repeating: "11", count: 32))
        #expect(result.packageName == "com.example.app")
    }
}

@Suite("App category guess")
struct AppCategoryTests {
    struct Case: Sendable, CustomTestStringConvertible {
        var name: String
        var label: String?
        var features: [String] = []
        var prefixes: Set<String> = []
        var expected: AppCategory
        var testDescription: String { "\(name) → \(expected)" }
    }

    @Test(arguments: [
        Case(name: "com.studio.supergame", expected: .game),
        Case(name: "com.x.y", label: "Puzzle Games", expected: .game),
        Case(name: "com.x.y", features: ["android.hardware.gamepad"], expected: .game),
        Case(name: "com.x.y", prefixes: ["com/unity3d/player/"], expected: .game),
        Case(name: "com.x.messenger", expected: .communication),
        Case(name: "com.x.sms", expected: .communication),
        Case(name: "com.x.musicplayer", expected: .media),
        Case(name: "com.x.flashlight", expected: .utility),
        Case(name: "com.x.calculator", expected: .utility),
        Case(name: "com.x.y", expected: .other),
    ])
    func guesses(_ example: Case) {
        let guess = AppCategory.guess(
            packageName: example.name, label: example.label, features: example.features, dexPrefixes: example.prefixes
        )
        #expect(guess == example.expected)
    }
}

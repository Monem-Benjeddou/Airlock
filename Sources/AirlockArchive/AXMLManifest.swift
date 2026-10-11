// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation

extension AXMLParser {
    /// Parses a binary `AndroidManifest.xml` and maps it to an ``ApkManifest``.
    ///
    /// Framework attributes are resolved by resource ID (see ``AXMLElement/attribute(_:)``), so manifests with
    /// stripped attribute names still parse. Only direct children of `<manifest>` count for `uses-sdk`,
    /// `uses-permission*`, `uses-feature` and `application`, matching where Android's package parser looks.
    ///
    /// Mapping details:
    /// - `versionCode` combines `versionCodeMajor` (high 32 bits) with `versionCode` (low 32 bits).
    /// - `targetSdk` falls back to `minSdk` when `uses-sdk` has no `targetSdkVersion` at all, as on Android. SDK values
    ///   given as codenames (`"VanillaIceCream"`) map to nil.
    /// - `isSplitRequired` is true for `android:isSplitRequired="true"` or a non-empty `android:requiredSplitTypes`.
    /// - `label` is set only for a literal string; resource references (`@string/app_name`) give nil.
    /// - `features` lists named `uses-feature` entries unless `android:required="false"`.
    /// - `debuggable` / `testOnly` are true only for a literal true value; references count as false.
    public static func manifest(from data: Data) throws(AXMLError) -> ApkManifest {
        try manifest(from: parse(data))
    }

    /// Maps an already parsed document to an ``ApkManifest``.
    public static func manifest(from document: AXMLDocument) throws(AXMLError) -> ApkManifest {
        let root = document.root
        guard root.name == "manifest" else { throw .notAManifest(root.name) }
        guard let packageName = root.plainAttribute("package")?.value.stringValue, !packageName.isEmpty else {
            throw .missingPackage
        }
        let minor = root.attribute(.versionCode)?.value.integerValue ?? 0
        let major = root.attribute(.versionCodeMajor)?.value.integerValue ?? 0
        let versionCode = Int64(bitPattern: (UInt64(truncatingIfNeeded: major) << 32) | UInt64(UInt32(truncatingIfNeeded: minor)))

        let sdk = root.children(named: "uses-sdk").first
        let minSdk = sdk?.attribute(.minSdkVersion).flatMap(sdkLevel)
        let targetAttribute = sdk?.attribute(.targetSdkVersion)
        let targetSdk = targetAttribute == nil ? minSdk : targetAttribute.flatMap(sdkLevel)

        let requiredSplitTypes = root.attribute(.requiredSplitTypes)?.value.stringValue ?? ""
        let application = root.children(named: "application").first

        return ApkManifest(
            packageName: packageName,
            versionCode: versionCode,
            versionName: root.attribute(.versionName)?.value.stringValue,
            minSdk: minSdk,
            targetSdk: targetSdk,
            splitName: root.plainAttribute("split")?.value.stringValue,
            isSplitRequired: root.attribute(.isSplitRequired)?.value.boolValue == true || !requiredSplitTypes.isEmpty,
            label: application?.attribute(.label)?.value.stringValue,
            permissions: permissions(in: root),
            features: features(in: root),
            isTestOnly: application?.attribute(.testOnly)?.value.boolValue == true,
            isDebuggable: application?.attribute(.debuggable)?.value.boolValue == true
        )
    }

    private static let permissionTags: Set<String> = ["uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"]

    private static func permissions(in root: AXMLElement) -> [String] {
        unique(root.children.filter { permissionTags.contains($0.name) }.compactMap { $0.attribute(.name)?.value.stringValue })
    }

    private static func features(in root: AXMLElement) -> [String] {
        unique(root.children(named: "uses-feature").compactMap { feature in
            guard feature.attribute(.required)?.value.boolValue != false else { return nil }
            return feature.attribute(.name)?.value.stringValue
        })
    }

    private static func sdkLevel(_ attribute: AXMLAttribute) -> Int? {
        guard let level = attribute.value.integerValue, (0...10_000).contains(level) else { return nil }
        return Int(level)
    }

    /// Drops empty strings and repeats, keeping first-seen order.
    private static func unique(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { !$0.isEmpty && seen.insert($0).inserted }
    }
}

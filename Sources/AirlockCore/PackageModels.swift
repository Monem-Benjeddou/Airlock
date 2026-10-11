// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Container format, detected from contents rather than the file extension.
public enum PackageFormat: String, Hashable, Sendable, Codable {
    /// A single APK (zip with `AndroidManifest.xml`).
    case apk
    /// bundletool output: zip of APKs (often with `toc.pb`).
    case apks
    /// APKPure-style: zip with `manifest.json`, APKs and optional `Android/obb/`.
    case xapk
    /// APKMirror bundle: zip of APKs with `info.json`.
    case apkm
    /// A folder of split APKs dropped as-is.
    case splitFolder
}

/// Facts read from one APK's binary `AndroidManifest.xml`.
public struct ApkManifest: Hashable, Sendable, Codable {
    public let packageName: String
    public let versionCode: Int64
    public let versionName: String?
    public let minSdk: Int?
    public let targetSdk: Int?
    /// Non-nil for split APKs (`split="config.arm64_v8a"`).
    public let splitName: String?
    public let isSplitRequired: Bool
    public let label: String?
    public let permissions: [String]
    public let features: [String]
    public let isTestOnly: Bool
    public let isDebuggable: Bool

    public init(
        packageName: String,
        versionCode: Int64,
        versionName: String? = nil,
        minSdk: Int? = nil,
        targetSdk: Int? = nil,
        splitName: String? = nil,
        isSplitRequired: Bool = false,
        label: String? = nil,
        permissions: [String] = [],
        features: [String] = [],
        isTestOnly: Bool = false,
        isDebuggable: Bool = false
    ) {
        self.packageName = packageName
        self.versionCode = versionCode
        self.versionName = versionName
        self.minSdk = minSdk
        self.targetSdk = targetSdk
        self.splitName = splitName
        self.isSplitRequired = isSplitRequired
        self.label = label
        self.permissions = permissions
        self.features = features
        self.isTestOnly = isTestOnly
        self.isDebuggable = isDebuggable
    }
}

/// An X.509 signing certificate pulled from an APK signature block.
public struct SignerCertificate: Hashable, Sendable, Codable {
    public let subject: String
    public let issuer: String
    /// Lowercase hex SHA-256 of the DER certificate.
    public let sha256: String
    public let notValidBefore: Date?
    public let notValidAfter: Date?

    public init(subject: String, issuer: String, sha256: String, notValidBefore: Date? = nil, notValidAfter: Date? = nil) {
        self.subject = subject
        self.issuer = issuer
        self.sha256 = sha256
        self.notValidBefore = notValidBefore
        self.notValidAfter = notValidAfter
    }
}

/// Which APK Signature Schemes were found and verified.
public struct SignatureCheck: Hashable, Sendable, Codable {
    public enum Status: String, Hashable, Sendable, Codable {
        /// The signature verified against the APK contents.
        case verified
        /// A signature exists but does not match the contents (tampered or corrupt).
        case invalid
        /// No signature of any scheme.
        case unsigned
        /// A signature exists but uses something Airlock cannot verify; the certificate is still shown.
        case unverifiable
    }

    public let status: Status
    /// Schemes present, e.g. `[1, 2, 3]`.
    public let schemes: [Int]
    public let certificates: [SignerCertificate]
    public let problem: String?

    public init(status: Status, schemes: [Int], certificates: [SignerCertificate], problem: String? = nil) {
        self.status = status
        self.schemes = schemes
        self.certificates = certificates
        self.problem = problem
    }
}

/// One APK after inspection in the parser helper.
public struct InspectedAPK: Hashable, Sendable, Codable {
    public let fileName: String
    public let sizeBytes: Int64
    /// Lowercase hex SHA-256 of the APK file.
    public let sha256: String
    public let manifest: ApkManifest
    public let signature: SignatureCheck
    /// Native-library ABIs present under `lib/`.
    public let nativeABIs: [String]
    /// Class-name prefixes (`com/facebook/ads/`) found in `classes*.dex` string tables, for tracker matching.
    public let dexClassPrefixes: Set<String>

    public init(
        fileName: String,
        sizeBytes: Int64,
        sha256: String,
        manifest: ApkManifest,
        signature: SignatureCheck,
        nativeABIs: [String] = [],
        dexClassPrefixes: Set<String> = []
    ) {
        self.fileName = fileName
        self.sizeBytes = sizeBytes
        self.sha256 = sha256
        self.manifest = manifest
        self.signature = signature
        self.nativeABIs = nativeABIs
        self.dexClassPrefixes = dexClassPrefixes
    }
}

/// An OBB expansion file to push to `/sdcard/Android/obb/<package>/`.
public struct OBBFile: Hashable, Sendable, Codable {
    public let fileName: String
    public let sizeBytes: Int64
    public let sha256: String
    /// Location in the extracted job folder.
    public let localURL: URL

    public init(fileName: String, sizeBytes: Int64, sha256: String, localURL: URL) {
        self.fileName = fileName
        self.sizeBytes = sizeBytes
        self.sha256 = sha256
        self.localURL = localURL
    }
}

/// A dropped file after safe extraction and inspection; the input to safety checks and install.
public struct InspectedPackage: Hashable, Sendable, Codable {
    public let sourceFile: URL
    public let format: PackageFormat
    /// SHA-256 of the dropped file itself (what VirusTotal is asked about for single APKs).
    public let sourceSHA256: String
    public let base: InspectedAPK
    public let splits: [InspectedAPK]
    public let obbFiles: [OBBFile]
    /// Folder under `~/Library/Caches/Airlock/jobs/<uuid>` holding extracted files.
    public let workDirectory: URL

    public init(
        sourceFile: URL,
        format: PackageFormat,
        sourceSHA256: String,
        base: InspectedAPK,
        splits: [InspectedAPK],
        obbFiles: [OBBFile],
        workDirectory: URL
    ) {
        self.sourceFile = sourceFile
        self.format = format
        self.sourceSHA256 = sourceSHA256
        self.base = base
        self.splits = splits
        self.obbFiles = obbFiles
        self.workDirectory = workDirectory
    }

    public var packageName: String { base.manifest.packageName }
    public var allAPKs: [InspectedAPK] { [base] + splits }
    public var totalSizeBytes: Int64 { allAPKs.reduce(0) { $0 + $1.sizeBytes } + obbFiles.reduce(0) { $0 + $1.sizeBytes } }

    public var splitAPKs: [SplitAPK] {
        splits.map { SplitAPK(fileName: $0.fileName, splitName: $0.manifest.splitName ?? $0.fileName) }
    }
}

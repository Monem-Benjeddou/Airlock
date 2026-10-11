// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation

/// One APK or OBB inside a dropped package.
public struct PackageItem: Hashable, Sendable {
    public enum Location: Hashable, Sendable {
        /// The dropped file itself (a single APK).
        case sourceFile
        /// An entry inside the dropped zip; extract it with ``SafeExtractor``.
        case archiveEntry(ZipEntry)
        /// A file inside a dropped folder.
        case folderFile(URL)
    }

    public let location: Location
    /// Path relative to the container: the entry name, or the file name in a folder.
    public let path: String
    public let fileName: String
    /// Uncompressed size in bytes.
    public let sizeBytes: UInt64

    public var archiveEntry: ZipEntry? {
        if case .archiveEntry(let entry) = location { return entry }
        return nil
    }
}

/// An OBB expansion file and where it belongs on the device, relative to shared storage (`/sdcard`).
public struct OBBItem: Hashable, Sendable {
    public let item: PackageItem
    /// Always `Android/obb/<package>/<file>`; validated never to leave that folder.
    public let installPath: String
    /// The `<package>` folder name under `Android/obb/`.
    public let packageDirectory: String
}

/// What a dropped file or folder contains, worked out from its contents.
///
/// Base and split roles come from file names (and the XAPK manifest when present). The binary-manifest
/// parser confirms them later: a split APK declares `split="…"` in its `AndroidManifest.xml`.
public struct PackageLayout: Hashable, Sendable {
    public let source: URL
    public let format: PackageFormat
    public let base: PackageItem
    public let splits: [PackageItem]
    public let obbFiles: [OBBItem]
    /// APKs that are not part of the install set, such as bundletool `standalones/` next to `splits/`.
    public let alternativeAPKs: [PackageItem]
    public let xapkManifest: XAPKManifest?

    /// The archive entries to extract before install: base, splits and OBBs, in that order.
    public var entriesToExtract: [ZipEntry] {
        ([base] + splits + obbFiles.map(\.item)).compactMap(\.archiveEntry)
    }
}

/// A container as returned by ``FormatDetector``: its layout, plus the open archive for extraction.
public struct DetectedPackage: Sendable {
    public let layout: PackageLayout
    /// The validated archive; `nil` for a folder of split APKs.
    public let archive: ZipArchive?
}

/// The subset of an XAPK `manifest.json` that Airlock uses. Unknown keys are ignored; known keys are typed strictly.
public struct XAPKManifest: Hashable, Sendable, Decodable {
    public struct Split: Hashable, Sendable, Decodable {
        public let file: String
        public let id: String
    }

    public struct Expansion: Hashable, Sendable, Decodable {
        public let file: String
        public let installLocation: String?
        public let installPath: String

        private enum CodingKeys: String, CodingKey {
            case file
            case installLocation = "install_location"
            case installPath = "install_path"
        }
    }

    public let packageName: PackageName
    public let versionCode: Int64
    public let splitAPKs: [Split]
    public let expansions: [Expansion]

    private enum CodingKeys: String, CodingKey {
        case packageName = "package_name"
        case versionCode = "version_code"
        case splitAPKs = "split_apks"
        case expansions
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        packageName = try container.decode(PackageName.self, forKey: .packageName)
        // APKPure writes version_code as a string; other tools as a number.
        if let number = try? container.decode(Int64.self, forKey: .versionCode) {
            versionCode = number
        } else {
            let text = try container.decode(String.self, forKey: .versionCode)
            guard let number = Int64(text) else {
                throw DecodingError.dataCorruptedError(forKey: .versionCode, in: container, debugDescription: "not an integer")
            }
            versionCode = number
        }
        splitAPKs = try container.decodeIfPresent([Split].self, forKey: .splitAPKs) ?? []
        expansions = try container.decodeIfPresent([Expansion].self, forKey: .expansions) ?? []
    }

    static func decode(_ data: Data) throws(ArchiveError) -> XAPKManifest {
        do {
            return try JSONDecoder().decode(XAPKManifest.self, from: data)
        } catch {
            throw .invalidMetadata("manifest.json", reason: Self.reason(for: error))
        }
    }

    private static func reason(for error: any Error) -> String {
        switch error {
        case DecodingError.keyNotFound(let key, _): "missing \(key.stringValue)"
        case DecodingError.typeMismatch(_, let context), DecodingError.dataCorrupted(let context):
            context.codingPath.isEmpty ? context.debugDescription : "bad \(context.codingPath.map(\.stringValue).joined(separator: "."))"
        default: "not valid JSON"
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation

/// Works out what a dropped file or folder is from its contents, never its extension.
///
/// - APK: a zip with `AndroidManifest.xml` at the root.
/// - XAPK: a zip with `manifest.json` and `.apk` entries, optionally `Android/obb/…`.
/// - APKM: a zip with `info.json` and `.apk` entries.
/// - APKS: any other zip of `.apk` entries (bundletool: `toc.pb`, `splits/`, `standalones/`).
/// - Split folder: a directory of `.apk` files.
///
/// Stored APKs inside a container are opened in place and must have a root `AndroidManifest.xml`.
/// Deflated ones cannot be checked without extracting; open them with ``ZipArchive`` after extraction.
public struct FormatDetector: Sendable {
    public let limits: ExtractionLimits

    /// File extensions of containers, which may not appear inside another container.
    private static let containerExtensions: Set<String> = ["apks", "xapk", "apkm", "zip"]

    public init(limits: ExtractionLimits = .default) {
        self.limits = limits
    }

    public func format(at url: URL) throws(ArchiveError) -> PackageFormat {
        try detect(at: url).layout.format
    }

    /// Validates the package at `url` and describes its layout. A symlink to the dropped item itself is followed.
    public func detect(at url: URL) throws(ArchiveError) -> DetectedPackage {
        let resolved = url.resolvingSymlinksInPath()
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: resolved.path, isDirectory: &isDirectory) else {
            throw .unreadable("\(url.lastPathComponent) does not exist")
        }
        if isDirectory.boolValue {
            return DetectedPackage(layout: try folderLayout(resolved), archive: nil)
        }
        let archive = try ZipArchive(contentsOf: resolved, limits: limits)
        return DetectedPackage(layout: try zipLayout(archive, source: resolved), archive: archive)
    }

    // MARK: Zip containers

    private func zipLayout(_ archive: ZipArchive, source: URL) throws(ArchiveError) -> PackageLayout {
        if let manifest = archive.entry(named: "AndroidManifest.xml"), !manifest.isDirectory {
            let item = PackageItem(
                location: .sourceFile, path: source.lastPathComponent, fileName: source.lastPathComponent,
                sizeBytes: archive.archiveSize
            )
            return PackageLayout(
                source: source, format: .apk, base: item, splits: [], obbFiles: [], alternativeAPKs: [], xapkManifest: nil
            )
        }

        let files = archive.entries.filter { !$0.isDirectory }
        if files.contains(where: { Self.containerExtensions.contains(Self.fileExtension($0.fileName)) }) {
            throw .nestingTooDeep(limit: limits.maxNestingDepth)
        }
        let apkEntries = files.filter { Self.fileExtension($0.fileName) == "apk" }
        guard !apkEntries.isEmpty else { throw .noAPKs }
        for entry in apkEntries where entry.method == .stored {
            try verifyInnerAPK(entry, in: archive)
        }

        let xapkManifest = try readXAPKManifest(archive)
        let format: PackageFormat = if xapkManifest != nil {
            .xapk
        } else if archive.entry(named: "info.json") != nil {
            .apkm
        } else {
            .apks
        }

        var candidates = apkEntries.map(Self.item(for:))
        var alternatives: [PackageItem] = []
        // bundletool writes standalone APKs for old devices next to the split set; they are alternatives.
        if candidates.contains(where: { $0.path.hasPrefix("splits/") }) {
            alternatives = candidates.filter { $0.path.hasPrefix("standalones/") }
            candidates.removeAll { $0.path.hasPrefix("standalones/") }
        }
        let baseHint = xapkManifest.map { manifest in
            manifest.splitAPKs.first { $0.id == "base" }?.file ?? "\(manifest.packageName.rawValue).apk"
        }
        let baseIndex = try BaseAPKHeuristic.chooseBase(paths: candidates.map(\.path), hint: baseHint)
        let base = candidates.remove(at: baseIndex)

        return PackageLayout(
            source: source, format: format, base: base, splits: candidates,
            obbFiles: try obbFiles(in: archive, manifest: xapkManifest), alternativeAPKs: alternatives,
            xapkManifest: xapkManifest
        )
    }

    private func verifyInnerAPK(_ entry: ZipEntry, in archive: ZipArchive) throws(ArchiveError) {
        let inner: ZipArchive
        do {
            inner = try archive.openNested(entry)
        } catch .notAnArchive {
            throw .invalidAPK(entry.name)
        }
        guard inner.entry(named: "AndroidManifest.xml") != nil else { throw .invalidAPK(entry.name) }
    }

    private func readXAPKManifest(_ archive: ZipArchive) throws(ArchiveError) -> XAPKManifest? {
        guard let entry = archive.entry(named: "manifest.json"), !entry.isDirectory else { return nil }
        guard entry.uncompressedSize <= limits.maxMetadataBytes else {
            throw .invalidMetadata("manifest.json", reason: "larger than \(limits.maxMetadataBytes) bytes")
        }
        let manifest = try XAPKManifest.decode(archive.data(for: entry, maxBytes: Int(limits.maxMetadataBytes)))
        for split in manifest.splitAPKs where archive.entry(named: split.file) == nil {
            throw .missingEntry(split.file)
        }
        return manifest
    }

    /// OBBs declared by the XAPK manifest, then any other `Android/obb/<package>/<file>.obb` entries.
    private func obbFiles(in archive: ZipArchive, manifest: XAPKManifest?) throws(ArchiveError) -> [OBBItem] {
        var result: [OBBItem] = []
        var seen: Set<String> = []
        for expansion in manifest?.expansions ?? [] {
            guard let entry = archive.entry(named: expansion.file), !entry.isDirectory else {
                throw .missingEntry(expansion.file)
            }
            let packageDirectory = try validateOBBPath(expansion.installPath, packageName: manifest?.packageName.rawValue)
            result.append(OBBItem(item: Self.item(for: entry), installPath: expansion.installPath, packageDirectory: packageDirectory))
            seen.insert(entry.name)
        }
        for entry in archive.entries where !entry.isDirectory && !seen.contains(entry.name) {
            let parts = entry.pathComponents
            guard parts.count == 4, parts[0] == "Android", parts[1] == "obb", Self.fileExtension(parts[3]) == "obb" else {
                continue
            }
            let installPath = parts.joined(separator: "/")
            result.append(OBBItem(item: Self.item(for: entry), installPath: installPath, packageDirectory: parts[2]))
        }
        return result
    }

    /// Accepts only `Android/obb/<package>/<file>`, where `<package>` is the app's own package when known.
    /// Returns the package folder name.
    private func validateOBBPath(_ path: String, packageName: String?) throws(ArchiveError) -> String {
        let components: [String]
        do {
            (_, components) = try EntryName.validate(Array(path.utf8), limits: limits)
        } catch {
            throw .unsafeOBBPath(path)
        }
        guard components.count == 4, components[0] == "Android", components[1] == "obb",
              packageName == nil || components[2] == packageName else {
            throw .unsafeOBBPath(path)
        }
        return components[2]
    }

    // MARK: Folders

    private func folderLayout(_ folder: URL) throws(ArchiveError) -> PackageLayout {
        let names: [String]
        do {
            names = try FileManager.default.contentsOfDirectory(atPath: folder.path).sorted()
        } catch {
            throw .unreadable("cannot list \(folder.lastPathComponent)")
        }
        // `._name.apk` files are AppleDouble metadata that macOS writes on non-Apple volumes.
        let apkNames = names.filter { Self.fileExtension($0) == "apk" && !$0.hasPrefix("._") }
        guard apkNames.count <= limits.maxEntries else {
            throw .tooManyEntries(count: UInt64(apkNames.count), limit: limits.maxEntries)
        }
        var items: [PackageItem] = []
        for name in apkNames {
            let url = folder.appendingPathComponent(name)
            let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
            let type = attributes?[.type] as? FileAttributeType
            if type == .typeSymbolicLink { throw .symlinkEntry(name) }
            guard type == .typeRegular else { continue }
            let archive: ZipArchive
            do {
                archive = try ZipArchive(contentsOf: url, limits: limits)
            } catch .notAnArchive {
                throw .invalidAPK(name)
            }
            guard archive.entry(named: "AndroidManifest.xml") != nil else { throw .invalidAPK(name) }
            items.append(PackageItem(location: .folderFile(url), path: name, fileName: name, sizeBytes: archive.archiveSize))
        }
        guard !items.isEmpty else { throw .noAPKs }
        let baseIndex = try BaseAPKHeuristic.chooseBase(paths: items.map(\.path), hint: nil)
        let base = items.remove(at: baseIndex)
        return PackageLayout(
            source: folder, format: .splitFolder, base: base, splits: items, obbFiles: [], alternativeAPKs: [], xapkManifest: nil
        )
    }

    // MARK: Helpers

    private static func item(for entry: ZipEntry) -> PackageItem {
        PackageItem(location: .archiveEntry(entry), path: entry.name, fileName: entry.fileName, sizeBytes: entry.uncompressedSize)
    }

    private static func fileExtension(_ name: String) -> String {
        guard let dot = name.lastIndex(of: "."), dot != name.startIndex else { return "" }
        return name[name.index(after: dot)...].lowercased()
    }
}

/// Picks the base APK from file names until the manifest parser can confirm it.
enum BaseAPKHeuristic {
    private static let preferredNames: Set<String> = ["base.apk", "base-master.apk"]

    /// Returns the index of the base APK in `paths`.
    static func chooseBase(paths: [String], hint: String?) throws(ArchiveError) -> Int {
        if paths.count == 1 { return 0 }
        if let hint, let index = paths.firstIndex(of: hint) { return index }
        let preferred = paths.indices.filter { preferredNames.contains(fileName(paths[$0]).lowercased()) }
        if preferred.count == 1 { return preferred[0] }
        let candidates = paths.indices.filter { !isSplitLike(paths[$0]) }
        guard let first = candidates.first else { throw .noBaseAPK }
        guard candidates.count == 1 else { throw .ambiguousBaseAPK(candidates.map { paths[$0] }.sorted()) }
        return first
    }

    /// bundletool (`splits/base-xxhdpi.apk`, `splits/feature-master.apk`), APKMirror (`split_config.en.apk`)
    /// and APKPure (`config.arm64_v8a.apk`) naming for non-base APKs.
    static func isSplitLike(_ path: String) -> Bool {
        let name = fileName(path).lowercased()
        if path.hasPrefix("splits/") { return name != "base-master.apk" }
        return name.hasPrefix("split_") || name.hasPrefix("config.") || name.contains(".config.")
    }

    private static func fileName(_ path: String) -> String {
        path.split(separator: "/").last.map(String.init) ?? path
    }
}

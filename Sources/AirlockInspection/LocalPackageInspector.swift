// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockArchive
import AirlockCore
import AirlockSafety
import CryptoKit
import Foundation

/// Turns a dropped file into an ``InspectedPackage`` using only Airlock's own hardened parsers.
///
/// Steps: detect the format by contents, extract into a fresh job folder with zip-slip and zip-bomb
/// protection, then parse each APK's manifest, DEX string tables and signature. Nothing from the file is
/// ever executed. In the app bundle this runs inside the sandboxed parser helper with no network access.
public struct LocalPackageInspector: PackageInspector {
    /// Caps on what is read into memory from a single APK.
    static let maxManifestBytes = 8 * 1024 * 1024
    static let maxDexBytes = 256 * 1024 * 1024
    static let maxSignatureBlockBytes = 1024 * 1024

    private let detector: FormatDetector
    private let extractor: SafeExtractor
    private let verifier = APKSignatureVerifier()

    public init(limits: ExtractionLimits = .default, jobsRoot: URL = SafeExtractor.defaultJobsRoot) {
        detector = FormatDetector(limits: limits)
        extractor = SafeExtractor(jobsRoot: jobsRoot, limits: limits)
    }

    public func inspect(_ file: URL) async throws(InstallError) -> InspectedPackage {
        let detected = try archive { try detector.detect(at: file) }
        let extraction = try archive { try extractor.extract(detected) }
        let job = extraction.job
        do throws(InstallError) {
            return try inspect(detected, extraction: extraction, source: file)
        } catch {
            extractor.removeJob(job)
            throw error
        }
    }

    public func signerDigests(ofAPKAt url: URL) async throws(InstallError) -> [String] {
        verifier.verify(apkAt: url).certificates.map(\.sha256)
    }

    // MARK: Steps

    private func inspect(_ detected: DetectedPackage, extraction: ExtractionResult, source: URL) throws(InstallError) -> InspectedPackage {
        let layout = detected.layout
        let job = extraction.job
        var apks: [InspectedAPK] = []
        for item in [layout.base] + layout.splits {
            let local = try place(item, source: source, extraction: extraction, in: job)
            apks.append(try inspectAPK(at: local))
        }

        // The manifest, not the file name, decides which APK is the base.
        let bases = apks.filter { $0.manifest.splitName == nil }
        guard bases.count == 1, let base = bases.first else {
            throw .unsupportedFile(bases.isEmpty ? "The bundle has no base APK." : "The bundle contains more than one base APK.")
        }
        let splits = apks.filter { $0.manifest.splitName != nil }

        var obbFiles: [OBBFile] = []
        for obb in layout.obbFiles {
            let local = try place(obb.item, source: source, extraction: extraction, in: job)
            obbFiles.append(OBBFile(
                fileName: obb.item.fileName, sizeBytes: try Self.size(of: local), sha256: try Self.sha256(of: local), localURL: local
            ))
        }

        let isDirectory = (try? source.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false
        return InspectedPackage(
            sourceFile: source,
            format: layout.format,
            sourceSHA256: isDirectory ? base.sha256 : try Self.sha256(of: source),
            base: base,
            splits: splits,
            obbFiles: obbFiles,
            workDirectory: job.directory
        )
    }

    /// Returns the item's file inside the job folder, copying it there when it was not extracted.
    private func place(
        _ item: PackageItem, source: URL, extraction: ExtractionResult, in job: ExtractionJob
    ) throws(InstallError) -> URL {
        let original: URL
        switch item.location {
        case .archiveEntry(let entry):
            guard let file = extraction.file(forEntry: entry.name) else { throw .unsafeArchive("Missing extracted entry \(item.path)") }
            original = file.url
        case .sourceFile:
            return try copy(from: source, named: item.fileName, into: job)
        case .folderFile(let url):
            return try copy(from: url, named: item.fileName, into: job)
        }
        // Flatten into the job root under the item's file name, which the install step expects.
        let flat = job.directory.appendingPathComponent(item.fileName)
        if original.standardizedFileURL != flat.standardizedFileURL {
            do {
                if FileManager.default.fileExists(atPath: flat.path) {
                    throw InstallError.unsafeArchive("Duplicate file name \(item.fileName)")
                }
                try FileManager.default.moveItem(at: original, to: flat)
            } catch let error as InstallError {
                throw error
            } catch {
                throw .transport("Could not prepare \(item.fileName): \(error.localizedDescription)")
            }
        }
        return flat
    }

    private func copy(from source: URL, named name: String, into job: ExtractionJob) throws(InstallError) -> URL {
        let destination = job.directory.appendingPathComponent(name)
        guard destination.deletingLastPathComponent().standardizedFileURL == job.directory.standardizedFileURL else {
            throw .unsafeArchive("Unsafe file name \(name)")
        }
        do {
            try FileManager.default.copyItem(at: source, to: destination)
        } catch {
            throw .transport("Could not copy \(name): \(error.localizedDescription)")
        }
        return destination
    }

    private func inspectAPK(at url: URL) throws(InstallError) -> InspectedAPK {
        let apk = try archive { try ZipArchive(contentsOf: url) }
        guard let manifestEntry = apk.entry(named: "AndroidManifest.xml") else {
            throw .unsupportedFile("\(url.lastPathComponent) is not a valid APK: it has no manifest.")
        }
        let manifestData = try archive { try apk.data(for: manifestEntry, maxBytes: Self.maxManifestBytes) }
        let manifest: ApkManifest
        do {
            manifest = try AXMLParser.manifest(from: manifestData)
        } catch {
            throw .unsupportedFile("\(url.lastPathComponent) has a damaged manifest.")
        }

        let dexEntries = apk.entries.filter { $0.isAtRoot && $0.name.hasPrefix("classes") && $0.name.hasSuffix(".dex") }
        var dexFiles: [Data] = []
        for entry in dexEntries { dexFiles.append(try archive { try apk.data(for: entry, maxBytes: Self.maxDexBytes) }) }
        // A DEX that cannot be scanned only means trackers cannot be listed; it is not fatal.
        let prefixes = (try? DexScanner.packagePrefixes(in: dexFiles)) ?? []

        let abis = Set(apk.entries.compactMap { entry -> String? in
            let parts = entry.pathComponents
            return parts.count == 3 && parts[0] == "lib" && parts[2].hasSuffix(".so") ? parts[1] : nil
        })

        let names = apk.entries.map(\.name)
        let jarEntries = JARSignature.signatureEntries(in: names)
        var blocks: [Data] = []
        for jar in jarEntries {
            if let entry = apk.entry(named: jar.signatureBlock) {
                blocks.append(try archive { try apk.data(for: entry, maxBytes: Self.maxSignatureBlockBytes) })
            }
        }
        let evidence = jarEntries.isEmpty ? nil : JARSignatureEvidence(entries: jarEntries, signatureBlocks: blocks)

        return InspectedAPK(
            fileName: url.lastPathComponent,
            sizeBytes: try Self.size(of: url),
            sha256: try Self.sha256(of: url),
            manifest: manifest,
            signature: verifier.verify(apkAt: url, jarSignature: evidence),
            nativeABIs: abis.sorted(),
            dexClassPrefixes: prefixes
        )
    }

    // MARK: Helpers

    static func sha256(of url: URL) throws(InstallError) -> String {
        do {
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            var hasher = SHA256()
            while let chunk = try handle.read(upToCount: 1024 * 1024), !chunk.isEmpty {
                hasher.update(data: chunk)
            }
            return hasher.finalize().map { String(format: "%02x", $0) }.joined()
        } catch {
            throw .transport("Could not read \(url.lastPathComponent).")
        }
    }

    static func size(of url: URL) throws(InstallError) -> Int64 {
        do {
            return (try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.int64Value ?? 0
        } catch {
            throw .transport("Could not read \(url.lastPathComponent).")
        }
    }

    private func archive<T>(_ body: () throws -> T) throws(InstallError) -> T {
        do {
            return try body()
        } catch let error as ArchiveError {
            throw Self.map(error)
        } catch {
            throw .transport(String(describing: error))
        }
    }

    static func map(_ error: ArchiveError) -> InstallError {
        switch error {
        case .cancelled:
            .cancelled
        case .notAnArchive, .noAPKs, .invalidAPK, .noBaseAPK, .ambiguousBaseAPK, .invalidMetadata, .missingEntry, .unreadable,
             .truncated, .malformed, .corruptData, .unsupportedCompression, .encryptedEntry, .fileSystem:
            .unsupportedFile(error.description)
        default:
            .unsafeArchive(error.description)
        }
    }
}

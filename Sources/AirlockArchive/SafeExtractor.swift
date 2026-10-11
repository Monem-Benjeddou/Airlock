// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// A per-install scratch folder, `<jobsRoot>/<uuid>`, readable only by the user.
public struct ExtractionJob: Hashable, Sendable {
    public let id: UUID
    public let directory: URL
}

/// One file written by ``SafeExtractor``.
public struct ExtractedFile: Hashable, Sendable {
    /// The entry's name inside the archive.
    public let entryName: String
    public let url: URL
    public let sizeBytes: UInt64
}

public struct ExtractionResult: Hashable, Sendable {
    public let job: ExtractionJob
    /// Regular files in the order they were requested; directories are created but not listed.
    public let files: [ExtractedFile]

    public func file(forEntry name: String) -> ExtractedFile? {
        files.first { $0.entryName == name }
    }
}

/// Writes selected archive entries into a job folder without ever escaping it.
///
/// Defence in depth on top of ``ZipArchive``'s name validation:
/// - every path is checked to resolve inside the job folder;
/// - directories are walked with `openat`/`mkdirat` and `O_NOFOLLOW`, so a symlink planted in the job
///   folder is never followed;
/// - files are created with `O_CREAT | O_EXCL | O_NOFOLLOW` and mode 0644, never executable;
/// - actual inflated bytes are counted against the limits, whatever the archive declares;
/// - on any failure, including cancellation, the whole job folder is removed.
///
/// Work is synchronous; run it off the main actor. Cancelling the calling task stops it between chunks.
public struct SafeExtractor: Sendable {
    public let jobsRoot: URL
    public let limits: ExtractionLimits

    /// `~/Library/Caches/Airlock/jobs` on macOS (the app container's caches when sandboxed).
    public static var defaultJobsRoot: URL {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        return caches.appendingPathComponent("Airlock", isDirectory: true).appendingPathComponent("jobs", isDirectory: true)
    }

    public init(jobsRoot: URL = SafeExtractor.defaultJobsRoot, limits: ExtractionLimits = .default) {
        self.jobsRoot = jobsRoot
        self.limits = limits
    }

    /// Creates an empty job folder with mode 0700.
    public func makeJob() throws(ArchiveError) -> ExtractionJob {
        do {
            try FileManager.default.createDirectory(
                at: jobsRoot, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw .fileSystem("cannot create jobs folder: \(error.localizedDescription)")
        }
        let id = UUID()
        let directory = jobsRoot.resolvingSymlinksInPath().appendingPathComponent(id.uuidString, isDirectory: true)
        guard mkdir(directory.path, 0o700) == 0 else {
            throw .fileSystem("cannot create job folder: \(String(cString: strerror(errno)))")
        }
        return ExtractionJob(id: id, directory: directory)
    }

    /// Removes a job folder and everything in it. Symlinks inside are deleted, not followed.
    public func removeJob(_ job: ExtractionJob) {
        try? FileManager.default.removeItem(at: job.directory)
    }

    /// Extracts `entries` into a new job folder. On failure the folder is removed and nothing is left behind.
    public func extract(_ entries: [ZipEntry], from archive: ZipArchive) throws(ArchiveError) -> ExtractionResult {
        let job = try makeJob()
        let files = try extract(entries, from: archive, into: job)
        return ExtractionResult(job: job, files: files)
    }

    /// Extracts a detected package's base, splits and OBBs into a new job folder.
    ///
    /// A single APK or a folder of splits needs no extraction: the job is created empty and the files are
    /// used where they are.
    public func extract(_ package: DetectedPackage) throws(ArchiveError) -> ExtractionResult {
        guard let archive = package.archive else { return ExtractionResult(job: try makeJob(), files: []) }
        return try extract(package.layout.entriesToExtract, from: archive)
    }

    /// Extracts `entries` into an existing job folder. On failure the job folder is removed.
    public func extract(
        _ entries: [ZipEntry], from archive: ZipArchive, into job: ExtractionJob
    ) throws(ArchiveError) -> [ExtractedFile] {
        do {
            return try writeEntries(entries, from: archive, into: job)
        } catch {
            removeJob(job)
            throw error
        }
    }

    /// `true` when `components` appended to `directory` still resolve strictly inside it.
    static func isContained(_ components: [String], in directory: URL) -> Bool {
        let root = directory.standardizedFileURL.path
        let target = components.reduce(directory) { $0.appendingPathComponent($1) }.standardizedFileURL.path
        return target.hasPrefix(root.hasSuffix("/") ? root : root + "/")
    }

    // MARK: Writing

    private func writeEntries(
        _ entries: [ZipEntry], from archive: ZipArchive, into job: ExtractionJob
    ) throws(ArchiveError) -> [ExtractedFile] {
        let budget = limits.uncompressedBudget(forArchiveBytes: archive.archiveSize)
        var written: UInt64 = 0
        var files: [ExtractedFile] = []
        let jobDescriptor = try openDirectory(job.directory.path)
        defer { close(jobDescriptor) }

        for entry in entries {
            if Task.isCancelled { throw .cancelled }
            guard archive.entry(named: entry.name) == entry else { throw .missingEntry(entry.name) }
            guard Self.isContained(entry.pathComponents, in: job.directory) else { throw .pathEscapesJob(entry.name) }

            let directories = entry.isDirectory ? entry.pathComponents : Array(entry.pathComponents.dropLast())
            let parent = try makeDirectories(directories, under: jobDescriptor)
            defer { if parent != jobDescriptor { close(parent) } }
            if entry.isDirectory { continue }

            let file = try createFile(named: entry.fileName, in: parent)
            defer { close(file) }
            try archive.stream(entry) { chunk throws(ArchiveError) in
                written += UInt64(chunk.count)
                if written > limits.maxTotalUncompressedBytes {
                    throw .totalSizeLimitExceeded(bytes: written, limit: limits.maxTotalUncompressedBytes)
                }
                if written > budget {
                    throw .totalRatioLimitExceeded(bytes: written, archiveBytes: archive.archiveSize, ratio: limits.maxTotalRatio)
                }
                try Self.writeAll(chunk, to: file, name: entry.name)
            }
            let url = entry.pathComponents.reduce(job.directory) { $0.appendingPathComponent($1) }
            files.append(ExtractedFile(entryName: entry.name, url: url, sizeBytes: entry.uncompressedSize))
        }
        return files
    }

    private func openDirectory(_ path: String) throws(ArchiveError) -> Int32 {
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.posixError("cannot open job folder") }
        return descriptor
    }

    /// Walks (creating as needed) `components` below `root` without following symlinks.
    /// Returns a descriptor for the innermost directory, which is `root` itself when `components` is empty.
    private func makeDirectories(_ components: [String], under root: Int32) throws(ArchiveError) -> Int32 {
        var current = root
        for component in components {
            if mkdirat(current, component, 0o755) != 0, errno != EEXIST {
                let error = Self.posixError("cannot create folder \(component)")
                if current != root { close(current) }
                throw error
            }
            let next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            let error = next < 0 ? Self.posixError("cannot enter folder \(component)") : nil
            if current != root { close(current) }
            if let error { throw error }
            current = next
        }
        return current
    }

    private func createFile(named name: String, in directory: Int32) throws(ArchiveError) -> Int32 {
        let descriptor = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o644))
        guard descriptor >= 0 else { throw Self.posixError("cannot create \(name)") }
        // The umask can only remove bits, but be explicit: never executable, never group/world writable.
        _ = fchmod(descriptor, 0o644)
        return descriptor
    }

    private static func writeAll(_ data: Data, to descriptor: Int32, name: String) throws(ArchiveError) {
        let failed = data.withUnsafeBytes { buffer -> Bool in
            guard let base = buffer.baseAddress else { return false }
            var offset = 0
            while offset < buffer.count {
                let count = write(descriptor, base + offset, buffer.count - offset)
                if count < 0 {
                    if errno == EINTR { continue }
                    return true
                }
                offset += count
            }
            return false
        }
        if failed { throw posixError("cannot write \(name)") }
    }

    private static func posixError(_ context: String) -> ArchiveError {
        .fileSystem("\(context): \(String(cString: strerror(errno)))")
    }
}

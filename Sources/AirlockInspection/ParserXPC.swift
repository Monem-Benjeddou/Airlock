// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockArchive
import AirlockCore
import Foundation

/// The interface of the sandboxed parser helper (an XPC service with no network entitlement).
///
/// The helper cannot open the user's files itself, so the app passes open file handles. Results come
/// back as JSON-encoded ``InspectionReply`` values.
@objc public protocol ParserXPCProtocol {
    /// Inspects one dropped file. `fileName` keeps the original name for display and format hints.
    ///
    /// The reply carries the encoded ``InspectionReply`` and one read handle per extracted file, in the order of
    /// ``InspectionReply/files``, so the app can copy them into a folder it owns.
    func inspect(file: FileHandle, fileName: String, reply: @escaping @Sendable (Data, [FileHandle]) -> Void)
    /// Inspects a dropped folder of split APKs, passed as one handle per `.apk` file. Replies like ``inspect``.
    func inspectFolder(
        files: [FileHandle], fileNames: [String], folderName: String, reply: @escaping @Sendable (Data, [FileHandle]) -> Void
    )
    func signerDigests(file: FileHandle, reply: @escaping @Sendable (Data) -> Void)
}

public enum ParserXPCInterface {
    /// The interface with the collection classes XPC must allow for the array arguments.
    public static func make() -> NSXPCInterface {
        let interface = NSXPCInterface(with: (any ParserXPCProtocol).self)
        let handles = classes(NSArray.self, FileHandle.self)
        let folder = #selector((any ParserXPCProtocol).inspectFolder(files:fileNames:folderName:reply:))
        interface.setClasses(handles, for: folder, argumentIndex: 0, ofReply: false)
        interface.setClasses(classes(NSArray.self, NSString.self), for: folder, argumentIndex: 1, ofReply: false)
        interface.setClasses(handles, for: folder, argumentIndex: 1, ofReply: true)
        let file = #selector((any ParserXPCProtocol).inspect(file:fileName:reply:))
        interface.setClasses(handles, for: file, argumentIndex: 1, ofReply: true)
        return interface
    }

    /// Bridges class objects into the `Set<AnyHashable>` that `setClasses` expects.
    private static func classes(_ types: AnyClass...) -> Set<AnyHashable> {
        (NSSet(array: types) as? Set<AnyHashable>) ?? []
    }
}

/// What the helper sends back; exactly one of the fields is set.
public struct InspectionReply: Codable, Sendable {
    public var package: InspectedPackage?
    /// Paths of the extracted files relative to the package's work folder, matching the reply's file handles.
    public var files: [String]?
    public var digests: [String]?
    public var error: WireError?

    public init(package: InspectedPackage? = nil, files: [String]? = nil, digests: [String]? = nil, error: WireError? = nil) {
        self.package = package
        self.files = files
        self.digests = digests
        self.error = error
    }
}

/// ``InstallError`` cases the helper can produce, in a Codable form.
public enum WireError: Codable, Sendable, Equatable {
    case unsupportedFile(String)
    case unsafeArchive(String)
    case cancelled
    case other(String)

    public init(_ error: InstallError) {
        switch error {
        case .unsupportedFile(let message): self = .unsupportedFile(message)
        case .unsafeArchive(let message): self = .unsafeArchive(message)
        case .cancelled: self = .cancelled
        default: self = .other(String(describing: error))
        }
    }

    public var installError: InstallError {
        switch self {
        case .unsupportedFile(let message): .unsupportedFile(message)
        case .unsafeArchive(let message): .unsafeArchive(message)
        case .cancelled: .cancelled
        case .other(let message): .transport(message)
        }
    }
}

/// Runs inside the helper: copies the handed-over files into its own container, inspects them there, and hands
/// the extracted files back as open handles before deleting its copies.
public final class ParserXPCService: NSObject, ParserXPCProtocol, @unchecked Sendable {
    private let inspector: LocalPackageInspector
    private let incoming: URL

    /// - Parameter container: the helper's writable folder (its sandbox container's caches).
    public init(container: URL) {
        incoming = container.appendingPathComponent("Incoming", isDirectory: true)
        inspector = LocalPackageInspector(jobsRoot: container.appendingPathComponent("Airlock/jobs", isDirectory: true))
    }

    public func inspect(file: FileHandle, fileName: String, reply: @escaping @Sendable (Data, [FileHandle]) -> Void) {
        let inspector = inspector
        let target = incoming.appendingPathComponent(UUID().uuidString, isDirectory: true)
        Task {
            await Self.handOver(reply) {
                let local = try Self.receive(file, as: fileName, into: target)
                defer { try? FileManager.default.removeItem(at: target) }
                return try await inspector.inspect(local)
            }
        }
    }

    public func inspectFolder(
        files: [FileHandle], fileNames: [String], folderName: String, reply: @escaping @Sendable (Data, [FileHandle]) -> Void
    ) {
        let inspector = inspector
        let target = incoming.appendingPathComponent(UUID().uuidString, isDirectory: true)
        Task {
            await Self.handOver(reply) {
                guard files.count == fileNames.count else { throw InstallError.unsupportedFile("The folder could not be read.") }
                let folder = target.appendingPathComponent(Self.safeName(folderName), isDirectory: true)
                defer { try? FileManager.default.removeItem(at: target) }
                for (handle, name) in zip(files, fileNames) { _ = try Self.receive(handle, as: name, into: folder) }
                return try await inspector.inspect(folder)
            }
        }
    }

    /// Replies with the package and a read handle per extracted file, then deletes the helper's job folder.
    /// The app's handles stay valid after the delete because open descriptors outlive the path.
    private static func handOver(
        _ reply: @Sendable (Data, [FileHandle]) -> Void, _ work: () async throws -> InspectedPackage
    ) async {
        var jobFolder: URL?
        defer { if let jobFolder { try? FileManager.default.removeItem(at: jobFolder) } }
        let data = await run {
            let package = try await work()
            jobFolder = package.workDirectory
            let files = try regularFiles(under: package.workDirectory)
            let handles = try files.map { try FileHandle(forReadingFrom: package.workDirectory.appendingPathComponent($0)) }
            return (InspectionReply(package: package, files: files), handles)
        }
        reply(data.0, data.1)
    }

    /// Relative paths of the regular files below `root`, sorted.
    static func regularFiles(under root: URL) throws -> [String] {
        let base = root.resolvingSymlinksInPath().pathComponents
        let keys: [URLResourceKey] = [.isRegularFileKey]
        guard let walker = FileManager.default.enumerator(at: root, includingPropertiesForKeys: keys) else { return [] }
        var files: [String] = []
        for case let url as URL in walker where try url.resourceValues(forKeys: Set(keys)).isRegularFile == true {
            let components = url.resolvingSymlinksInPath().pathComponents
            guard components.starts(with: base) else { continue }
            files.append(components.dropFirst(base.count).joined(separator: "/"))
        }
        return files.sorted()
    }

    public func signerDigests(file: FileHandle, reply: @escaping @Sendable (Data) -> Void) {
        let inspector = inspector
        let target = incoming.appendingPathComponent(UUID().uuidString, isDirectory: true)
        Task {
            reply(await Self.run {
                let local = try Self.receive(file, as: "installed.apk", into: target)
                defer { try? FileManager.default.removeItem(at: target) }
                return (InspectionReply(digests: try await inspector.signerDigests(ofAPKAt: local)), [])
            }.0)
        }
    }

    private static func run(_ work: () async throws -> (InspectionReply, [FileHandle])) async -> (Data, [FileHandle]) {
        let reply: InspectionReply
        var handles: [FileHandle] = []
        do {
            (reply, handles) = try await work()
        } catch let error as InstallError {
            reply = InspectionReply(error: WireError(error))
        } catch {
            reply = InspectionReply(error: .other(error.localizedDescription))
        }
        return ((try? JSONEncoder().encode(reply)) ?? Data(), handles)
    }

    /// Streams a handle to `folder/<sanitised name>` without loading it into memory.
    static func receive(_ handle: FileHandle, as name: String, into folder: URL) throws -> URL {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let destination = folder.appendingPathComponent(safeName(name))
        guard FileManager.default.createFile(atPath: destination.path, contents: nil) else {
            throw InstallError.transport("Could not receive \(name).")
        }
        let output = try FileHandle(forWritingTo: destination)
        defer { try? output.close() }
        try handle.seek(toOffset: 0)
        while let chunk = try handle.read(upToCount: 1024 * 1024), !chunk.isEmpty {
            try output.write(contentsOf: chunk)
        }
        return destination
    }

    /// The last path component with anything unusual replaced, so a name can never escape `folder`.
    static func safeName(_ name: String) -> String {
        let last = (name as NSString).lastPathComponent
        let cleaned = String(last.map { $0.isLetter || $0.isNumber || "._-".contains($0) ? $0 : "_" })
        return cleaned.isEmpty || cleaned == "." || cleaned == ".." ? "file" : String(cleaned.prefix(200))
    }
}

/// App side: a ``PackageInspector`` that runs every parse in the sandboxed helper.
///
/// If the helper crashes or hangs, the install fails with a message; the app keeps running. Extracted files are
/// copied out of the helper into a job folder the app owns; the helper's file list is treated as untrusted.
public final class XPCPackageInspector: PackageInspector, @unchecked Sendable {
    /// More files than any real bundle has; a longer list means the helper misbehaves.
    static let maximumFiles = 512

    private let makeConnection: @Sendable () -> NSXPCConnection
    private let timeout: Duration
    private let jobsRoot: URL
    private let lock = NSLock()
    private var connection: NSXPCConnection?

    public convenience init(
        serviceName: String = "dev.airlock.Airlock.Parser",
        timeout: Duration = .seconds(300),
        jobsRoot: URL = SafeExtractor.defaultJobsRoot
    ) {
        self.init(timeout: timeout, jobsRoot: jobsRoot) { NSXPCConnection(serviceName: serviceName) }
    }

    /// For tests: connect to any endpoint, e.g. an in-process anonymous listener.
    public init(timeout: Duration, jobsRoot: URL, makeConnection: @escaping @Sendable () -> NSXPCConnection) {
        self.makeConnection = makeConnection
        self.timeout = timeout
        self.jobsRoot = jobsRoot
    }

    public func inspect(_ file: URL) async throws(InstallError) -> InspectedPackage {
        let isDirectory = (try? file.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false
        let delivery: Delivery
        if isDirectory {
            let apks = ((try? FileManager.default.contentsOfDirectory(at: file, includingPropertiesForKeys: nil)) ?? [])
                .filter { $0.pathExtension.lowercased() == "apk" }
                .sorted { $0.lastPathComponent < $1.lastPathComponent }
            let handles = try apks.map { url throws(InstallError) in try Self.open(url) }
            delivery = try await call { proxy, done in
                let names = apks.map(\.lastPathComponent)
                proxy.inspectFolder(files: handles, fileNames: names, folderName: file.lastPathComponent) { done(Delivery($0, $1)) }
            }
        } else {
            let handle = try Self.open(file)
            delivery = try await call { proxy, done in
                proxy.inspect(file: handle, fileName: file.lastPathComponent) { done(Delivery($0, $1)) }
            }
        }
        let reply = try Self.decode(delivery.data)
        if let error = reply.error { throw error.installError }
        guard let package = reply.package else { throw .transport("The parser returned no result.") }
        return try adopt(package, from: file, files: reply.files ?? [], handles: delivery.handles)
    }

    public func signerDigests(ofAPKAt url: URL) async throws(InstallError) -> [String] {
        let handle = try Self.open(url)
        let delivery = try await call { proxy, done in proxy.signerDigests(file: handle) { done(Delivery($0, [])) } }
        let reply = try Self.decode(delivery.data)
        if let error = reply.error { throw error.installError }
        return reply.digests ?? []
    }

    /// Copies the helper's files into a new job folder of the app's and points the package at it.
    /// Reports the user's original file, not the helper's private copy.
    private func adopt(
        _ package: InspectedPackage, from source: URL, files: [String], handles: [FileHandle]
    ) throws(InstallError) -> InspectedPackage {
        let broken = InstallError.transport("The parser helper sent an inconsistent reply. The file may be malformed.")
        guard files.count == handles.count, files.count <= Self.maximumFiles, Set(files).count == files.count else {
            throw broken
        }
        let job = jobsRoot.appendingPathComponent(UUID().uuidString, isDirectory: true)
        do {
            for (path, handle) in zip(files, handles) {
                guard let destination = Self.destination(of: path, in: job) else { throw broken }
                _ = try ParserXPCService.receive(handle, as: destination.lastPathComponent,
                                                 into: destination.deletingLastPathComponent())
            }
            let delivered = Set(files)
            guard package.allAPKs.allSatisfy({ delivered.contains($0.fileName) }) else { throw broken }
            let obbFiles = try package.obbFiles.map { obb in
                let prefix = package.workDirectory.path + "/"
                let path = obb.localURL.path
                guard path.hasPrefix(prefix), delivered.contains(String(path.dropFirst(prefix.count))),
                      let local = Self.destination(of: String(path.dropFirst(prefix.count)), in: job)
                else { throw broken }
                return OBBFile(fileName: obb.fileName, sizeBytes: obb.sizeBytes, sha256: obb.sha256, localURL: local)
            }
            return InspectedPackage(
                sourceFile: source, format: package.format, sourceSHA256: package.sourceSHA256, base: package.base,
                splits: package.splits, obbFiles: obbFiles, workDirectory: job
            )
        } catch {
            try? FileManager.default.removeItem(at: job)
            throw (error as? InstallError) ?? .transport("Airlock could not copy the unpacked files: \(error.localizedDescription)")
        }
    }

    /// `job/path` if `path` is a plain relative path of ordinary names, otherwise nil.
    static func destination(of path: String, in job: URL) -> URL? {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !path.hasPrefix("/"), (1...8).contains(parts.count),
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && ParserXPCService.safeName($0) == $0 })
        else { return nil }
        return parts.reduce(job) { $0.appendingPathComponent($1) }
    }

    private static func decode(_ data: Data) throws(InstallError) -> InspectionReply {
        guard let reply = try? JSONDecoder().decode(InspectionReply.self, from: data) else {
            throw .transport("The parser helper sent an unreadable reply.")
        }
        return reply
    }

    private static func open(_ url: URL) throws(InstallError) -> FileHandle {
        do {
            return try FileHandle(forReadingFrom: url)
        } catch {
            throw .unsupportedFile("Airlock could not open \(url.lastPathComponent).")
        }
    }

    private func call(
        _ body: @escaping @Sendable (any ParserXPCProtocol, @escaping @Sendable (Delivery) -> Void) -> Void
    ) async throws(InstallError) -> Delivery {
        let connection = ConnectionBox(value: currentConnection())
        do {
            return try await withThrowingTaskGroup(of: Delivery.self) { group in
                group.addTask {
                    let once = Once()
                    // The continuation must resume on cancellation too, or the group would wait forever
                    // for a helper that never answers.
                    return try await withTaskCancellationHandler {
                        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Delivery, any Error>) in
                            once.install(continuation)
                            let proxy = connection.value.remoteObjectProxyWithErrorHandler { error in once.fail(error) }
                            guard let parser = proxy as? any ParserXPCProtocol else {
                                once.fail(InstallError.transport("The parser helper is unavailable."))
                                return
                            }
                            body(parser) { once.succeed($0) }
                        }
                    } onCancel: {
                        once.fail(CancellationError())
                    }
                }
                group.addTask { [timeout] in
                    try await Task.sleep(for: timeout)
                    throw InstallError.transport("The parser helper did not respond in time.")
                }
                let first = try await group.next() ?? Delivery(Data(), [])
                group.cancelAll()
                return first
            }
        } catch let error as InstallError {
            resetConnection()
            throw error
        } catch is CancellationError {
            throw .cancelled
        } catch {
            resetConnection()
            throw .transport("The parser helper stopped unexpectedly. The file may be malformed.")
        }
    }

    private func currentConnection() -> NSXPCConnection {
        lock.withLock {
            if let connection { return connection }
            let created = makeConnection()
            created.remoteObjectInterface = ParserXPCInterface.make()
            created.invalidationHandler = { [weak self] in self?.resetConnection() }
            created.resume()
            connection = created
            return created
        }
    }

    private func resetConnection() {
        lock.withLock {
            connection?.invalidate()
            connection = nil
        }
    }
}

/// One reply from the helper: the encoded ``InspectionReply`` plus any file handles that came with it.
private struct Delivery: @unchecked Sendable {
    let data: Data
    let handles: [FileHandle]
    init(_ data: Data, _ handles: [FileHandle]) {
        self.data = data
        self.handles = handles
    }
}

/// `NSXPCConnection` is documented as thread-safe but not annotated `Sendable`.
private struct ConnectionBox: @unchecked Sendable {
    let value: NSXPCConnection
}

/// Resumes a continuation exactly once, whichever of reply or error handler fires first.
private final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Delivery, any Error>?
    /// A failure that arrived before the continuation was installed (cancellation can come first).
    private var earlyFailure: (any Error)?
    private var finished = false

    func install(_ continuation: CheckedContinuation<Delivery, any Error>) {
        let early: (any Error)? = lock.withLock {
            if let earlyFailure {
                finished = true
                return earlyFailure
            }
            self.continuation = continuation
            return nil
        }
        if let early { continuation.resume(throwing: early) }
    }

    func succeed(_ delivery: Delivery) { take()?.resume(returning: delivery) }

    func fail(_ error: any Error) {
        let pending: CheckedContinuation<Delivery, any Error>? = lock.withLock {
            guard !finished else { return nil }
            guard let continuation else {
                earlyFailure = error
                return nil
            }
            finished = true
            self.continuation = nil
            return continuation
        }
        pending?.resume(throwing: error)
    }

    private func take() -> CheckedContinuation<Delivery, any Error>? {
        lock.withLock {
            guard !finished, let continuation else { return nil }
            finished = true
            self.continuation = nil
            return continuation
        }
    }
}

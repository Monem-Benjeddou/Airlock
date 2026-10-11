// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation

/// The interface of the sandboxed parser helper (an XPC service with no network entitlement).
///
/// The helper cannot open the user's files itself, so the app passes open file handles. Results come
/// back as JSON-encoded ``InspectionReply`` values.
@objc public protocol ParserXPCProtocol {
    /// Inspects one dropped file. `fileName` keeps the original name for display and format hints.
    func inspect(file: FileHandle, fileName: String, reply: @escaping @Sendable (Data) -> Void)
    /// Inspects a dropped folder of split APKs, passed as one handle per `.apk` file.
    func inspectFolder(files: [FileHandle], fileNames: [String], folderName: String, reply: @escaping @Sendable (Data) -> Void)
    func signerDigests(file: FileHandle, reply: @escaping @Sendable (Data) -> Void)
}

public enum ParserXPCInterface {
    /// The interface with the collection classes XPC must allow for the folder call.
    public static func make() -> NSXPCInterface {
        let interface = NSXPCInterface(with: (any ParserXPCProtocol).self)
        let selector = #selector((any ParserXPCProtocol).inspectFolder(files:fileNames:folderName:reply:))
        interface.setClasses(classes(NSArray.self, FileHandle.self), for: selector, argumentIndex: 0, ofReply: false)
        interface.setClasses(classes(NSArray.self, NSString.self), for: selector, argumentIndex: 1, ofReply: false)
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
    public var digests: [String]?
    public var error: WireError?

    public init(package: InspectedPackage? = nil, digests: [String]? = nil, error: WireError? = nil) {
        self.package = package
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

/// Runs inside the helper: copies the handed-over files into its own container and inspects them there.
public final class ParserXPCService: NSObject, ParserXPCProtocol, @unchecked Sendable {
    private let inspector: LocalPackageInspector
    private let incoming: URL

    /// - Parameter container: the helper's writable folder (its sandbox container's caches).
    public init(container: URL) {
        incoming = container.appendingPathComponent("Incoming", isDirectory: true)
        inspector = LocalPackageInspector(jobsRoot: container.appendingPathComponent("Airlock/jobs", isDirectory: true))
    }

    public func inspect(file: FileHandle, fileName: String, reply: @escaping @Sendable (Data) -> Void) {
        let inspector = inspector
        let target = incoming.appendingPathComponent(UUID().uuidString, isDirectory: true)
        Task {
            reply(await Self.run {
                let local = try Self.receive(file, as: fileName, into: target)
                defer { try? FileManager.default.removeItem(at: target) }
                return InspectionReply(package: try await inspector.inspect(local))
            })
        }
    }

    public func inspectFolder(files: [FileHandle], fileNames: [String], folderName: String, reply: @escaping @Sendable (Data) -> Void) {
        let inspector = inspector
        let target = incoming.appendingPathComponent(UUID().uuidString, isDirectory: true)
        Task {
            reply(await Self.run {
                guard files.count == fileNames.count else { throw InstallError.unsupportedFile("The folder could not be read.") }
                let folder = target.appendingPathComponent(Self.safeName(folderName), isDirectory: true)
                for (handle, name) in zip(files, fileNames) { _ = try Self.receive(handle, as: name, into: folder) }
                defer { try? FileManager.default.removeItem(at: target) }
                return InspectionReply(package: try await inspector.inspect(folder))
            })
        }
    }

    public func signerDigests(file: FileHandle, reply: @escaping @Sendable (Data) -> Void) {
        let inspector = inspector
        let target = incoming.appendingPathComponent(UUID().uuidString, isDirectory: true)
        Task {
            reply(await Self.run {
                let local = try Self.receive(file, as: "installed.apk", into: target)
                defer { try? FileManager.default.removeItem(at: target) }
                return InspectionReply(digests: try await inspector.signerDigests(ofAPKAt: local))
            })
        }
    }

    private static func run(_ work: () async throws -> InspectionReply) async -> Data {
        let reply: InspectionReply
        do {
            reply = try await work()
        } catch let error as InstallError {
            reply = InspectionReply(error: WireError(error))
        } catch {
            reply = InspectionReply(error: .other(error.localizedDescription))
        }
        return (try? JSONEncoder().encode(reply)) ?? Data()
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
/// If the helper crashes or hangs, the install fails with a message; the app keeps running.
public final class XPCPackageInspector: PackageInspector, @unchecked Sendable {
    private let makeConnection: @Sendable () -> NSXPCConnection
    private let timeout: Duration
    private let lock = NSLock()
    private var connection: NSXPCConnection?

    public convenience init(serviceName: String = "dev.airlock.Airlock.Parser", timeout: Duration = .seconds(300)) {
        self.init(timeout: timeout) { NSXPCConnection(serviceName: serviceName) }
    }

    /// For tests: connect to any endpoint, e.g. an in-process anonymous listener.
    public init(timeout: Duration, makeConnection: @escaping @Sendable () -> NSXPCConnection) {
        self.makeConnection = makeConnection
        self.timeout = timeout
    }

    public func inspect(_ file: URL) async throws(InstallError) -> InspectedPackage {
        let isDirectory = (try? file.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false
        let reply: InspectionReply
        if isDirectory {
            let apks = ((try? FileManager.default.contentsOfDirectory(at: file, includingPropertiesForKeys: nil)) ?? [])
                .filter { $0.pathExtension.lowercased() == "apk" }
                .sorted { $0.lastPathComponent < $1.lastPathComponent }
            let handles = try apks.map { url throws(InstallError) in try Self.open(url) }
            reply = try await call { proxy, done in
                let names = apks.map(\.lastPathComponent)
                proxy.inspectFolder(files: handles, fileNames: names, folderName: file.lastPathComponent, reply: done)
            }
        } else {
            let handle = try Self.open(file)
            reply = try await call { proxy, done in proxy.inspect(file: handle, fileName: file.lastPathComponent, reply: done) }
        }
        if let error = reply.error { throw error.installError }
        guard let package = reply.package else { throw .transport("The parser returned no result.") }
        // Report the user's original file, not the helper's private copy.
        return InspectedPackage(
            sourceFile: file, format: package.format, sourceSHA256: package.sourceSHA256, base: package.base,
            splits: package.splits, obbFiles: package.obbFiles, workDirectory: package.workDirectory
        )
    }

    public func signerDigests(ofAPKAt url: URL) async throws(InstallError) -> [String] {
        let handle = try Self.open(url)
        let reply = try await call { proxy, done in proxy.signerDigests(file: handle, reply: done) }
        if let error = reply.error { throw error.installError }
        return reply.digests ?? []
    }

    private static func open(_ url: URL) throws(InstallError) -> FileHandle {
        do {
            return try FileHandle(forReadingFrom: url)
        } catch {
            throw .unsupportedFile("Airlock could not open \(url.lastPathComponent).")
        }
    }

    private func call(
        _ body: @escaping @Sendable (any ParserXPCProtocol, @escaping @Sendable (Data) -> Void) -> Void
    ) async throws(InstallError) -> InspectionReply {
        let connection = ConnectionBox(value: currentConnection())
        let data: Data
        do {
            data = try await withThrowingTaskGroup(of: Data.self) { group in
                group.addTask {
                    let once = Once()
                    // The continuation must resume on cancellation too, or the group would wait forever
                    // for a helper that never answers.
                    return try await withTaskCancellationHandler {
                        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, any Error>) in
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
                let first = try await group.next() ?? Data()
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
        guard let reply = try? JSONDecoder().decode(InspectionReply.self, from: data) else {
            throw .transport("The parser helper sent an unreadable reply.")
        }
        return reply
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

/// `NSXPCConnection` is documented as thread-safe but not annotated `Sendable`.
private struct ConnectionBox: @unchecked Sendable {
    let value: NSXPCConnection
}

/// Resumes a continuation exactly once, whichever of reply or error handler fires first.
private final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, any Error>?
    /// A failure that arrived before the continuation was installed (cancellation can come first).
    private var earlyFailure: (any Error)?
    private var finished = false

    func install(_ continuation: CheckedContinuation<Data, any Error>) {
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

    func succeed(_ data: Data) { take()?.resume(returning: data) }

    func fail(_ error: any Error) {
        let pending: CheckedContinuation<Data, any Error>? = lock.withLock {
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

    private func take() -> CheckedContinuation<Data, any Error>? {
        lock.withLock {
            guard !finished, let continuation else { return nil }
            finished = true
            self.continuation = nil
            return continuation
        }
    }
}

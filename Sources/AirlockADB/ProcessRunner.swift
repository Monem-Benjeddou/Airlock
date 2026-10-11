// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// A process to launch. Arguments are passed to `execve` as-is; no shell ever sees them.
public struct ProcessRequest: Sendable, Hashable {
    public let executable: URL
    public let arguments: [String]
    /// Full environment for the child. `nil` inherits the parent's environment.
    public let environment: [String: String]?
    public let timeout: Duration
    public let standardInput: Data?

    public init(
        executable: URL,
        arguments: [String],
        environment: [String: String]? = nil,
        timeout: Duration,
        standardInput: Data? = nil
    ) {
        self.executable = executable
        self.arguments = arguments
        self.environment = environment
        self.timeout = timeout
        self.standardInput = standardInput
    }
}

public struct ProcessResult: Sendable, Hashable {
    public let exitCode: Int32
    public let stdout: Data
    public let stderr: Data

    public init(exitCode: Int32, stdout: Data, stderr: Data) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }

    public var stdoutText: String { String(decoding: stdout, as: UTF8.self) }
    public var stderrText: String { String(decoding: stderr, as: UTF8.self) }
}

public enum ProcessEvent: Sendable, Hashable {
    case stdout(Data)
    case stderr(Data)
    /// Always the last event of a stream that was not cancelled, timed out or failed.
    case exited(Int32)
}

public enum ProcessError: Error, Hashable, Sendable {
    case launchFailed(String)
    case timedOut(after: Duration)
    case cancelled
    case outputTooLarge(limit: Int)
}

public protocol ProcessRunning: Sendable {
    /// Runs to completion and collects output. Task cancellation terminates the process.
    func run(_ request: ProcessRequest) async throws(ProcessError) -> ProcessResult
    /// Streams output as it arrives. Ending iteration early terminates the process.
    func stream(_ request: ProcessRequest) -> AsyncThrowingStream<ProcessEvent, any Error>
}

/// Runs real processes with `Foundation.Process`: argument arrays, timeouts, cancellation, output caps.
public struct SystemProcessRunner: ProcessRunning {
    /// Combined stdout + stderr cap; adb output beyond this is a bug or an attack.
    public let maxOutputBytes: Int

    public init(maxOutputBytes: Int = 64 * 1024 * 1024) {
        self.maxOutputBytes = maxOutputBytes
        // A child that exits before reading stdin must not kill us with SIGPIPE.
        signal(SIGPIPE, SIG_IGN)
    }

    public func run(_ request: ProcessRequest) async throws(ProcessError) -> ProcessResult {
        if Task.isCancelled { throw .cancelled }
        var stdout = Data()
        var stderr = Data()
        var exitCode: Int32?
        do {
            for try await event in stream(request) {
                switch event {
                case .stdout(let chunk): stdout.append(chunk)
                case .stderr(let chunk): stderr.append(chunk)
                case .exited(let code): exitCode = code
                }
            }
        } catch let error as ProcessError {
            throw error
        } catch {
            throw .launchFailed(String(describing: error))
        }
        guard let exitCode, !Task.isCancelled else { throw .cancelled }
        return ProcessResult(exitCode: exitCode, stdout: stdout, stderr: stderr)
    }

    public func stream(_ request: ProcessRequest) -> AsyncThrowingStream<ProcessEvent, any Error> {
        AsyncThrowingStream { continuation in
            let execution = ProcessExecution(request: request, maxOutputBytes: maxOutputBytes, continuation: continuation)
            continuation.onTermination = { termination in
                if case .cancelled = termination { execution.cancel() }
            }
            execution.start()
        }
    }
}

/// One running child process. All mutable state is guarded by `lock`.
private final class ProcessExecution: @unchecked Sendable {
    private let request: ProcessRequest
    private let maxOutputBytes: Int
    private let continuation: AsyncThrowingStream<ProcessEvent, any Error>.Continuation
    private let process = Process()
    private let stdoutPipe = Pipe()
    private let stderrPipe = Pipe()
    private let stdinPipe = Pipe()
    private let finished = DispatchGroup()

    private let lock = NSLock()
    private var outputBytes = 0
    private var failure: ProcessError?
    private var isDone = false

    init(
        request: ProcessRequest,
        maxOutputBytes: Int,
        continuation: AsyncThrowingStream<ProcessEvent, any Error>.Continuation
    ) {
        self.request = request
        self.maxOutputBytes = maxOutputBytes
        self.continuation = continuation
    }

    func start() {
        process.executableURL = request.executable
        process.arguments = request.arguments
        if let environment = request.environment { process.environment = environment }
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        process.standardInput = request.standardInput == nil ? FileHandle.nullDevice : stdinPipe

        finished.enter()
        finished.enter()
        finished.enter()
        attach(stdoutPipe.fileHandleForReading, wrap: ProcessEvent.stdout)
        attach(stderrPipe.fileHandleForReading, wrap: ProcessEvent.stderr)
        process.terminationHandler = { [finished] _ in finished.leave() }

        do {
            try process.run()
        } catch {
            stdoutPipe.fileHandleForReading.readabilityHandler = nil
            stderrPipe.fileHandleForReading.readabilityHandler = nil
            finish(with: .launchFailed(error.localizedDescription))
            return
        }

        if let input = request.standardInput { feed(input) }
        scheduleTimeout()
        finished.notify(queue: .global()) { [self] in
            let code = process.terminationStatus
            lock.lock()
            let failure = failure
            lock.unlock()
            if let failure {
                finish(with: failure)
            } else {
                continuation.yield(.exited(code))
                finish(with: nil)
            }
        }
    }

    func cancel() {
        fail(.cancelled)
    }

    private func attach(_ handle: FileHandle, wrap: @escaping @Sendable (Data) -> ProcessEvent) {
        handle.readabilityHandler = { [self] handle in
            let chunk = handle.availableData
            if chunk.isEmpty {
                handle.readabilityHandler = nil
                finished.leave()
                return
            }
            lock.lock()
            outputBytes += chunk.count
            let overLimit = outputBytes > maxOutputBytes
            lock.unlock()
            if overLimit {
                fail(.outputTooLarge(limit: maxOutputBytes))
            } else {
                continuation.yield(wrap(chunk))
            }
        }
    }

    private func feed(_ input: Data) {
        let writer = stdinPipe.fileHandleForWriting
        DispatchQueue.global().async {
            // EPIPE (child exited early) surfaces as a thrown error because SIGPIPE is ignored.
            try? writer.write(contentsOf: input)
            try? writer.close()
        }
    }

    private func scheduleTimeout() {
        let nanoseconds = request.timeout.components.seconds * 1_000_000_000
            + request.timeout.components.attoseconds / 1_000_000_000
        DispatchQueue.global().asyncAfter(deadline: .now() + .nanoseconds(Int(nanoseconds))) { [self] in
            fail(.timedOut(after: request.timeout))
        }
    }

    /// Records the first failure and terminates the child: SIGTERM, then SIGKILL after a grace period.
    private func fail(_ error: ProcessError) {
        lock.lock()
        guard failure == nil, !isDone else {
            lock.unlock()
            return
        }
        failure = error
        lock.unlock()

        guard process.isRunning else { return }
        let pid = process.processIdentifier
        process.terminate()
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) { [process] in
            if process.isRunning { kill(pid, SIGKILL) }
        }
    }

    private func finish(with error: ProcessError?) {
        lock.lock()
        guard !isDone else {
            lock.unlock()
            return
        }
        isDone = true
        lock.unlock()
        if let error {
            continuation.finish(throwing: error)
        } else {
            continuation.finish()
        }
    }
}

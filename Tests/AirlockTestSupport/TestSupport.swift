// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockADB
import AirlockCore
import Foundation

/// Locates recorded fixtures copied into the test-support bundle.
public enum Fixture {
    /// Devices with recorded adb output under `Fixtures/adb/<name>/`.
    public static let recordedDevices = ["samsung-s24ultra-android16", "google-emulator-android15"]

    public static func url(_ relativePath: String) -> URL {
        guard let root = Bundle.module.url(forResource: "Fixtures", withExtension: nil) else {
            preconditionFailure("Fixtures folder missing from AirlockTestSupport bundle")
        }
        return root.appendingPathComponent(relativePath)
    }

    public static func data(_ relativePath: String) -> Data {
        do {
            return try Data(contentsOf: url(relativePath))
        } catch {
            preconditionFailure("Missing fixture \(relativePath): \(error)")
        }
    }

    public static func text(_ relativePath: String) -> String {
        String(decoding: data(relativePath), as: UTF8.self)
    }

    /// Recorded output of one adb command on one device, e.g. `adb("samsung-s24ultra-android16", "getprop.txt")`.
    public static func adb(_ device: String, _ file: String) -> String {
        text("adb/\(device)/\(file)")
    }
}

/// A scripted stand-in for the adb binary, used by contract and service tests.
///
/// Responses are matched on the exact argument array adb would receive, so tests also pin down
/// which commands Airlock sends. Unmatched commands fail loudly instead of silently succeeding.
public final class FakeADB: ProcessRunning, @unchecked Sendable {
    public struct Response: Sendable {
        public var stdout: String
        public var stderr: String
        public var exitCode: Int32
        public var delay: Duration
        public var error: ProcessError?

        public init(stdout: String = "", stderr: String = "", exitCode: Int32 = 0, delay: Duration = .zero, error: ProcessError? = nil) {
            self.stdout = stdout
            self.stderr = stderr
            self.exitCode = exitCode
            self.delay = delay
            self.error = error
        }

        public static func ok(_ stdout: String = "") -> Response { Response(stdout: stdout) }
        public static func failure(_ stderr: String, exitCode: Int32 = 1) -> Response {
            Response(stderr: stderr, exitCode: exitCode)
        }
    }

    private let lock = NSLock()
    private var exact: [[String]: [Response]] = [:]
    private var prefixes: [([String], Response)] = []
    private var log: [[String]] = []
    private var active = 0
    private var maxActive = 0

    public init() {}

    /// Responds to exactly these arguments. Multiple registrations are consumed in order; the last repeats.
    public func on(_ arguments: [String], _ response: Response) {
        lock.withLock { exact[arguments, default: []].append(response) }
    }

    /// Replaces any earlier registrations for these arguments.
    public func replace(_ arguments: [String], _ response: Response) {
        lock.withLock { exact[arguments] = [response] }
    }

    /// Responds to any command starting with these arguments (lower priority than exact matches).
    public func onPrefix(_ arguments: [String], _ response: Response) {
        lock.withLock { prefixes.append((arguments, response)) }
    }

    /// Every argument array received, in order.
    public var calls: [[String]] { lock.withLock { log } }

    /// Waits until a command containing `word` has been received, so tests can act at a precise point
    /// instead of guessing with sleeps. Fails after `timeout`.
    public func waitForCall(containing word: String, timeout: Duration = .seconds(10)) async throws {
        let deadline = ContinuousClock.now + timeout
        while !calls.contains(where: { $0.contains(word) }) {
            guard ContinuousClock.now < deadline else { throw WaitTimeout(word: word) }
            try await Task.sleep(for: .milliseconds(5))
        }
    }

    public struct WaitTimeout: Error {
        public let word: String
    }

    /// Highest number of commands that ran at the same time (to verify per-device serialisation).
    public var maxConcurrentCalls: Int { lock.withLock { maxActive } }

    private func response(for arguments: [String]) -> Response? {
        lock.withLock {
            log.append(arguments)
            if var queue = exact[arguments], let first = queue.first {
                if queue.count > 1 {
                    queue.removeFirst()
                    exact[arguments] = queue
                }
                return first
            }
            return prefixes.last { arguments.starts(with: $0.0) }?.1
        }
    }

    public func run(_ request: ProcessRequest) async throws(ProcessError) -> ProcessResult {
        if Task.isCancelled { throw .cancelled }
        guard let response = response(for: request.arguments) else {
            return ProcessResult(
                exitCode: 127, stdout: Data(),
                stderr: Data("FakeADB: unexpected command \(request.arguments)".utf8)
            )
        }
        lock.withLock {
            active += 1
            maxActive = max(maxActive, active)
        }
        defer { lock.withLock { active -= 1 } }
        if response.delay > .zero {
            do {
                try await Task.sleep(for: response.delay)
            } catch {
                throw .cancelled
            }
        }
        if let error = response.error { throw error }
        return ProcessResult(exitCode: response.exitCode, stdout: Data(response.stdout.utf8), stderr: Data(response.stderr.utf8))
    }

    public func stream(_ request: ProcessRequest) -> AsyncThrowingStream<ProcessEvent, any Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    let result = try await self.run(request)
                    if !result.stdout.isEmpty { continuation.yield(.stdout(result.stdout)) }
                    if !result.stderr.isEmpty { continuation.yield(.stderr(result.stderr)) }
                    continuation.yield(.exited(result.exitCode))
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }
}

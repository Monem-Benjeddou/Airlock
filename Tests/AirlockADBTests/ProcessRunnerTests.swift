// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

@testable import AirlockADB
import Foundation
import Testing

/// Exercises the real `Process`-backed runner with harmless system binaries (never a shell).
@Suite("SystemProcessRunner")
struct SystemProcessRunnerTests {
    let runner = SystemProcessRunner()

    private func request(_ path: String, _ args: [String], timeout: Duration = .seconds(10), stdin: Data? = nil) -> ProcessRequest {
        ProcessRequest(executable: URL(fileURLWithPath: path), arguments: args, timeout: timeout, standardInput: stdin)
    }

    @Test func capturesStdoutAndExitCode() async throws {
        let result = try await runner.run(request("/bin/echo", ["hello", "world"]))
        #expect(result.exitCode == 0)
        #expect(result.stdoutText == "hello world\n")
        #expect(result.stderr.isEmpty)
    }

    @Test func argumentsAreNeverInterpretedByAShell() async throws {
        // If a shell were involved, `$(id)` or `;` would be expanded or split.
        let hostile = "a; echo pwned $(id) `id` && reboot | cat > /tmp/x"
        let result = try await runner.run(request("/bin/echo", [hostile]))
        #expect(result.stdoutText == hostile + "\n")
    }

    @Test func capturesStderrAndNonZeroExit() async throws {
        let result = try await runner.run(request("/bin/ls", ["/definitely/not/here"]))
        #expect(result.exitCode != 0)
        #expect(!result.stderr.isEmpty)
        #expect(result.stderrText.contains("/definitely/not/here"))
    }

    @Test func feedsStandardInput() async throws {
        let result = try await runner.run(request("/bin/cat", [], stdin: Data("piped input".utf8)))
        #expect(result.stdoutText == "piped input")
    }

    @Test func handlesLargeOutputWithoutDeadlock() async throws {
        // 4 MB through stdout exceeds any pipe buffer.
        let payload = Data(repeating: UInt8(ascii: "x"), count: 4 * 1024 * 1024)
        let result = try await runner.run(request("/bin/cat", [], stdin: payload))
        #expect(result.stdout.count == payload.count)
    }

    @Test func timesOutAndKillsTheProcess() async throws {
        let clock = ContinuousClock()
        let start = clock.now
        await #expect(throws: ProcessError.timedOut(after: .milliseconds(300))) {
            try await runner.run(request("/bin/sleep", ["30"], timeout: .milliseconds(300)))
        }
        #expect(clock.now - start < .seconds(5))
    }

    @Test func cancellationTerminatesTheProcess() async throws {
        let clock = ContinuousClock()
        let start = clock.now
        let task = Task { try await runner.run(request("/bin/sleep", ["30"])) }
        try await Task.sleep(for: .milliseconds(200))
        task.cancel()
        let result = await task.result
        #expect(throws: ProcessError.cancelled) { try result.get() }
        #expect(clock.now - start < .seconds(5))
    }

    @Test func alreadyCancelledTaskDoesNotLaunch() async throws {
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await runner.run(request("/bin/sleep", ["30"]))
        }
        let result = await task.result
        #expect(throws: ProcessError.cancelled) { try result.get() }
    }

    @Test func missingExecutableThrowsLaunchFailed() async {
        await #expect {
            try await runner.run(request("/nonexistent/adb", []))
        } throws: { error in
            guard case ProcessError.launchFailed = error else { return false }
            return true
        }
    }

    @Test func enforcesOutputLimit() async {
        let limited = SystemProcessRunner(maxOutputBytes: 1024)
        let payload = Data(repeating: UInt8(ascii: "y"), count: 64 * 1024)
        await #expect(throws: ProcessError.outputTooLarge(limit: 1024)) {
            try await limited.run(request("/bin/cat", [], stdin: payload))
        }
    }

    @Test func streamsOutputIncrementally() async throws {
        var collected = Data()
        var sawExit: Int32?
        for try await event in runner.stream(request("/bin/echo", ["streamed"])) {
            switch event {
            case .stdout(let chunk): collected.append(chunk)
            case .stderr: break
            case .exited(let code): sawExit = code
            }
        }
        #expect(String(decoding: collected, as: UTF8.self) == "streamed\n")
        #expect(sawExit == 0)
    }

    @Test func streamCancellationTerminatesProcess() async throws {
        let clock = ContinuousClock()
        let start = clock.now
        let task = Task {
            for try await _ in runner.stream(request("/bin/sleep", ["30"])) {}
        }
        try await Task.sleep(for: .milliseconds(200))
        task.cancel()
        _ = await task.result
        #expect(clock.now - start < .seconds(5))
    }

    @Test func environmentIsExplicit() async throws {
        let request = ProcessRequest(
            executable: URL(fileURLWithPath: "/usr/bin/env"), arguments: [],
            environment: ["AIRLOCK_TEST": "1"], timeout: .seconds(5)
        )
        let result = try await runner.run(request)
        #expect(result.stdoutText == "AIRLOCK_TEST=1\n")
    }
}

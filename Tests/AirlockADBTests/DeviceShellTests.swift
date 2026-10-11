// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

@testable import AirlockADB
import AirlockCore
import Foundation
import Testing

@Suite("DeviceShell quoting")
struct DeviceShellTests {
    @Test(arguments: [
        "pm", "list", "--user", "0", "com.example.app", "/sdcard/Android/obb/a.b/main.1.a.b.obb", "-S", "1234", "a=b:c,d@e%f+g",
    ])
    func safeArgumentsPassThroughUnquoted(_ argument: String) throws {
        #expect(try DeviceShell.quote(argument) == argument)
    }

    @Test(arguments: [
        ("a b", "'a b'"),
        ("a;reboot", "'a;reboot'"),
        ("$(id)", "'$(id)'"),
        ("`id`", "'`id`'"),
        ("it's", "'it'\\''s'"),
        ("", "''"),
        ("a\nb", "'a\nb'"),
        ("*", "'*'"),
        ("~", "'~'"),
    ])
    func unsafeArgumentsAreSingleQuoted(_ argument: String, _ expected: String) throws {
        #expect(try DeviceShell.quote(argument) == expected)
    }

    @Test func rejectsNUL() {
        #expect(throws: DeviceShellError.containsNUL) { try DeviceShell.quote("a\u{0}b") }
    }

    /// Round-trips through a real POSIX shell on the Mac to prove the quoting is correct.
    /// (This is the only place the test suite invokes a shell, deliberately, to check the escaping.)
    @Test(arguments: ["plain", "two words", "it's", "$(echo pwned)", "`id`", "a;b|c&d>e<f", "\\back\\slash", "'''", "\"dq\"", "tab\there"])
    func quotingSurvivesARealShell(_ argument: String) async throws {
        let quoted = try DeviceShell.quote(argument)
        let runner = SystemProcessRunner()
        // swiftlint:disable:next no_shell_strings
        let (shell, flag) = (URL(fileURLWithPath: "/bin/sh"), "-c")
        let result = try await runner.run(ProcessRequest(
            executable: shell, arguments: [flag, "printf %s " + quoted], timeout: .seconds(5)
        ))
        #expect(result.stdoutText == argument)
    }
}

@Suite("RemotePath")
struct RemotePathTests {
    @Test(arguments: ["/sdcard/Android/obb/com.a.b/main.1.com.a.b.obb", "/data/local/tmp/airlock-1/base.apk", "/data"])
    func acceptsAbsolutePaths(_ raw: String) throws {
        #expect(try RemotePath(raw).rawValue == raw)
    }

    @Test(arguments: ["relative/path", "/sdcard/../data", "/a/./b", "/a\nb", "/a\u{0}b", "", "/" + String(repeating: "a", count: 1100)])
    func rejectsUnsafePaths(_ raw: String) {
        #expect(throws: RemotePathError.self) { try RemotePath(raw) }
    }

    @Test func obbDirectoryIsBuiltFromValidatedPackage() throws {
        let path = RemotePath.obbDirectory(for: try PackageName("com.example.game"))
        #expect(path.rawValue == "/sdcard/Android/obb/com.example.game")
    }

    @Test func appendingValidatesFileNames() throws {
        let base = try RemotePath("/data/local/tmp/airlock-x")
        #expect(try base.appending("base.apk").rawValue == "/data/local/tmp/airlock-x/base.apk")
        #expect(throws: RemotePathError.self) { try base.appending("../evil") }
        #expect(throws: RemotePathError.self) { try base.appending("a/b") }
        #expect(throws: RemotePathError.self) { try base.appending("") }
        #expect(throws: RemotePathError.self) { try base.appending("..") }
        #expect(throws: RemotePathError.self) { try base.appending("a b;c") }
    }

    @Test func stagingDirectoriesAreUnderAirlockPrefix() throws {
        let staging = RemotePath.stagingDirectory(id: UUID(uuidString: "00000000-0000-0000-0000-000000000001") ?? UUID())
        #expect(staging.rawValue == "/data/local/tmp/airlock-00000000-0000-0000-0000-000000000001")
        #expect(staging.isAirlockStaging)
        #expect(try !RemotePath("/data/local/tmp").isAirlockStaging)
        #expect(try !RemotePath("/sdcard").isAirlockStaging)
    }
}

@Suite("DeviceCommandQueue")
struct DeviceCommandQueueTests {
    actor Recorder {
        var events: [String] = []
        func record(_ event: String) { events.append(event) }
    }

    @Test func runsJobsOneAtATimeInOrder() async throws {
        let queue = DeviceCommandQueue()
        let recorder = Recorder()
        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0..<5 {
                group.addTask {
                    try await queue.enqueue {
                        await recorder.record("start \(index)")
                        try await Task.sleep(for: .milliseconds(20))
                        await recorder.record("end \(index)")
                    }
                }
                // Make enqueue order deterministic.
                try await Task.sleep(for: .milliseconds(2))
            }
            try await group.waitForAll()
        }
        let events = await recorder.events
        let expected = (0..<5).flatMap { ["start \($0)", "end \($0)"] }
        #expect(events == expected)
    }

    @Test func failureDoesNotBlockLaterJobs() async throws {
        struct Boom: Error {}
        let queue = DeviceCommandQueue()
        await #expect(throws: Boom.self) { try await queue.enqueue { throw Boom() } }
        let value = try await queue.enqueue { 42 }
        #expect(value == 42)
    }

    @Test func cancellationPropagatesToTheJob() async throws {
        let queue = DeviceCommandQueue()
        let task = Task {
            try await queue.enqueue {
                try await Task.sleep(for: .seconds(30))
                return 1
            }
        }
        try await Task.sleep(for: .milliseconds(50))
        task.cancel()
        let result = await task.result
        #expect(throws: CancellationError.self) { try result.get() }
        // The queue keeps working afterwards.
        #expect(try await queue.enqueue { 2 } == 2)
    }
}

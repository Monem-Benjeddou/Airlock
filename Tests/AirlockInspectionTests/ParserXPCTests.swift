// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
@testable import AirlockInspection
import AirlockTestSupport
import Foundation
import Testing

/// Hosts ParserXPCService on an anonymous in-process XPC listener, so the real NSXPC transport is used.
final class InProcessParserHost: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    let listener = NSXPCListener.anonymous()
    let service: ParserXPCService

    init(container: URL) {
        service = ParserXPCService(container: container)
        super.init()
        listener.delegate = self
        listener.resume()
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = ParserXPCInterface.make()
        connection.exportedObject = service
        connection.resume()
        return true
    }

    func client(timeout: Duration = .seconds(30)) -> XPCPackageInspector {
        let endpoint = listener.endpoint
        return XPCPackageInspector(timeout: timeout) { NSXPCConnection(listenerEndpoint: endpoint) }
    }
}

@Suite("Parser XPC")
struct ParserXPCTests {
    let scratch: URL
    let host: InProcessParserHost

    init() throws {
        scratch = FileManager.default.temporaryDirectory.appendingPathComponent("airlock-xpc-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        host = InProcessParserHost(container: scratch.appendingPathComponent("container"))
    }

    private func write(_ data: Data, _ name: String) throws -> URL {
        let url = scratch.appendingPathComponent(name)
        try data.write(to: url)
        return url
    }

    @Test func inspectsASignedAPKAcrossXPC() async throws {
        let url = try write(try FixtureAPKs.data(.v2RSA), "game.apk")
        let package = try await host.client().inspect(url)
        #expect(package.packageName == "org.airlock.fixture")
        #expect(package.sourceFile == url, "the user's file is reported, not the helper's copy")
        #expect(package.base.signature.status == .verified)
        #expect(package.workDirectory.path.contains("container/Airlock/jobs"))
        let incoming = scratch.appendingPathComponent("container/Incoming").path
        let leftovers = (try? FileManager.default.contentsOfDirectory(atPath: incoming)) ?? []
        #expect(leftovers.isEmpty, "received copies are deleted after inspection")
    }

    @Test func inspectsAFolderAcrossXPC() async throws {
        let folder = scratch.appendingPathComponent("splits")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try FixtureAPKs.data(.v2RSA).write(to: folder.appendingPathComponent("base.apk"))
        try FixtureAPKs.data(.splitArm64).write(to: folder.appendingPathComponent("split_config.arm64_v8a.apk"))
        try Data("ignore me".utf8).write(to: folder.appendingPathComponent("readme.txt"))
        let package = try await host.client().inspect(folder)
        #expect(package.format == .splitFolder)
        #expect(package.splits.count == 1)
    }

    @Test func errorsCrossTheBoundaryTyped() async throws {
        let url = try write(Data("not a zip".utf8), "fake.apk")
        await #expect {
            try await host.client().inspect(url)
        } throws: { error in
            guard case InstallError.unsupportedFile = error else { return false }
            return true
        }
    }

    @Test func signerDigestsAcrossXPC() async throws {
        let url = try write(try FixtureAPKs.data(.v2RSA), "installed.apk")
        let digests = try await host.client().signerDigests(ofAPKAt: url)
        #expect(digests.count == 1 && digests[0].count == 64)
    }

    @Test func unreadableFileFailsBeforeCallingTheHelper() async {
        await #expect(throws: InstallError.self) {
            try await host.client().inspect(URL(fileURLWithPath: "/nonexistent/x.apk"))
        }
    }

    @Test func silentHelperTimesOutInsteadOfHanging() async throws {
        // Regression: the reply continuation ignored cancellation, so the timeout never fired.
        final class SilentHost: NSObject, NSXPCListenerDelegate, ParserXPCProtocol, @unchecked Sendable {
            let listener = NSXPCListener.anonymous()
            override init() { super.init(); listener.delegate = self; listener.resume() }
            func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
                connection.exportedInterface = ParserXPCInterface.make()
                connection.exportedObject = self
                connection.resume()
                return true
            }
            func inspect(file: FileHandle, fileName: String, reply: @escaping @Sendable (Data) -> Void) {}
            func inspectFolder(files: [FileHandle], fileNames: [String], folderName: String, reply: @escaping @Sendable (Data) -> Void) {}
            func signerDigests(file: FileHandle, reply: @escaping @Sendable (Data) -> Void) {}
        }
        let silent = SilentHost()
        let endpoint = silent.listener.endpoint
        let client = XPCPackageInspector(timeout: .milliseconds(300)) { NSXPCConnection(listenerEndpoint: endpoint) }
        let url = try write(try FixtureAPKs.data(.v2RSA), "game.apk")
        let clock = ContinuousClock()
        let start = clock.now
        await #expect(throws: InstallError.transport("The parser helper did not respond in time.")) { try await client.inspect(url) }
        #expect(clock.now - start < .seconds(5))
    }

    @Test func deadHelperIsReportedNotFatal() async throws {
        let url = try write(try FixtureAPKs.data(.v2RSA), "game.apk")
        // A connection to an endpoint nobody serves: the error handler fires instead of a reply.
        let orphan = NSXPCListener.anonymous()
        let endpoint = orphan.endpoint
        orphan.invalidate()
        let client = XPCPackageInspector(timeout: .seconds(1)) { NSXPCConnection(listenerEndpoint: endpoint) }
        await #expect(throws: InstallError.self) { try await client.inspect(url) }
    }

    @Test(arguments: [
        ("game.apk", "game.apk"), ("../../evil.apk", "evil.apk"), ("a b;c.apk", "a_b_c.apk"), ("..", "file"), ("", "file"),
        ("/etc/passwd", "passwd"),
    ])
    func safeNames(_ input: String, _ expected: String) {
        #expect(ParserXPCService.safeName(input) == expected)
    }

    @Test func wireErrorsRoundTrip() {
        let cases: [InstallError] = [.unsupportedFile("a"), .unsafeArchive("b"), .cancelled]
        for error in cases { #expect(WireError(error).installError == error) }
        #expect(WireError(.deviceDisconnected) == .other("deviceDisconnected"))
        #expect(WireError.other("x").installError == .transport("x"))
    }
}

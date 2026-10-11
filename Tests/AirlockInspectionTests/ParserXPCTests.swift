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

    func client(timeout: Duration = .seconds(30), jobsRoot: URL) -> XPCPackageInspector {
        let endpoint = listener.endpoint
        return XPCPackageInspector(timeout: timeout, jobsRoot: jobsRoot) { NSXPCConnection(listenerEndpoint: endpoint) }
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

    /// The app's own job folder, separate from the helper's container.
    private var appJobs: URL { scratch.appendingPathComponent("app/Airlock/jobs") }

    private func client(timeout: Duration = .seconds(30)) -> XPCPackageInspector {
        host.client(timeout: timeout, jobsRoot: appJobs)
    }

    private func contents(_ path: String) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: scratch.appendingPathComponent(path).path)) ?? []
    }

    private func write(_ data: Data, _ name: String) throws -> URL {
        let url = scratch.appendingPathComponent(name)
        try data.write(to: url)
        return url
    }

    @Test func inspectsASignedAPKAcrossXPC() async throws {
        let url = try write(try FixtureAPKs.data(.v2RSA), "game.apk")
        let package = try await client().inspect(url)
        #expect(package.packageName == "org.airlock.fixture")
        #expect(package.sourceFile == url, "the user's file is reported, not the helper's copy")
        #expect(package.base.signature.status == .verified)
        #expect(contents("container/Incoming").isEmpty, "received copies are deleted after inspection")
    }

    @Test func extractedFilesLandInTheAppsOwnJobFolder() async throws {
        // Regression: the work folder pointed into the helper's sandbox container, which the app may not read
        // (macOS 15 guards other apps' containers) and must not write to.
        let folder = scratch.appendingPathComponent("splits")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try FixtureAPKs.data(.v2RSA).write(to: folder.appendingPathComponent("base.apk"))
        try FixtureAPKs.data(.splitArm64).write(to: folder.appendingPathComponent("split_config.arm64_v8a.apk"))
        let package = try await client().inspect(folder)
        #expect(package.workDirectory.deletingLastPathComponent().standardizedFileURL == appJobs.standardizedFileURL)
        for apk in package.allAPKs {
            let copy = package.workDirectory.appendingPathComponent(apk.fileName)
            #expect(try LocalPackageInspector.sha256(of: copy) == apk.sha256, "\(apk.fileName) arrived intact")
        }
        #expect(contents("container/Airlock/jobs").isEmpty, "the helper keeps nothing once the app has the files")
    }

    @Test func obbFilesPointIntoTheAppsJobFolder() async throws {
        let manifest = """
        {"xapk_version": 2, "package_name": "org.airlock.fixture", "version_code": "42", "name": "Fixture",
         "split_apks": [{"file": "org.airlock.fixture.apk", "id": "base"}],
         "expansions": [{"file": "Android/obb/org.airlock.fixture/main.42.org.airlock.fixture.obb",
                         "install_location": "EXTERNAL_STORAGE",
                         "install_path": "Android/obb/org.airlock.fixture/main.42.org.airlock.fixture.obb"}]}
        """
        let zip = ZipBuilder(files: [
            ("manifest.json", Array(manifest.utf8)),
            ("org.airlock.fixture.apk", Array(try FixtureAPKs.data(.v2RSA))),
            ("Android/obb/org.airlock.fixture/main.42.org.airlock.fixture.obb", [UInt8](repeating: 7, count: 4096)),
        ])
        let package = try await client().inspect(try write(Data(zip.build()), "game.xapk"))
        let obb = try #require(package.obbFiles.first)
        #expect(obb.localURL.path.hasPrefix(package.workDirectory.path + "/"))
        #expect(try LocalPackageInspector.sha256(of: obb.localURL) == obb.sha256)
    }

    @Test func helperCannotWriteOutsideTheJobFolder() async throws {
        // The helper parses hostile files, so a compromised one must not be able to plant files in the app's space.
        final class EvilHost: NSObject, NSXPCListenerDelegate, ParserXPCProtocol, @unchecked Sendable {
            let listener = NSXPCListener.anonymous()
            let payload: URL
            let paths: [String]
            init(payload: URL, paths: [String]) {
                self.payload = payload
                self.paths = paths
                super.init()
                listener.delegate = self
                listener.resume()
            }
            func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
                connection.exportedInterface = ParserXPCInterface.make()
                connection.exportedObject = self
                connection.resume()
                return true
            }
            func inspect(file: FileHandle, fileName: String, reply: @escaping @Sendable (Data, [FileHandle]) -> Void) {
                let apk = InspectedAPK(
                    fileName: "base.apk", sizeBytes: 1, sha256: "00", manifest: ApkManifest(packageName: "org.evil", versionCode: 1),
                    signature: SignatureCheck(status: .unsigned, schemes: [], certificates: [])
                )
                let package = InspectedPackage(sourceFile: payload, format: .apk, sourceSHA256: "00", base: apk, splits: [],
                                               obbFiles: [], workDirectory: URL(fileURLWithPath: "/helper/jobs/x"))
                let handles = paths.compactMap { _ in try? FileHandle(forReadingFrom: payload) }
                reply((try? JSONEncoder().encode(InspectionReply(package: package, files: paths))) ?? Data(), handles)
            }
            func inspectFolder(files: [FileHandle], fileNames: [String], folderName: String,
                               reply: @escaping @Sendable (Data, [FileHandle]) -> Void) {}
            func signerDigests(file: FileHandle, reply: @escaping @Sendable (Data) -> Void) {}
        }
        let payload = try write(Data("planted".utf8), "payload.bin")
        for paths in [["../escape.apk"], ["/tmp/airlock-escape.apk"], ["a/../../escape.apk"], ["missing.apk"], ["base.apk", "base.apk"]] {
            let evil = EvilHost(payload: payload, paths: paths)
            let endpoint = evil.listener.endpoint
            let client = XPCPackageInspector(timeout: .seconds(5), jobsRoot: appJobs) { NSXPCConnection(listenerEndpoint: endpoint) }
            let target = try write(Data("x".utf8), "victim.apk")
            await #expect(throws: InstallError.self, "\(paths)") { try await client.inspect(target) }
            #expect(!FileManager.default.fileExists(atPath: scratch.appendingPathComponent("app/Airlock/escape.apk").path))
            #expect(!FileManager.default.fileExists(atPath: "/tmp/airlock-escape.apk"))
            #expect(contents("app/Airlock/jobs").isEmpty, "a rejected reply leaves no job folder behind")
        }
    }

    @Test func inspectsAFolderAcrossXPC() async throws {
        let folder = scratch.appendingPathComponent("splits")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try FixtureAPKs.data(.v2RSA).write(to: folder.appendingPathComponent("base.apk"))
        try FixtureAPKs.data(.splitArm64).write(to: folder.appendingPathComponent("split_config.arm64_v8a.apk"))
        try Data("ignore me".utf8).write(to: folder.appendingPathComponent("readme.txt"))
        let package = try await client().inspect(folder)
        #expect(package.format == .splitFolder)
        #expect(package.splits.count == 1)
    }

    @Test func errorsCrossTheBoundaryTyped() async throws {
        let url = try write(Data("not a zip".utf8), "fake.apk")
        await #expect {
            try await client().inspect(url)
        } throws: { error in
            guard case InstallError.unsupportedFile = error else { return false }
            return true
        }
    }

    @Test func signerDigestsAcrossXPC() async throws {
        let url = try write(try FixtureAPKs.data(.v2RSA), "installed.apk")
        let digests = try await client().signerDigests(ofAPKAt: url)
        #expect(digests.count == 1 && digests[0].count == 64)
    }

    @Test func unreadableFileFailsBeforeCallingTheHelper() async {
        await #expect(throws: InstallError.self) {
            try await client().inspect(URL(fileURLWithPath: "/nonexistent/x.apk"))
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
            func inspect(file: FileHandle, fileName: String, reply: @escaping @Sendable (Data, [FileHandle]) -> Void) {}
            func inspectFolder(files: [FileHandle], fileNames: [String], folderName: String,
                               reply: @escaping @Sendable (Data, [FileHandle]) -> Void) {}
            func signerDigests(file: FileHandle, reply: @escaping @Sendable (Data) -> Void) {}
        }
        let silent = SilentHost()
        let endpoint = silent.listener.endpoint
        let client = XPCPackageInspector(timeout: .milliseconds(300), jobsRoot: appJobs) { NSXPCConnection(listenerEndpoint: endpoint) }
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
        let client = XPCPackageInspector(timeout: .seconds(1), jobsRoot: appJobs) { NSXPCConnection(listenerEndpoint: endpoint) }
        await #expect(throws: InstallError.self) { try await client.inspect(url) }
    }

    @Test(arguments: [
        ("game.apk", "game.apk"), ("../../evil.apk", "evil.apk"), ("a b;c.apk", "a_b_c.apk"), ("..", "file"), ("", "file"),
        ("/etc/passwd", "passwd"),
    ])
    func safeNames(_ input: String, _ expected: String) {
        #expect(ParserXPCService.safeName(input) == expected)
    }

    @Test(arguments: [
        ("base.apk", true), ("Android/obb/org.x/main.1.org.x.obb", true), ("../x.apk", false), ("/etc/x", false),
        ("a//b", false), ("a/./b", false), ("", false), ("a b.apk", false), ("a/b/c/d/e/f/g/h/i", false),
    ])
    func helperPathsAreChecked(_ path: String, _ accepted: Bool) {
        let job = URL(fileURLWithPath: "/jobs/1")
        let result = XPCPackageInspector.destination(of: path, in: job)
        #expect((result != nil) == accepted)
        if let result { #expect(result.path.hasPrefix("/jobs/1/")) }
    }

    @Test func wireErrorsRoundTrip() {
        let cases: [InstallError] = [.unsupportedFile("a"), .unsafeArchive("b"), .cancelled]
        for error in cases { #expect(WireError(error).installError == error) }
        #expect(WireError(.deviceDisconnected) == .other("deviceDisconnected"))
        #expect(WireError.other("x").installError == .transport("x"))
    }
}

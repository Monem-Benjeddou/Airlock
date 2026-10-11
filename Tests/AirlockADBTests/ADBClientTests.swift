// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

@testable import AirlockADB
import AirlockCore
import AirlockTestSupport
import Foundation
import Testing

private let s24 = "samsung-s24ultra-android16"
private let serial = "FIXTURESERIAL01"

private func makeClient(_ fake: FakeADB) -> ADBClient {
    ADBClient(configuration: ADBConfiguration(executable: URL(fileURLWithPath: "/fake/adb"), homeDirectory: "/Users/test"), runner: fake)
}

private func pkg(_ raw: String) -> PackageName {
    PackageName(rawValue: raw) ?? { preconditionFailure("bad test package \(raw)") }()
}

private func device(_ fake: FakeADB) throws -> DeviceChannel {
    makeClient(fake).device(try DeviceSerial(serial))
}

@Suite("ADBClient host commands")
struct ADBClientHostTests {
    @Test func devicesUsesLongListing() async throws {
        let fake = FakeADB()
        fake.on(["devices", "-l"], .ok(Fixture.adb(s24, "devices-l.txt")))
        let devices = try await makeClient(fake).devices()
        #expect(devices.map(\.serial.rawValue) == [serial])
        #expect(fake.calls == [["devices", "-l"]])
    }

    @Test func environmentIsMinimalAndLocalhostOnly() {
        let config = ADBConfiguration(executable: URL(fileURLWithPath: "/fake/adb"), serverPort: 5099, homeDirectory: "/Users/test")
        let request = ADBClient(configuration: config, runner: FakeADB()).request(["devices"])
        #expect(request.environment == ["HOME": "/Users/test", "ANDROID_ADB_SERVER_PORT": "5099", "PATH": "/usr/bin:/bin"])
        #expect(!request.arguments.contains("-a"))
    }

    @Test func versionParses() async throws {
        let fake = FakeADB()
        fake.on(["version"], .ok("Android Debug Bridge version 1.0.41\nVersion 37.0.1-15733141\n"))
        #expect(try await makeClient(fake).version() == "37.0.1")
    }

    @Test func startServerFailureIsReported() async {
        let fake = FakeADB()
        fake.on(["start-server"], .failure("could not bind to port"))
        await #expect {
            try await makeClient(fake).startServer()
        } throws: { error in
            guard case ADBError.commandFailed(let command, _, let output) = error else { return false }
            return command == "start-server" && output.contains("bind")
        }
    }

    @Test func processErrorsAreWrapped() async {
        let fake = FakeADB()
        fake.on(["devices", "-l"], FakeADB.Response(error: .timedOut(after: .seconds(30))))
        await #expect(throws: ADBError.process(.timedOut(after: .seconds(30)))) { try await makeClient(fake).devices() }
    }

    @Test func pairValidatesInputBeforeRunning() async throws {
        let fake = FakeADB()
        let client = makeClient(fake)
        await #expect(throws: ADBError.self) { try await client.pair(host: "1.2.3.4;reboot", port: 5555, code: "123456") }
        await #expect(throws: ADBError.self) { try await client.pair(host: "1.2.3.4", port: 0, code: "123456") }
        await #expect(throws: ADBError.self) { try await client.pair(host: "1.2.3.4", port: 37000, code: "12a456") }
        await #expect(throws: ADBError.self) { try await client.pair(host: "-flag", port: 37000, code: "123456") }
        #expect(fake.calls.isEmpty)

        fake.on(["pair", "192.168.1.20:37099", "123456"], .ok("Successfully paired to 192.168.1.20:37099 [guid=adb-X]"))
        #expect(try await client.pair(host: "192.168.1.20", port: 37099, code: "123456") == .paired)
    }

    @Test func connectAndDisconnect() async throws {
        let fake = FakeADB()
        fake.on(["connect", "192.168.1.20:5555"], .ok("connected to 192.168.1.20:5555\n"))
        fake.on(["disconnect", "192.168.1.20:5555"], .ok("disconnected 192.168.1.20:5555\n"))
        let client = makeClient(fake)
        #expect(try await client.connect(host: "192.168.1.20", port: 5555) == .connected)
        try await client.disconnect(try DeviceSerial("192.168.1.20:5555"))
        await #expect(throws: ADBError.self) { try await client.connect(host: "a b", port: 5555) }
    }

    @Test func mdns() async throws {
        let fake = FakeADB()
        fake.on(["mdns", "check"], .ok("mdns daemon version [adb discovery 0.0.0]\n"))
        fake.on(["mdns", "services"], .ok("List of discovered mdns services\nadb-X\t_adb-tls-pairing._tcp\t10.0.0.2:40000\n"))
        let client = makeClient(fake)
        #expect(try await client.mdnsCheck())
        #expect(try await client.mdnsServices().first?.port == 40000)
    }

    @Test func trackDevicesDecodesLengthPrefixedSnapshots() throws {
        var decoder = TrackDevicesDecoder()
        let first = "emulator-5554\tdevice product:p model:m device:d transport_id:1\n"
        let framed = String(format: "%04x", first.utf8.count) + first + "0000"
        let bytes = Data(framed.utf8)
        // Feed in awkward chunks to exercise buffering.
        var snapshots: [[ConnectedDevice]] = []
        snapshots += try decoder.feed(bytes.prefix(3))
        snapshots += try decoder.feed(bytes.dropFirst(3).prefix(20))
        snapshots += try decoder.feed(bytes.dropFirst(23))
        #expect(snapshots.count == 2)
        #expect(snapshots[0].first?.serial.rawValue == "emulator-5554")
        #expect(snapshots[1].isEmpty)
    }

    @Test func trackDevicesRejectsBadFraming() {
        var decoder = TrackDevicesDecoder()
        #expect(throws: ADBError.self) { try decoder.feed(Data("zzzz".utf8)) }
        var big = TrackDevicesDecoder()
        #expect(throws: ADBError.self) { try big.feed(Data("ffff".utf8)) }
    }

    @Test func trackDevicesStreamsFromRunner() async throws {
        let fake = FakeADB()
        let payload = "emulator-5554\tdevice transport_id:1\n"
        fake.on(["track-devices", "-l"], .ok(String(format: "%04x", payload.utf8.count) + payload))
        var received: [[ConnectedDevice]] = []
        for try await snapshot in makeClient(fake).trackDevices() { received.append(snapshot) }
        #expect(received.count == 1)
    }
}

@Suite("DeviceChannel commands")
struct DeviceChannelTests {
    private func shell(_ args: String...) -> [String] { ["-s", serial, "shell"] + args }

    @Test func readsDevicePropertiesFromRecordedOutput() async throws {
        let fake = FakeADB()
        fake.on(shell("getprop"), .ok(Fixture.adb(s24, "getprop.txt")))
        fake.on(shell("dumpsys", "battery"), .ok(Fixture.adb(s24, "dumpsys-battery.txt")))
        fake.on(shell("wm", "density"), .ok(Fixture.adb(s24, "wm-density.txt")))
        fake.on(shell("df", "/data"), .ok(Fixture.adb(s24, "df-data.txt")))
        let channel = try device(fake)
        #expect(try await channel.properties()["ro.product.model"] == "SM-S928B")
        #expect(try await channel.batteryLevel() == 95)
        #expect(try await channel.density() == 560)
        #expect(try await channel.freeBytes() == 75_619_616 * 1024)
    }

    @Test func listsPackagesForUserZeroOnly() async throws {
        let fake = FakeADB()
        fake.on(
            shell("pm", "list", "packages", "--user", "0", "-f", "-U", "--show-versioncode", "-i"),
            .ok(Fixture.adb(s24, "pm-list-packages.txt"))
        )
        fake.on(shell("pm", "list", "packages", "--user", "0", "-d"), .ok(Fixture.adb(s24, "pm-list-disabled.txt")))
        fake.on(shell("pm", "list", "packages", "--user", "0"), .ok("package:com.a.b\n"))
        let channel = try device(fake)
        #expect(try await channel.packages().count == 597)
        #expect(try await channel.packageNames(.disabled).count == 20)
        #expect(try await channel.packageNames(.all) == ["com.a.b"])
        #expect(fake.calls.allSatisfy { $0.contains("--user") })
    }

    @Test func packageQueries() async throws {
        let fake = FakeADB()
        fake.on(shell("dumpsys", "package", "com.android.settings"), .ok(Fixture.adb(s24, "dumpsys-package.txt")))
        fake.on(shell("pm", "path", "com.android.settings"), .ok(Fixture.adb(s24, "pm-path.txt")))
        fake.on(shell("pm", "path", "com.does.not.exist"), FakeADB.Response(exitCode: 1))
        let home = shell(
            "cmd", "package", "query-activities", "--brief",
            "-a", "android.intent.action.MAIN", "-c", "android.intent.category.HOME"
        )
        fake.on(home, .ok(Fixture.adb(s24, "home-activities.txt")))
        fake.on(shell("ime", "list", "-s"), .ok(Fixture.adb(s24, "ime-list.txt")))
        let channel = try device(fake)
        #expect(try await channel.dump(pkg("com.android.settings")).versionCode == 36)
        #expect(try await channel.apkPaths(pkg("com.android.settings")).count == 1)
        #expect(try await channel.apkPaths(pkg("com.does.not.exist")).isEmpty)
        #expect(try await channel.launchers().first == "com.sec.android.app.launcher")
        #expect(try await channel.inputMethods().count == 3)
    }

    @Test func packageOperationsSendExactCommands() async throws {
        let fake = FakeADB()
        let name = "com.facebook.appmanager"
        fake.on(shell("pm", "uninstall", "-k", "--user", "0", name), .ok("Success\n"))
        fake.on(shell("pm", "disable-user", "--user", "0", name), .ok("Package \(name) new state: disabled-user\n"))
        fake.on(shell("pm", "enable", "--user", "0", name), .ok("Package \(name) new state: enabled\n"))
        fake.on(shell("cmd", "package", "install-existing", "--user", "0", name), .ok("Package \(name) installed for user: 0\n"))
        fake.on(shell("pm", "uninstall", name), .ok("Success\n"))
        let channel = try device(fake)
        try await channel.uninstallForUser(pkg(name))
        try await channel.disableForUser(pkg(name))
        try await channel.enable(pkg(name))
        try await channel.installExisting(pkg(name))
        try await channel.uninstall(pkg(name))
        #expect(fake.calls.count == 5)
    }

    @Test func packageOperationFailureSurfacesDeviceMessage() async throws {
        let fake = FakeADB()
        fake.on(shell("pm", "disable-user", "--user", "0", "com.android.systemui"),
                FakeADB.Response(stderr: "java.lang.SecurityException: Cannot disable a protected package", exitCode: 255))
        fake.on(shell("pm", "uninstall", "-k", "--user", "0", "com.x.y"), .ok("Failure [not installed for 0]\n"))
        let channel = try device(fake)
        await #expect {
            try await channel.disableForUser(pkg("com.android.systemui"))
        } throws: { error in
            guard case ADBError.commandFailed(_, _, let output) = error else { return false }
            return output.contains("protected package")
        }
        await #expect(throws: ADBError.self) { try await channel.uninstallForUser(pkg("com.x.y")) }
    }

    @Test func transportErrorsAreClassified() async throws {
        let fake = FakeADB()
        fake.on(shell("getprop"), .failure("adb: device 'FIXTURESERIAL01' not found"))
        fake.on(shell("wm", "density"), .failure("adb: device unauthorized.\nThis adb server's $ADB_VENDOR_KEYS is not set"))
        fake.on(shell("dumpsys", "battery"), .failure("adb: device offline"))
        let channel = try device(fake)
        let expected = try DeviceSerial(serial)
        await #expect(throws: ADBError.deviceNotFound(expected)) { try await channel.properties() }
        await #expect(throws: ADBError.deviceUnauthorized(expected)) { try await channel.density() }
        await #expect(throws: ADBError.deviceOffline(expected)) { try await channel.batteryLevel() }
    }

    @Test func transportErrorWinsEvenWhenFailureIsAllowed() async throws {
        let fake = FakeADB()
        fake.on(shell("pm", "path", "com.a.b"), .failure("adb: device 'FIXTURESERIAL01' not found"))
        await #expect(throws: ADBError.deviceNotFound(try DeviceSerial(serial))) {
            try await device(fake).apkPaths(pkg("com.a.b"))
        }
    }

    @Test func installSessionLifecycle() async throws {
        let fake = FakeADB()
        fake.on(shell("pm", "install-create", "-r", "-S", "3000"), .ok("Success: created install session [77]\n"))
        fake.on(
            shell("pm", "install-write", "-S", "1000", "77", "base", "/data/local/tmp/airlock-x/base.apk"),
            .ok("Success: streamed 1000 bytes\n")
        )
        fake.on(shell("pm", "install-commit", "77"), .ok("Success\n"))
        fake.on(shell("pm", "install-abandon", "77"), .ok("Success\n"))
        let channel = try device(fake)
        let session = try await channel.createInstallSession(totalBytes: 3000)
        #expect(session == 77)
        try await channel.writeToSession(77, name: "base", size: 1000, from: try RemotePath("/data/local/tmp/airlock-x/base.apk"))
        #expect(try await channel.commitInstallSession(77) == nil)
        try await channel.abandonInstallSession(77)
    }

    @Test func commitFailureReturnsParsedCode() async throws {
        let fake = FakeADB()
        let olderSDK = "Failure [INSTALL_FAILED_OLDER_SDK: Requires newer sdk version #34 (current version is #30)]\n"
        fake.on(shell("pm", "install-commit", "9"), FakeADB.Response(stdout: olderSDK, exitCode: 1))
        fake.on(shell("pm", "install-commit", "10"), FakeADB.Response(stdout: "Exception occurred\n", exitCode: 1))
        let channel = try device(fake)
        #expect(try await channel.commitInstallSession(9)?.code == "INSTALL_FAILED_OLDER_SDK")
        #expect(try await channel.commitInstallSession(10)?.code == "INSTALL_FAILED_UNKNOWN")
    }

    @Test func writeFailureThrows() async throws {
        let fake = FakeADB()
        fake.on(
            shell("pm", "install-write", "-S", "1", "5", "base", "/data/local/tmp/airlock-x/base.apk"),
            .ok("Error: Unable to open file\n")
        )
        await #expect(throws: ADBError.self) {
            try await device(fake).writeToSession(5, name: "base", size: 1, from: try RemotePath("/data/local/tmp/airlock-x/base.apk"))
        }
    }

    @Test func removeStagingRefusesOtherPaths() async throws {
        let fake = FakeADB()
        let channel = try device(fake)
        await #expect(throws: ADBError.self) { try await channel.removeStaging(try RemotePath("/sdcard")) }
        await #expect(throws: ADBError.self) { try await channel.removeStaging(try RemotePath("/data/local/tmp")) }
        #expect(fake.calls.isEmpty)
        let staging = RemotePath.stagingDirectory(id: UUID())
        fake.on(shell("rm", "-rf", staging.rawValue), .ok())
        try await channel.removeStaging(staging)
        #expect(fake.calls.count == 1)
    }

    @Test func filesAndTransfers() async throws {
        let fake = FakeADB()
        let remote = try RemotePath("/sdcard/Android/obb/com.a.b/main.1.com.a.b.obb")
        let hash = String(repeating: "0f", count: 32)
        fake.on(shell("stat", "-c", "%s", remote.rawValue), .ok("42\n"))
        fake.on(shell("sha256sum", remote.rawValue), .ok("\(hash)  \(remote.rawValue)\n"))
        fake.on(shell("mkdir", "-p", "/sdcard/Android/obb/com.a.b"), .ok())
        fake.on(["-s", serial, "push", "/tmp/main.obb", remote.rawValue], .ok("1 file pushed\n"))
        fake.on(["-s", serial, "pull", "/data/app/x/base.apk", "/tmp/base.apk"], .ok("1 file pulled\n"))
        let channel = try device(fake)
        try await channel.makeDirectory(RemotePath.obbDirectory(for: pkg("com.a.b")))
        try await channel.push(URL(fileURLWithPath: "/tmp/main.obb"), to: remote)
        #expect(try await channel.fileSize(remote) == 42)
        #expect(try await channel.sha256(remote) == hash)
        try await channel.pull(try RemotePath("/data/app/x/base.apk"), to: URL(fileURLWithPath: "/tmp/base.apk"))
    }

    @Test func pushFailureIsReported() async throws {
        let fake = FakeADB()
        fake.on(["-s", serial, "push", "/tmp/a", "/sdcard/a"], .failure("adb: error: failed to copy: No space left on device"))
        await #expect(throws: ADBError.self) {
            try await device(fake).push(URL(fileURLWithPath: "/tmp/a"), to: try RemotePath("/sdcard/a"))
        }
    }

    @Test func pathsWithSpacesAreQuotedForTheDeviceShell() async throws {
        let fake = FakeADB()
        fake.on(shell("stat", "-c", "%s", "'/sdcard/My Files/a.obb'"), .ok("1\n"))
        #expect(try await device(fake).fileSize(try RemotePath("/sdcard/My Files/a.obb")) == 1)
    }

    @Test func tcpipAndWifiAddress() async throws {
        let fake = FakeADB()
        fake.on(["-s", serial, "tcpip", "5555"], .ok("restarting in TCP mode port: 5555\n"))
        fake.on(shell("ip", "-4", "-o", "addr", "show", "wlan0"),
                .ok("47: wlan0    inet 192.168.1.20/24 brd 192.168.1.255 scope global wlan0\\       valid_lft forever\n"))
        let channel = try device(fake)
        try await channel.enableTCPIP()
        #expect(try await channel.wifiAddress() == "192.168.1.20")
        await #expect(throws: ADBError.self) { try await channel.enableTCPIP(port: 80) }
    }

    @Test func wifiAddressMissing() async throws {
        let fake = FakeADB()
        fake.on(shell("ip", "-4", "-o", "addr", "show", "wlan0"), FakeADB.Response(stderr: "Device \"wlan0\" does not exist.", exitCode: 1))
        #expect(try await device(fake).wifiAddress() == nil)
    }

    @Test func parseFailuresAreWrapped() async throws {
        let fake = FakeADB()
        fake.on(shell("wm", "density"), .ok("garbage\n"))
        fake.on(shell("pm", "install-create", "-r", "-S", "1"), .ok("Error\n"))
        let channel = try device(fake)
        await #expect { try await channel.density() } throws: { error in
            guard case ADBError.parse = error else { return false }
            return true
        }
        await #expect(throws: ADBError.self) { try await channel.createInstallSession(totalBytes: 1) }
    }

    @Test func commandsOnOneDeviceNeverOverlap() async throws {
        let fake = FakeADB()
        fake.onPrefix(["-s", serial, "shell"], FakeADB.Response(stdout: "Physical density: 420\n", delay: .milliseconds(20)))
        let client = makeClient(fake)
        let serialValue = try DeviceSerial(serial)
        try await withThrowingTaskGroup(of: Int.self) { group in
            for _ in 0..<6 {
                // Separate channel values for the same serial must still share one queue.
                group.addTask { try await client.device(serialValue).density() }
            }
            for try await value in group { #expect(value == 420) }
        }
        #expect(fake.maxConcurrentCalls == 1)
        #expect(fake.calls.count == 6)
    }

    @Test func differentDevicesRunInParallel() async throws {
        let fake = FakeADB()
        fake.onPrefix(["-s"], FakeADB.Response(stdout: "Physical density: 420\n", delay: .milliseconds(100)))
        let client = makeClient(fake)
        let serials = try ["A1", "B2", "C3"].map { try DeviceSerial($0) }
        try await withThrowingTaskGroup(of: Int.self) { group in
            for serial in serials { group.addTask { try await client.device(serial).density() } }
            try await group.waitForAll()
        }
        #expect(fake.maxConcurrentCalls > 1)
    }

    @Test func cancellationMapsToProcessCancelled() async throws {
        let fake = FakeADB()
        fake.on(shell("getprop"), FakeADB.Response(delay: .seconds(30)))
        let channel = try device(fake)
        let task = Task { try await channel.properties() }
        try await Task.sleep(for: .milliseconds(50))
        task.cancel()
        let result = await task.result
        #expect(throws: ADBError.process(.cancelled)) { try result.get() }
    }

    @Test func nulInArgumentsIsRejected() async throws {
        let fake = FakeADB()
        await #expect(throws: ADBError.invalidArgument("NUL byte in shell argument")) {
            try await device(fake).shell(["echo", "a\u{0}b"])
        }
    }
}

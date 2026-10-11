// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockADB
import AirlockCore
@testable import AirlockServices
import AirlockTestSupport
import Foundation
import Testing

let s24 = "samsung-s24ultra-android16"
let s24Serial = "FIXTURESERIAL01"

func makeADB(_ fake: FakeADB) -> ADBClient {
    ADBClient(configuration: ADBConfiguration(executable: URL(fileURLWithPath: "/fake/adb"), homeDirectory: "/Users/test"), runner: fake)
}

func shell(_ args: String...) -> [String] { ["-s", s24Serial, "shell"] + args }

func pkg(_ raw: String) -> PackageName {
    PackageName(rawValue: raw) ?? { preconditionFailure(raw) }()
}

/// Registers the recorded S24 responses for every read-only query the services make.
func registerS24(_ fake: FakeADB) {
    fake.on(["devices", "-l"], .ok(Fixture.adb(s24, "devices-l.txt")))
    fake.on(shell("getprop"), .ok(Fixture.adb(s24, "getprop.txt")))
    fake.on(shell("dumpsys", "battery"), .ok(Fixture.adb(s24, "dumpsys-battery.txt")))
    fake.on(shell("wm", "density"), .ok(Fixture.adb(s24, "wm-density.txt")))
    fake.on(shell("df", "/data"), .ok(Fixture.adb(s24, "df-data.txt")))
}

@Suite("DefaultDeviceService")
struct DeviceServiceTests {
    private func collect(_ service: DefaultDeviceService, count: Int) async -> [[ConnectedDevice]] {
        var snapshots: [[ConnectedDevice]] = []
        for await snapshot in service.deviceUpdates() {
            snapshots.append(snapshot)
            if snapshots.count == count { break }
        }
        return snapshots
    }

    @Test func emitsInitialListThenOnlyChanges() async throws {
        let fake = FakeADB()
        let empty = "List of devices attached\n\n"
        let unauthorized = "List of devices attached\nR58\tunauthorized usb:1 transport_id:1\n"
        let ready = "List of devices attached\nR58\tdevice model:Pixel_9 transport_id:1\n"
        for output in [empty, empty, unauthorized, unauthorized, ready] {
            fake.on(["devices", "-l"], .ok(output))
        }
        let service = DefaultDeviceService(adb: makeADB(fake), pollInterval: .milliseconds(5))
        let snapshots = await collect(service, count: 3)
        #expect(snapshots.map { $0.map(\.state) } == [[], [.unauthorized], [.ready]])
    }

    @Test func reconnectsAfterUnplugWithNewTransport() async throws {
        let fake = FakeADB()
        let plugged = "List of devices attached\nR58\tdevice transport_id:35\n"
        let replugged = "List of devices attached\nR58\tdevice transport_id:36\n"
        for output in [plugged, "List of devices attached\n\n", replugged] { fake.on(["devices", "-l"], .ok(output)) }
        let service = DefaultDeviceService(adb: makeADB(fake), pollInterval: .milliseconds(5))
        let snapshots = await collect(service, count: 3)
        #expect(snapshots.map(\.count) == [1, 0, 1])
        #expect(snapshots[2].first?.transportID == "36")
    }

    @Test func adbFailuresReportNoDevicesAndKeepPolling() async throws {
        let fake = FakeADB()
        fake.on(["devices", "-l"], .ok("List of devices attached\nR58\tdevice\n"))
        fake.on(["devices", "-l"], FakeADB.Response(error: .timedOut(after: .seconds(5))))
        fake.on(["devices", "-l"], .ok("List of devices attached\nR58\tdevice\n"))
        let service = DefaultDeviceService(adb: makeADB(fake), pollInterval: .milliseconds(5))
        let snapshots = await collect(service, count: 3)
        #expect(snapshots.map(\.count) == [1, 0, 1])
    }

    @Test func multipleDevicesAreSorted() async throws {
        let fake = FakeADB()
        fake.on(["devices", "-l"], .ok("List of devices attached\nZZZ\tdevice\nAAA\tdevice\nemulator-5554\toffline\n"))
        let service = DefaultDeviceService(adb: makeADB(fake), pollInterval: .milliseconds(5))
        let snapshot = await collect(service, count: 1)[0]
        #expect(snapshot.map(\.serial.rawValue) == ["AAA", "ZZZ", "emulator-5554"])
    }

    @Test func stoppingIterationStopsPolling() async throws {
        let fake = FakeADB()
        fake.on(["devices", "-l"], .ok("List of devices attached\n\n"))
        let service = DefaultDeviceService(adb: makeADB(fake), pollInterval: .milliseconds(5))
        _ = await collect(service, count: 1)
        try await Task.sleep(for: .milliseconds(100))
        let callsAfterStop = fake.calls.count
        try await Task.sleep(for: .milliseconds(100))
        #expect(fake.calls.count <= callsAfterStop + 1)
    }

    @Test func readsDeviceInfoFromRecordedS24() async throws {
        let fake = FakeADB()
        registerS24(fake)
        let service = DefaultDeviceService(adb: makeADB(fake))
        let info = try await service.info(for: try DeviceSerial(s24Serial))
        #expect(info.model == "SM-S928B")
        #expect(info.manufacturer == "samsung")
        #expect(info.brand == .samsung)
        #expect(info.androidVersion == "16")
        #expect(info.batteryPercent == 95)
        #expect(info.stableID == "FIXTURESERIAL01")
        #expect(info.properties == DeviceProperties(abis: ["arm64-v8a"], densityDPI: 560, locales: ["en-GB"], sdkLevel: 36))
    }

    @Test func infoFallsBackWhenPropertiesAreMissing() async throws {
        let fake = FakeADB()
        fake.on(shell("getprop"), .ok("[ro.build.version.sdk]: [26]\n[ro.product.locale]: [fr-FR]\n"))
        fake.on(shell("dumpsys", "battery"), .ok("present: false\n"))
        fake.on(shell("wm", "density"), .ok("Physical density: 320\n"))
        let info = try await DefaultDeviceService(adb: makeADB(fake)).info(for: try DeviceSerial(s24Serial))
        #expect(info.model == "Android device")
        #expect(info.stableID == s24Serial)
        #expect(info.batteryPercent == nil)
        #expect(info.brand == .other)
        #expect(info.properties.locales == ["fr-FR"])
        #expect(info.properties.abis.isEmpty)
    }

    @Test func infoOnUnauthorizedDeviceThrows() async throws {
        let fake = FakeADB()
        fake.on(shell("getprop"), .failure("adb: device unauthorized."))
        await #expect(throws: ADBError.deviceUnauthorized(try DeviceSerial(s24Serial))) {
            try await DefaultDeviceService(adb: makeADB(fake)).info(for: try DeviceSerial(s24Serial))
        }
    }
}

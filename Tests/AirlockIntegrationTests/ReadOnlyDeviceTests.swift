// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockADB
import AirlockCore
import Foundation
import Testing

/// Runs ONLY read-only commands against a real device or emulator.
///
///     AIRLOCK_INTEGRATION=1 AIRLOCK_DEVICE=<serial> swift test --filter Integration
///
/// Safe on a personal phone: nothing here changes device state. Tests that install or remove apps
/// live in `EmulatorWriteTests` and refuse to run on anything but an emulator.
enum IntegrationEnvironment {
    static let environment = ProcessInfo.processInfo.environment
    static var enabled: Bool { environment["AIRLOCK_INTEGRATION"] == "1" }
    static var serial: DeviceSerial? { environment["AIRLOCK_DEVICE"].flatMap(DeviceSerial.init(rawValue:)) }

    static func client() throws -> ADBClient {
        let location = try #require(ADBLocator().locate(), "adb not found")
        return ADBClient(configuration: ADBConfiguration(executable: location.url))
    }
}

@Suite("Integration: read-only device", .enabled(if: IntegrationEnvironment.enabled && IntegrationEnvironment.serial != nil))
struct ReadOnlyDeviceTests {
    @Test func deviceIsListedAndReady() async throws {
        let serial = try #require(IntegrationEnvironment.serial)
        let devices = try await IntegrationEnvironment.client().devices()
        let device = try #require(devices.first { $0.serial == serial })
        #expect(device.state == .ready)
    }

    @Test func readsPropertiesBatteryDensityAndStorage() async throws {
        let channel = try IntegrationEnvironment.client().device(try #require(IntegrationEnvironment.serial))
        let props = try await channel.properties()
        #expect(Int(props["ro.build.version.sdk"] ?? "") ?? 0 >= 26)
        #expect(!(props["ro.product.cpu.abilist"] ?? "").isEmpty)
        let battery = try await channel.batteryLevel()
        #expect((0...100).contains(battery ?? -1))
        #expect(try await channel.density() > 100)
        #expect(try await channel.freeBytes() > 0)
    }

    @Test func listsAndDumpsPackages() async throws {
        let channel = try IntegrationEnvironment.client().device(try #require(IntegrationEnvironment.serial))
        let packages = try await channel.packages()
        #expect(packages.count > 50)
        let settings = try #require(packages.first { $0.packageName.rawValue == "com.android.settings" })
        let dump = try await channel.dump(settings.packageName)
        #expect(dump.versionCode > 0)
        #expect(dump.isSystem)
        #expect(try await !channel.apkPaths(settings.packageName).isEmpty)
        #expect(try await !channel.launchers().isEmpty)
    }

    @Test func parallelReadsAreSerialisedWithoutErrors() async throws {
        let channel = try IntegrationEnvironment.client().device(try #require(IntegrationEnvironment.serial))
        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<8 { group.addTask { _ = try await channel.density() } }
            try await group.waitForAll()
        }
    }
}

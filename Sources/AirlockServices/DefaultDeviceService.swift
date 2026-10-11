// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockADB
import AirlockCore
import Foundation

/// F1: watches connected devices and reads their details.
///
/// Polls `adb devices -l` rather than holding a `track-devices` connection: polling survives adb server
/// restarts and cable resets without special handling, and a 1 s interval meets the 3 s detection target.
public struct DefaultDeviceService: DeviceService {
    private let adb: ADBClient
    private let pollInterval: Duration

    public init(adb: ADBClient, pollInterval: Duration = .seconds(1)) {
        self.adb = adb
        self.pollInterval = pollInterval
    }

    public func deviceUpdates() -> AsyncStream<[ConnectedDevice]> {
        let adb = adb
        let interval = pollInterval
        return AsyncStream { continuation in
            let task = Task {
                var last: [ConnectedDevice]?
                while !Task.isCancelled {
                    // A failing adb (server restarting, binary missing) reads as "no devices" until it recovers.
                    let current = ((try? await adb.devices()) ?? []).sorted { $0.serial.rawValue < $1.serial.rawValue }
                    if current != last {
                        continuation.yield(current)
                        last = current
                    }
                    try? await Task.sleep(for: interval)
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    public func info(for serial: DeviceSerial) async throws -> DeviceInfo {
        let channel = adb.device(serial)
        let props = try await channel.properties()
        let battery = try await channel.batteryLevel()
        let density = try await channel.density()
        // Optional: an older or locked-down device without `settings` still shows its model code.
        let ownerName = try? await channel.ownerDeviceName()

        let manufacturer = props["ro.product.manufacturer"] ?? ""
        let abis = (props["ro.product.cpu.abilist"] ?? "").split(separator: ",").map(String.init)
        let locale = [props["persist.sys.locale"], props["ro.product.locale"]].compactMap { $0 }.first { !$0.isEmpty } ?? "en-US"
        let serialNumber = props["ro.serialno"].flatMap { $0.isEmpty ? nil : $0 } ?? serial.rawValue
        let model = props["ro.product.model"].flatMap { $0.isEmpty ? nil : $0 } ?? "Android device"
        let marketName = [props["ro.product.marketname"], props["ro.product.vendor.marketname"]]
            .compactMap { $0 }.first { !$0.isEmpty }

        return DeviceInfo(
            serial: serial,
            stableID: serialNumber,
            model: model,
            displayName: DeviceNames.friendlyName(ownerName: ownerName, marketName: marketName, model: model),
            manufacturer: manufacturer,
            brand: DeviceBrand(manufacturer: manufacturer, brand: props["ro.product.brand"] ?? ""),
            androidVersion: props["ro.build.version.release"] ?? "?",
            properties: DeviceProperties(
                abis: abis,
                densityDPI: density,
                locales: locale.split(separator: ",").map(String.init),
                sdkLevel: Int(props["ro.build.version.sdk"] ?? "") ?? 0
            ),
            batteryPercent: battery
        )
    }
}

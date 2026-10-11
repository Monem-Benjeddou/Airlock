// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation
import Observation

/// What the onboarding screen should explain for the current situation.
public enum OnboardingStage: Hashable, Sendable {
    case noDevice
    /// Waiting for the user to tap "Allow" on the phone's USB debugging prompt.
    case tapAllow
    case offline
    case noPermission
    case unsupportedMode(String)
    case ready
}

/// F1: the device list, the selected device and its details.
@MainActor
@Observable
public final class DevicesModel {
    public private(set) var devices: [ConnectedDevice] = []
    public private(set) var details: [DeviceSerial: DeviceInfo] = [:]
    public private(set) var detailErrors: [DeviceSerial: String] = [:]
    public var selectedSerial: DeviceSerial?

    private let service: any DeviceService

    public init(service: any DeviceService) {
        self.service = service
    }

    public var selectedDevice: ConnectedDevice? {
        devices.first { $0.serial == selectedSerial }
    }

    public var selectedInfo: DeviceInfo? {
        selectedSerial.flatMap { details[$0] }
    }

    public var stage: OnboardingStage {
        guard let device = selectedDevice else { return .noDevice }
        switch device.state {
        case .ready: return .ready
        case .unauthorized, .authorizing: return .tapAllow
        case .offline: return .offline
        case .noPermissions: return .noPermission
        case .other(let mode): return .unsupportedMode(mode)
        }
    }

    /// Follows device changes until the calling task is cancelled.
    public func run() async {
        for await snapshot in service.deviceUpdates() {
            await apply(snapshot)
        }
    }

    func apply(_ snapshot: [ConnectedDevice]) async {
        devices = snapshot
        let present = Set(snapshot.map(\.serial))
        details = details.filter { present.contains($0.key) }
        detailErrors = detailErrors.filter { present.contains($0.key) }

        // Keep the selection while the device is attached; otherwise prefer a ready device.
        if selectedSerial.map(present.contains) != true {
            selectedSerial = snapshot.first { $0.state == .ready }?.serial ?? snapshot.first?.serial
        }
        for device in snapshot where device.state == .ready && details[device.serial] == nil {
            await loadDetails(device.serial)
        }
    }

    public func loadDetails(_ serial: DeviceSerial) async {
        do {
            details[serial] = try await service.info(for: serial)
            detailErrors[serial] = nil
        } catch {
            detailErrors[serial] = "Could not read device details. Try reconnecting the cable."
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import SwiftUI

/// The device everything acts on, always visible in the toolbar. A click lists every device with its status
/// and offers Wi-Fi pairing.
struct DevicePicker: View {
    let devices: DevicesModel
    let connectOverWiFi: () -> Void
    @State private var isOpen = false

    var body: some View {
        Button { isOpen.toggle() } label: { label }
            .buttonStyle(.borderless)
            .accessibilityIdentifier("devicePicker")
            .accessibilityLabel(accessibilityText)
            .accessibilityHint("Shows connected phones")
            .help("Choose the phone Airlock works on")
            .popover(isPresented: $isOpen, arrowEdge: .bottom) {
                DeviceList(devices: devices) {
                    isOpen = false
                    connectOverWiFi()
                } onChoose: {
                    isOpen = false
                }
            }
    }

    private var label: some View {
        HStack(spacing: Spacing.small) {
            Image(systemName: symbol)
                .font(.title3)
                .foregroundStyle(.secondary)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 0) {
                Text(title).font(.headline).lineLimit(1)
                if let subtitle { Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1) }
            }
            Image(systemName: "chevron.down").font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
        }
        .padding(.horizontal, Spacing.small)
        .padding(.vertical, 2)
        .contentShape(Rectangle())
        .accessibilityHidden(true)
    }

    private var selected: ConnectedDevice? { devices.selectedDevice }

    private var symbol: String {
        guard let selected else { return "iphone.slash" }
        return selected.serial.isWireless ? "wifi" : "iphone"
    }

    private var title: String {
        guard let selected else { return "No phone connected" }
        return DeviceRow.name(of: selected, info: devices.details[selected.serial])
    }

    private var subtitle: String? {
        guard let selected else { return nil }
        return DeviceRow.status(of: selected.state, info: devices.details[selected.serial],
                                failed: devices.detailErrors[selected.serial] != nil)
    }

    private var accessibilityText: String {
        guard let selected else { return "No phone connected" }
        let connection = selected.serial.isWireless ? "connected over Wi-Fi" : "connected by USB"
        return [title, subtitle, connection].compactMap { $0 }.joined(separator: ", ")
    }
}

/// Every device with its status; choosing one makes it the target, and choosing one that failed retries it.
struct DeviceList: View {
    let devices: DevicesModel
    let connectOverWiFi: () -> Void
    let onChoose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.xSmall) {
            if devices.devices.isEmpty {
                Text("No phone connected").foregroundStyle(.secondary).padding(Spacing.small)
            }
            ForEach(devices.devices) { device in
                Button {
                    devices.selectedSerial = device.serial
                    if devices.detailErrors[device.serial] != nil {
                        Task { await devices.loadDetails(device.serial) }
                    }
                    onChoose()
                } label: {
                    DeviceRow(
                        device: device, info: devices.details[device.serial],
                        failed: devices.detailErrors[device.serial] != nil,
                        isSelected: device.serial == devices.selectedSerial
                    )
                    .padding(.horizontal, Spacing.small)
                    .padding(.vertical, Spacing.xSmall)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("device-\(device.serial.rawValue)")
            }
            Divider().padding(.vertical, Spacing.xSmall)
            Button("Connect over Wi-Fi…", systemImage: "wifi", action: connectOverWiFi)
                .buttonStyle(.borderless)
                .padding(.horizontal, Spacing.small)
                .accessibilityIdentifier("connectWiFiFromDevices")
        }
        .padding(Spacing.small)
        .frame(width: 300)
    }
}

/// One device: how it is connected, its name, and its state.
struct DeviceRow: View {
    let device: ConnectedDevice
    let info: DeviceInfo?
    /// Reading the device's details failed; the row says so and a click retries.
    let failed: Bool
    let isSelected: Bool

    var body: some View {
        HStack(spacing: Spacing.medium) {
            Image(systemName: device.serial.isWireless ? "wifi" : "cable.connector")
                .font(.title3)
                .foregroundStyle(.secondary)
                .frame(width: 22)
                .accessibilityLabel(device.serial.isWireless ? "Wi-Fi" : "USB")
            VStack(alignment: .leading, spacing: 2) {
                Text(Self.name(of: device, info: info)).font(.headline)
                Text(status).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if isSelected {
                Image(systemName: "checkmark").foregroundStyle(Color.accentColor).accessibilityLabel("Selected")
            }
        }
    }

    private var status: String { Self.status(of: device.state, info: info, failed: failed) }

    /// The friendly name once details are read; until then adb's model with spaces, or the serial.
    nonisolated static func name(of device: ConnectedDevice, info: DeviceInfo?) -> String {
        info?.displayName ?? device.model?.replacingOccurrences(of: "_", with: " ") ?? device.serial.rawValue
    }

    nonisolated static func status(of state: DeviceConnectionState, info: DeviceInfo?, failed: Bool) -> String {
        switch state {
        case .ready:
            if let info { details(of: info) } else if failed { "Couldn't read details. Click to retry." } else { "Reading details…" }
        case .unauthorized, .authorizing: "Waiting for Allow"
        case .offline: "Not responding"
        case .noPermissions: "No permission"
        case .other(let mode): mode.capitalized
        }
    }

    /// "SM-S928B · Android 16 · 87%": the model code stays visible under a friendly name.
    nonisolated static func details(of info: DeviceInfo) -> String {
        let model = info.displayName == info.model ? [] : [info.model]
        let battery = info.batteryPercent.map { ["\($0)%"] } ?? []
        return (model + ["Android \(info.androidVersion)"] + battery).joined(separator: " · ")
    }
}

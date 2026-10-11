// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import SwiftUI

public enum Section: String, CaseIterable, Identifiable, Hashable {
    case install = "Install"
    case apps = "Apps"
    case history = "History"
    case wireless = "Wireless"

    public var id: String { rawValue }

    var symbol: String {
        switch self {
        case .install: "square.and.arrow.down.on.square"
        case .apps: "square.grid.2x2"
        case .history: "clock.arrow.circlepath"
        case .wireless: "wifi"
        }
    }
}

/// The main window: devices and sections in the sidebar, the selected section on the right.
public struct RootView: View {
    let environment: AppEnvironment
    @State private var section: Section? = .install

    public init(environment: AppEnvironment) {
        self.environment = environment
    }

    public var body: some View {
        NavigationSplitView {
            Sidebar(devices: environment.devices, section: $section)
                .navigationSplitViewColumnWidth(min: 220, ideal: 240)
        } detail: {
            detail
                .frame(minWidth: 560, minHeight: 480)
        }
        .task { await environment.devices.run() }
        .onChange(of: environment.devices.selectedSerial, initial: true) { _, serial in
            environment.installQueue.targetDevice = environment.devices.stage == .ready ? serial : nil
            environment.apps.device = serial
        }
        .onChange(of: environment.devices.stage) { _, stage in
            environment.installQueue.targetDevice = stage == .ready ? environment.devices.selectedSerial : nil
        }
    }

    @ViewBuilder private var detail: some View {
        if let problem = environment.startupProblem {
            ContentUnavailableView("Airlock cannot start", systemImage: "exclamationmark.triangle", description: Text(problem))
                .accessibilityIdentifier("startupProblem")
        } else if section == .wireless {
            let usb = environment.devices.stage == .ready ? environment.devices.selectedSerial : nil
            PairingView(model: environment.pairing, usbSerial: usb)
        } else if environment.devices.stage != .ready {
            OnboardingView(
                stage: environment.devices.stage,
                brand: environment.devices.selectedInfo?.brand ?? .other
            )
        } else {
            switch section ?? .install {
            case .install: InstallView(queue: environment.installQueue, device: environment.devices.selectedInfo)
            case .apps: AppsView(model: environment.apps, brand: environment.devices.selectedInfo?.brand ?? .other)
            case .history: HistoryView(model: environment.apps)
            case .wireless: EmptyView()
            }
        }
    }
}

struct Sidebar: View {
    let devices: DevicesModel
    @Binding var section: Section?

    var body: some View {
        List(selection: $section) {
            SwiftUI.Section("Devices") {
                if devices.devices.isEmpty {
                    Label("No phone connected", systemImage: "iphone.slash")
                }
                ForEach(devices.devices) { device in
                    DeviceRow(device: device, info: devices.details[device.serial], isSelected: device.serial == devices.selectedSerial)
                        .contentShape(Rectangle())
                        .onTapGesture { devices.selectedSerial = device.serial }
                        .accessibilityIdentifier("device-\(device.serial.rawValue)")
                }
            }
            SwiftUI.Section("Airlock") {
                ForEach(Section.allCases) { item in
                    Label(item.rawValue, systemImage: item.symbol)
                        .tag(item)
                        .accessibilityIdentifier("section-\(item.rawValue)")
                }
            }
        }
        .listStyle(.sidebar)
    }
}

struct DeviceRow: View {
    let device: ConnectedDevice
    let info: DeviceInfo?
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: device.serial.isWireless ? "wifi" : "cable.connector")
                .foregroundStyle(isSelected ? Color.accentColor : .secondary)
                .accessibilityLabel(device.serial.isWireless ? "Wi-Fi" : "USB")
            VStack(alignment: .leading, spacing: 2) {
                Text(info?.model ?? device.model?.replacingOccurrences(of: "_", with: " ") ?? device.serial.rawValue)
                    .fontWeight(isSelected ? .semibold : .regular)
                Text(status).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var status: String {
        switch device.state {
        case .ready:
            if let info { "Android \(info.androidVersion)" + (info.batteryPercent.map { " · \($0)%" } ?? "") } else { "Connected" }
        case .unauthorized, .authorizing: "Waiting for Allow"
        case .offline: "Not responding"
        case .noPermissions: "No permission"
        case .other(let mode): mode.capitalized
        }
    }
}

struct OnboardingView: View {
    let stage: OnboardingStage
    let brand: DeviceBrand
    @State private var chosenBrand: DeviceBrand?

    var body: some View {
        let explanation = OnboardingGuide.explanation(for: stage)
        let shownBrand = chosenBrand ?? brand
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(explanation.title).font(.largeTitle.bold()).accessibilityIdentifier("onboardingTitle")
                    Text(explanation.detail).font(.title3)
                }
                Picker("Phone brand", selection: Binding(get: { shownBrand }, set: { chosenBrand = $0 })) {
                    ForEach(DeviceBrand.allCases, id: \.self) { Text(OnboardingGuide.title(for: $0)).tag($0) }
                }
                .pickerStyle(.segmented)
                .accessibilityIdentifier("brandPicker")
                ForEach(Array(OnboardingGuide.steps(for: shownBrand).enumerated()), id: \.element.id) { index, step in
                    HStack(alignment: .top, spacing: 14) {
                        Image(systemName: step.symbol)
                            .font(.title2)
                            .frame(width: 36)
                            .foregroundStyle(Color.accentColor)
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 4) {
                            Text("\(index + 1). \(step.title)").font(.headline)
                            Text(step.detail).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .accessibilityElement(children: .combine)
                }
            }
            .padding(32)
            .frame(maxWidth: 720, alignment: .leading)
        }
    }
}

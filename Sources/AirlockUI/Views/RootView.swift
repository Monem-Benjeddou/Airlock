// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation
import SwiftUI

public enum Section: String, CaseIterable, Identifiable, Hashable {
    case install = "Install"
    case apps = "Apps"
    case history = "History"

    public var id: String { rawValue }

    /// The page to open on: `AIRLOCK_SECTION=apps` (any case), for screenshots and previews. Install otherwise.
    public static func initial(_ environment: [String: String] = ProcessInfo.processInfo.environment) -> Section {
        let wanted = environment["AIRLOCK_SECTION"]?.lowercased()
        return allCases.first { $0.rawValue.lowercased() == wanted } ?? .install
    }

    var symbol: String {
        switch self {
        case .install: "square.and.arrow.down.on.square"
        case .apps: "square.grid.2x2"
        case .history: "clock.arrow.circlepath"
        }
    }
}

/// The main window: pages in the sidebar, the phone in the toolbar, the selected page on the right.
public struct RootView: View {
    let environment: AppEnvironment
    @State private var section: Section?
    @State private var showWiFi: Bool

    public init(environment: AppEnvironment, section: Section = .initial()) {
        self.environment = environment
        _section = State(initialValue: section)
        _showWiFi = State(initialValue: ProcessInfo.processInfo.environment["AIRLOCK_SHOW_WIFI"] == "1")
    }

    public var body: some View {
        NavigationSplitView {
            Sidebar(environment: environment, section: $section) { showWiFi = true }
                .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 260)
        } detail: {
            detail
                .frame(minWidth: 560, minHeight: 480)
                .navigationTitle((section ?? .install).rawValue)
                .toolbar {
                    ToolbarItem(placement: .principal) {
                        DevicePicker(devices: environment.devices) { showWiFi = true }
                    }
                }
                // On the detail column, like the review sheet: attached to the split view, the sheet failed the
                // accessibility audit's parent/child check.
                .sheet(isPresented: $showWiFi) {
                    let usb = environment.devices.stage == .ready ? environment.devices.selectedSerial : nil
                    WiFiSheet(model: environment.pairing, usbSerial: usb)
                }
        }
        .task { await environment.devices.run() }
        .task { await environment.pairing.reconnectRemembered() }
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
            }
        }
    }
}

/// Pages only, each with a count, and Wi-Fi pairing at the bottom.
struct Sidebar: View {
    let environment: AppEnvironment
    @Binding var section: Section?
    let connectOverWiFi: () -> Void

    var body: some View {
        List(selection: $section) {
            ForEach(Section.allCases) { item in
                Label(item.rawValue, systemImage: item.symbol)
                    .badge(Self.badge(for: item, environment: environment))
                    .tag(item)
                    .accessibilityIdentifier("section-\(item.rawValue)")
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            Button(action: connectOverWiFi) {
                Label("Connect over Wi-Fi…", systemImage: "wifi")
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .buttonStyle(.borderless)
            .padding(Spacing.medium)
            .accessibilityIdentifier("connectWiFi")
        }
    }

    /// Files still in the queue, apps on the phone, and recorded changes. Zero shows no badge.
    @MainActor
    static func badge(for section: Section, environment: AppEnvironment) -> Int {
        switch section {
        case .install: environment.installQueue.items.filter { !$0.state.isFinished }.count
        case .apps: environment.apps.apps.count
        case .history: environment.apps.history.count
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

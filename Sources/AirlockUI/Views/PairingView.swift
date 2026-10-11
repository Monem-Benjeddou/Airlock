// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import AirlockPairing
import SwiftUI

/// The ways to pair: QR for Android 11 and later, a pairing code when scanning isn't possible, and legacy
/// TCP mode over USB for older phones.
enum PairingMethod: String, CaseIterable, Identifiable {
    case qr = "QR Code"
    case code = "Pairing Code"
    case legacy = "Android 10 and Older"

    var id: Self { self }
}

/// F5: pair over Wi-Fi. The QR code shows straight away; the other methods are one tab away.
struct PairingView: View {
    @Bindable var model: PairingModel
    let usbSerial: DeviceSerial?
    @State private var method = PairingMethod.qr

    var body: some View {
        Form {
            SwiftUI.Section {
                Picker("Method", selection: $method) {
                    ForEach(PairingMethod.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .accessibilityIdentifier("pairingMethod")
            }
            switch method {
            case .qr: qrSection
            case .code: codeSection
            case .legacy: legacySection
            }
            if !model.remembered.isEmpty { rememberedSection }
        }
        .formStyle(.grouped)
        .onChange(of: method, initial: true) { _, method in
            if method == .qr, model.state == .idle { model.startQRPairing() }
            if method != .qr, model.state == .waitingForScan { model.stop() }
        }
        .onDisappear { model.stop() }
    }

    private var qrSection: some View {
        SwiftUI.Section {
            Text("On your phone, open Developer options › Wireless debugging › Pair device with QR code, then scan this code.")
                .foregroundStyle(.secondary)
            switch model.state {
            case .waitingForScan:
                if let image = model.qrImage {
                    Image(image, scale: 1, label: Text("Pairing QR code")).interpolation(.none).resizable()
                        .frame(width: 220, height: 220)
                        .frame(maxWidth: .infinity)
                        .accessibilityIdentifier("pairingQR")
                }
                HStack(spacing: Spacing.small) {
                    ProgressView().controlSize(.small)
                    Text("Waiting for your phone…")
                    Spacer()
                    Button("Stop") { model.stop() }
                }
            case .paired(let device):
                Label("Connected to \(device.name) at \(device.host)", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(Palette.success)
                Button("Pair Another Phone") { model.startQRPairing() }
            case .failed(let error):
                PairingProblem(error: error)
                Button("Show a New QR Code") { model.startQRPairing() }
            case .idle:
                Button("Show QR Code") { model.startQRPairing() }.accessibilityIdentifier("showQR")
            }
        }
    }

    private var codeSection: some View {
        SwiftUI.Section {
            Text("On your phone, tap Pair device with pairing code and enter what it shows.")
                .foregroundStyle(.secondary)
            TextField("IP address", text: $model.codeHost, prompt: Text("192.168.1.20"))
            TextField("Pairing port", text: $model.codePort, prompt: Text("37000"))
            TextField("Pairing code", text: $model.code, prompt: Text("Six digits"))
            TextField("Connect port", text: $model.connectPort, prompt: Text("Under IP address & Port"))
                .help("The port shown under IP address & Port on the Wireless debugging screen.")
            Button("Pair") { Task { await model.pairWithCode() } }.disabled(!model.canSubmitCode)
            if case .failed(let error) = model.state { PairingProblem(error: error) }
        }
    }

    private var legacySection: some View {
        SwiftUI.Section {
            Text("Connect the phone by USB first. Airlock switches it to wireless mode on port 5555; "
                + "it stays available until the phone restarts.")
                .foregroundStyle(.secondary)
            Button("Switch to Wireless") {
                if let usbSerial { Task { await model.enableLegacy(usb: usbSerial) } }
            }
            .disabled(usbSerial == nil)
        }
    }

    private var rememberedSection: some View {
        SwiftUI.Section("Paired phones") {
            ForEach(model.remembered, id: \.name) { device in
                LabeledContent("\(device.name)") {
                    Text("\(device.host):\(device.port)").foregroundStyle(.secondary)
                    Button("Forget") { model.forget(device) }
                }
            }
        }
    }
}

/// The app's Settings window.
public struct SettingsView: View {
    @Bindable var model: SettingsModel

    public init(model: SettingsModel) {
        self.model = model
    }

    public var body: some View {
        Form {
            SwiftUI.Section("VirusTotal") {
                Text("Airlock can look up a file's SHA-256 hash on VirusTotal with your own free API key. "
                    + "Only the hash is sent: never the file, its name or your apps.")
                if model.hasKey {
                    LabeledContent("API key", value: "Saved in your keychain")
                    Button("Remove Key", role: .destructive) { model.removeKey() }
                } else {
                    SecureField("API key", text: $model.keyInput)
                    Button("Save Key") { model.saveKey() }
                }
                if let message = model.message { Text(message).font(.caption) }
            }
        }
        .formStyle(.grouped)
        .frame(width: 480)
        .padding()
    }
}

/// Why pairing failed: a short headline, then what to try as a list, wrapped to the sheet's width.
struct PairingProblem: View {
    let error: PairingError

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.small) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Palette.warning).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Spacing.xSmall) {
                Text(Self.headline(of: error)).font(.headline)
                ForEach(Self.tips(for: error), id: \.self) { tip in
                    Text("• " + tip).foregroundStyle(.secondary)
                }
            }
            .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("pairingError")
    }

    nonisolated static func headline(of error: PairingError) -> String {
        if case .notFound(let diagnosis) = error { diagnosis.title } else { error.explanation }
    }

    nonisolated static func tips(for error: PairingError) -> [String] {
        if case .notFound(let diagnosis) = error { diagnosis.suggestions } else { [] }
    }
}

/// Wi-Fi pairing as a sheet: a one-time setup task, not a page.
struct WiFiSheet: View {
    let model: PairingModel
    let usbSerial: DeviceSerial?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: Spacing.xSmall) {
                Text("Connect over Wi-Fi").font(.title2.bold()).accessibilityAddTraits(.isHeader)
                Text("Pair once; after that Airlock reconnects whenever your phone is on the same network.")
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding([.horizontal, .top], Spacing.xLarge)
            PairingView(model: model, usbSerial: usbSerial)
            Divider()
            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("closeWiFi")
            }
            .padding(Spacing.large)
        }
        .frame(minWidth: 560, idealWidth: 600, minHeight: 560, idealHeight: 640)
        .onChange(of: model.state) { _, state in
            // Close once the phone connects, after a moment to read the confirmation.
            guard case .paired = state else { return }
            Task {
                try? await Task.sleep(for: .seconds(1.5))
                dismiss()
            }
        }
    }
}

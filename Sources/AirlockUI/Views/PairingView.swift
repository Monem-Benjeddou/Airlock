// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import AirlockPairing
import SwiftUI

/// F5: pair over Wi-Fi with a QR code, a pairing code, or legacy mode over USB.
struct PairingView: View {
    @Bindable var model: PairingModel
    let usbSerial: DeviceSerial?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Wireless debugging").font(.largeTitle.bold())
                GroupBox("Pair with a QR code (Android 11 and later)") { qrSection }
                GroupBox("Pair with a pairing code") { codeSection }
                GroupBox("Older phones (Android 10 and earlier)") { legacySection }
                if !model.remembered.isEmpty {
                    GroupBox("Paired phones") { rememberedSection }
                }
            }
            .padding(28)
            .frame(maxWidth: 720, alignment: .leading)
        }
        .task { await model.reconnectRemembered() }
        .onDisappear { model.stop() }
    }

    @ViewBuilder private var qrSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("On your phone, open Developer options › Wireless debugging › Pair device with QR code, then scan this code.")
                .foregroundStyle(.secondary)
            switch model.state {
            case .waitingForScan:
                if let image = model.qrImage {
                    Image(decorative: image, scale: 1).interpolation(.none).resizable().frame(width: 220, height: 220)
                        .accessibilityIdentifier("pairingQR")
                }
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Waiting for your phone…")
                    Button("Stop") { model.stop() }
                }
            case .paired(let device):
                Label("Connected to \(device.name) at \(device.host)", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                Button("Pair Another Phone") { model.startQRPairing() }
            case .failed(let error):
                Label(error.explanation, systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                    .accessibilityIdentifier("pairingError")
                Button("Try Again") { model.startQRPairing() }
            case .idle:
                Button("Show QR Code") { model.startQRPairing() }.accessibilityIdentifier("showQR")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var codeSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Tap Pair device with pairing code on your phone and enter what it shows.").foregroundStyle(.secondary)
            HStack {
                TextField("IP address", text: $model.codeHost).frame(width: 150)
                TextField("Port", text: $model.codePort).frame(width: 70)
                TextField("Six-digit code", text: $model.code).frame(width: 110)
                TextField("Connect port", text: $model.connectPort).frame(width: 100)
                    .help("The port shown under IP address & Port on the Wireless debugging screen.")
            }
            .textFieldStyle(.roundedBorder)
            Button("Pair") { Task { await model.pairWithCode() } }.disabled(!model.canSubmitCode)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var legacySection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Connect the phone by USB first. Airlock switches it to wireless mode on port 5555; "
                + "it stays available until the phone restarts.")
                .foregroundStyle(.secondary)
            Button("Switch to Wireless") {
                if let usbSerial { Task { await model.enableLegacy(usb: usbSerial) } }
            }
            .disabled(usbSerial == nil)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var rememberedSection: some View {
        VStack(alignment: .leading) {
            ForEach(model.remembered, id: \.name) { device in
                HStack {
                    Text("\(device.name) · \(device.host):\(device.port)")
                    Spacer()
                    Button("Forget") { model.forget(device) }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
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
                    .foregroundStyle(.secondary)
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

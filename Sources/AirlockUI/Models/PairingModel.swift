// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import AirlockPairing
import CoreGraphics
import Foundation
import Observation

/// F5: QR pairing with pairing-code and legacy fallbacks.
@MainActor
@Observable
public final class PairingModel {
    public enum State: Equatable, Sendable {
        case idle
        case waitingForScan
        case paired(PairedDevice)
        case failed(PairingError)
    }

    public private(set) var state: State = .idle
    public private(set) var session: PairingSession?
    public private(set) var remembered: [PairedDevice] = []
    public var codeHost = ""
    public var codePort = ""
    public var code = ""
    public var connectPort = ""

    private let pairing: any WirelessPairing
    private var task: Task<Void, Never>?

    public init(pairing: any WirelessPairing) {
        self.pairing = pairing
        remembered = pairing.rememberedDevices()
    }

    public var qrImage: CGImage? {
        session.map { QRCodeRenderer.image(for: $0.qrPayload, scale: 8) } ?? nil
    }

    public func startQRPairing() {
        task?.cancel()
        let session = PairingSession.random()
        self.session = session
        state = .waitingForScan
        let pairing = pairing
        task = Task { [weak self] in
            do throws(PairingError) {
                let device = try await pairing.pairWithQR(session)
                self?.finish(.paired(device))
            } catch {
                if error != .cancelled { self?.finish(.failed(error)) }
            }
        }
    }

    public func stop() {
        task?.cancel()
        task = nil
        session = nil
        state = .idle
    }

    public var canSubmitCode: Bool {
        !codeHost.isEmpty && Int(codePort) != nil && code.count == 6 && Int(connectPort) != nil
    }

    public func pairWithCode() async {
        guard let port = Int(codePort), let connect = Int(connectPort) else {
            state = .failed(.invalidInput)
            return
        }
        do {
            finish(.paired(try await pairing.pairWithCode(host: codeHost, pairingPort: port, code: code, connectPort: connect)))
        } catch {
            finish(.failed(error))
        }
    }

    public func enableLegacy(usb serial: DeviceSerial) async {
        do {
            finish(.paired(try await pairing.enableLegacyWireless(usb: serial, port: 5555)))
        } catch {
            finish(.failed(error))
        }
    }

    public func reconnectRemembered() async {
        _ = await pairing.reconnectRemembered()
        remembered = pairing.rememberedDevices()
    }

    public func forget(_ device: PairedDevice) {
        pairing.forget(device)
        remembered = pairing.rememberedDevices()
    }

    private func finish(_ newState: State) {
        state = newState
        task = nil
        if case .paired = newState { session = nil }
        remembered = pairing.rememberedDevices()
    }
}

extension PairingError {
    /// Plain-language explanation for the UI.
    public var explanation: String {
        switch self {
        case .notFound(let diagnosis): diagnosis.title + ". " + diagnosis.suggestions.joined(separator: " ")
        case .wrongCode: "The pairing code was not accepted. Check the code on your phone and try again."
        case .unreachable: "Airlock could not reach your phone. Make sure it is on the same Wi-Fi network and the pairing screen is open."
        case .pairedButNotConnected: "Your phone is paired but did not offer a connection. Toggle Wireless debugging off and on, then try again."
        case .phoneNotOnWiFi: "Your phone is not connected to Wi-Fi."
        case .invalidInput: "Check the address, ports and code."
        case .cancelled: "Pairing was cancelled."
        case .failed(let message): message
        }
    }
}

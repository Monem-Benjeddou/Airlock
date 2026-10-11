// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockADB
import AirlockCore
import Foundation

/// A phone paired for wireless debugging, remembered for reconnecting on launch.
public struct PairedDevice: Hashable, Sendable, Codable {
    /// mDNS instance name (`adb-<serial>-<suffix>`) or the USB serial for legacy mode.
    public let name: String
    public let host: String
    public let port: Int

    public init(name: String, host: String, port: Int) {
        self.name = name
        self.host = host
        self.port = port
    }
}

public protocol PairedDeviceStore: Sendable {
    func load() -> [PairedDevice]
    func save(_ devices: [PairedDevice])
}

public struct UserDefaultsPairedDeviceStore: PairedDeviceStore, @unchecked Sendable {
    private let defaults: UserDefaults
    private let key = "pairedDevices"

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    public func load() -> [PairedDevice] {
        guard let data = defaults.data(forKey: key) else { return [] }
        return (try? JSONDecoder().decode([PairedDevice].self, from: data)) ?? []
    }

    public func save(_ devices: [PairedDevice]) {
        defaults.set(try? JSONEncoder().encode(devices), forKey: key)
    }
}

public enum PairingError: Error, Hashable, Sendable {
    /// The phone's pairing service did not appear in time.
    case notFound(NetworkDiagnosis)
    case wrongCode
    case unreachable
    case pairedButNotConnected
    case phoneNotOnWiFi
    case invalidInput
    case cancelled
    case failed(String)
}

/// F5: wireless pairing by QR code, pairing code, or legacy `adb tcpip`.
///
/// Discovery uses adb's own mDNS client (`adb mdns services`); Airlock never listens on a port.
public struct PairingService: Sendable {
    private let adb: ADBClient
    private let network: any NetworkInspector
    private let store: any PairedDeviceStore
    private let scanTimeout: Duration
    private let discoveryTimeout: Duration
    private let pollInterval: Duration

    public init(
        adb: ADBClient,
        network: any NetworkInspector = SystemNetworkInspector(),
        store: any PairedDeviceStore = UserDefaultsPairedDeviceStore(),
        scanTimeout: Duration = .seconds(180),
        discoveryTimeout: Duration = .seconds(10),
        pollInterval: Duration = .seconds(1)
    ) {
        self.adb = adb
        self.network = network
        self.store = store
        self.scanTimeout = scanTimeout
        self.discoveryTimeout = discoveryTimeout
        self.pollInterval = pollInterval
    }

    // MARK: QR

    /// Waits for the phone that scanned `session`'s QR code, pairs, then connects. The wait for the scan is long
    /// (`scanTimeout`): the person has to find Wireless debugging on the phone first.
    public func pairWithQR(_ session: PairingSession) async throws(PairingError) -> PairedDevice {
        let pairingService = try await discover(for: scanTimeout) {
            $0.type == .pairing && $0.instance == session.serviceName
        }
        guard let pairingService else { throw .notFound(await diagnose(phoneAddress: nil)) }

        let guid = try await pair(host: pairingService.host, port: pairingService.port, code: session.password)
        let connectService = try await discover(for: discoveryTimeout) {
            $0.type == .connect && (guid.map($0.instance.hasPrefix) ?? true)
        }
        guard let connectService else { throw .pairedButNotConnected }
        return try await connect(name: connectService.instance, host: connectService.host, port: connectService.port)
    }

    // MARK: Fallbacks

    /// "Pair with pairing code": the user types the address, port and six-digit code shown on the phone.
    public func pairWithCode(host: String, pairingPort: Int, code: String, connectPort: Int) async throws(PairingError) -> PairedDevice {
        let guid = try await pair(host: host, port: pairingPort, code: code)
        return try await connect(name: guid ?? host, host: host, port: connectPort)
    }

    /// Legacy wireless for Android 10 and older: switches a USB-connected phone to `adb tcpip 5555`.
    public func enableLegacyWireless(usb serial: DeviceSerial, port: Int = 5555) async throws(PairingError) -> PairedDevice {
        let channel = adb.device(serial)
        let address = try await adbCall { try await channel.wifiAddress() }
        guard let address else { throw .phoneNotOnWiFi }
        try await adbCall { try await channel.enableTCPIP(port: port) }
        return try await connect(name: serial.rawValue, host: address, port: port)
    }

    // MARK: Remembered devices

    /// Reconnects every remembered device that is reachable, preferring addresses currently advertised over mDNS.
    public func reconnectRemembered() async -> [PairedDevice] {
        let advertised = (try? await adb.mdnsServices())?.filter { $0.type == .connect } ?? []
        var connected: [PairedDevice] = []
        for device in store.load() {
            let current = advertised.first { $0.instance == device.name }
            let host = current?.host ?? device.host
            let port = current?.port ?? device.port
            if let result = try? await connect(name: device.name, host: host, port: port) { connected.append(result) }
        }
        return connected
    }

    public func rememberedDevices() -> [PairedDevice] { store.load() }

    public func forget(_ device: PairedDevice) {
        store.save(store.load().filter { $0.name != device.name })
    }

    // MARK: Diagnosis

    /// Explains why discovery found nothing. `phoneAddress` is known when the phone is also on USB.
    public func diagnose(phoneAddress: String?) async -> NetworkDiagnosis {
        let addresses = network.localIPv4Addresses()
        guard let primary = addresses.first else { return .macNotOnNetwork }
        guard (try? await adb.mdnsCheck()) == true else { return .discoveryUnavailable }
        if let phoneAddress, !addresses.contains(where: { $0.contains(phoneAddress) }) {
            return .differentNetworks(mac: primary.address, phone: phoneAddress)
        }
        return .noServiceSeen
    }

    // MARK: Steps

    private func discover(
        for timeout: Duration, _ matches: @Sendable (MdnsService) -> Bool
    ) async throws(PairingError) -> MdnsService? {
        let deadline = ContinuousClock.now + timeout
        repeat {
            if Task.isCancelled { throw .cancelled }
            let services = try await adbCall { try await adb.mdnsServices() }
            if let found = services.first(where: matches) { return found }
            do {
                try await Task.sleep(for: pollInterval)
            } catch {
                throw .cancelled
            }
        } while ContinuousClock.now < deadline
        return nil
    }

    /// Returns the guid (mDNS instance name of the phone's connect service) when adb reports one.
    private func pair(host: String, port: Int, code: String) async throws(PairingError) -> String? {
        let result: PairResult
        do {
            result = try await adb.pair(host: host, port: port, code: code)
        } catch .invalidArgument {
            throw .invalidInput
        } catch {
            throw Self.map(error)
        }
        switch result {
        case .paired(let guid): return guid
        case .wrongCode: throw .wrongCode
        case .unreachable: throw .unreachable
        case .failed(let message): throw .failed(message)
        }
    }

    private func connect(name: String, host: String, port: Int) async throws(PairingError) -> PairedDevice {
        let result: ConnectResult
        do {
            result = try await adb.connect(host: host, port: port)
        } catch .invalidArgument {
            throw .invalidInput
        } catch {
            throw Self.map(error)
        }
        guard result == .connected else {
            if case .failed(let message) = result { throw .failed(message) }
            throw .unreachable
        }
        let device = PairedDevice(name: name, host: host, port: port)
        var devices = store.load()
        if let index = devices.firstIndex(where: { $0.name == name }) {
            devices[index] = device
        } else {
            devices.append(device)
        }
        store.save(devices)
        return device
    }

    private func adbCall<T>(_ body: () async throws -> T) async throws(PairingError) -> T {
        do {
            return try await body()
        } catch let error as ADBError {
            throw Self.map(error)
        } catch {
            throw .failed(String(describing: error))
        }
    }

    private static func map(_ error: ADBError) -> PairingError {
        if case .process(.cancelled) = error { return .cancelled }
        return .failed(String(describing: error))
    }
}

/// What the UI needs from pairing; ``PairingService`` is the real implementation.
public protocol WirelessPairing: Sendable {
    func pairWithQR(_ session: PairingSession) async throws(PairingError) -> PairedDevice
    func pairWithCode(host: String, pairingPort: Int, code: String, connectPort: Int) async throws(PairingError) -> PairedDevice
    func enableLegacyWireless(usb serial: DeviceSerial, port: Int) async throws(PairingError) -> PairedDevice
    func reconnectRemembered() async -> [PairedDevice]
    func rememberedDevices() -> [PairedDevice]
    func forget(_ device: PairedDevice)
    func diagnose(phoneAddress: String?) async -> NetworkDiagnosis
}

extension PairingService: WirelessPairing {}

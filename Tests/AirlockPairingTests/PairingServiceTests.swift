// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockADB
import AirlockCore
@testable import AirlockPairing
import AirlockTestSupport
import Foundation
import Testing

private func makeADB(_ fake: FakeADB) -> ADBClient {
    ADBClient(configuration: ADBConfiguration(executable: URL(fileURLWithPath: "/fake/adb"), homeDirectory: "/Users/test"), runner: fake)
}

struct FixedNetwork: NetworkInspector {
    var addresses: [LocalAddress]
    func localIPv4Addresses() -> [LocalAddress] { addresses }
}

final class MemoryStore: PairedDeviceStore, @unchecked Sendable {
    private let lock = NSLock()
    private var devices: [PairedDevice] = []
    func load() -> [PairedDevice] { lock.withLock { devices } }
    func save(_ devices: [PairedDevice]) { lock.withLock { self.devices = devices } }
}

private let wifi = FixedNetwork(addresses: [LocalAddress(interface: "en0", address: "192.168.1.10", netmask: "255.255.255.0")])

private func service(
    _ fake: FakeADB,
    network: FixedNetwork = wifi,
    store: MemoryStore = MemoryStore(),
    timeout: Duration = .seconds(10)
) -> PairingService {
    PairingService(adb: makeADB(fake), network: network, store: store, discoveryTimeout: timeout, pollInterval: .milliseconds(5))
}

@Suite("QR pairing payload")
struct QRPayloadTests {
    @Test func payloadFollowsTheAndroidStudioFormat() {
        let session = PairingSession.random()
        #expect(session.qrPayload == "WIFI:T:ADB;S:\(session.serviceName);P:\(session.password);;")
        #expect(session.serviceName.hasPrefix("airlock-"))
        #expect(session.password.count == 12)
    }

    @Test func namesAndPasswordsNeedNoEscaping() {
        for _ in 0..<200 {
            let session = PairingSession.random()
            let text = session.serviceName + session.password
            #expect(text.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") })
        }
    }

    @Test func sessionsAreUnique() {
        let names = Set((0..<100).map { _ in PairingSession.random().password })
        #expect(names.count == 100)
    }

    @Test func qrImageIsGenerated() throws {
        let image = try #require(QRCodeRenderer.image(for: PairingSession.random().qrPayload, scale: 8))
        #expect(image.width >= 200)
        #expect(image.width == image.height)
    }
}

@Suite("PairingService QR flow")
struct QRPairingTests {
    @Test func pairsWhenThePhoneAdvertisesOurServiceThenConnects() async throws {
        let fake = FakeADB()
        let session = PairingSession(serviceName: "airlock-abc123", password: "Pw1234567890")
        fake.on(["mdns", "services"], .ok("List of discovered mdns services\n"))
        fake.on(["mdns", "services"], .ok("List of discovered mdns services\nairlock-abc123\t_adb-tls-pairing._tcp\t192.168.1.20:37099\n"))
        fake.on(["pair", "192.168.1.20:37099", "Pw1234567890"], .ok("Successfully paired to 192.168.1.20:37099 [guid=adb-R58M-x]\n"))
        fake.on(["mdns", "services"], .ok("List of discovered mdns services\nadb-R58M-x\t_adb-tls-connect._tcp\t192.168.1.20:41235\n"))
        fake.on(["connect", "192.168.1.20:41235"], .ok("connected to 192.168.1.20:41235\n"))
        let store = MemoryStore()
        let result = try await service(fake, store: store).pairWithQR(session)
        #expect(result == PairedDevice(name: "adb-R58M-x", host: "192.168.1.20", port: 41235))
        #expect(store.load() == [result])
    }

    @Test func connectsOnlyToThePhoneThatPaired() async throws {
        // Regression: the guid from `adb pair` was ignored, so another phone's connect service could be used.
        let fake = FakeADB()
        fake.on(["mdns", "services"], .ok("airlock-z\t_adb-tls-pairing._tcp\t10.0.0.5:4000\n"))
        fake.on(["pair", "10.0.0.5:4000", "pw1234"], .ok("Successfully paired to 10.0.0.5:4000 [guid=adb-MINE-1]\n"))
        fake.on(["mdns", "services"], .ok("""
        adb-OTHER-9\t_adb-tls-connect._tcp\t10.0.0.9:5000
        adb-MINE-1\t_adb-tls-connect._tcp\t10.0.0.5:41000
        """))
        fake.on(["connect", "10.0.0.5:41000"], .ok("connected to 10.0.0.5:41000\n"))
        let device = try await service(fake).pairWithQR(PairingSession(serviceName: "airlock-z", password: "pw1234"))
        #expect(device.name == "adb-MINE-1")
        #expect(!fake.calls.contains(["connect", "10.0.0.9:5000"]))
    }

    @Test func qrPasswordIsPassedToAdbPair() async throws {
        // adb pair accepts the QR password in place of a six-digit code.
        let fake = FakeADB()
        let session = PairingSession(serviceName: "airlock-x", password: "abcdefABCDEF")
        fake.on(["mdns", "services"], .ok("airlock-x\t_adb-tls-pairing._tcp\t10.0.0.5:4000\n"))
        fake.on(["pair", "10.0.0.5:4000", "abcdefABCDEF"], .ok("Failed: Wrong password or connection was dropped.\n"))
        await #expect(throws: PairingError.wrongCode) { try await service(fake).pairWithQR(session) }
    }

    @Test func ignoresOtherPairingServices() async throws {
        let fake = FakeADB()
        fake.on(["mdns", "services"], .ok("someone-else\t_adb-tls-pairing._tcp\t192.168.1.30:1\n"))
        fake.on(["mdns", "check"], .ok("mdns daemon version [adb discovery 0.0.0]\n"))
        await #expect(throws: PairingError.self) {
            try await service(fake, timeout: .milliseconds(100)).pairWithQR(PairingSession(serviceName: "airlock-mine", password: "x"))
        }
        #expect(!fake.calls.contains { $0.first == "pair" })
    }

    @Test func timeoutProducesADiagnosis() async throws {
        let fake = FakeADB()
        fake.on(["mdns", "services"], .ok("List of discovered mdns services\n"))
        fake.on(["mdns", "check"], .ok("mdns daemon version [adb discovery 0.0.0]\n"))
        await #expect(throws: PairingError.notFound(.noServiceSeen)) {
            try await service(fake, timeout: .milliseconds(100)).pairWithQR(.random())
        }
    }

    @Test func cancellationStopsDiscovery() async throws {
        let fake = FakeADB()
        fake.on(["mdns", "services"], .ok("List of discovered mdns services\n"))
        let pairing = service(fake, timeout: .seconds(30))
        let task = Task { try await pairing.pairWithQR(.random()) }
        try await fake.waitForCall(containing: "services")
        task.cancel()
        let result = await task.result
        #expect(throws: PairingError.cancelled) { try result.get() }
    }

    @Test func pairedButConnectServiceNeverAppears() async throws {
        let fake = FakeADB()
        fake.on(["mdns", "services"], .ok("airlock-q\t_adb-tls-pairing._tcp\t10.0.0.5:4000\n"))
        fake.on(["pair", "10.0.0.5:4000", "pw1234"], .ok("Successfully paired to 10.0.0.5:4000 [guid=adb-Q-1]\n"))
        fake.on(["mdns", "services"], .ok("List of discovered mdns services\n"))
        fake.on(["mdns", "check"], .ok("mdns daemon version\n"))
        await #expect(throws: PairingError.pairedButNotConnected) {
            try await service(fake, timeout: .milliseconds(100)).pairWithQR(PairingSession(serviceName: "airlock-q", password: "pw1234"))
        }
    }
}

@Suite("PairingService fallbacks")
struct PairingFallbackTests {
    @Test func pairingCodeThenConnectPort() async throws {
        let fake = FakeADB()
        fake.on(["pair", "192.168.1.20:37099", "123456"], .ok("Successfully paired to 192.168.1.20:37099 [guid=adb-R58M-x]\n"))
        fake.on(["connect", "192.168.1.20:41235"], .ok("connected to 192.168.1.20:41235\n"))
        let store = MemoryStore()
        let device = try await service(fake, store: store)
            .pairWithCode(host: "192.168.1.20", pairingPort: 37099, code: "123456", connectPort: 41235)
        #expect(device.port == 41235)
        #expect(store.load().count == 1)
    }

    @Test func pairingCodeErrors() async throws {
        let fake = FakeADB()
        fake.on(["pair", "192.168.1.20:37099", "000000"], .ok("Failed: Wrong password or connection was dropped.\n"))
        fake.on(["pair", "192.168.1.21:37099", "123456"], .ok("error: unable to connect for pairing\n"))
        let pairing = service(fake)
        await #expect(throws: PairingError.wrongCode) {
            try await pairing.pairWithCode(host: "192.168.1.20", pairingPort: 37099, code: "000000", connectPort: 5555)
        }
        await #expect(throws: PairingError.unreachable) {
            try await pairing.pairWithCode(host: "192.168.1.21", pairingPort: 37099, code: "123456", connectPort: 5555)
        }
        await #expect(throws: PairingError.invalidInput) {
            try await pairing.pairWithCode(host: "x;y", pairingPort: 1, code: "123456", connectPort: 5555)
        }
    }

    @Test func legacyTCPIPOverUSB() async throws {
        let fake = FakeADB()
        let serial = try DeviceSerial("R58M")
        fake.on(["-s", "R58M", "shell", "ip", "-4", "-o", "addr", "show", "wlan0"], .ok("3: wlan0 inet 192.168.1.20/24 brd x\n"))
        fake.on(["-s", "R58M", "tcpip", "5555"], .ok("restarting in TCP mode port: 5555\n"))
        fake.on(["connect", "192.168.1.20:5555"], .ok("connected to 192.168.1.20:5555\n"))
        let device = try await service(fake).enableLegacyWireless(usb: serial)
        #expect(device == PairedDevice(name: "R58M", host: "192.168.1.20", port: 5555))
    }

    @Test func legacyWithoutWiFiExplainsWhy() async throws {
        let fake = FakeADB()
        let serial = try DeviceSerial("R58M")
        fake.on(["-s", "R58M", "shell", "ip", "-4", "-o", "addr", "show", "wlan0"], FakeADB.Response(exitCode: 1))
        await #expect(throws: PairingError.phoneNotOnWiFi) { try await service(fake).enableLegacyWireless(usb: serial) }
    }

    @Test func reconnectsRememberedDevices() async throws {
        let fake = FakeADB()
        let store = MemoryStore()
        store.save([
            PairedDevice(name: "adb-A", host: "192.168.1.20", port: 41235),
            PairedDevice(name: "adb-B", host: "192.168.1.21", port: 5555),
        ])
        fake.on(["mdns", "services"], .ok("adb-A\t_adb-tls-connect._tcp\t192.168.1.20:40000\n"))
        fake.on(["connect", "192.168.1.20:40000"], .ok("connected to 192.168.1.20:40000\n"))
        fake.on(["connect", "192.168.1.21:5555"], .ok("failed to connect to '192.168.1.21:5555': Connection refused\n"))
        let connected = await service(fake, store: store).reconnectRemembered()
        #expect(connected == [PairedDevice(name: "adb-A", host: "192.168.1.20", port: 40000)])
        #expect(store.load().first?.port == 40000, "the new port is remembered")
    }

    @Test func forgetRemovesADevice() async throws {
        let store = MemoryStore()
        store.save([PairedDevice(name: "adb-A", host: "h", port: 1)])
        service(FakeADB(), store: store).forget(PairedDevice(name: "adb-A", host: "h", port: 1))
        #expect(store.load().isEmpty)
    }
}

@Suite("Network diagnosis")
struct NetworkDiagnosisTests {
    @Test func macWithoutWiFi() async {
        let fake = FakeADB()
        fake.on(["mdns", "check"], .ok("mdns daemon version\n"))
        let diagnosis = await service(fake, network: FixedNetwork(addresses: [])).diagnose(phoneAddress: nil)
        #expect(diagnosis == .macNotOnNetwork)
    }

    @Test func mdnsUnavailable() async {
        let fake = FakeADB()
        fake.on(["mdns", "check"], .ok("ERROR: mdns discovery disabled\n"))
        #expect(await service(fake).diagnose(phoneAddress: nil) == .discoveryUnavailable)
    }

    @Test func differentSubnets() async {
        let fake = FakeADB()
        fake.on(["mdns", "check"], .ok("mdns daemon version\n"))
        #expect(await service(fake).diagnose(phoneAddress: "10.0.0.7") == .differentNetworks(mac: "192.168.1.10", phone: "10.0.0.7"))
    }

    @Test func sameSubnetButNothingSeenSuggestsIsolation() async {
        let fake = FakeADB()
        fake.on(["mdns", "check"], .ok("mdns daemon version\n"))
        #expect(await service(fake).diagnose(phoneAddress: "192.168.1.77") == .noServiceSeen)
        #expect(await service(fake).diagnose(phoneAddress: nil) == .noServiceSeen)
    }

    @Test(arguments: NetworkDiagnosis.allExamples)
    func everyDiagnosisHasAPlainFix(_ diagnosis: NetworkDiagnosis) {
        #expect(!diagnosis.title.isEmpty)
        #expect(!diagnosis.suggestions.isEmpty)
        #expect(diagnosis.suggestions.allSatisfy { $0.hasSuffix(".") })
    }

    @Test(arguments: [
        ("192.168.1.10", "255.255.255.0", "192.168.1.200", true),
        ("192.168.1.10", "255.255.255.0", "192.168.2.1", false),
        ("10.1.2.3", "255.0.0.0", "10.200.0.1", true),
        ("bad", "255.0.0.0", "10.0.0.1", false),
    ])
    func subnetMath(_ address: String, _ mask: String, _ other: String, _ same: Bool) {
        #expect(LocalAddress(interface: "en0", address: address, netmask: mask).contains(other) == same)
    }

    @Test func systemNetworkInspectorReturnsPrivateIPv4Only() {
        for address in SystemNetworkInspector().localIPv4Addresses() {
            #expect(!address.address.hasPrefix("127."))
            #expect(address.address.split(separator: ".").count == 4)
        }
    }

    @Test func userDefaultsStoreRoundTrips() throws {
        let suite = "dev.airlock.tests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = UserDefaultsPairedDeviceStore(defaults: defaults)
        #expect(store.load().isEmpty)
        store.save([PairedDevice(name: "adb-A", host: "h", port: 1)])
        #expect(store.load() == [PairedDevice(name: "adb-A", host: "h", port: 1)])
        defaults.set(Data("garbage".utf8), forKey: "pairedDevices")
        #expect(store.load().isEmpty)
    }
}

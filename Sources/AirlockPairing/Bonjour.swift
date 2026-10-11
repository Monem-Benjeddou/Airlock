// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockADB
import Foundation
import Network

/// Another way to find the adb services phones advertise on the network.
public protocol ServiceBrowser: Sendable {
    /// The services seen so far. The first call starts browsing, so it may return nothing yet.
    func services() async -> [MdnsService]
}

/// Finds adb services with macOS's own Bonjour. adb's built-in discovery can miss them: adb 37 from Homebrew
/// listed nothing while `dns-sd` saw the phone's pairing service, so the phone waited on "Pairing device".
public final class BonjourBrowser: ServiceBrowser, @unchecked Sendable {
    private static let types: [(String, MdnsService.Kind)] = [
        ("_adb-tls-pairing._tcp", .pairing), ("_adb-tls-connect._tcp", .connect),
    ]

    // Everything below is touched only on `queue`, which is why the class can be @unchecked Sendable.
    private let queue = DispatchQueue(label: "dev.airlock.bonjour")
    private var browsers: [NWBrowser] = []
    private var seen: [Key: NWEndpoint] = [:]
    private var resolved: [Key: MdnsService] = [:]
    private var resolving: [Key: NWConnection] = [:]

    private struct Key: Hashable {
        let kind: MdnsService.Kind
        let name: String
    }

    public init() {}

    deinit {
        browsers.forEach { $0.cancel() }
        resolving.values.forEach { $0.cancel() }
    }

    public func services() async -> [MdnsService] {
        await withCheckedContinuation { continuation in
            queue.async {
                self.startIfNeeded()
                // Retry anything whose address is still unknown, such as a resolve that failed.
                for (key, endpoint) in self.seen where self.resolved[key] == nil { self.resolve(endpoint, key: key) }
                continuation.resume(returning: Array(self.resolved.values))
            }
        }
    }

    private func startIfNeeded() {
        guard browsers.isEmpty else { return }
        for (type, kind) in Self.types {
            let browser = NWBrowser(for: .bonjour(type: type, domain: "local."), using: .tcp)
            browser.browseResultsChangedHandler = { [weak self] results, _ in self?.update(results, kind: kind) }
            browser.start(queue: queue)
            browsers.append(browser)
        }
    }

    private func update(_ results: Set<NWBrowser.Result>, kind: MdnsService.Kind) {
        var live: [Key: NWEndpoint] = [:]
        for result in results {
            guard case .service(let name, _, _, _) = result.endpoint else { continue }
            live[Key(kind: kind, name: name)] = result.endpoint
        }
        for key in seen.keys where key.kind == kind && live[key] == nil {
            seen[key] = nil
            resolved[key] = nil
            resolving.removeValue(forKey: key)?.cancel()
        }
        for (key, endpoint) in live where seen[key] == nil {
            seen[key] = endpoint
            resolve(endpoint, key: key)
        }
    }

    /// Resolves a service to an IPv4 address and port. A UDP "connection" resolves the service without sending
    /// anything to the phone; adb then talks to the address itself.
    private func resolve(_ endpoint: NWEndpoint, key: Key) {
        guard resolving[key] == nil else { return }
        let parameters = NWParameters.udp
        // adb takes host:port; an IPv6 address would need brackets and a scope id.
        (parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options)?.version = .v4
        let connection = NWConnection(to: endpoint, using: parameters)
        resolving[key] = connection
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self, let connection else { return }
            switch state {
            case .ready:
                if case .hostPort(let host, let port)? = connection.currentPath?.remoteEndpoint,
                   let address = Self.address(of: host) {
                    resolved[key] = MdnsService(instance: key.name, type: key.kind, host: address, port: Int(port.rawValue))
                }
                connection.cancel()
                resolving[key] = nil
            case .failed, .cancelled:
                if resolving[key] === connection { resolving[key] = nil }
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    /// "192.168.1.20" from an IPv4 host, without the "%en0" interface suffix Network adds.
    static func address(of host: NWEndpoint.Host) -> String? {
        guard case .ipv4(let address) = host else { return nil }
        return "\(address)".split(separator: "%").first.map(String.init)
    }
}

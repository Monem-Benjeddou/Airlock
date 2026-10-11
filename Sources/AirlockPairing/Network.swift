// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Darwin
import Foundation

/// An IPv4 address of one of the Mac's network interfaces.
public struct LocalAddress: Hashable, Sendable {
    public let interface: String
    public let address: String
    public let netmask: String

    public init(interface: String, address: String, netmask: String) {
        self.interface = interface
        self.address = address
        self.netmask = netmask
    }

    /// True when `other` is on the same IPv4 subnet.
    public func contains(_ other: String) -> Bool {
        guard let mine = Self.parse(address), let mask = Self.parse(netmask), let theirs = Self.parse(other) else { return false }
        return mine & mask == theirs & mask
    }

    static func parse(_ text: String) -> UInt32? {
        let parts = text.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4, text.split(separator: ".").count == 4 else { return nil }
        return parts.reduce(0) { $0 << 8 | UInt32($1) }
    }
}

public protocol NetworkInspector: Sendable {
    func localIPv4Addresses() -> [LocalAddress]
}

/// Reads interface addresses with `getifaddrs`. Never opens a port.
public struct SystemNetworkInspector: NetworkInspector {
    public init() {}

    public func localIPv4Addresses() -> [LocalAddress] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        var result: [LocalAddress] = []
        for pointer in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let entry = pointer.pointee
            let flags = Int32(entry.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0,
                  let address = entry.ifa_addr, address.pointee.sa_family == UInt8(AF_INET),
                  let mask = entry.ifa_netmask else { continue }
            result.append(LocalAddress(
                interface: String(cString: entry.ifa_name),
                address: Self.string(address),
                netmask: Self.string(mask)
            ))
        }
        return result
    }

    private static func string(_ socketAddress: UnsafeMutablePointer<sockaddr>) -> String {
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        getnameinfo(socketAddress, socklen_t(socketAddress.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
        return String(decoding: host.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}

/// Why the phone could not be found on the network, with what the user can do about it.
public enum NetworkDiagnosis: Hashable, Sendable {
    case macNotOnNetwork
    case discoveryUnavailable
    case differentNetworks(mac: String, phone: String)
    /// Same network but no mDNS traffic: typical for guest networks and access points with client isolation.
    case noServiceSeen

    public static let allExamples: [NetworkDiagnosis] = [
        .macNotOnNetwork, .discoveryUnavailable, .differentNetworks(mac: "192.168.1.2", phone: "10.0.0.2"), .noServiceSeen,
    ]

    public var title: String {
        switch self {
        case .macNotOnNetwork: "Your Mac is not connected to a network"
        case .discoveryUnavailable: "Device discovery is not available"
        case .differentNetworks: "Your Mac and phone are on different networks"
        case .noServiceSeen: "Airlock cannot see your phone on this network"
        }
    }

    public var suggestions: [String] {
        switch self {
        case .macNotOnNetwork:
            ["Connect your Mac to the same Wi-Fi network as your phone."]
        case .discoveryUnavailable:
            ["Quit other Android tools that may be running their own adb, then try again.",
             "Use the pairing code option instead."]
        case .differentNetworks(let mac, let phone):
            ["Your Mac is at \(mac) and your phone at \(phone). Join both to the same Wi-Fi network.",
             "If your router has separate 2.4 GHz and 5 GHz networks, use the same one on both devices."]
        case .noServiceSeen:
            ["Guest networks and some office or hotel networks block devices from seeing each other. "
                + "Use your home network or a phone hotspot.",
             "Turn off \"AP isolation\" or \"client isolation\" in your router settings if you can.",
             "Use the pairing code option, or connect by USB and use the legacy wireless mode."]
        }
    }
}

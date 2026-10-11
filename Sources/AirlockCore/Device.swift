// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

public enum DeviceSerialError: Error, Equatable, Sendable {
    case invalid(String)
}

/// The identifier adb uses for a device: a USB serial, `host:port`, or an mDNS service name.
///
/// Serials come from device output, so they are validated before being passed back to `adb -s`.
public struct DeviceSerial: RawRepresentable, Hashable, Sendable, Codable, CustomStringConvertible {
    public static let maxLength = 128

    public let rawValue: String

    public init(_ raw: String) throws(DeviceSerialError) {
        guard Self.isValid(raw) else { throw .invalid(raw) }
        rawValue = raw
    }

    public init?(rawValue: String) {
        guard Self.isValid(rawValue) else { return nil }
        self.rawValue = rawValue
    }

    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        guard Self.isValid(raw) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Invalid serial"))
        }
        rawValue = raw
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    public var description: String { rawValue }

    /// True for serials that refer to a device over the network rather than USB.
    public var isWireless: Bool {
        rawValue.contains("._adb-tls-connect._tcp") || rawValue.contains(":")
    }

    /// Letters, digits and `. _ - : [ ]` only (covers USB serials, IPv4/IPv6 `host:port` and mDNS names).
    public static func isValid(_ raw: String) -> Bool {
        guard !raw.isEmpty, raw.utf8.count <= maxLength, raw.first != "-" else { return false }
        return raw.utf8.allSatisfy { byte in
            switch byte {
            case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"),
                 UInt8(ascii: "0")...UInt8(ascii: "9"):
                true
            case UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "-"), UInt8(ascii: ":"),
                 UInt8(ascii: "["), UInt8(ascii: "]"):
                true
            default:
                false
            }
        }
    }
}

/// Connection state as reported by `adb devices`, reduced to what the UI must explain.
public enum DeviceConnectionState: Hashable, Sendable, Codable {
    /// Authorised and usable.
    case ready
    /// The phone has not accepted this Mac's RSA key yet ("tap Allow on your phone").
    case unauthorized
    /// Authorisation dialog is showing or the key exchange is in progress.
    case authorizing
    /// Connected but not responding; usually fixed by replugging or toggling USB debugging.
    case offline
    /// The host lacks permission to open the USB device.
    case noPermissions
    /// Any other adb state (recovery, sideload, bootloader, host, connecting...).
    case other(String)

    public init(adbState: String) {
        switch adbState {
        case "device": self = .ready
        case "unauthorized": self = .unauthorized
        case "authorizing": self = .authorizing
        case "offline": self = .offline
        case "no permissions": self = .noPermissions
        default: self = .other(adbState)
        }
    }
}

/// A device line from `adb devices -l` before any per-device queries.
public struct ConnectedDevice: Hashable, Sendable, Identifiable, Codable {
    public var id: DeviceSerial { serial }
    public let serial: DeviceSerial
    public let state: DeviceConnectionState
    public let model: String?
    public let product: String?
    public let deviceName: String?
    public let transportID: String?

    public init(
        serial: DeviceSerial,
        state: DeviceConnectionState,
        model: String? = nil,
        product: String? = nil,
        deviceName: String? = nil,
        transportID: String? = nil
    ) {
        self.serial = serial
        self.state = state
        self.model = model
        self.product = product
        self.deviceName = deviceName
        self.transportID = transportID
    }
}

/// Device facts used for split selection and pre-install checks. Read once per connection.
public struct DeviceProperties: Hashable, Sendable, Codable {
    /// Supported ABIs, most preferred first (`ro.product.cpu.abilist`).
    public let abis: [String]
    /// Screen density in dpi (`wm density`, override wins over physical).
    public let densityDPI: Int
    /// BCP-47 locales, most preferred first.
    public let locales: [String]
    public let sdkLevel: Int

    public init(abis: [String], densityDPI: Int, locales: [String], sdkLevel: Int) {
        self.abis = abis
        self.densityDPI = densityDPI
        self.locales = locales
        self.sdkLevel = sdkLevel
    }
}

public enum DeviceBrand: String, Hashable, Sendable, Codable, CaseIterable {
    case pixel, samsung, xiaomi, oneplus, other

    /// Maps `ro.product.manufacturer` / `ro.product.brand` to an onboarding flavour.
    public init(manufacturer: String, brand: String = "") {
        let value = (manufacturer + " " + brand).lowercased()
        if value.contains("google") {
            self = .pixel
        } else if value.contains("samsung") {
            self = .samsung
        } else if value.contains("xiaomi") || value.contains("redmi") || value.contains("poco") {
            self = .xiaomi
        } else if value.contains("oneplus") {
            self = .oneplus
        } else {
            self = .other
        }
    }
}

/// Everything the device card shows for a ready device.
public struct DeviceInfo: Hashable, Sendable, Codable {
    public let serial: DeviceSerial
    /// Hardware serial (`ro.serialno`): stays the same over USB and Wi-Fi. Keys the action journal.
    public let stableID: String
    /// The model code, e.g. `SM-S928B`.
    public let model: String
    /// The name to show, e.g. "Galaxy S24 Ultra" or the name the owner gave the phone (see ``DeviceNames``).
    /// On screen only: it can contain the owner's own name, so it is never logged or stored.
    public let displayName: String
    public let manufacturer: String
    public let brand: DeviceBrand
    public let androidVersion: String
    public let properties: DeviceProperties
    /// Battery level 0-100, nil when the device does not report it.
    public let batteryPercent: Int?

    public init(
        serial: DeviceSerial,
        stableID: String,
        model: String,
        displayName: String? = nil,
        manufacturer: String,
        brand: DeviceBrand,
        androidVersion: String,
        properties: DeviceProperties,
        batteryPercent: Int?
    ) {
        self.serial = serial
        self.stableID = stableID
        self.model = model
        self.displayName = displayName ?? model
        self.manufacturer = manufacturer
        self.brand = brand
        self.androidVersion = androidVersion
        self.properties = properties
        self.batteryPercent = batteryPercent
    }
}

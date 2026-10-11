// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation

// Pure parsers for every adb / device output Airlock reads. Each is covered by golden-file contract
// tests against recorded real devices (Tests/AirlockTestSupport/Fixtures/adb).

public enum ADBParseError: Error, Hashable, Sendable {
    case unexpectedOutput(command: String, output: String)
    case invalidSerial(String)
    case invalidPackageName(String)
    case packageNotFound(String)

    static func unexpected(_ command: String, _ output: String) -> ADBParseError {
        .unexpectedOutput(command: command, output: String(output.prefix(500)))
    }
}

// MARK: - adb devices -l

public enum DevicesParser {
    public static func parse(_ output: String) throws(ADBParseError) -> [ConnectedDevice] {
        var devices: [ConnectedDevice] = []
        for line in output.split(whereSeparator: \.isNewline) {
            let line = String(line)
            if line.isEmpty || line.hasPrefix("*") || line.hasPrefix("List of devices") { continue }
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard fields.count >= 2 else { continue }

            guard let serial = DeviceSerial(rawValue: fields[0]) else { throw .invalidSerial(fields[0]) }
            let rawState = fields[1] == "no" && fields.count > 2 && fields[2] == "permissions" ? "no permissions" : fields[1]

            var properties: [String: String] = [:]
            for field in fields.dropFirst(2) {
                let pair = field.split(separator: ":", maxSplits: 1).map(String.init)
                if pair.count == 2, ["model", "product", "device", "transport_id", "usb"].contains(pair[0]) {
                    properties[pair[0]] = pair[1]
                }
            }
            devices.append(ConnectedDevice(
                serial: serial,
                state: DeviceConnectionState(adbState: rawState),
                model: properties["model"],
                product: properties["product"],
                deviceName: properties["device"],
                transportID: properties["transport_id"]
            ))
        }
        return devices
    }
}

// MARK: - getprop

public enum GetpropParser {
    /// Parses `[key]: [value]` lines; values may span lines.
    public static func parse(_ output: String) -> [String: String] {
        var result: [String: String] = [:]
        var pendingKey: String?
        var pendingValue = ""
        for line in output.components(separatedBy: "\n") {
            if let key = pendingKey {
                if line.hasSuffix("]") {
                    result[key] = pendingValue + "\n" + line.dropLast()
                    pendingKey = nil
                } else {
                    pendingValue += "\n" + line
                }
                continue
            }
            guard line.hasPrefix("["), let close = line.range(of: "]: [") else { continue }
            let key = String(line[line.index(after: line.startIndex)..<close.lowerBound])
            let rest = line[close.upperBound...]
            if rest.hasSuffix("]") {
                result[key] = String(rest.dropLast())
            } else {
                pendingKey = key
                pendingValue = String(rest)
            }
        }
        return result
    }
}

// MARK: - dumpsys battery

public enum BatteryParser {
    /// Battery percent from the first `level:` / `scale:` pair, nil when absent.
    public static func level(_ output: String) -> Int? {
        var level: Int?
        var scale: Int?
        for line in output.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if level == nil, trimmed.hasPrefix("level:") { level = Int(trimmed.dropFirst(6).trimmingCharacters(in: .whitespaces)) }
            if scale == nil, trimmed.hasPrefix("scale:") { scale = Int(trimmed.dropFirst(6).trimmingCharacters(in: .whitespaces)) }
        }
        guard let level else { return nil }
        guard let scale, scale > 0 else { return level }
        return level * 100 / scale
    }
}

// MARK: - wm density

public enum DensityParser {
    /// The override density when set, otherwise the physical density.
    public static func parse(_ output: String) throws(ADBParseError) -> Int {
        var physical: Int?
        var override: Int?
        for line in output.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":", maxSplits: 1)
            guard parts.count == 2, let value = Int(parts[1].trimmingCharacters(in: .whitespaces)) else { continue }
            if parts[0].hasPrefix("Physical") { physical = value }
            if parts[0].hasPrefix("Override") { override = value }
        }
        guard let density = override ?? physical else { throw .unexpected("wm density", output) }
        return density
    }
}

// MARK: - pm list packages

public struct PackageListEntry: Hashable, Sendable {
    public let packageName: PackageName
    public let apkPath: String
    public let versionCode: Int64?
    public let installer: String?
    public let uid: Int?
}

public enum PackageListParser {
    /// Parses `package:<path>=<name> versionCode:<n>  installer=<pkg> uid:<n>` (fields after the name are optional).
    ///
    /// Names that fail strict validation are skipped rather than failing the whole list: real devices
    /// list the single-segment `android` framework package, and nothing invalid may reach a command.
    public static func parse(_ output: String) -> [PackageListEntry] {
        var entries: [PackageListEntry] = []
        for line in output.split(whereSeparator: \.isNewline) where line.hasPrefix("package:") {
            let fields = line.dropFirst("package:".count).split(separator: " ", omittingEmptySubsequences: true)
            guard let first = fields.first else { continue }

            var path = ""
            var rawName = String(first)
            if let lastEquals = first.lastIndex(of: "=") {
                path = String(first[..<lastEquals])
                rawName = String(first[first.index(after: lastEquals)...])
            }
            guard let name = PackageName(rawValue: rawName) else { continue }

            var versionCode: Int64?
            var installer: String?
            var uid: Int?
            for field in fields.dropFirst() {
                if field.hasPrefix("versionCode:") { versionCode = Int64(field.dropFirst("versionCode:".count)) }
                if field.hasPrefix("installer=") {
                    let value = String(field.dropFirst("installer=".count))
                    installer = value == "null" ? nil : value
                }
                if field.hasPrefix("uid:") { uid = Int(field.dropFirst("uid:".count)) }
            }
            entries.append(PackageListEntry(packageName: name, apkPath: path, versionCode: versionCode, installer: installer, uid: uid))
        }
        return entries
    }

    /// Valid package names from a plain `pm list packages` listing; invalid names are dropped.
    public static func names(_ output: String) -> Set<String> {
        Set(output.split(whereSeparator: \.isNewline).compactMap { line -> String? in
            guard line.hasPrefix("package:") else { return nil }
            let name = String(line.dropFirst("package:".count)).trimmingCharacters(in: .whitespaces)
            return PackageName.isValid(name) ? name : nil
        })
    }
}

// MARK: - df

public enum DiskFreeParser {
    /// Available bytes from `df <path>` (toybox 1K-blocks, or old toolbox human-readable sizes).
    public static func availableBytes(_ output: String) throws(ADBParseError) -> Int64 {
        let lines = output.split(whereSeparator: \.isNewline).map(String.init)
        guard lines.count >= 2 else { throw .unexpected("df", output) }
        let header = lines[0].split(separator: " ", omittingEmptySubsequences: true)
        let row = lines[1].split(separator: " ", omittingEmptySubsequences: true)

        if lines[0].contains("1K-blocks") {
            guard let column = header.firstIndex(of: "Available"), column < row.count,
                  let kilobytes = Int64(row[column]) else { throw .unexpected("df", output) }
            return kilobytes * 1024
        }
        guard let column = header.firstIndex(of: "Free"), column < row.count,
              let bytes = humanReadableBytes(String(row[column])) else { throw .unexpected("df", output) }
        return bytes
    }

    private static func humanReadableBytes(_ value: String) -> Int64? {
        let units: [Character: Double] = ["K": 1024, "M": 1_048_576, "G": 1_073_741_824, "T": 1_099_511_627_776]
        guard let last = value.last else { return nil }
        if let multiplier = units[last], let number = Double(value.dropLast()) { return Int64(number * multiplier) }
        return Int64(value)
    }
}

// MARK: - dumpsys package <pkg>

public enum PackageEnabledState: Hashable, Sendable {
    case `default`, enabled, disabled, disabledUser, disabledUntilUsed

    /// `PackageManager.COMPONENT_ENABLED_STATE_*` codes.
    public init(rawCode: Int) {
        switch rawCode {
        case 1: self = .enabled
        case 2: self = .disabled
        case 3: self = .disabledUser
        case 4: self = .disabledUntilUsed
        default: self = .default
        }
    }

    public var isEnabled: Bool { self == .default || self == .enabled }
}

public struct PackageDump: Hashable, Sendable {
    public struct UserState: Hashable, Sendable {
        public let installed: Bool
        public let enabledState: PackageEnabledState
    }

    public var versionCode: Int64 = 0
    public var versionName: String?
    public var minSdk: Int?
    public var targetSdk: Int?
    public var codePath: String?
    public var isSystem = false
    public var installer: String?
    public var splits: [String] = []
    public var lastUpdateTime: String?
    public var apkSigningVersion: Int?
    /// State for user 0.
    public var userState: UserState?
}

public enum DumpsysPackageParser {
    public static func parse(_ output: String, package: String) throws(ADBParseError) -> PackageDump {
        let lines = output.components(separatedBy: "\n")
        guard let start = lines.firstIndex(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("Package [\(package)]") }) else {
            throw .packageNotFound(package)
        }
        var dump = PackageDump()
        for line in lines[(start + 1)...] {
            // The block ends at the next package or the next top-level section.
            if line.hasPrefix("  Package [") || (!line.isEmpty && !line.hasPrefix(" ")) { break }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            apply(trimmed, to: &dump)
        }
        return dump
    }

    private static func apply(_ line: String, to dump: inout PackageDump) {
        if line.hasPrefix("versionCode=") {
            for field in line.split(separator: " ") {
                let pair = field.split(separator: "=", maxSplits: 1)
                guard pair.count == 2 else { continue }
                switch pair[0] {
                case "versionCode": dump.versionCode = Int64(pair[1]) ?? 0
                case "minSdk": dump.minSdk = Int(pair[1])
                case "targetSdk": dump.targetSdk = Int(pair[1])
                default: break
                }
            }
        } else if let value = value(of: "versionName=", in: line) {
            dump.versionName = value
        } else if let value = value(of: "codePath=", in: line) {
            dump.codePath = value
        } else if line.hasPrefix("flags=[") || line.hasPrefix("pkgFlags=[") {
            dump.isSystem = dump.isSystem || line.contains(" SYSTEM ")
        } else if let value = value(of: "installerPackageName=", in: line) {
            dump.installer = value == "null" ? nil : value
        } else if let value = value(of: "splits=[", in: line) {
            dump.splits = value.dropLast().split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        } else if let value = value(of: "lastUpdateTime=", in: line) {
            dump.lastUpdateTime = value
        } else if let value = value(of: "apkSigningVersion=", in: line) {
            dump.apkSigningVersion = Int(value)
        } else if line.hasPrefix("User 0:"), dump.userState == nil {
            dump.userState = userState(line)
        }
    }

    private static func value(of prefix: String, in line: String) -> String? {
        line.hasPrefix(prefix) ? String(line.dropFirst(prefix.count)) : nil
    }

    private static func userState(_ line: String) -> PackageDump.UserState {
        var installed = true
        var enabled = PackageEnabledState.default
        for field in line.split(separator: " ") {
            if field.hasPrefix("installed=") { installed = field.hasSuffix("true") }
            if field.hasPrefix("enabled="), let code = Int(field.dropFirst("enabled=".count)) {
                enabled = PackageEnabledState(rawCode: code)
            }
        }
        return PackageDump.UserState(installed: installed, enabledState: enabled)
    }
}

// MARK: - pm path, launchers, keyboards

public enum PmPathParser {
    public static func parse(_ output: String) -> [String] {
        output.split(whereSeparator: \.isNewline)
            .filter { $0.hasPrefix("package:") }
            .map { String($0.dropFirst("package:".count)).trimmingCharacters(in: .whitespaces) }
    }
}

/// `cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.HOME`
public enum HomeActivitiesParser {
    public static func parse(_ output: String) -> [String] {
        componentPackages(output)
    }

    /// Package names from lines of the form `com.pkg/.Component`, in order, without duplicates.
    static func componentPackages(_ output: String) -> [String] {
        var seen = Set<String>()
        var result: [String] = []
        for line in output.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard let slash = trimmed.firstIndex(of: "/"), !trimmed.contains(" ") else { continue }
            let name = String(trimmed[..<slash])
            if PackageName.isValid(name), seen.insert(name).inserted { result.append(name) }
        }
        return result
    }
}

/// `ime list -s`
public enum InputMethodParser {
    public static func parse(_ output: String) -> [String] {
        HomeActivitiesParser.componentPackages(output)
    }
}

// MARK: - Install sessions

public enum InstallSessionParser {
    /// `Success: created install session [123]`
    public static func sessionID(_ output: String) throws(ADBParseError) -> Int {
        guard output.contains("Success"), let open = output.firstIndex(of: "["), let close = output.firstIndex(of: "]"),
              open < close, let id = Int(output[output.index(after: open)..<close]) else {
            throw .unexpected("pm install-create", output)
        }
        return id
    }

    public static func isSuccess(_ output: String) -> Bool {
        output.split(whereSeparator: \.isNewline).contains { $0.hasPrefix("Success") }
    }
}

// MARK: - Wireless

public struct MdnsService: Hashable, Sendable {
    public enum Kind: Hashable, Sendable {
        case pairing, connect, legacy
    }

    public let instance: String
    public let type: Kind
    public let host: String
    public let port: Int
}

public enum MdnsServicesParser {
    public static func parse(_ output: String) -> [MdnsService] {
        output.split(whereSeparator: \.isNewline).compactMap { line in
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard fields.count == 3 else { return nil }
            let kind: MdnsService.Kind
            switch fields[1].trimmingCharacters(in: CharacterSet(charactersIn: ".")) {
            case "_adb-tls-pairing._tcp": kind = .pairing
            case "_adb-tls-connect._tcp": kind = .connect
            case "_adb._tcp": kind = .legacy
            default: return nil
            }
            guard let colon = fields[2].lastIndex(of: ":"), let port = Int(fields[2][fields[2].index(after: colon)...]) else {
                return nil
            }
            return MdnsService(instance: fields[0], type: kind, host: String(fields[2][..<colon]), port: port)
        }
    }

    /// `adb mdns check` reports a daemon version when discovery works.
    public static func isDiscoveryAvailable(_ output: String) -> Bool {
        output.contains("mdns daemon version")
    }
}

public enum PairResult: Hashable, Sendable {
    case paired
    case wrongCode
    case unreachable
    case failed(String)
}

public enum PairOutputParser {
    public static func parse(_ output: String) -> PairResult {
        let text = output.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.contains("Successfully paired") { return .paired }
        if text.contains("Wrong password") { return .wrongCode }
        if text.contains("unable to connect") { return .unreachable }
        return .failed(text)
    }
}

public enum ConnectResult: Hashable, Sendable {
    case connected
    case refused
    case unreachable
    case unauthorized
    case failed(String)
}

public enum ConnectOutputParser {
    public static func parse(_ output: String) -> ConnectResult {
        let text = output.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasPrefix("connected to") || text.hasPrefix("already connected to") { return .connected }
        if text.contains("failed to authenticate") { return .unauthorized }
        if text.contains("Connection refused") { return .refused }
        if text.hasPrefix("cannot connect") || text.contains("No route to host") || text.contains("timed out") { return .unreachable }
        return .failed(text)
    }
}

// MARK: - Misc

public enum ADBVersionParser {
    /// `Version 37.0.1-15733141` → `37.0.1`
    public static func parse(_ output: String) -> String? {
        for line in output.split(whereSeparator: \.isNewline) where line.hasPrefix("Version ") {
            return line.dropFirst("Version ".count).split(separator: "-").first.map(String.init)
        }
        return nil
    }
}

public enum StatParser {
    /// Output of `stat -c %s <file>`.
    public static func size(_ output: String) throws(ADBParseError) -> Int64 {
        guard let size = Int64(output.trimmingCharacters(in: .whitespacesAndNewlines)) else { throw .unexpected("stat", output) }
        return size
    }
}

public enum Sha256SumParser {
    /// Output of `sha256sum <file>`: lowercase hex digest then the path.
    public static func digest(_ output: String) throws(ADBParseError) -> String {
        let digest = output.split(separator: " ").first.map(String.init) ?? ""
        let isHex = digest.count == 64 && digest.allSatisfy { $0.isHexDigit && !$0.isUppercase }
        guard isHex else { throw .unexpected("sha256sum", output) }
        return digest
    }
}

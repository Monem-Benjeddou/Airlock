// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation

public enum ADBError: Error, Hashable, Sendable {
    case process(ProcessError)
    case parse(ADBParseError)
    case deviceNotFound(DeviceSerial)
    case deviceUnauthorized(DeviceSerial)
    case deviceOffline(DeviceSerial)
    /// A command ran but reported failure. `output` is trimmed device or adb output.
    case commandFailed(command: String, exitCode: Int32, output: String)
    case invalidArgument(String)
}

public struct ADBConfiguration: Sendable {
    public let executable: URL
    /// The adb server only ever listens on localhost; Airlock never passes `-a`.
    public let serverPort: Int
    public let defaultTimeout: Duration
    /// For pushes, pulls and installs of large files.
    public let transferTimeout: Duration
    public let homeDirectory: String

    public init(
        executable: URL,
        serverPort: Int = 5037,
        defaultTimeout: Duration = .seconds(30),
        transferTimeout: Duration = .seconds(30 * 60),
        homeDirectory: String = NSHomeDirectory()
    ) {
        self.executable = executable
        self.serverPort = serverPort
        self.defaultTimeout = defaultTimeout
        self.transferTimeout = transferTimeout
        self.homeDirectory = homeDirectory
    }

    /// A minimal, explicit environment: adb needs HOME for `~/.android/adbkey`.
    var environment: [String: String] {
        ["HOME": homeDirectory, "ANDROID_ADB_SERVER_PORT": String(serverPort), "PATH": "/usr/bin:/bin"]
    }
}

/// The only component in Airlock that runs adb.
///
/// Host-level commands (devices, pairing) run directly; device commands go through ``DeviceChannel``,
/// which serialises them per device.
public struct ADBClient: Sendable {
    public let configuration: ADBConfiguration
    let runner: any ProcessRunning
    private let queues = DeviceQueues()

    public init(configuration: ADBConfiguration, runner: any ProcessRunning = SystemProcessRunner()) {
        self.configuration = configuration
        self.runner = runner
    }

    /// A channel for one device. Channels for the same serial share one command queue.
    public func device(_ serial: DeviceSerial) -> DeviceChannel {
        DeviceChannel(client: self, serial: serial, queue: queues.queue(for: serial))
    }

    // MARK: Host commands

    public func version() async throws(ADBError) -> String? {
        ADBVersionParser.parse(try await run(["version"]).stdoutText)
    }

    public func startServer() async throws(ADBError) {
        try await checked(["start-server"])
    }

    public func devices() async throws(ADBError) -> [ConnectedDevice] {
        let result = try await checked(["devices", "-l"])
        do {
            return try DevicesParser.parse(result.stdoutText)
        } catch {
            throw .parse(error)
        }
    }

    /// Streams the device list each time it changes (`adb track-devices -l`).
    public func trackDevices() -> AsyncThrowingStream<[ConnectedDevice], any Error> {
        let events = runner.stream(request(["track-devices", "-l"], timeout: .seconds(365 * 24 * 3600)))
        return AsyncThrowingStream { continuation in
            let task = Task {
                var decoder = TrackDevicesDecoder()
                do {
                    for try await event in events {
                        guard case .stdout(let chunk) = event else { continue }
                        for snapshot in try decoder.feed(chunk) { continuation.yield(snapshot) }
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    /// Pairs with a six-digit code or the password from a QR pairing session (ASCII letters and digits).
    public func pair(host: String, port: Int, code: String) async throws(ADBError) -> PairResult {
        let validCode = (6...64).contains(code.count) && code.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber) }
        guard Self.isValidHost(host), (1...65_535).contains(port), validCode else {
            throw .invalidArgument("pair \(host):\(port)")
        }
        let result = try await run(["pair", "\(host):\(port)", code])
        return PairOutputParser.parse(result.stdoutText + result.stderrText)
    }

    public func connect(host: String, port: Int) async throws(ADBError) -> ConnectResult {
        guard Self.isValidHost(host), (1...65_535).contains(port) else { throw .invalidArgument("connect \(host):\(port)") }
        let result = try await run(["connect", "\(host):\(port)"])
        return ConnectOutputParser.parse(result.stdoutText + result.stderrText)
    }

    public func disconnect(_ serial: DeviceSerial) async throws(ADBError) {
        _ = try await run(["disconnect", serial.rawValue])
    }

    public func mdnsCheck() async throws(ADBError) -> Bool {
        let result = try await run(["mdns", "check"])
        return MdnsServicesParser.isDiscoveryAvailable(result.stdoutText + result.stderrText)
    }

    public func mdnsServices() async throws(ADBError) -> [MdnsService] {
        MdnsServicesParser.parse(try await run(["mdns", "services"]).stdoutText)
    }

    /// IPv4, bracket-free IPv6 or an mDNS host name.
    static func isValidHost(_ host: String) -> Bool {
        !host.isEmpty && host.count <= 253 && host.first != "-"
            && host.utf8.allSatisfy { $0 == UInt8(ascii: ".") || $0 == UInt8(ascii: ":") || $0 == UInt8(ascii: "-")
                || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) || (UInt8(ascii: "a")...UInt8(ascii: "z")).contains($0)
                || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains($0) }
    }

    // MARK: Running

    func request(_ arguments: [String], timeout: Duration? = nil, standardInput: Data? = nil) -> ProcessRequest {
        ProcessRequest(
            executable: configuration.executable,
            arguments: arguments,
            environment: configuration.environment,
            timeout: timeout ?? configuration.defaultTimeout,
            standardInput: standardInput
        )
    }

    func run(_ arguments: [String], timeout: Duration? = nil) async throws(ADBError) -> ProcessResult {
        do {
            return try await runner.run(request(arguments, timeout: timeout))
        } catch {
            throw .process(error)
        }
    }

    /// Runs and maps a non-zero exit to ``ADBError``.
    @discardableResult
    func checked(_ arguments: [String], serial: DeviceSerial? = nil, timeout: Duration? = nil) async throws(ADBError) -> ProcessResult {
        let result = try await run(arguments, timeout: timeout)
        if result.exitCode != 0 {
            throw Self.classify(result, arguments: arguments, serial: serial)
        }
        return result
    }

    static func classify(_ result: ProcessResult, arguments: [String], serial: DeviceSerial?) -> ADBError {
        let output = (result.stderrText + result.stdoutText).trimmingCharacters(in: .whitespacesAndNewlines)
        if let serial {
            if output.contains("not found") && output.contains("device") { return .deviceNotFound(serial) }
            if output.contains("unauthorized") { return .deviceUnauthorized(serial) }
            if output.contains("device offline") { return .deviceOffline(serial) }
        }
        let command = arguments.prefix(4).joined(separator: " ")
        return .commandFailed(command: command, exitCode: result.exitCode, output: String(output.prefix(2000)))
    }
}

/// Hands out one queue per serial.
private final class DeviceQueues: @unchecked Sendable {
    private let lock = NSLock()
    private var queues: [DeviceSerial: DeviceCommandQueue] = [:]

    func queue(for serial: DeviceSerial) -> DeviceCommandQueue {
        lock.withLock {
            if let queue = queues[serial] { return queue }
            let queue = DeviceCommandQueue()
            queues[serial] = queue
            return queue
        }
    }
}

/// Decodes the length-prefixed stream of `adb track-devices`: 4 hex digits of length, then that many bytes.
struct TrackDevicesDecoder {
    private var buffer = Data()
    /// A frame lists every attached device; 16 KiB is hundreds of devices.
    private static let maxPayload = 16 * 1024

    mutating func feed(_ chunk: Data) throws(ADBError) -> [[ConnectedDevice]] {
        buffer.append(chunk)
        var snapshots: [[ConnectedDevice]] = []
        while buffer.count >= 4 {
            let header = String(decoding: buffer.prefix(4), as: UTF8.self)
            guard let length = Int(header, radix: 16), length <= Self.maxPayload else {
                throw .parse(.unexpected("track-devices", header))
            }
            guard buffer.count >= 4 + length else { break }
            let payload = String(decoding: buffer.dropFirst(4).prefix(length), as: UTF8.self)
            buffer = Data(buffer.dropFirst(4 + length))
            do {
                snapshots.append(try DevicesParser.parse(payload))
            } catch {
                throw .parse(error)
            }
        }
        return snapshots
    }
}

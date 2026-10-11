// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation

/// Filters for `pm list packages`; always scoped to user 0 (Samsung's Secure Folder user otherwise
/// makes the command fail with a SecurityException).
public enum PackageFilter: String, Sendable, CaseIterable {
    case all = ""
    case system = "-s"
    case thirdParty = "-3"
    case disabled = "-d"
    /// Includes packages removed for user 0 that are still on the system partition.
    case includingUninstalled = "-u"
}

/// Typed adb commands for one device. Every command runs through the device's serial queue.
///
/// This is the complete set of commands Airlock can send to a phone. Arguments are typed
/// (``PackageName``, ``RemotePath``) and shell-quoted, so nothing from a file or the device can
/// change what runs.
public struct DeviceChannel: Sendable {
    let client: ADBClient
    public let serial: DeviceSerial
    let queue: DeviceCommandQueue

    // MARK: Reading

    public func properties() async throws(ADBError) -> [String: String] {
        GetpropParser.parse(try await shell(["getprop"]).stdoutText)
    }

    public func batteryLevel() async throws(ADBError) -> Int? {
        BatteryParser.level(try await shell(["dumpsys", "battery"]).stdoutText)
    }

    public func density() async throws(ADBError) -> Int {
        try await parsing { try DensityParser.parse(try await shell(["wm", "density"]).stdoutText) }
    }

    public func packages() async throws(ADBError) -> [PackageListEntry] {
        let output = try await shell(["pm", "list", "packages", "--user", "0", "-f", "-U", "--show-versioncode", "-i"]).stdoutText
        return PackageListParser.parse(output)
    }

    public func packageNames(_ filter: PackageFilter) async throws(ADBError) -> Set<String> {
        var arguments = ["pm", "list", "packages", "--user", "0"]
        if filter != .all { arguments.append(filter.rawValue) }
        return PackageListParser.names(try await shell(arguments).stdoutText)
    }

    public func dump(_ package: PackageName) async throws(ADBError) -> PackageDump {
        let output = try await shell(["dumpsys", "package", package.rawValue]).stdoutText
        return try await parsing { try DumpsysPackageParser.parse(output, package: package.rawValue) }
    }

    public func apkPaths(_ package: PackageName) async throws(ADBError) -> [String] {
        PmPathParser.parse(try await shell(["pm", "path", package.rawValue], allowFailure: true).stdoutText)
    }

    public func freeBytes(at path: RemotePath = .data) async throws(ADBError) -> Int64 {
        let output = try await shell(["df", path.rawValue]).stdoutText
        return try await parsing { try DiskFreeParser.availableBytes(output) }
    }

    public func launchers() async throws(ADBError) -> [String] {
        let output = try await shell([
            "cmd", "package", "query-activities", "--brief",
            "-a", "android.intent.action.MAIN", "-c", "android.intent.category.HOME",
        ]).stdoutText
        return HomeActivitiesParser.parse(output)
    }

    public func inputMethods() async throws(ADBError) -> [String] {
        InputMethodParser.parse(try await shell(["ime", "list", "-s"]).stdoutText)
    }

    public func fileSize(_ path: RemotePath) async throws(ADBError) -> Int64 {
        let output = try await shell(["stat", "-c", "%s", path.rawValue]).stdoutText
        return try await parsing { try StatParser.size(output) }
    }

    public func sha256(_ path: RemotePath) async throws(ADBError) -> String {
        let output = try await shell(["sha256sum", path.rawValue], timeout: client.configuration.transferTimeout).stdoutText
        return try await parsing { try Sha256SumParser.digest(output) }
    }

    // MARK: Package operations (callers check the denylist and journal first)

    public func uninstall(_ package: PackageName) async throws(ADBError) {
        try await packageManager(["pm", "uninstall", package.rawValue], expect: "Success")
    }

    /// `-k` keeps the app's data so `install-existing` restores it exactly as it was.
    public func uninstallForUser(_ package: PackageName) async throws(ADBError) {
        try await packageManager(["pm", "uninstall", "-k", "--user", "0", package.rawValue], expect: "Success")
    }

    public func disableForUser(_ package: PackageName) async throws(ADBError) {
        try await packageManager(["pm", "disable-user", "--user", "0", package.rawValue], expect: "new state: disabled-user")
    }

    public func enable(_ package: PackageName) async throws(ADBError) {
        try await packageManager(["pm", "enable", "--user", "0", package.rawValue], expect: "new state: enabled")
    }

    public func installExisting(_ package: PackageName) async throws(ADBError) {
        try await packageManager(["cmd", "package", "install-existing", "--user", "0", package.rawValue], expect: "installed for user")
    }

    // MARK: Install sessions

    public func createInstallSession(totalBytes: Int64) async throws(ADBError) -> Int {
        let output = try await shell(["pm", "install-create", "-r", "-S", String(totalBytes)]).stdoutText
        return try await parsing { try InstallSessionParser.sessionID(output) }
    }

    /// Adds a staged APK to a session. `name` is a split name made of safe characters.
    public func writeToSession(_ session: Int, name: String, size: Int64, from path: RemotePath) async throws(ADBError) {
        let result = try await shell(
            ["pm", "install-write", "-S", String(size), String(session), name, path.rawValue],
            timeout: client.configuration.transferTimeout, allowFailure: true
        )
        guard InstallSessionParser.isSuccess(result.stdoutText) else {
            throw .commandFailed(command: "pm install-write", exitCode: result.exitCode, output: result.stdoutText + result.stderrText)
        }
    }

    /// Commits a session. Returns the package manager failure instead of throwing for install errors.
    public func commitInstallSession(_ session: Int) async throws(ADBError) -> InstallFailure? {
        let result = try await shell(
            ["pm", "install-commit", String(session)], timeout: client.configuration.transferTimeout, allowFailure: true
        )
        let output = result.stdoutText + result.stderrText
        if InstallSessionParser.isSuccess(result.stdoutText) { return nil }
        return InstallFailure.parse(output) ?? InstallFailure(code: "INSTALL_FAILED_UNKNOWN", detail: output)
    }

    public func abandonInstallSession(_ session: Int) async throws(ADBError) {
        _ = try await shell(["pm", "install-abandon", String(session)], allowFailure: true)
    }

    // MARK: Files

    public func makeDirectory(_ path: RemotePath) async throws(ADBError) {
        _ = try await shell(["mkdir", "-p", path.rawValue])
    }

    /// Deletes an Airlock staging folder. Refuses any other path.
    public func removeStaging(_ path: RemotePath) async throws(ADBError) {
        guard path.isAirlockStaging else { throw .invalidArgument("refusing to delete \(path)") }
        _ = try await shell(["rm", "-rf", path.rawValue], allowFailure: true)
    }

    public func push(_ local: URL, to remote: RemotePath) async throws(ADBError) {
        try await enqueued { () throws(ADBError) in
            _ = try await client.checked(
                ["-s", serial.rawValue, "push", local.path, remote.rawValue],
                serial: serial, timeout: client.configuration.transferTimeout
            )
        }
    }

    public func pull(_ remote: RemotePath, to local: URL) async throws(ADBError) {
        try await enqueued { () throws(ADBError) in
            _ = try await client.checked(
                ["-s", serial.rawValue, "pull", remote.rawValue, local.path],
                serial: serial, timeout: client.configuration.transferTimeout
            )
        }
    }

    // MARK: Connectivity

    /// Switches the device to legacy TCP mode (`adb tcpip`), for wireless on Android 10 and older.
    public func enableTCPIP(port: Int = 5555) async throws(ADBError) {
        guard (1024...65_535).contains(port) else { throw .invalidArgument("port \(port)") }
        try await enqueued { () throws(ADBError) in
            _ = try await client.checked(["-s", serial.rawValue, "tcpip", String(port)], serial: serial)
        }
    }

    /// The device's Wi-Fi IPv4 address from `ip -4 addr show wlan0`, if connected.
    public func wifiAddress() async throws(ADBError) -> String? {
        let output = try await shell(["ip", "-4", "-o", "addr", "show", "wlan0"], allowFailure: true).stdoutText
        guard let range = output.range(of: "inet ") else { return nil }
        let address = output[range.upperBound...].prefix { $0 != "/" && $0 != " " }
        return address.isEmpty ? nil : String(address)
    }

    // MARK: Plumbing

    /// Runs `adb -s <serial> shell <quoted args>` on this device's queue.
    func shell(_ arguments: [String], timeout: Duration? = nil, allowFailure: Bool = false) async throws(ADBError) -> ProcessResult {
        let quoted: [String]
        do {
            quoted = try DeviceShell.quote(arguments)
        } catch {
            throw .invalidArgument("NUL byte in shell argument")
        }
        let command = ["-s", serial.rawValue, "shell"] + quoted
        return try await enqueued { () throws(ADBError) in
            let result = try await client.run(command, timeout: timeout)
            if result.exitCode != 0, !allowFailure || Self.isTransportFailure(result) {
                throw ADBClient.classify(result, arguments: arguments, serial: serial)
            }
            return result
        }
    }

    /// Package-manager mutations print their result on stdout; anything else is a failure.
    private func packageManager(_ arguments: [String], expect marker: String) async throws(ADBError) {
        let result = try await shell(arguments, allowFailure: true)
        let output = (result.stdoutText + result.stderrText).trimmingCharacters(in: .whitespacesAndNewlines)
        guard output.contains(marker) else {
            throw .commandFailed(command: arguments.prefix(3).joined(separator: " "), exitCode: result.exitCode, output: output)
        }
    }

    private static func isTransportFailure(_ result: ProcessResult) -> Bool {
        let text = result.stderrText
        return text.contains("device") && (text.contains("not found") || text.contains("offline") || text.contains("unauthorized"))
    }

    private func enqueued<T: Sendable>(_ job: @escaping @Sendable () async throws(ADBError) -> T) async throws(ADBError) -> T {
        do {
            return try await queue.enqueue { try await job() }
        } catch let error as ADBError {
            throw error
        } catch is CancellationError {
            throw .process(.cancelled)
        } catch {
            throw .process(.launchFailed(String(describing: error)))
        }
    }

    private func parsing<T>(_ body: () async throws -> T) async throws(ADBError) -> T {
        do {
            return try await body()
        } catch let error as ADBError {
            throw error
        } catch let error as ADBParseError {
            throw .parse(error)
        } catch {
            throw .process(.launchFailed(String(describing: error)))
        }
    }
}

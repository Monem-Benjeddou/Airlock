// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation

public enum DeviceShellError: Error, Hashable, Sendable {
    case containsNUL
}

/// Quoting for commands run with `adb shell`.
///
/// `adb shell a b c` joins its arguments with spaces and hands the result to the device's `sh`, so an
/// argument array alone does NOT prevent injection on the device side. Every argument is therefore
/// quoted for a POSIX shell here, in the one place that builds device commands.
public enum DeviceShell {
    /// Returns the argument unchanged when it only contains characters with no shell meaning,
    /// otherwise wraps it in single quotes (`'` becomes `'\''`).
    public static func quote(_ argument: String) throws(DeviceShellError) -> String {
        if argument.utf8.contains(0) { throw .containsNUL }
        if !argument.isEmpty, argument.utf8.allSatisfy(isSafe) { return argument }
        return "'" + argument.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    public static func quote(_ arguments: [String]) throws(DeviceShellError) -> [String] {
        var quoted: [String] = []
        quoted.reserveCapacity(arguments.count)
        for argument in arguments { quoted.append(try quote(argument)) }
        return quoted
    }

    private static func isSafe(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "0")...UInt8(ascii: "9"):
            true
        case UInt8(ascii: "_"), UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "/"), UInt8(ascii: ":"),
             UInt8(ascii: "="), UInt8(ascii: "@"), UInt8(ascii: "%"), UInt8(ascii: "+"), UInt8(ascii: ","):
            true
        default:
            false
        }
    }
}

public enum RemotePathError: Error, Hashable, Sendable {
    case invalid(String)
}

/// An absolute path on the device, free of traversal and control characters.
public struct RemotePath: Hashable, Sendable, CustomStringConvertible {
    public static let maxLength = 1024
    static let stagingPrefix = "/data/local/tmp/airlock-"

    public let rawValue: String

    public init(_ raw: String) throws(RemotePathError) {
        guard raw.hasPrefix("/"), raw.utf8.count <= Self.maxLength,
              !raw.utf8.contains(where: { $0 < 0x20 || $0 == 0x7f }) else { throw .invalid(raw) }
        let components = raw.split(separator: "/", omittingEmptySubsequences: false).dropFirst()
        guard !components.contains(where: { $0 == ".." || $0 == "." }) else { throw .invalid(raw) }
        rawValue = raw
    }

    private init(trusted: String) {
        rawValue = trusted
    }

    public var description: String { rawValue }

    /// Appends one file name. Names come from archives, so they are restricted to `[A-Za-z0-9._-]`.
    public func appending(_ fileName: String) throws(RemotePathError) -> RemotePath {
        let allowed = fileName.utf8.allSatisfy { byte in
            (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte) || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte)
                || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
                || byte == UInt8(ascii: ".") || byte == UInt8(ascii: "_") || byte == UInt8(ascii: "-")
        }
        guard allowed, !fileName.isEmpty, fileName != ".", fileName != ".." else { throw .invalid(fileName) }
        return try RemotePath(rawValue + "/" + fileName)
    }

    public static let data = RemotePath(trusted: "/data")

    /// `/sdcard/Android/obb/<package>`.
    public static func obbDirectory(for package: PackageName) -> RemotePath {
        RemotePath(trusted: "/sdcard/Android/obb/" + package.rawValue)
    }

    /// A per-job folder for staging APKs before `pm install-write`.
    public static func stagingDirectory(id: UUID) -> RemotePath {
        RemotePath(trusted: stagingPrefix + id.uuidString.lowercased())
    }

    /// True only for folders Airlock itself creates, the only ones it may ever delete recursively.
    public var isAirlockStaging: Bool {
        rawValue.hasPrefix(Self.stagingPrefix) && rawValue.count > Self.stagingPrefix.count
    }
}

/// Runs jobs for one device strictly one after another, including across suspension points.
///
/// adb tolerates parallel commands, but Airlock's multi-step operations (install sessions, journaled
/// changes) must never interleave on the same phone.
public actor DeviceCommandQueue {
    private var tail: Task<Void, Never>?

    public init() {}

    public func enqueue<T: Sendable>(_ job: @escaping @Sendable () async throws -> T) async throws -> T {
        let previous = tail
        let task = Task<T, any Error> {
            await previous?.value
            try Task.checkCancellation()
            return try await job()
        }
        tail = Task { _ = await task.result }
        return try await withTaskCancellationHandler {
            try await task.value
        } onCancel: {
            task.cancel()
        }
    }
}

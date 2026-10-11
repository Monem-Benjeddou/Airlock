// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockADB
import AirlockCore
import Foundation

/// An APK on the Mac, ready to go into an install session.
struct StagedAPK: Sendable {
    let localURL: URL
    let sizeBytes: Int64
}

/// Installs a set of APKs atomically with a package-manager session.
///
/// APKs are pushed to a private staging folder, written into one session and committed together, so
/// the phone ends up with either the complete new version or nothing. Cancellation before the commit
/// abandons the session; the commit itself is never interrupted. The staging folder is always removed.
struct SessionInstaller {
    let channel: DeviceChannel

    /// - Parameter progress: called with 0...1 over the push and write phases.
    func install(_ apks: [StagedAPK], progress: @escaping @Sendable (Double) -> Void) async throws(InstallError) {
        let staging = RemotePath.stagingDirectory(id: UUID())
        let channel = channel
        var session: Int?
        do {
            try await stageAndCommit(apks, staging: staging, session: &session, progress: progress)
        } catch {
            if let session { await Self.uncancellable { try? await channel.abandonInstallSession(session) } }
            await Self.uncancellable { try? await channel.removeStaging(staging) }
            throw error
        }
        await Self.uncancellable { try? await channel.removeStaging(staging) }
    }

    private func stageAndCommit(
        _ apks: [StagedAPK],
        staging: RemotePath,
        session: inout Int?,
        progress: @escaping @Sendable (Double) -> Void
    ) async throws(InstallError) {
        let total = max(apks.reduce(0) { $0 + $1.sizeBytes }, 1)
        var pushed: Int64 = 0
        var remotes: [(RemotePath, StagedAPK)] = []

        try checkCancellation()
        try await adb { try await channel.makeDirectory(staging) }
        for (index, apk) in apks.enumerated() {
            try checkCancellation()
            let remote = try remotePath(staging, index)
            try await adb { try await channel.push(apk.localURL, to: remote) }
            remotes.append((remote, apk))
            pushed += apk.sizeBytes
            progress(0.9 * Double(pushed) / Double(total))
        }

        try checkCancellation()
        let id = try await adb { try await channel.createInstallSession(totalBytes: total) }
        session = id
        for (index, (remote, apk)) in remotes.enumerated() {
            try checkCancellation()
            let name = index == 0 ? "base" : "split\(index)"
            try await adb { try await channel.writeToSession(id, name: name, size: apk.sizeBytes, from: remote) }
        }

        // Last point where cancelling leaves the phone untouched.
        try checkCancellation()
        let committer = channel
        let failure = await Self.uncancellable { () -> Result<InstallFailure?, ADBError> in
            do {
                return .success(try await committer.commitInstallSession(id))
            } catch let error as ADBError {
                return .failure(error)
            } catch {
                return .failure(.process(.launchFailed(String(describing: error))))
            }
        }
        session = nil // A committed session needs no abandon, whatever the outcome.
        switch failure {
        case .success(nil): progress(1)
        case .success(let failure?): throw .packageManager(InstallErrorMapper.explain(failure))
        case .failure(let error): throw Self.map(error)
        }
    }

    private func remotePath(_ staging: RemotePath, _ index: Int) throws(InstallError) -> RemotePath {
        do {
            return try staging.appending("\(index).apk")
        } catch {
            throw .transport("Invalid staging path")
        }
    }

    private func checkCancellation() throws(InstallError) {
        if Task.isCancelled { throw .cancelled }
    }

    private func adb<T>(_ body: () async throws -> T) async throws(InstallError) -> T {
        do {
            return try await body()
        } catch let error as ADBError {
            throw Self.map(error)
        } catch {
            throw .transport(String(describing: error))
        }
    }

    static func map(_ error: ADBError) -> InstallError {
        switch error {
        case .deviceNotFound, .deviceOffline, .deviceUnauthorized: .deviceDisconnected
        case .process(.cancelled): .cancelled
        default: .transport(String(describing: error))
        }
    }

    /// Runs work that must finish even if the calling task was cancelled (cleanup, commits).
    static func uncancellable<T: Sendable>(_ work: @escaping @Sendable () async -> T) async -> T {
        await Task.detached { await work() }.value
    }
}

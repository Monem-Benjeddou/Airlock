// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockReputation
import Foundation
import Observation

/// Stores and removes the user's own VirusTotal API key.
public protocol APIKeyStoring: Sendable {
    func apiKey() -> String?
    func save(_ key: String) throws(KeychainError)
    func delete() throws(KeychainError)
}

extension KeychainKeyStore: APIKeyStoring {}

@MainActor
@Observable
public final class SettingsModel {
    public var keyInput = ""
    public private(set) var hasKey: Bool
    public private(set) var message: String?

    private let keys: any APIKeyStoring

    public init(keys: any APIKeyStoring) {
        self.keys = keys
        hasKey = keys.apiKey() != nil
    }

    public func saveKey() {
        do {
            try keys.save(keyInput)
            keyInput = ""
            hasKey = true
            message = "Saved. Only file hashes are ever sent to VirusTotal."
        } catch .emptyKey {
            message = "Paste your VirusTotal API key first."
        } catch {
            message = "Could not save the key to your keychain."
        }
    }

    public func removeKey() {
        do {
            try keys.delete()
            hasKey = false
            message = "Removed. Safety reports will skip the VirusTotal lookup."
        } catch {
            message = "Could not remove the key from your keychain."
        }
    }
}

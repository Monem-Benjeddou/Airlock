// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation
import Security

public enum KeychainError: Error, Hashable, Sendable {
    case emptyKey
    /// The keychain is locked or not accessible (for example on a CI runner).
    case unavailable
    case unexpected(OSStatus)
}

/// Stores the user's VirusTotal API key in the login keychain.
public struct KeychainKeyStore: APIKeyProvider {
    public let service: String
    private let account = "virustotal-api-key"

    public init(service: String = "dev.airlock.virustotal") {
        self.service = service
    }

    public func apiKey() -> String? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public func save(_ key: String) throws(KeychainError) {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw .emptyKey }
        let data = Data(trimmed.utf8)
        let update = SecItemUpdate(baseQuery as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw Self.map(update) }
        var add = baseQuery
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw Self.map(status) }
    }

    public func delete() throws(KeychainError) {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw Self.map(status) }
    }

    private var baseQuery: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
    }

    private static func map(_ status: OSStatus) -> KeychainError {
        switch status {
        case errSecInteractionNotAllowed, errSecNotAvailable, errSecAuthFailed, errSecNoSuchKeychain: .unavailable
        default: .unexpected(status)
        }
    }
}

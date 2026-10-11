// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
@testable import AirlockReputation
import Foundation
import Testing

private let hash = String(repeating: "a1", count: 32)

/// Records requests and replies with canned responses; never touches the network.
final class FakeHTTP: HTTPClient, @unchecked Sendable {
    private let lock = NSLock()
    private var responses: [(Int, Data)]
    private var error: (any Error)?
    private(set) var requests: [URLRequest] = []

    init(status: Int = 200, body: String = "", error: (any Error)? = nil) {
        responses = [(status, Data(body.utf8))]
        self.error = error
    }

    var requestCount: Int { lock.withLock { requests.count } }

    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try lock.withLock {
            requests.append(request)
            if let error { throw error }
            let (status, body) = responses[0]
            guard let url = request.url, let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: nil, headerFields: nil) else {
                throw URLError(.badURL)
            }
            return (body, response)
        }
    }
}

struct FixedKey: APIKeyProvider {
    let key: String?
    func apiKey() -> String? { key }
}

private let foundBody = """
{"data": {"id": "\(hash)", "type": "file", "attributes": {
  "last_analysis_stats": {"malicious": 3, "suspicious": 1, "undetected": 60, "harmless": 0, "timeout": 2,
                          "type-unsupported": 4, "failure": 0, "confirmed-timeout": 0},
  "meaningful_name": "game.apk", "sha256": "\(hash)"}}}
"""

@Suite("VirusTotalClient")
struct VirusTotalClientTests {
    private func client(_ http: FakeHTTP, key: String? = "test-key", now: @escaping @Sendable () -> Date = Date.init) -> VirusTotalClient {
        VirusTotalClient(http: http, keys: FixedKey(key: key), now: now)
    }

    @Test func sendsOnlyTheHashWithTheUsersKey() async throws {
        let http = FakeHTTP(body: foundBody)
        let result = await client(http).lookup(sha256: hash)
        let request = try #require(http.requests.first)
        #expect(request.url?.absoluteString == "https://www.virustotal.com/api/v3/files/\(hash)")
        #expect(request.httpMethod == "GET")
        #expect(request.httpBody == nil)
        #expect(request.value(forHTTPHeaderField: "x-apikey") == "test-key")
        #expect(result == .found(
            malicious: 3, suspicious: 1, total: 70,
            permalink: URL(string: "https://www.virustotal.com/gui/file/\(hash)")
        ))
    }

    @Test func notFoundMeansUnknown() async {
        let http = FakeHTTP(status: 404, body: #"{"error": {"code": "NotFoundError"}}"#)
        #expect(await client(http).lookup(sha256: hash) == .unknown)
    }

    @Test func noKeyMeansNotConfiguredAndNoRequest() async {
        let http = FakeHTTP(body: foundBody)
        #expect(await client(http, key: nil).lookup(sha256: hash) == .notConfigured)
        #expect(await client(http, key: "  ").lookup(sha256: hash) == .notConfigured)
        #expect(http.requestCount == 0)
    }

    @Test(arguments: [
        (401, "The VirusTotal API key was rejected."),
        (403, "The VirusTotal API key was rejected."),
        (429, "The VirusTotal lookup limit was reached. Try again later."),
        (500, "VirusTotal returned an error (500)."),
    ])
    func httpErrorsAreUnavailableWithPlainMessages(_ status: Int, _ message: String) async {
        let http = FakeHTTP(status: status, body: "{}")
        #expect(await client(http).lookup(sha256: hash) == .unavailable(message))
    }

    @Test func networkFailureIsUnavailable() async {
        let http = FakeHTTP(error: URLError(.notConnectedToInternet))
        #expect(await client(http).lookup(sha256: hash) == .unavailable("VirusTotal could not be reached."))
    }

    @Test func malformedJSONIsUnavailable() async {
        let http = FakeHTTP(body: "{not json")
        #expect(await client(http).lookup(sha256: hash) == .unavailable("VirusTotal sent a response Airlock could not read."))
    }

    @Test(arguments: ["", "abc", String(repeating: "g", count: 64), String(repeating: "A", count: 64), "../" + String(repeating: "a", count: 61)])
    func rejectsInvalidHashesWithoutARequest(_ bad: String) async {
        let http = FakeHTTP(body: foundBody)
        #expect(await client(http).lookup(sha256: bad) == .unavailable("Invalid file hash."))
        #expect(http.requestCount == 0)
    }

    @Test func cachesResultsFor24Hours() async {
        let http = FakeHTTP(body: foundBody)
        let clock = MutableClock(Date(timeIntervalSince1970: 0))
        let vt = client(http) { clock.now }
        _ = await vt.lookup(sha256: hash)
        _ = await vt.lookup(sha256: hash)
        #expect(http.requestCount == 1)
        clock.advance(by: 23 * 3600)
        _ = await vt.lookup(sha256: hash)
        #expect(http.requestCount == 1)
        clock.advance(by: 2 * 3600)
        _ = await vt.lookup(sha256: hash)
        #expect(http.requestCount == 2)
    }

    @Test func failuresAreNotCached() async {
        let http = FakeHTTP(error: URLError(.timedOut))
        let vt = client(http)
        _ = await vt.lookup(sha256: hash)
        _ = await vt.lookup(sha256: hash)
        #expect(http.requestCount == 2)
    }

    @Test func requestHasTimeout() async throws {
        let http = FakeHTTP(body: foundBody)
        _ = await client(http).lookup(sha256: hash)
        #expect(try #require(http.requests.first).timeoutInterval == 10)
    }
}

final class MutableClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date
    init(_ start: Date) { current = start }
    var now: Date { lock.withLock { current } }
    func advance(by seconds: TimeInterval) { lock.withLock { current += seconds } }
}

@Suite("Keychain API key store")
struct KeychainKeyStoreTests {
    @Test func storesReadsAndDeletes() throws {
        let store = KeychainKeyStore(service: "dev.airlock.tests.\(UUID().uuidString)")
        defer { try? store.delete() }
        do {
            try store.save("secret-1")
        } catch KeychainError.unavailable {
            return // Locked keychain on CI runners; covered on developer machines.
        }
        #expect(store.apiKey() == "secret-1")
        try store.save("secret-2")
        #expect(store.apiKey() == "secret-2")
        try store.delete()
        #expect(store.apiKey() == nil)
    }

    @Test func emptyKeyIsRejected() {
        let store = KeychainKeyStore(service: "dev.airlock.tests.\(UUID().uuidString)")
        #expect(throws: KeychainError.emptyKey) { try store.save("  ") }
    }
}

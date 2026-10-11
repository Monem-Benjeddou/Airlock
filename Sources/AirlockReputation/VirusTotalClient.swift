// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation

public protocol HTTPClient: Sendable {
    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

extension URLSession: HTTPClient {
    public func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await data(for: request, delegate: nil)
        guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        return (data, http)
    }
}

public protocol APIKeyProvider: Sendable {
    func apiKey() -> String?
}

/// Hash-only VirusTotal v3 lookups with the user's own API key.
///
/// Only the SHA-256 leaves the Mac: no file, no file name, no package name. Results are cached for
/// 24 hours; failures are not cached so a retry can succeed.
public actor VirusTotalClient {
    public static let cacheLifetime: TimeInterval = 24 * 3600
    private static let baseURL = "https://www.virustotal.com/api/v3/files/"

    private let http: any HTTPClient
    private let keys: any APIKeyProvider
    private let now: @Sendable () -> Date
    private var cache: [String: (result: ReputationResult, storedAt: Date)] = [:]

    public init(
        http: any HTTPClient = URLSession(configuration: .ephemeral),
        keys: any APIKeyProvider,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.http = http
        self.keys = keys
        self.now = now
    }

    public func lookup(sha256: String) async -> ReputationResult {
        guard Self.isValidHash(sha256) else { return .unavailable("Invalid file hash.") }
        guard let key = keys.apiKey()?.trimmingCharacters(in: .whitespacesAndNewlines), !key.isEmpty else { return .notConfigured }

        if let cached = cache[sha256], now().timeIntervalSince(cached.storedAt) < Self.cacheLifetime {
            return cached.result
        }
        let result = await fetch(sha256: sha256, key: key)
        switch result {
        case .found, .unknown: cache[sha256] = (result, now())
        case .notConfigured, .unavailable: break
        }
        return result
    }

    private func fetch(sha256: String, key: String) async -> ReputationResult {
        guard let url = URL(string: Self.baseURL + sha256) else { return .unavailable("Invalid file hash.") }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10)
        request.httpMethod = "GET"
        request.setValue(key, forHTTPHeaderField: "x-apikey")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await http.data(for: request)
        } catch {
            return .unavailable("VirusTotal could not be reached.")
        }
        switch response.statusCode {
        case 200: break
        case 404: return .unknown
        case 401, 403: return .unavailable("The VirusTotal API key was rejected.")
        case 429: return .unavailable("The VirusTotal lookup limit was reached. Try again later.")
        default: return .unavailable("VirusTotal returned an error (\(response.statusCode)).")
        }
        guard let report = try? JSONDecoder().decode(FileReport.self, from: data) else {
            return .unavailable("VirusTotal sent a response Airlock could not read.")
        }
        let stats = report.data.attributes.lastAnalysisStats
        return .found(
            malicious: stats.malicious,
            suspicious: stats.suspicious,
            total: stats.total,
            permalink: URL(string: "https://www.virustotal.com/gui/file/" + sha256)
        )
    }

    static func isValidHash(_ value: String) -> Bool {
        value.count == 64 && value.utf8.allSatisfy {
            (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains($0)
        }
    }
}

/// The subset of the v3 file object Airlock reads.
private struct FileReport: Decodable {
    struct Payload: Decodable { let attributes: Attributes }
    struct Attributes: Decodable {
        let lastAnalysisStats: Stats
        enum CodingKeys: String, CodingKey { case lastAnalysisStats = "last_analysis_stats" }
    }

    struct Stats: Decodable {
        let malicious: Int
        let suspicious: Int
        let undetected: Int
        let harmless: Int
        let timeout: Int
        let typeUnsupported: Int
        let failure: Int

        enum CodingKeys: String, CodingKey {
            case malicious, suspicious, undetected, harmless, timeout, failure
            case typeUnsupported = "type-unsupported"
        }

        init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            func count(_ key: CodingKeys) throws -> Int { try container.decodeIfPresent(Int.self, forKey: key) ?? 0 }
            malicious = try count(.malicious)
            suspicious = try count(.suspicious)
            undetected = try count(.undetected)
            harmless = try count(.harmless)
            timeout = try count(.timeout)
            typeUnsupported = try count(.typeUnsupported)
            failure = try count(.failure)
        }

        /// Every engine that reported, as VirusTotal's web page counts them.
        var total: Int { malicious + suspicious + undetected + harmless + timeout + typeUnsupported + failure }
    }

    let data: Payload
}

extension VirusTotalClient: ReputationLookup {}

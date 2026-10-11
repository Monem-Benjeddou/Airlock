// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Foundation
import GRDB

public enum JournalError: Error, Hashable, Sendable {
    case entryNotFound(UUID)
}

/// The action journal, stored in SQLite.
///
/// Each entry is stored as JSON alongside indexed columns for lookups, so the schema survives new
/// action kinds without migrations. Writes go through GRDB's serialised writer.
public final class SQLiteJournalStore: JournalStore {
    private let database: any DatabaseWriter
    private let now: @Sendable () -> Date

    /// Opens (or creates) the journal at `url`, e.g. `~/Library/Application Support/Airlock/journal.sqlite`.
    public convenience init(url: URL, now: @escaping @Sendable () -> Date = Date.init) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        var configuration = Configuration()
        configuration.label = "Airlock journal"
        try self.init(database: DatabasePool(path: url.path, configuration: configuration), now: now)
    }

    public static func inMemory(now: @escaping @Sendable () -> Date = Date.init) throws -> SQLiteJournalStore {
        try SQLiteJournalStore(database: DatabaseQueue(), now: now)
    }

    private init(database: any DatabaseWriter, now: @escaping @Sendable () -> Date) throws {
        self.database = database
        self.now = now
        try Self.migrator.migrate(database)
    }

    private static var migrator: DatabaseMigrator {
        var migrator = DatabaseMigrator()
        migrator.registerMigration("v1") { db in
            try db.create(table: "journal") { table in
                table.primaryKey("id", .text)
                table.column("deviceID", .text).notNull().indexed()
                table.column("status", .text).notNull().indexed()
                table.column("createdAt", .double).notNull()
                table.column("payload", .blob).notNull()
            }
        }
        return migrator
    }

    public func append(_ entry: JournalEntry) async throws {
        let payload = try Self.encoder.encode(entry)
        try await database.write { db in
            try db.execute(
                sql: "INSERT INTO journal (id, deviceID, status, createdAt, payload) VALUES (?, ?, ?, ?, ?)",
                arguments: [entry.id.uuidString, entry.deviceID, entry.status.rawValue, entry.createdAt.timeIntervalSince1970, payload]
            )
        }
    }

    public func update(id: UUID, status: JournalEntry.Status, note: String?) async throws {
        let timestamp = now()
        try await database.write { db in
            guard let payload = try Data.fetchOne(db, sql: "SELECT payload FROM journal WHERE id = ?", arguments: [id.uuidString]) else {
                throw JournalError.entryNotFound(id)
            }
            var entry = try Self.decoder.decode(JournalEntry.self, from: payload)
            entry.status = status
            entry.note = note
            entry.updatedAt = timestamp
            try db.execute(
                sql: "UPDATE journal SET status = ?, payload = ? WHERE id = ?",
                arguments: [status.rawValue, try Self.encoder.encode(entry), id.uuidString]
            )
        }
    }

    public func entries(deviceID: String) async throws -> [JournalEntry] {
        try await fetch(sql: "SELECT payload FROM journal WHERE deviceID = ? ORDER BY createdAt DESC", arguments: [deviceID])
    }

    public func pendingEntries() async throws -> [JournalEntry] {
        try await fetch(
            sql: "SELECT payload FROM journal WHERE status = ? ORDER BY createdAt ASC",
            arguments: [JournalEntry.Status.pending.rawValue]
        )
    }

    private func fetch(sql: String, arguments: StatementArguments) async throws -> [JournalEntry] {
        let payloads = try await database.read { db in try Data.fetchAll(db, sql: sql, arguments: arguments) }
        return try payloads.map { try Self.decoder.decode(JournalEntry.self, from: $0) }
    }

    /// Writes a raw row; only for tests that exercise corrupt data.
    public func insertRawForTesting(id: UUID, deviceID: String, payload: Data) async throws {
        try await database.write { db in
            try db.execute(
                sql: "INSERT INTO journal (id, deviceID, status, createdAt, payload) VALUES (?, ?, 'pending', 0, ?)",
                arguments: [id.uuidString, deviceID, payload]
            )
        }
    }

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return decoder
    }()
}

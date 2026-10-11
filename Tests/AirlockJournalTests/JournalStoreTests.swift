// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import AirlockJournal
import Foundation
import Testing

@Suite("SQLiteJournalStore")
struct JournalStoreTests {
    private func pkg(_ raw: String) -> PackageName {
        PackageName(rawValue: raw) ?? { preconditionFailure(raw) }()
    }

    private func entry(_ device: String = "R58", _ package: String = "com.a.b", at seconds: TimeInterval = 0,
                       kind: JournalEntry.Kind = .operation(.disableForUser), restore: RestoreAction = .enable) -> JournalEntry {
        JournalEntry(
            deviceID: device, packageName: pkg(package), kind: kind, restore: restore,
            createdAt: Date(timeIntervalSince1970: 1_800_000_000 + seconds)
        )
    }

    @Test func appendsAndReadsBackNewestFirst() async throws {
        let store = try SQLiteJournalStore.inMemory()
        let first = entry(at: 0)
        let second = entry("R58", "com.c.d", at: 10, kind: .operation(.uninstallForUser), restore: .installExisting)
        try await store.append(first)
        try await store.append(second)
        let entries = try await store.entries(deviceID: "R58")
        #expect(entries.map(\.id) == [second.id, first.id])
        #expect(entries[0] == second)
    }

    @Test func separatesDevices() async throws {
        let store = try SQLiteJournalStore.inMemory()
        try await store.append(entry("A"))
        try await store.append(entry("B"))
        #expect(try await store.entries(deviceID: "A").count == 1)
        #expect(try await store.entries(deviceID: "missing").isEmpty)
    }

    @Test func updatesStatusAndNote() async throws {
        let later = Date(timeIntervalSince1970: 1_900_000_000)
        let store = try SQLiteJournalStore.inMemory { later }
        let original = entry()
        try await store.append(original)
        try await store.update(id: original.id, status: .applied, note: "ok")
        let updated = try #require(try await store.entries(deviceID: "R58").first)
        #expect(updated.status == .applied)
        #expect(updated.note == "ok")
        #expect(updated.updatedAt == later)
        #expect(updated.createdAt == original.createdAt)
        #expect(updated.isRestorable)
    }

    @Test func updatingUnknownEntryThrows() async throws {
        let store = try SQLiteJournalStore.inMemory()
        await #expect(throws: JournalError.entryNotFound(UUID(uuidString: "00000000-0000-0000-0000-000000000009") ?? UUID())) {
            try await store.update(id: UUID(uuidString: "00000000-0000-0000-0000-000000000009") ?? UUID(), status: .failed, note: nil)
        }
    }

    @Test func pendingEntriesSurviveForReconciliation() async throws {
        let store = try SQLiteJournalStore.inMemory()
        let pending = entry("A", "com.a.b")
        let applied = entry("B", "com.c.d")
        try await store.append(pending)
        try await store.append(applied)
        try await store.update(id: applied.id, status: .applied, note: nil)
        #expect(try await store.pendingEntries().map(\.id) == [pending.id])
    }

    @Test func roundTripsEveryKindAndRestoreAction() async throws {
        let store = try SQLiteJournalStore.inMemory()
        let entries = [
            entry(at: 1, kind: .operation(.uninstall), restore: .reinstallFromBackup(apkPaths: ["/tmp/a/base.apk", "/tmp/a/split.apk"])),
            entry(at: 2, kind: .install(versionCode: 9_000_000_001, wasUpdate: false), restore: .uninstallInstalled),
            entry(at: 3, kind: .install(versionCode: 5, wasUpdate: true), restore: .notRestorable),
            entry(at: 4, kind: .operation(.enable), restore: .notRestorable),
        ]
        for item in entries { try await store.append(item) }
        let read = try await store.entries(deviceID: "R58")
        #expect(Set(read) == Set(entries))
    }

    @Test func persistsAcrossReopenOnDisk() async throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("airlock-journal-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: folder) }
        let url = folder.appendingPathComponent("journal.sqlite")
        let original = entry()
        do {
            let store = try SQLiteJournalStore(url: url)
            try await store.append(original)
        }
        let reopened = try SQLiteJournalStore(url: url)
        #expect(try await reopened.entries(deviceID: "R58") == [original])
    }

    @Test func duplicateIDIsRejected() async throws {
        let store = try SQLiteJournalStore.inMemory()
        let original = entry()
        try await store.append(original)
        await #expect(throws: (any Error).self) { try await store.append(original) }
    }

    @Test func concurrentAppendsAreAllRecorded() async throws {
        let store = try SQLiteJournalStore.inMemory()
        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0..<50 {
                group.addTask { try await store.append(entry(at: TimeInterval(index))) }
            }
            try await group.waitForAll()
        }
        #expect(try await store.entries(deviceID: "R58").count == 50)
    }

    @Test func corruptPayloadSurfacesAsError() async throws {
        let store = try SQLiteJournalStore.inMemory()
        try await store.insertRawForTesting(id: UUID(), deviceID: "R58", payload: Data("not json".utf8))
        await #expect(throws: (any Error).self) { try await store.entries(deviceID: "R58") }
    }
}

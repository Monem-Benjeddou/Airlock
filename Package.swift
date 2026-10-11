// swift-tools-version:6.0
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import PackageDescription

/// Strict concurrency is the default in the Swift 6 language mode; warnings are errors everywhere.
let strict: [SwiftSetting] = [
    .unsafeFlags(["-warnings-as-errors"]),
    .enableUpcomingFeature("ExistentialAny"),
]

let package = Package(
    name: "Airlock",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "AirlockCore", targets: ["AirlockCore"]),
        .library(name: "AirlockArchive", targets: ["AirlockArchive"]),
        .library(name: "AirlockADB", targets: ["AirlockADB"]),
        .library(name: "AirlockSafety", targets: ["AirlockSafety"]),
        .library(name: "AirlockJournal", targets: ["AirlockJournal"]),
        .library(name: "AirlockReputation", targets: ["AirlockReputation"]),
        .library(name: "AirlockPairing", targets: ["AirlockPairing"]),
        .library(name: "AirlockServices", targets: ["AirlockServices"]),
        .library(name: "AirlockUI", targets: ["AirlockUI"]),
        .executable(name: "AirlockDev", targets: ["AirlockDev"]),
    ],
    dependencies: [
        .package(url: "https://github.com/groue/GRDB.swift.git", exact: "7.4.1"),
    ],
    targets: [
        // Domain models, service protocols and pure logic. No I/O.
        .target(name: "AirlockCore", swiftSettings: strict),

        // Hostile-input parsing: zip, binary XML, DEX, APK signing block. Foundation + zlib only,
        // so it also builds on Linux for libFuzzer. Runs inside the ParserXPC helper in the app.
        .target(
            name: "AirlockArchive",
            dependencies: ["AirlockCore", .target(name: "CZlib", condition: .when(platforms: [.linux]))],
            swiftSettings: strict,
            linkerSettings: [.linkedLibrary("z")]
        ),
        // Linux has no `zlib` Clang module (Apple SDKs do); this module map exposes the system zlib.h.
        .systemLibrary(name: "CZlib", path: "Sources/CZlib"),

        // The only code that talks to adb.
        .target(name: "AirlockADB", dependencies: ["AirlockCore"], swiftSettings: strict),

        .target(
            name: "AirlockSafety",
            dependencies: ["AirlockCore", "AirlockArchive"],
            resources: [.process("Resources")],
            swiftSettings: strict
        ),
        .target(
            name: "AirlockJournal",
            dependencies: ["AirlockCore", .product(name: "GRDB", package: "GRDB.swift")],
            swiftSettings: strict
        ),
        .target(name: "AirlockReputation", dependencies: ["AirlockCore"], swiftSettings: strict),
        .target(name: "AirlockPairing", dependencies: ["AirlockCore", "AirlockADB"], swiftSettings: strict),
        .target(
            name: "AirlockServices",
            dependencies: [
                "AirlockCore", "AirlockADB", "AirlockArchive", "AirlockSafety",
                "AirlockJournal", "AirlockReputation", "AirlockPairing",
            ],
            resources: [.copy("Resources/presets")],
            swiftSettings: strict
        ),
        .target(
            name: "AirlockUI",
            dependencies: [
                "AirlockCore", "AirlockADB", "AirlockJournal", "AirlockSafety", "AirlockServices",
                "AirlockPairing", "AirlockReputation",
            ],
            swiftSettings: strict
        ),

        // Runs the SwiftUI app straight from SwiftPM for development (`swift run AirlockDev`).
        // The shipping app is the Xcode target in App/, generated from project.yml.
        .executableTarget(name: "AirlockDev", dependencies: ["AirlockUI"], swiftSettings: strict),

        // MARK: Tests

        .target(
            name: "AirlockTestSupport",
            dependencies: ["AirlockCore", "AirlockADB"],
            path: "Tests/AirlockTestSupport",
            resources: [.copy("Fixtures")],
            swiftSettings: strict
        ),
        .testTarget(name: "AirlockCoreTests", dependencies: ["AirlockCore"], swiftSettings: strict),
        .testTarget(
            name: "AirlockArchiveTests",
            dependencies: ["AirlockArchive", "AirlockTestSupport"],
            swiftSettings: strict
        ),
        .testTarget(
            name: "AirlockADBTests",
            dependencies: ["AirlockADB", "AirlockTestSupport"],
            swiftSettings: strict
        ),
        .testTarget(
            name: "AirlockSafetyTests",
            dependencies: ["AirlockSafety", "AirlockTestSupport"],
            swiftSettings: strict
        ),
        .testTarget(name: "AirlockJournalTests", dependencies: ["AirlockJournal"], swiftSettings: strict),
        .testTarget(name: "AirlockReputationTests", dependencies: ["AirlockReputation"], swiftSettings: strict),
        .testTarget(
            name: "AirlockPairingTests",
            dependencies: ["AirlockPairing", "AirlockTestSupport"],
            swiftSettings: strict
        ),
        .testTarget(
            name: "AirlockServicesTests",
            dependencies: ["AirlockServices", "AirlockTestSupport"],
            swiftSettings: strict
        ),
        .testTarget(
            name: "AirlockUITests",
            dependencies: ["AirlockUI", "AirlockTestSupport"],
            swiftSettings: strict
        ),
        // Talks to a real emulator; skipped unless AIRLOCK_INTEGRATION=1.
        .testTarget(
            name: "AirlockIntegrationTests",
            dependencies: ["AirlockServices", "AirlockJournal", "AirlockSafety", "AirlockTestSupport"],
            swiftSettings: strict
        ),
    ]
)

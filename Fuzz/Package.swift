// swift-tools-version:6.0
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import PackageDescription

// libFuzzer harness for the hostile-archive parsers. Linux only (Apple's toolchain ships no libFuzzer);
// run it with scripts/fuzz.sh, which builds in the swift:6.1 Docker image with
// `-sanitize=fuzzer,address`. The root package must be checked out in a folder named `Airlock`.
let package = Package(
    name: "AirlockFuzz",
    dependencies: [
        .package(name: "Airlock", path: ".."),
    ],
    targets: [
        // Declares LLVMFuzzerRunDriver. SwiftPM renames an executable's entry point in debug builds, so
        // main.swift keeps its own main() and hands control to libFuzzer explicitly.
        .target(name: "CFuzzerDriver", path: "CFuzzerDriver"),
        .executableTarget(
            name: "ArchiveFuzz",
            dependencies: ["CFuzzerDriver", .product(name: "AirlockArchive", package: "Airlock")],
            path: "ArchiveFuzz"
        ),
    ]
)

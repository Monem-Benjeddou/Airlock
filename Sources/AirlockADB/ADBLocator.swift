// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Finds the adb binary to use.
///
/// Order: the copy inside the app bundle (version-pinned, if the release ships one), then an Android
/// SDK or Homebrew install. Whether Airlock may redistribute Google's binary is an open licensing
/// question, so the app must work with a user-installed adb too.
public struct ADBLocator: Sendable {
    /// The platform-tools version Airlock is tested against.
    public static let testedVersion = "37.0.1"

    public enum Source: Hashable, Sendable {
        case bundled
        case androidSDK
        case homebrew
        case custom
    }

    public struct Location: Hashable, Sendable {
        public let url: URL
        public let source: Source
    }

    private let candidates: [(URL, Source)]
    private let isExecutable: @Sendable (String) -> Bool

    public init(
        bundledURL: URL? = Bundle.main.url(forResource: "adb", withExtension: nil, subdirectory: "platform-tools"),
        customPath: String? = nil,
        homeDirectory: String = NSHomeDirectory(),
        isExecutable: @escaping @Sendable (String) -> Bool = { FileManager.default.isExecutableFile(atPath: $0) }
    ) {
        var candidates: [(URL, Source)] = []
        if let customPath { candidates.append((URL(fileURLWithPath: customPath), .custom)) }
        if let bundledURL { candidates.append((bundledURL, .bundled)) }
        candidates.append((URL(fileURLWithPath: homeDirectory + "/Library/Android/sdk/platform-tools/adb"), .androidSDK))
        candidates.append((URL(fileURLWithPath: "/opt/homebrew/bin/adb"), .homebrew))
        candidates.append((URL(fileURLWithPath: "/usr/local/bin/adb"), .homebrew))
        self.candidates = candidates
        self.isExecutable = isExecutable
    }

    public func locate() -> Location? {
        candidates.first { isExecutable($0.0.path) }.map { Location(url: $0.0, source: $0.1) }
    }

    /// True when the major.minor of `version` matches the tested version.
    public static func isTested(_ version: String) -> Bool {
        version.split(separator: ".").prefix(2) == testedVersion.split(separator: ".").prefix(2)
    }
}

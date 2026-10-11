// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// Locates the APK fixtures built by `scripts/make-test-apks.sh`.
///
/// Files live in `Fixtures/apk/` (whole APKs) and `Fixtures/apk/raw/` (entries pulled out of them, so parser
/// tests do not need a zip reader). Every key in `keys/` is a test-only key.
public enum FixtureAPKs {
    public enum FixtureError: Error, Equatable {
        case missing(String)
    }

    /// The whole APKs, by file stem.
    public enum APK: String, CaseIterable, Sendable {
        case unsigned = "app-unsigned"
        case flagsUnsigned = "flags-unsigned"
        case v1RSA = "app-v1-rsa"
        case v2RSA = "app-v2-rsa"
        case v3RSA = "app-v3-rsa"
        case v123RSA = "app-v123-rsa"
        case v1EC = "app-v1-ec"
        case v2EC = "app-v2-ec"
        case v123EC = "app-v123-ec"
        /// v2 + v4; the detached `app-v24-rsa.apk.idsig` sits next to it.
        case v24RSA = "app-v24-rsa"
        /// Key rotation RSA → EC: v2 + v3 (old signer) + v3.1 (new signer).
        case rotated = "app-rotated"
        /// `app-v123-rsa` with one byte flipped after signing.
        case tampered = "app-tampered"
        /// `split="config.arm64_v8a"`, v2-signed.
        case splitArm64 = "split-arm64-v2-rsa"
    }

    /// The fixtures folder (`Fixtures/apk`).
    public static func directory() throws -> URL {
        guard let url = Bundle.module.url(forResource: "Fixtures/apk", withExtension: nil) else {
            throw FixtureError.missing("Fixtures/apk")
        }
        return url
    }

    public static func url(_ apk: APK) throws -> URL {
        try existing(directory().appendingPathComponent("\(apk.rawValue).apk"))
    }

    /// A file under `Fixtures/apk/raw/`, e.g. `app.AndroidManifest.xml` or `classes.dex`.
    public static func rawURL(_ name: String) throws -> URL {
        try existing(directory().appendingPathComponent("raw").appendingPathComponent(name))
    }

    public static func raw(_ name: String) throws -> Data {
        try Data(contentsOf: rawURL(name))
    }

    public static func data(_ apk: APK) throws -> Data {
        try Data(contentsOf: url(apk))
    }

    /// Binary `AndroidManifest.xml` of the plain app, the flags app and the split.
    public static func appManifest() throws -> Data { try raw("app.AndroidManifest.xml") }
    public static func flagsManifest() throws -> Data { try raw("flags.AndroidManifest.xml") }
    public static func splitManifest() throws -> Data { try raw("split.AndroidManifest.xml") }
    /// `classes.dex` compiled from stubs in `com/facebook/ads`, `com/google/firebase/analytics` and
    /// `org/airlock/fixture/deep/inner`.
    public static func classesDex() throws -> Data { try raw("classes.dex") }

    /// Zip entry names of a v1-signed fixture (`app-v1-rsa` or `app-v1-ec`).
    public static func entryNames(_ stem: String) throws -> [String] {
        let text = String(decoding: try raw("\(stem).entries.txt"), as: UTF8.self)
        return text.split(separator: "\n").map(String.init)
    }

    private static func existing(_ url: URL) throws -> URL {
        guard FileManager.default.fileExists(atPath: url.path) else { throw FixtureError.missing(url.lastPathComponent) }
        return url
    }
}

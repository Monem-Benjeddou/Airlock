// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation
import SwiftUI

/// A rounded square with the app's first letter, standing in for an icon Airlock cannot read. Its colour comes
/// from the package name, so one app always gets the same tile.
struct AppTile: View {
    let name: String
    let seed: String
    var size: CGFloat = 36

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
            .fill(AppTile.color(for: seed).gradient)
            .frame(width: size, height: size)
            .overlay {
                Text(AppTile.monogram(for: name))
                    .font(.system(size: size * 0.48, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
            }
            .accessibilityHidden(true)
    }

    static let colors: [Color] = [
        Color(red: 0.20, green: 0.47, blue: 0.85), Color(red: 0.13, green: 0.58, blue: 0.61),
        Color(red: 0.36, green: 0.60, blue: 0.25), Color(red: 0.80, green: 0.50, blue: 0.13),
        Color(red: 0.78, green: 0.30, blue: 0.30), Color(red: 0.58, green: 0.35, blue: 0.75),
        Color(red: 0.42, green: 0.45, blue: 0.52), Color(red: 0.75, green: 0.32, blue: 0.55),
    ]

    /// FNV-1a over the UTF-8 bytes: stable across launches, unlike `hashValue`.
    static func color(for seed: String) -> Color {
        var hash: UInt32 = 2_166_136_261
        for byte in seed.utf8 {
            hash ^= UInt32(byte)
            hash = hash &* 16_777_619
        }
        return colors[Int(hash % UInt32(colors.count))]
    }

    static func monogram(for name: String) -> String {
        name.first { $0.isLetter || $0.isNumber }.map { String($0).uppercased() } ?? "?"
    }
}

/// Readable names for apps when Airlock only knows a package or file name.
enum AppNaming {
    /// Package segments that say nothing about the app.
    private static let generic: Set<String> = [
        "android", "app", "apps", "mobile", "client", "main", "free", "pro", "lite", "release", "prod", "phone",
    ]

    /// "com.google.android.apps.tips" → "Tips", "org.thoughtcrime.securesms" → "Securesms".
    static func name(forPackage package: String) -> String {
        let segments = package.split(separator: ".").map(String.init)
        let meaningful = segments.dropFirst().last { !generic.contains($0.lowercased()) } ?? segments.last ?? package
        return words(meaningful)
    }

    /// "Signal-Android-7.1.apk" → "Signal Android 7.1"; a folder keeps its name.
    static func name(forFile file: URL) -> String {
        let base = ["apk", "apks", "xapk", "apkm"].contains(file.pathExtension.lowercased())
            ? file.deletingPathExtension().lastPathComponent : file.lastPathComponent
        return words(base)
    }

    /// Splits on `_`, `-` and camelCase, and capitalises the first letter of each word.
    static func words(_ raw: String) -> String {
        var result = ""
        var previous: Character?
        for character in raw {
            if character == "_" || character == "-" {
                result.append(" ")
            } else {
                if let previous, previous.isLowercase, character.isUppercase { result.append(" ") }
                result.append(character)
            }
            previous = character
        }
        let parts = result.split(separator: " ").map { $0.prefix(1).uppercased() + $0.dropFirst() }
        return parts.isEmpty ? raw : parts.joined(separator: " ")
    }
}

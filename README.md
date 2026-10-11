<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Airlock contributors -->

# Airlock

Airlock is a free, open-source native macOS app that installs, vets and manages Android apps over USB or Wi-Fi.
Every APK passes through the airlock, a plain-English safety check, before it reaches your phone.

> **Status:** pre-release, under active development. Not ready for everyday use yet.

## What it does

| Feature | What you get |
| --- | --- |
| Device connection | Detects phones over USB, explains "unauthorized" and "offline", and walks you through enabling USB debugging on Pixel, Samsung, Xiaomi and OnePlus. |
| Drag-and-drop installer | Installs `.apk`, `.apks`, `.xapk`, `.apkm` and folders of split APKs, picks the right splits for your phone, pushes OBB game data and verifies it. Cancel never leaves a half-installed app. |
| Safety report | Before every install: who signed the app, what its permissions let it do in plain language, which tracker SDKs it contains, and an optional VirusTotal hash lookup. Verdicts are Low, Medium or High risk, never "safe". |
| App manager and debloat | Lists every app, disables or removes bloatware with brand presets, logs every change and restores it in one click. Core system packages cannot be removed. |
| Wireless pairing | Pair over Wi-Fi with a QR code (Android 11+), a pairing code, or `adb tcpip` for older phones, with diagnosis when the network blocks discovery. |

Airlock never hosts or links to APKs and does not modify, repackage or crack apps. Use it for software you have the right to install.

## Requirements

- macOS 14 Sonoma or later, Apple silicon or Intel
- An Android phone with USB debugging enabled (Airlock shows you how)

## Privacy

Airlock works offline. The only network request it can make is the optional VirusTotal lookup, which sends the file's SHA-256 hash, never the file, and only after you add your own API key. Analytics and crash reports are off unless you opt in, and never include file names, package names or device identifiers.

## Building from source

```sh
git clone https://github.com/Monem-Benjeddou/Airlock.git
cd Airlock
swift build            # core libraries
swift test             # unit, contract and property tests
swift run AirlockDev   # run the app straight from SwiftPM (development only)
```

The shipping app bundle, with its sandboxed parser helper, is built from `project.yml`:

```sh
brew install xcodegen
xcodegen generate
xcodebuild -scheme Airlock -destination 'platform=macOS' build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the architecture, test layers and how to add device presets.

## Architecture in one paragraph

SwiftUI views talk only to four service protocols (`DeviceService`, `InstallPipeline`, `SafetyEngine`, `AppManager`). Services use a platform layer in which only `ADBClient` talks to `adb`, always with argument arrays and never a shell, through one serial queue per device. Untrusted archives are parsed in an XPC helper with no network access. Every device change is written to a SQLite journal first, so it can be restored.

## Licence

GPL-3.0-only. See [LICENSE](LICENSE). Debloat presets build on the [UAD-ng](https://github.com/Universal-Debloater-Alliance/universal-android-debloater-next-generation) lists (GPL-3.0).

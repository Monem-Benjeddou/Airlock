<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Airlock contributors -->

# Changelog

## 0.1.0

The first preview. Airlock is not notarized yet, so macOS blocks the first launch until you allow it in System Settings › Privacy & Security (see Installing in the README).

### What you can do

- **Connect a phone over USB.** Airlock detects it, explains "unauthorized" and "offline", and walks you through turning on USB debugging for Pixel, Samsung, Xiaomi and OnePlus.
- **Install apps.** Drop APK, APKS, XAPK or APKM files, or a folder of split APKs. Airlock queues up to 20, picks the right splits for the phone, pushes OBB data, and checks the installed version afterwards.
- **Read a safety report before installing.** You see the signature, the developer, permissions in plain words, known trackers, and an optional VirusTotal hash lookup. The verdict is Low, Medium or High risk with reasons, never "safe". Low-risk files install straight away; anything else waits for you.
- **Manage installed apps.** Browse, disable, remove for the current user, export APKs, and apply debloat presets based on UAD-ng. Every change asks first, is journaled, and can be undone from History. Core system apps are protected.
- **Pair over Wi-Fi.** Android 11 and later can pair with a QR code or pairing code; older phones use the USB-to-Wi-Fi switch. Airlock reconnects remembered phones.

### Accessibility

- Every control and status has a name VoiceOver reads; decorative symbols are hidden from it.
- Risk is shown by text and a symbol, never by colour alone, and all text uses full-strength colours.
- Apple's accessibility audit runs on the main screens in every CI build.

### Safety

- Untrusted archives are parsed in a sandboxed helper with no network access. Path traversal, zip bombs and symlinks are rejected.
- Airlock never runs anything from an APK, and only ever calls `adb` with argument arrays, never through a shell.
- Pressing Return on a High risk report never installs it: the safe choice is the default, and Install Anyway needs a tick first.
- Your Mac stays awake and out of App Nap while installs run, so transfers are not cut short.

### Known limitations

- `adb` is not bundled. Install it with `brew install android-platform-tools` or Android Studio.
- APKs signed only with the old v1 (JAR) scheme are reported as "can't verify" instead of verified.
- The list of known developer signatures is still empty.

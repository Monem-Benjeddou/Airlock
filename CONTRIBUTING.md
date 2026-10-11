<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Airlock contributors -->

# Contributing to Airlock

Thanks for helping. Airlock touches phones with debug access, so the bar for correctness is high, but the
easiest contributions (device presets and recorded adb output) need no Swift at all.

## Ground rules

- Be kind. We follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Sign off every commit with the [Developer Certificate of Origin](https://developercertificate.org/):
  `git commit -s`. There is no CLA.
- Every Swift file starts with the SPDX header:

  ```swift
  // SPDX-License-Identifier: GPL-3.0-only
  // SPDX-FileCopyrightText: 2026 Airlock contributors
  ```

## Easy first contributions

1. **Record adb output from your phone.** Run `scripts/record-fixtures.sh <serial>`, which only runs read-only
   commands, check the files for anything personal, and open a PR adding them under
   `Tests/AirlockTestSupport/Fixtures/adb/<brand-model-android>/`. The contract tests will then make sure
   Airlock parses your phone correctly forever.
2. **Improve a debloat preset.** Presets live in `Sources/AirlockServices/Resources/presets/`. Each entry needs a
   risk tag (`safe`, `caution`, `expert`) and a one-line description of what breaks when it is removed.

## Architecture

```
SwiftUI views (AirlockUI)
   │  protocols only
   ▼
Core services (AirlockServices): DeviceService, InstallPipeline, SafetyEngine, AppManager
   │
   ▼
Platform layer
   ├─ AirlockADB         the ONLY code that runs adb (argument arrays, timeouts, one queue per device)
   ├─ AirlockArchive     hostile-input parsers (zip, binary XML, DEX, signing block), run in the XPC helper
   ├─ AirlockJournal     SQLite action journal (GRDB)
   ├─ AirlockReputation  VirusTotal hash-only client
   └─ AirlockPairing     QR pairing, mDNS discovery, network diagnosis
```

Domain types and the service protocols live in `AirlockCore`, which has no I/O.

### Non-negotiable rules

- Never build a shell command string. Use `ProcessRunner` with an argument array. SwiftLint rejects `"/bin/sh"`
  and `"-c"`.
- Every package name passes through `PackageName` before reaching a command.
- Treat every archive as hostile: no extraction outside the job folder, size and ratio caps, no symlinks, and
  nothing from an APK is ever executed.
- Destructive device operations require a `ConfirmedOperation`, are journaled before they run, and are checked
  against `CriticalDenylist`.
- The safety report never says "safe".

## Tests

| Layer | Where | Run |
| --- | --- | --- |
| Unit | `Tests/<Module>Tests` | `swift test` |
| Contract (golden adb output) | `Tests/AirlockADBTests` + `Fixtures/adb` | `swift test --filter Contract` |
| Property | `Tests/AirlockArchiveTests` | `swift test --filter Property` |
| Fuzz | `Fuzz/` (Linux, libFuzzer) | `scripts/fuzz.sh` |
| Integration (emulator) | `Tests/AirlockIntegrationTests` | `AIRLOCK_INTEGRATION=1 swift test --filter Integration` |
| UI | `UITests/` | `xcodebuild test -scheme Airlock` |

Coverage targets: 90% line coverage on core modules, 100% on the error mapper, package-name validation and
the critical denylist. `scripts/coverage.sh` enforces them.

Every bug fix comes with a regression test that fails without the fix.

## Before you open a PR

```sh
scripts/lint.sh
scripts/coverage.sh
```

Both must pass. CI runs the same commands.

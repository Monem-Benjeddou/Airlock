# SPDX-License-Identifier: GPL-3.0-only
# SPDX-FileCopyrightText: 2026 Airlock contributors
"""Fails the build when coverage drops below the plan's targets."""
import json
import sys

# Path fragment -> minimum line coverage percent.
EXACT = {
    "AirlockCore/InstallErrorMapper.swift": 100.0,
    "AirlockCore/CriticalDenylist.swift": 100.0,
    "AirlockCore/PackageName.swift": 100.0,
}
# Modules whose aggregate line coverage must reach 90%.
CORE_MODULES = [
    "Sources/AirlockCore/", "Sources/AirlockADB/", "Sources/AirlockArchive/",
    "Sources/AirlockSafety/", "Sources/AirlockJournal/", "Sources/AirlockReputation/",
    "Sources/AirlockPairing/", "Sources/AirlockServices/",
]
CORE_MINIMUM = 90.0


def main(path: str) -> int:
    files = json.load(open(path))["data"][0]["files"]
    failures = []
    for fragment, minimum in EXACT.items():
        match = [f for f in files if f["filename"].endswith(fragment)]
        if not match:
            failures.append(f"{fragment}: not found in coverage data")
            continue
        pct = match[0]["summary"]["lines"]["percent"]
        status = "ok " if pct >= minimum else "LOW"
        print(f"{status} {pct:6.2f}% (min {minimum:.0f}%) {fragment}")
        if pct < minimum:
            failures.append(f"{fragment}: {pct:.2f}% < {minimum}%")
    for module in CORE_MODULES:
        selected = [f for f in files if module in f["filename"]]
        covered = sum(f["summary"]["lines"]["covered"] for f in selected)
        count = sum(f["summary"]["lines"]["count"] for f in selected)
        if count == 0:
            print(f"--  no code yet           {module}")
            continue
        pct = 100.0 * covered / count
        status = "ok " if pct >= CORE_MINIMUM else "LOW"
        print(f"{status} {pct:6.2f}% (min {CORE_MINIMUM:.0f}%) {module}")
        if pct < CORE_MINIMUM:
            failures.append(f"{module}: {pct:.2f}% < {CORE_MINIMUM}%")
    if failures:
        print("\nCoverage gate failed:\n  " + "\n  ".join(failures))
        return 1
    print("\nCoverage gate passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

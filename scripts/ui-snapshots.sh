#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# SPDX-FileCopyrightText: 2026 Airlock contributors
#
# Captures every main screen of the demo app, for design reviews and before/after comparisons.
# Demo mode only: no adb, no network, no phone. Only Airlock's own window is captured.
#
#   scripts/ui-snapshots.sh <output-folder> [scenario...]
#
# Scenarios: onboarding install queue review apps history wireless (all by default).
set -euo pipefail
OUT="$1"; shift
SCENARIOS=(onboarding install queue review apps history wireless)
[ $# -gt 0 ] && SCENARIOS=("$@")
cd "$(dirname "$0")/.."
mkdir -p "$OUT"
swift build --product AirlockDev >/dev/null
APP=".build/debug/AirlockDev"
WINDOW_ID="$(mktemp -d)/window-id.swift"
cat > "$WINDOW_ID" <<'SWIFT'
import CoreGraphics
let pid = Int(CommandLine.arguments[1]) ?? 0
let list = CGWindowListCopyWindowInfo([.optionAll], kCGNullWindowID) as? [[String: Any]] ?? []
// The largest normal window of the process: the main window, with any sheet drawn into it.
// All windows, not only on-screen ones: the window may open on another Space or display.
let windows = list.filter {
    ($0[kCGWindowOwnerPID as String] as? Int) == pid && ($0[kCGWindowLayer as String] as? Int) == 0
        && ($0[kCGWindowAlpha as String] as? Double ?? 0) > 0
        && (($0[kCGWindowBounds as String] as? [String: Double])?["Height"] ?? 0) > 100
}
let sized = windows.map { window -> (Int, Double) in
    let bounds = window[kCGWindowBounds as String] as? [String: Double] ?? [:]
    return (window[kCGWindowNumber as String] as? Int ?? 0, (bounds["Width"] ?? 0) * (bounds["Height"] ?? 0))
}
// The main window first, then any sheet, so a sheet is also captured on its own.
for window in sized.sorted(by: { $0.1 > $1.1 }) { print(window.0) }
SWIFT

# Forget window frames saved by earlier runs (only those keys), so every capture uses the default size.
forget_frames() {
    defaults read AirlockDev 2>/dev/null | grep -o '"NSWindow Frame [^"]*"' | tr -d '"' | while read -r key; do
        defaults delete AirlockDev "$key" 2>/dev/null || true
    done
}

capture() {
    forget_frames
    local name="$1" section="$2" queue="$3" mode="$4" wifi="${5:-0}"
    AIRLOCK_SECTION="$section" AIRLOCK_DEMO_QUEUE="$queue" AIRLOCK_SHOW_WIFI="$wifi" "$APP" "$mode" >/dev/null 2>&1 &
    local pid=$!
    local ids=""
    for _ in $(seq 1 40); do
        ids="$(swift "$WINDOW_ID" "$pid" 2>/dev/null || true)"
        [ -n "$ids" ] && break
        sleep 0.5
    done
    sleep 3  # let the demo device connect and the queue settle
    ids="$(swift "$WINDOW_ID" "$pid" 2>/dev/null || true)"
    if [ -n "$ids" ]; then
        local suffix=""
        for id in $ids; do
            screencapture -o -x -l "$id" "$OUT/$name$suffix.png"
            suffix="-sheet"
        done
        echo "captured $name"
    else
        echo "no window for $name" >&2
    fi
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

for scenario in "${SCENARIOS[@]}"; do
    case "$scenario" in
        onboarding) capture onboarding install "" --demo-no-device ;;
        install) capture install install "" --demo ;;
        queue) capture queue install "notes.apk,photos.apk,maps.apk" --demo ;;
        review) capture review install "risky.apk" --demo ;;
        apps) capture apps apps "" --demo ;;
        history) capture history history "" --demo ;;
        wireless) capture wireless install "" --demo 1 ;;
        *) echo "unknown scenario $scenario" >&2 ;;
    esac
done

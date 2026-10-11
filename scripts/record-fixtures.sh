#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# SPDX-FileCopyrightText: 2026 Airlock contributors
#
# Records the adb output Airlock parses, for golden-file contract tests.
# READ-ONLY: every command below only reads state; nothing on the phone changes.
#
#   scripts/record-fixtures.sh <serial> <fixture-name>     e.g. R58M123 samsung-s24ultra-android16
#
# Raw output goes to a temp folder; sanitize_fixtures.py then strips personal data (serials,
# third-party package names, battery serials) before anything is written to the repo.
set -euo pipefail
SERIAL="$1"; NAME="$2"
RAW="$(mktemp -d)"
cd "$RAW"
a() { adb -s "$SERIAL" "$@"; }
adb devices -l                                                          > devices-l.txt
a shell getprop                                                         > getprop.txt
a shell dumpsys battery                                                 > dumpsys-battery.txt
a shell wm density                                                      > wm-density.txt
a shell pm list packages --user 0 -f -U --show-versioncode -i          > pm-list-packages.txt
a shell pm list packages --user 0 -s                                    > pm-list-system.txt
a shell pm list packages --user 0 -3                                    > pm-list-third-party.txt
a shell pm list packages --user 0 -d                                    > pm-list-disabled.txt
a shell pm list packages --user 0 -u                                    > pm-list-including-uninstalled.txt
a shell df /data                                                        > df-data.txt
a shell pm path com.android.settings                                    > pm-path.txt
a shell dumpsys package com.android.settings                            > dumpsys-package.txt
a shell cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.HOME > home-activities.txt
a shell ime list -s                                                     > ime-list.txt
a shell pm list users                                                   > pm-list-users.txt
python3 -I "$(dirname "$0")/sanitize_fixtures.py" "$RAW" \
  "$(cd "$(dirname "$0")/.." && pwd)/Tests/AirlockTestSupport/Fixtures/adb/$NAME" "$SERIAL"
rm -rf "$RAW"

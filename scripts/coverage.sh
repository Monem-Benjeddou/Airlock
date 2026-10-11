#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# SPDX-FileCopyrightText: 2026 Airlock contributors
# Runs the test suite with coverage and enforces per-area thresholds.
#   90% line coverage on core services, 100% on error mapping and the critical denylist.
set -euo pipefail
cd "$(dirname "$0")/.."
swift test --enable-code-coverage --parallel "$@"
BIN_DIR="$(swift build --show-bin-path)"
PROFDATA="$BIN_DIR/codecov/default.profdata"
XCTEST="$(find "$BIN_DIR" -maxdepth 1 -name '*.xctest' | head -1)"
OBJECT="$XCTEST/Contents/MacOS/$(basename "$XCTEST" .xctest)"
LLVM_COV="$(xcrun -f llvm-cov)"
mkdir -p coverage
"$LLVM_COV" report "$OBJECT" -instr-profile "$PROFDATA" \
  -ignore-filename-regex='(\.build|Tests|AirlockDev|AirlockUI/Views)' > coverage/report.txt
"$LLVM_COV" export "$OBJECT" -instr-profile "$PROFDATA" -format=text -summary-only \
  -ignore-filename-regex='(\.build|Tests|AirlockDev|AirlockUI/Views)' > coverage/summary.json
cat coverage/report.txt | tail -60
python3 -I scripts/coverage_gate.py coverage/summary.json

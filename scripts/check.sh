#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# SPDX-FileCopyrightText: 2026 Airlock contributors
# Everything that must pass before a commit: lint, build with warnings as errors, tests and coverage.
set -euo pipefail
cd "$(dirname "$0")/.."
scripts/lint.sh
python3 -I -W error scripts/test_sanitize_fixtures.py
swift build --build-tests
scripts/coverage.sh
echo "All checks passed."

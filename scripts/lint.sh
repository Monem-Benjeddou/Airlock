#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# SPDX-FileCopyrightText: 2026 Airlock contributors
# Runs SwiftLint in strict mode. Works with full Xcode or only the Command Line Tools.
set -euo pipefail
cd "$(dirname "$0")/.."
if ! xcode-select -p | grep -q Xcode.app; then
  export DYLD_FRAMEWORK_PATH="$(xcode-select -p)/usr/lib"
fi
swiftlint lint --strict --quiet "$@"

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# SPDX-FileCopyrightText: 2026 Airlock contributors
#
# Fuzzes AirlockArchive with libFuzzer + AddressSanitizer in a Linux container. Apple's toolchain has no
# libFuzzer, so this needs Docker.
#
#   scripts/fuzz.sh [seconds]        default 300
#
# The corpus persists in Fuzz/corpus-archive/ and crashing inputs land in Fuzz/crash-* (both git-ignored).
# Reproduce a crash by passing its file to the same binary inside the container.
set -euo pipefail
cd "$(dirname "$0")/.."
DURATION="${1:-300}"
IMAGE="swift:6.1"
mkdir -p Fuzz/corpus-archive
# Seed the corpus with small valid zips (the Swift image has no Python, so do it on the host).
if command -v python3 >/dev/null; then python3 -I scripts/fuzz_seeds.py Fuzz/corpus-archive; fi

# The repo is mounted read-only and copied (without build products) to a folder named Airlock, which is the
# package identity Fuzz/Package.swift refers to.
docker run --rm \
  -v "$PWD":/src:ro \
  -v "$PWD/Fuzz":/out \
  "$IMAGE" bash -euo pipefail -c "
    mkdir -p /work/Airlock
    tar -C /src --exclude=./.build --exclude=./.git --exclude=./Fuzz/.build --exclude='./Fuzz/corpus-*' \
      --exclude='./Fuzz/crash-*' -cf - . | tar -C /work/Airlock -xf -
    cd /work/Airlock/Fuzz
    swift build -c debug -Xswiftc -sanitize=fuzzer,address
    ./.build/debug/ArchiveFuzz /out/corpus-archive \
      -max_total_time=$DURATION -max_len=65536 -timeout=10 -rss_limit_mb=2048 \
      -use_value_profile=1 -artifact_prefix=/out/crash-
  "

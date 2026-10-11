// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors
#pragma once
#include <stddef.h>
#include <stdint.h>

/// libFuzzer's driver (LLVM 11+), for harnesses that provide their own main().
int LLVMFuzzerRunDriver(int *argc, char ***argv, int (*callback)(const uint8_t *data, size_t size));

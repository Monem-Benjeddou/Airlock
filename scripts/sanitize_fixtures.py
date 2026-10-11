# SPDX-License-Identifier: GPL-3.0-only
# SPDX-FileCopyrightText: 2026 Airlock contributors
"""Strips personal data from raw adb recordings before they become test fixtures.

- the device serial becomes FIXTURESERIAL01
- third-party package names become com.example.userappN (system packages are kept)
- random /data/app path components are replaced deterministically
- getprop is reduced to an allowlist of non-identifying properties
- dumpsys battery keeps only the first block (later blocks hold battery serials)
- dumpsys package keeps only the "Packages:" block (other blocks list installed apps)
"""
import hashlib
import os
import re
import sys

PROP_ALLOWLIST = {
    "ro.build.version.release", "ro.build.version.sdk", "ro.product.cpu.abilist",
    "ro.product.cpu.abilist32", "ro.product.cpu.abilist64", "ro.product.model",
    "ro.product.manufacturer", "ro.product.brand", "ro.product.locale", "persist.sys.locale",
    "ro.product.device", "ro.product.name", "ro.build.version.security_patch",
    "ro.sf.lcd_density", "ro.build.characteristics", "ro.miui.ui.version.name",
    "ro.build.version.oneui", "ro.serialno",
}
FAKE_SERIAL = "FIXTURESERIAL01"


def read(raw, name):
    path = os.path.join(raw, name)
    return open(path, encoding="utf-8", errors="replace").read() if os.path.exists(path) else None


def third_party(raw):
    text = read(raw, "pm-list-third-party.txt") or read(raw, "pm-list-third.txt") or ""
    names = [line[len("package:"):].strip() for line in text.splitlines() if line.startswith("package:")]
    return {name: f"com.example.userapp{i + 1}" for i, name in enumerate(sorted(names))}


def scrub(text, mapping, serial):
    text = text.replace(serial, FAKE_SERIAL)
    # Longest names first so com.a.b.c is replaced before com.a.b.
    for real in sorted(mapping, key=len, reverse=True):
        text = re.sub(r"(?<![\w.])" + re.escape(real) + r"(?![\w])", mapping[real], text)
    # /data/app/~~<random>==/<pkg>-<random>==/ -> stable fake randoms
    def fake(match):
        digest = hashlib.sha256(match.group(0).encode()).hexdigest()[:22]
        return match.group(1) + digest + "=="
    text = re.sub(r"(~~|-)([A-Za-z0-9_\-]{22})==", lambda m: fake(re.match(r"(~~|-)(.*)", m.group(0))), text)
    return text


def getprop(text, serial):
    keep = []
    for line in text.splitlines():
        m = re.match(r"\[([^\]]+)\]: \[(.*)\]$", line)
        if m and m.group(1) in PROP_ALLOWLIST:
            value = FAKE_SERIAL if m.group(1) == "ro.serialno" else m.group(2)
            keep.append(f"[{m.group(1)}]: [{value}]")
    return "\n".join(keep) + "\n"


def first_block(text):
    return text.split("\n\n", 1)[0].rstrip("\n") + "\n"


def packages_block(text):
    m = re.search(r"^Packages:\n(?:.*\n)*?(?=^\S)", text, re.MULTILINE)
    return m.group(0) if m else ""


def main(raw, out, serial):
    os.makedirs(out, exist_ok=True)
    mapping = third_party(raw)
    for name in sorted(os.listdir(raw)):
        if not name.endswith(".txt"):
            continue
        text = read(raw, name)
        if name == "getprop.txt":
            text = getprop(text, serial)
        elif name == "dumpsys-battery.txt":
            text = first_block(text)
        elif name.startswith("dumpsys-package"):
            text = packages_block(text)
        text = scrub(text, mapping, serial)
        open(os.path.join(out, name), "w", encoding="utf-8").write(text)
        print(f"wrote {name}")


if __name__ == "__main__":
    main(*sys.argv[1:4])

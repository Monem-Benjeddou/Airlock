# SPDX-License-Identifier: GPL-3.0-only
# SPDX-FileCopyrightText: 2026 Airlock contributors
"""Converts UAD-ng's uad_lists.json (GPL-3.0) into Airlock debloat presets.

    python3 -I scripts/import_uad_presets.py <uad_lists.json> <upstream-commit-sha>

Removal levels map to Airlock risk tags: Recommended -> safe, Advanced -> caution, Expert -> expert.
"Unsafe" entries are never included. The app additionally filters every preset through the
critical-package denylist at load time.
"""
import json
import os
import re
import sys

NAME = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z0-9_]+)+$")
RISK = {"Recommended": "safe", "Advanced": "caution", "Expert": "expert"}
OEM = {
    "samsung": ("Samsung", ["com.samsung.", "com.sec.", "com.sem."]),
    "xiaomi": ("Xiaomi, Redmi and POCO", ["com.miui.", "com.xiaomi.", "com.mi.", "com.duokan.", "com.mfashiongallery."]),
    "oneplus": ("OnePlus", ["com.oneplus.", "net.oneplus.", "com.oplus.", "com.heytap.", "com.coloros."]),
}
GENERIC = {
    "google": ("Google apps", "Google"),
    "carrier": ("Carrier apps", "Carrier"),
    "misc": ("Preinstalled third-party apps", "Misc"),
}
OUT = os.path.join(os.path.dirname(__file__), "..", "Sources", "AirlockServices", "Resources", "presets")


def describe(text):
    first = " ".join(text.strip().split())
    return first if len(first) <= 280 else first[:277].rstrip() + "..."


def entry(name, item):
    return {"packageName": name, "risk": RISK[item["removal"]], "description": describe(item.get("description", ""))}


def main(path, commit):
    data = json.load(open(path, encoding="utf-8"))
    usable = {k: v for k, v in data.items() if NAME.match(k) and v.get("removal") in RISK}
    os.makedirs(OUT, exist_ok=True)
    source = f"UAD-ng uad_lists.json (GPL-3.0), commit {commit}"
    written = {}
    for brand, (title, prefixes) in OEM.items():
        items = sorted((k, v) for k, v in usable.items() if v["list"] == "Oem" and k.startswith(tuple(prefixes)))
        written[brand] = {"id": brand, "name": title, "brand": brand, "source": source, "entries": [entry(k, v) for k, v in items]}
    for key, (title, uad_list) in GENERIC.items():
        items = sorted((k, v) for k, v in usable.items() if v["list"] == uad_list)
        written[key] = {"id": key, "name": title, "brand": "other", "source": source, "entries": [entry(k, v) for k, v in items]}
    pixel = sorted((k, v) for k, v in usable.items() if v["list"] == "Google" and k.startswith("com.google.android.apps."))
    written["pixel"] = {"id": "pixel", "name": "Pixel extras", "brand": "pixel", "source": source, "entries": [entry(k, v) for k, v in pixel]}
    for key, preset in written.items():
        with open(os.path.join(OUT, f"{key}.json"), "w", encoding="utf-8") as handle:
            json.dump(preset, handle, indent=1, ensure_ascii=False)
            handle.write("\n")
        print(f"{key}: {len(preset['entries'])} entries")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

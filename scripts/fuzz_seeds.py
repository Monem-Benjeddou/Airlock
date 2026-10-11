# SPDX-License-Identifier: GPL-3.0-only
# SPDX-FileCopyrightText: 2026 Airlock contributors
"""Writes a few small, valid zips as a starting corpus for the archive fuzzer."""
import io
import json
import sys
import zipfile

MANIFEST = ("AndroidManifest.xml", bytes(range(64)))


def build(files, method, force_zip64=False):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", method) as archive:
        for path, data in files:
            with archive.open(path, "w", force_zip64=force_zip64) as handle:
                handle.write(data)
    return buffer.getvalue()


def main(out: str) -> None:
    apk = build([MANIFEST, ("classes.dex", b"dex\n035\0" * 8)], zipfile.ZIP_DEFLATED)
    xapk_manifest = json.dumps({"package_name": "com.a", "version_code": 1}).encode()
    seeds = {
        "apk": apk,
        "stored": build([MANIFEST, ("res/a.xml", b"<a/>" * 16)], zipfile.ZIP_STORED),
        "zip64": build([MANIFEST], zipfile.ZIP_DEFLATED, force_zip64=True),
        "apks": build([("toc.pb", b"\x01"), ("splits/base-master.apk", apk)], zipfile.ZIP_STORED),
        "xapk": build([("manifest.json", xapk_manifest), ("com.a.apk", apk)], zipfile.ZIP_STORED),
    }
    for name, data in seeds.items():
        with open(f"{out}/seed-{name}.zip", "wb") as handle:
            handle.write(data)


if __name__ == "__main__":
    main(sys.argv[1])

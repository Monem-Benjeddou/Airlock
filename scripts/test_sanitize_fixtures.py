# SPDX-License-Identifier: GPL-3.0-only
# SPDX-FileCopyrightText: 2026 Airlock contributors
"""Checks that sanitize_fixtures.py keeps personal data out of recorded fixtures.

    python3 -I scripts/test_sanitize_fixtures.py
"""
import importlib.util
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("sanitize_fixtures", os.path.join(HERE, "sanitize_fixtures.py"))
sanitize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sanitize)

SERIAL = "R5REALSERIAL"
OWNER = "Alex's Galaxy"


class SanitizeTests(unittest.TestCase):
    def record(self, files):
        raw, out = tempfile.mkdtemp(), tempfile.mkdtemp()
        for name, text in files.items():
            with open(os.path.join(raw, name), "w", encoding="utf-8") as handle:
                handle.write(text)
        sanitize.main(raw, out, SERIAL)
        result = {}
        for name in os.listdir(out):
            with open(os.path.join(out, name), encoding="utf-8") as handle:
                result[name] = handle.read()
        return result

    def test_owner_device_name_never_reaches_a_fixture(self):
        result = self.record({
            "settings-device-name.txt": OWNER + "\n",
            "getprop.txt": f"[ro.product.model]: [SM-S928B]\n[net.hostname]: [{OWNER}]\n",
            "dumpsys-battery.txt": f"Current Battery Service state:\n  name: {OWNER}\n",
        })
        self.assertEqual(result["settings-device-name.txt"], "Fixture Phone\n")
        for name, text in result.items():
            self.assertNotIn(OWNER, text, name)
            self.assertNotIn(SERIAL, text, name)

    def test_an_unset_device_name_stays_null(self):
        result = self.record({"settings-device-name.txt": "null\n"})
        self.assertEqual(result["settings-device-name.txt"], "null\n")

    def test_marketing_names_are_kept(self):
        result = self.record({
            "getprop.txt": "[ro.product.marketname]: [Redmi Note 13 Pro]\n[ro.serialno]: [R5REALSERIAL]\n",
        })
        self.assertIn("[ro.product.marketname]: [Redmi Note 13 Pro]", result["getprop.txt"])
        self.assertIn("[ro.serialno]: [FIXTURESERIAL01]", result["getprop.txt"])


if __name__ == "__main__":
    unittest.main()

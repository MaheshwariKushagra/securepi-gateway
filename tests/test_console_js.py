#!/usr/bin/env python3
"""
SecurePi Gateway - checks on app/static/app.js that need no browser.

csvCell() is pulled out of app.js and run under node (skipped where node
isn't installed), so the spreadsheet-safety rule is tested as code, not
just as text.

Run via `make test`, or directly: python3 -m unittest tests.test_console_js -v
"""

import json
import os
import re
import shutil
import subprocess
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(REPO_ROOT, "app", "static", "app.js")


def _function_source(name):
    with open(APP_JS) as fh:
        src = fh.read()
    m = re.search(r"\nfunction %s\(.*?\n}\n" % name, src, re.DOTALL)
    return m.group(0) if m else None


@unittest.skipIf(shutil.which("node") is None, "node is not installed")
class CsvCellTests(unittest.TestCase):
    """Audit10Oct M16: device names come from DHCP, so a device can call
    itself "=HYPERLINK(...)". Quoting alone doesn't stop a spreadsheet
    treating that as a formula; a leading apostrophe does."""

    def cell(self, value):
        code = _function_source("csvCell") + "\nprocess.stdout.write(csvCell(%s));" % json.dumps(value)
        return subprocess.run(["node", "-e", code], capture_output=True, text=True, check=True).stdout

    def test_formula_like_values_are_neutralised(self):
        for value in ("=HYPERLINK(\"http://x\")", "+1+2", "-2+3", "@SUM(A1)", "\tx", "\rx"):
            self.assertTrue(self.cell(value).lstrip('"').startswith("'"), value)

    def test_ordinary_values_are_unchanged(self):
        self.assertEqual(self.cell("Pixel 7"), "Pixel 7")
        self.assertEqual(self.cell("10.10.0.50"), "10.10.0.50")
        self.assertEqual(self.cell(42), "42")

    def test_quoting_still_works(self):
        self.assertEqual(self.cell('a,"b"'), '"a,""b"""')


if __name__ == "__main__":
    unittest.main()

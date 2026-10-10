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


class BackgroundPollTests(unittest.TestCase):
    """Audit10Oct M13: timer-driven polls are marked so the server doesn't
    count them as operator activity, and a 401 from the API (the session
    has ended) sends the browser to the login page instead of leaving a
    silently stale console."""

    def setUp(self):
        with open(APP_JS) as fh:
            self.src = fh.read()

    def test_the_fetch_wrapper_marks_background_requests(self):
        self.assertIn('headers.set("X-SP-Background", "1")', self.src)
        self.assertIn("function backgroundPoll(", self.src)

    def test_every_timer_runs_through_background_poll(self):
        self.assertIn("SP.timer = setInterval(tick, SP.intervalMs)", self.src)
        tick = re.search(r"\nfunction tick\(\) \{\n(.*?)\n\}\n", self.src, re.DOTALL).group(1)
        self.assertIn("backgroundPoll(", tick)
        for m in re.finditer(r"setInterval\((.*?)\);", self.src):
            body = m.group(1)
            if body.startswith("tick"):
                continue
            self.assertIn("backgroundPoll(", body, body)

    def test_a_401_from_the_api_goes_to_the_login_page(self):
        self.assertIn("res.status === 401", self.src)
        self.assertIn('"/login?next="', self.src)


if __name__ == "__main__":
    unittest.main()

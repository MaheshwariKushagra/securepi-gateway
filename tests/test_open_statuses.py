#!/usr/bin/env python3
"""
SecurePi Gateway - one meaning of an "open" incident (Audit10Oct M14).

The console counted only status 'new' as open, while risk scoring
(app/risk.py LIVE_STATUSES) also counts 'investigating'. Moving an
incident to "investigating" made it vanish from the dashboard's open count
and active list - the console could say "the network is quiet" in the
middle of an investigation. Structural, like test_security_headers.py:
FastAPI isn't installed on the Mac, so app/webapp.py is read as text.

Run via `make test`, or directly: python3 -m unittest tests.test_open_statuses -v
"""

import os
import re
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "app"))

import risk  # noqa: E402


def _read(*parts):
    with open(os.path.join(REPO_ROOT, *parts)) as fh:
        return fh.read()


class OpenStatusTests(unittest.TestCase):
    def setUp(self):
        self.webapp = _read("app", "webapp.py")
        self.js = _read("app", "static", "app.js")

    def test_investigating_counts_as_open_for_risk(self):
        self.assertEqual(set(risk.LIVE_STATUSES), {"new", "investigating"})

    def test_the_console_has_no_new_only_incident_queries_left(self):
        self.assertEqual(re.findall(r"status\s*=\s*'new'", self.webapp), [])

    def test_the_open_filter_is_built_from_the_risk_definition(self):
        self.assertIn("OPEN_STATUSES_SQL", self.webapp)
        self.assertIn("risk.LIVE_STATUSES", self.webapp)
        self.assertIn('status == "open"', self.webapp)

    def test_the_notification_badge_counts_open_incidents(self):
        self.assertIn('fetch("/api/incidents?status=open")', self.js)
        self.assertNotIn('fetch("/api/incidents?status=new")', self.js)


if __name__ == "__main__":
    unittest.main()

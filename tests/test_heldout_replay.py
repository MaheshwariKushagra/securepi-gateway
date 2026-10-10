#!/usr/bin/env python3
"""
SecurePi Gateway - tools/heldout_replay.py's rate arithmetic (Audit10Oct E2).

A dataset whose devices each have a single event has events but zero
device-hours of exposure; rate() divided by it and crashed.

Run via `make test`, or directly: python3 -m unittest tests.test_heldout_replay -v
"""

import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))

import heldout_replay  # noqa: E402


class RateTests(unittest.TestCase):
    def test_zero_exposure_gives_no_rate_instead_of_crashing(self):
        r = heldout_replay.rate(3, 0, scale=1000)
        self.assertEqual(r["count"], 3)
        self.assertIsNone(r["rate"])
        self.assertIsNone(r["ci95"])

    def test_an_ordinary_rate_is_unchanged(self):
        r = heldout_replay.rate(4, 2.0)
        self.assertEqual(r["rate"], 2.0)
        self.assertEqual(len(r["ci95"]), 2)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""
SecurePi Gateway - suppression rule tests (ENHANCEMENT-PLAN.md step 2.7).

Run via `make test`, or directly: python3 -m unittest tests.test_suppression -v
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

import suppression  # noqa: E402


class IsSuppressedTests(unittest.TestCase):
    def test_no_rules_means_not_suppressed(self):
        conn = fixtures.temp_db()
        self.assertFalse(suppression.is_suppressed(conn, "port_scan", 1))

    def test_a_device_scoped_rule_matches_only_that_device(self):
        conn = fixtures.temp_db()
        suppression.add_suppression(conn, "port_scan", 1, "known scanner appliance", "operator")
        self.assertTrue(suppression.is_suppressed(conn, "port_scan", 1))
        self.assertFalse(suppression.is_suppressed(conn, "port_scan", 2))

    def test_a_network_wide_rule_matches_every_device(self):
        conn = fixtures.temp_db()
        suppression.add_suppression(conn, "malicious_domain", None, "miscalibrated for this network", "operator")
        self.assertTrue(suppression.is_suppressed(conn, "malicious_domain", 1))
        self.assertTrue(suppression.is_suppressed(conn, "malicious_domain", 99))

    def test_a_rule_for_a_different_signal_type_does_not_match(self):
        conn = fixtures.temp_db()
        suppression.add_suppression(conn, "port_scan", 1, "test", "operator")
        self.assertFalse(suppression.is_suppressed(conn, "brute_force", 1))

    def test_an_expired_rule_no_longer_suppresses(self):
        conn = fixtures.temp_db()
        suppression.add_suppression(conn, "port_scan", 1, "temporary", "operator",
                                     expires_at=time.time() - 10)
        self.assertFalse(suppression.is_suppressed(conn, "port_scan", 1))

    def test_a_not_yet_expired_rule_still_suppresses(self):
        conn = fixtures.temp_db()
        suppression.add_suppression(conn, "port_scan", 1, "temporary", "operator",
                                     expires_at=time.time() + 3600)
        self.assertTrue(suppression.is_suppressed(conn, "port_scan", 1))

    def test_a_removed_rule_no_longer_suppresses(self):
        conn = fixtures.temp_db()
        rule_id = suppression.add_suppression(conn, "port_scan", 1, "test", "operator")
        self.assertTrue(suppression.is_suppressed(conn, "port_scan", 1))
        self.assertTrue(suppression.remove_suppression(conn, rule_id))
        self.assertFalse(suppression.is_suppressed(conn, "port_scan", 1))

    def test_removing_a_nonexistent_rule_returns_false(self):
        conn = fixtures.temp_db()
        self.assertFalse(suppression.remove_suppression(conn, 999))


class ListSuppressionsTests(unittest.TestCase):
    def test_reports_active_and_expired_correctly(self):
        conn = fixtures.temp_db()
        suppression.add_suppression(conn, "port_scan", 1, "still active", "operator")
        suppression.add_suppression(conn, "brute_force", 1, "expired", "operator",
                                     expires_at=time.time() - 10)
        rows = {r["reason"]: r["active"] for r in suppression.list_suppressions(conn)}
        self.assertTrue(rows["still active"])
        self.assertFalse(rows["expired"])


if __name__ == "__main__":
    unittest.main()

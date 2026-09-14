#!/usr/bin/env python3
"""
SecurePi Gateway - risk scoring tests for the campaign bonus
(ENHANCEMENT-PLAN.md step 2.8: "weighted into risk"). Pre-existing
severity-weighting logic in app/risk.py predates this test file and
this step - covered here only where step 2.8 changed it.

Run via `make test`, or directly: python3 -m unittest tests.test_risk -v
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

import risk  # noqa: E402


def _insert_campaign(conn, device_id, status="new", last_seen=None):
    now = time.time()
    conn.execute(
        "INSERT INTO campaigns (device_id, title, status, tactics, first_seen, last_seen,"
        " created_at, updated_at) VALUES (?, 'test campaign', ?, 'Discovery -> Credential Access',"
        " ?, ?, ?, ?)",
        (device_id, status, now, last_seen if last_seen is not None else now, now, now),
    )
    conn.commit()


class CampaignRiskBonusTests(unittest.TestCase):
    def test_an_open_campaign_adds_a_named_term(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        _insert_campaign(conn, 1)
        result = risk.device_risk(conn, 1)
        self.assertEqual(result["score"], risk.CAMPAIGN_BONUS)
        self.assertEqual(len(result["breakdown"]), 1)
        self.assertEqual(result["breakdown"][0]["campaign_id"], 1)

    def test_a_resolved_campaign_contributes_nothing(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        _insert_campaign(conn, 1, status="resolved")
        result = risk.device_risk(conn, 1)
        self.assertEqual(result["score"], 0)

    def test_campaign_bonus_decays_like_everything_else(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        _insert_campaign(conn, 1, last_seen=time.time() - risk.HALF_LIFE_SECONDS)
        result = risk.device_risk(conn, 1)
        self.assertAlmostEqual(result["score"], risk.CAMPAIGN_BONUS / 2, delta=1)

    def test_a_device_with_no_campaign_is_unaffected(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        result = risk.device_risk(conn, 1)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["breakdown"], [])


if __name__ == "__main__":
    unittest.main()

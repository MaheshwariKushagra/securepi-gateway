#!/usr/bin/env python3
"""
SecurePi Gateway - hourly rollup tests (app/rollup.py).

Run via `make test`, or directly: python3 -m unittest tests.test_rollup -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

import rollup  # noqa: E402

HOUR = 3600
# A fixed "now": 30 minutes into an hour, so the last closed hour is clear.
NOW = 1_790_000_000 - (1_790_000_000 % HOUR) + 1800
LAST_CLOSED = NOW - 1800 - HOUR


def bytes_down(conn, device_id, hour_start):
    row = conn.execute("SELECT bytes_down FROM device_hourly WHERE device_id=? AND hour_start=?",
                       (device_id, hour_start)).fetchone()
    return row["bytes_down"] if row else None


class RollupTests(unittest.TestCase):
    def test_a_closed_hour_is_rolled_up(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, LAST_CLOSED + 60, bytes_toclient=1000)
        rollup.rollup_closed_hours(conn, now=NOW)
        self.assertEqual(bytes_down(conn, 1, LAST_CLOSED), 1000)

    def test_the_current_open_hour_is_not_rolled_up(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, NOW - 60, bytes_toclient=1000)
        rollup.rollup_closed_hours(conn, now=NOW)
        self.assertIsNone(bytes_down(conn, 1, NOW - 1800))

    def test_late_data_in_a_recent_closed_hour_is_picked_up(self):
        # Audit.md: an event attributed after its hour was rolled up used
        # to be missing from the rollup for good.
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, LAST_CLOSED + 60, bytes_toclient=1000)
        rollup.rollup_closed_hours(conn, now=NOW)
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, LAST_CLOSED + 120, bytes_toclient=500)  # arrives late
        rollup.rollup_closed_hours(conn, now=NOW + 60)
        self.assertEqual(bytes_down(conn, 1, LAST_CLOSED), 1500)

    def test_progress_moves_past_hours_with_no_events(self):
        # Audit.md: empty hours write no rows, so MAX(hour_start) never
        # moved past a quiet spell and every cycle re-scanned it.
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, LAST_CLOSED - 48 * HOUR, bytes_toclient=1)
        rollup.rollup_closed_hours(conn, now=NOW)
        progress = conn.execute("SELECT last_run_ts FROM signal_state WHERE signal_type='rollup'").fetchone()
        self.assertEqual(progress["last_run_ts"], LAST_CLOSED)


if __name__ == "__main__":
    unittest.main()

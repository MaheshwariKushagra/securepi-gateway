#!/usr/bin/env python3
"""
SecurePi Gateway - registry attribution tests (ENHANCEMENT-PLAN.md step 1.6).

Run via `make test`, or directly: python3 -m unittest tests.test_registry -v
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

import registry  # noqa: E402


class AttributeEventsOverlapTieBreakTests(unittest.TestCase):
    """Regression tests for finding G6: two device_ips intervals for the
    SAME address that overlap in time used to be resolved arbitrarily
    (whichever row SQLite's correlated subquery happened to return
    first, with no ORDER BY). registry.py's Pass 1 now orders by
    first_seen DESC, preferring the most recently opened interval."""

    def test_an_overlapping_pair_resolves_to_the_more_recently_opened_interval(self):
        conn = fixtures.temp_db()
        ip = "10.10.0.77"
        fixtures.insert_device(conn, 1, hostname="old-device")
        fixtures.insert_device(conn, 2, hostname="new-device")
        now = time.time()
        # Two intervals for the SAME address, genuinely overlapping:
        # device 1's interval opened earlier and is still "open" (a wide
        # last_seen), device 2's opened later, inside device 1's window.
        conn.execute("INSERT INTO device_ips (device_id, ip, first_seen, last_seen) VALUES (1, ?, ?, ?)",
                     (ip, now - 1000, now + 1000))
        conn.execute("INSERT INTO device_ips (device_id, ip, first_seen, last_seen) VALUES (2, ?, ?, ?)",
                     (ip, now - 500, now + 1000))
        conn.commit()

        conn.execute(
            "INSERT INTO events (ts, ts_iso, source, event_type, src_ip, blocked)"
            " VALUES (?, 'test', 'suricata', 'flow', ?, 0)", (now, ip))
        conn.commit()

        registry.attribute_events(conn)
        row = conn.execute("SELECT device_id FROM events WHERE src_ip=?", (ip,)).fetchone()
        self.assertEqual(row["device_id"], 2, "must prefer the more recently OPENED interval (device 2)")

    def test_a_non_overlapping_case_is_unaffected(self):
        """Sanity check: the fix must not change attribution for the
        normal, unambiguous case where only one interval actually
        contains the event's timestamp."""
        conn = fixtures.temp_db()
        ip = "10.10.0.78"
        fixtures.insert_device(conn, 1, hostname="old-device")
        fixtures.insert_device(conn, 2, hostname="new-device")
        now = time.time()
        # Sequential, non-overlapping intervals for the same address (a
        # normal DHCP lease handoff).
        conn.execute("INSERT INTO device_ips (device_id, ip, first_seen, last_seen) VALUES (1, ?, ?, ?)",
                     (ip, now - 10000, now - 5000))
        conn.execute("INSERT INTO device_ips (device_id, ip, first_seen, last_seen) VALUES (2, ?, ?, ?)",
                     (ip, now - 100, now + 1000))
        conn.commit()

        conn.execute(
            "INSERT INTO events (ts, ts_iso, source, event_type, src_ip, blocked)"
            " VALUES (?, 'test', 'suricata', 'flow', ?, 0)", (now, ip))
        conn.commit()

        registry.attribute_events(conn)
        row = conn.execute("SELECT device_id FROM events WHERE src_ip=?", (ip,)).fetchone()
        self.assertEqual(row["device_id"], 2, "the event's timestamp only falls inside device 2's real interval")


if __name__ == "__main__":
    unittest.main()

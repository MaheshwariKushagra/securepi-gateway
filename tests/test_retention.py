#!/usr/bin/env python3
"""
SecurePi Gateway - retention tests (ENHANCEMENT-PLAN.md step 1.3).

Run via `make test`, or directly: python3 -m unittest tests.test_retention -v
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

import retention  # noqa: E402

DAY = 86400


class PruneEventsTests(unittest.TestCase):
    def test_old_flow_events_are_removed(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, now - 20 * DAY)  # older than 14d
        removed = retention.prune_events(conn, now)
        self.assertEqual(removed, 1)
        self.assertEqual(conn.execute("SELECT count(*) FROM events").fetchone()[0], 0)

    def test_recent_flow_events_are_kept(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, now - 5 * DAY)  # within 14d
        removed = retention.prune_events(conn, now)
        self.assertEqual(removed, 0)
        self.assertEqual(conn.execute("SELECT count(*) FROM events").fetchone()[0], 1)

    def test_dns_gets_the_longer_30_day_window(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        # 20 days old: past flow/TLS's 14-day window, but within DNS's 30-day one.
        fixtures.insert_dns_query(conn, 1, "example.com", now - 20 * DAY)
        removed = retention.prune_events(conn, now)
        self.assertEqual(removed, 0)
        self.assertEqual(conn.execute("SELECT count(*) FROM events").fetchone()[0], 1)

    def test_old_dns_beyond_30_days_is_removed(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        fixtures.insert_dns_query(conn, 1, "example.com", now - 40 * DAY)
        removed = retention.prune_events(conn, now)
        self.assertEqual(removed, 1)

    def test_an_event_still_linked_to_an_incident_is_never_pruned_by_age(self):
        """The evidence-chain-safety rule the module docstring describes:
        even a very old flow event must survive prune_events if it's
        still cited as evidence for a (not yet pruned) incident."""
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, now - 100 * DAY)  # far past 14d
        event_id = conn.execute("SELECT id FROM events").fetchone()[0]
        conn.execute(
            "INSERT INTO incidents (id, device_id, signal_type, severity, title, description, status,"
            " first_seen, last_seen, created_at, updated_at, evidence_count) VALUES"
            " (1, 1, 'port_scan', 'high', 't', 'd', 'new', ?, ?, ?, ?, 1)",
            (now - 100 * DAY, now - 100 * DAY, now - 100 * DAY, now - 100 * DAY))
        conn.execute("INSERT INTO incident_events (incident_id, event_id) VALUES (1, ?)", (event_id,))
        conn.commit()

        removed = retention.prune_events(conn, now)
        self.assertEqual(removed, 0, "an event still linked to a surviving incident must not be pruned")
        self.assertEqual(conn.execute("SELECT count(*) FROM events").fetchone()[0], 1)


class PruneIncidentsTests(unittest.TestCase):
    def test_old_incidents_are_removed_with_their_links(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        old = now - 400 * DAY
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, old)
        event_id = conn.execute("SELECT id FROM events").fetchone()[0]
        conn.execute(
            "INSERT INTO incidents (id, device_id, signal_type, severity, title, description, status,"
            " first_seen, last_seen, created_at, updated_at, evidence_count) VALUES"
            " (1, 1, 'port_scan', 'high', 't', 'd', 'resolved', ?, ?, ?, ?, 1)",
            (old, old, old, old))
        conn.execute("INSERT INTO incident_events (incident_id, event_id) VALUES (1, ?)", (event_id,))
        conn.execute(
            "INSERT INTO incident_notes (id, incident_id, ts, author, note) VALUES (1, 1, ?, 'securepi', 'n')",
            (old,))
        conn.execute("INSERT INTO notification_channels (id, kind, name, config, min_severity, enabled,"
                     " created_at, updated_at) VALUES (1, 'webhook', 'w', '{}', 'medium', 1, ?, ?)", (old, old))
        conn.execute("INSERT INTO notifications (channel_id, incident_id, ts, status) VALUES (1, 1, ?, 'sent')",
                     (old,))
        conn.commit()

        removed = retention.prune_incidents(conn, now)
        self.assertEqual(removed, 1)
        self.assertEqual(conn.execute("SELECT count(*) FROM incidents").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT count(*) FROM incident_events").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT count(*) FROM incident_notes").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT count(*) FROM notifications").fetchone()[0], 0)

    def test_a_backlog_bigger_than_sqlites_variable_limit_is_pruned(self):
        # Audit10Oct E1: every expired id went into one "IN (?, ?, ...)"
        # list, which fails past SQLite's limit on bound variables. The
        # limit is lowered here so the test needs only a few hundred rows.
        import sqlite3
        conn = fixtures.temp_db()
        old = time.time() - 400 * DAY
        conn.executemany(
            "INSERT INTO incidents (device_id, signal_type, severity, title, description, status,"
            " first_seen, last_seen, created_at, updated_at, evidence_count) VALUES"
            " (NULL, 'port_scan', 'low', 't', 'd', 'resolved', ?, ?, ?, ?, 0)", [(old, old, old, old)] * 300)
        conn.commit()
        conn.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 100)
        self.assertEqual(retention.prune_incidents(conn, time.time()), 300)
        self.assertEqual(conn.execute("SELECT count(*) FROM incidents").fetchone()[0], 0)

    def test_recent_incidents_are_kept(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        conn.execute(
            "INSERT INTO incidents (id, device_id, signal_type, severity, title, description, status,"
            " first_seen, last_seen, created_at, updated_at, evidence_count) VALUES"
            " (1, 1, 'port_scan', 'high', 't', 'd', 'new', ?, ?, ?, ?, 0)",
            (now - 5 * DAY, now - 5 * DAY, now - 5 * DAY, now - 5 * DAY))
        conn.commit()
        removed = retention.prune_incidents(conn, now)
        self.assertEqual(removed, 0)

    def test_evidence_event_becomes_eligible_only_after_its_incident_is_pruned(self):
        """The full evidence-chain-safety story end to end: an old event
        survives prune_events while its incident is still within the
        365-day window, and only becomes eligible for pruning once
        run_retention (which prunes incidents FIRST) removes the
        incident on a later run."""
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        old = now - 400 * DAY  # past both the incident's 365d window and the event's 14d one
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, old)
        event_id = conn.execute("SELECT id FROM events").fetchone()[0]
        conn.execute(
            "INSERT INTO incidents (id, device_id, signal_type, severity, title, description, status,"
            " first_seen, last_seen, created_at, updated_at, evidence_count) VALUES"
            " (1, 1, 'port_scan', 'high', 't', 'd', 'resolved', ?, ?, ?, ?, 1)",
            (old, old, old, old))
        conn.execute("INSERT INTO incident_events (incident_id, event_id) VALUES (1, ?)", (event_id,))
        conn.commit()

        removed = retention.run_retention(conn, now)
        self.assertEqual(removed["incidents"], 1)
        self.assertEqual(removed["events"], 1, "once unlinked by the incident's own removal, the event is prunable")
        self.assertEqual(conn.execute("SELECT count(*) FROM events").fetchone()[0], 0)


class PruneDeviceHourlyTests(unittest.TestCase):
    def test_old_rollups_removed_recent_kept(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        old_hour = int(now - 200 * DAY) // 3600 * 3600
        recent_hour = int(now - 5 * DAY) // 3600 * 3600
        fixtures.insert_device_hourly(conn, 1, old_hour, 1000, 500)
        fixtures.insert_device_hourly(conn, 1, recent_hour, 1000, 500)
        removed = retention.prune_device_hourly(conn, now)
        self.assertEqual(removed, 1)
        self.assertEqual(conn.execute("SELECT count(*) FROM device_hourly").fetchone()[0], 1)


class PruneExpiredSuppressionsTests(unittest.TestCase):
    """ENHANCEMENT-PLAN.md step 2.7: housekeeping only - an expired rule
    is already inert (app/suppression.py's is_suppressed() checks the
    same condition), so this just keeps the table tidy."""

    def test_expired_rules_are_removed_active_ones_kept(self):
        import suppression
        conn = fixtures.temp_db()
        now = time.time()
        suppression.add_suppression(conn, "port_scan", 1, "expired", "operator",
                                     expires_at=now - 10)
        suppression.add_suppression(conn, "port_scan", 1, "still active", "operator",
                                     expires_at=now + 3600)
        suppression.add_suppression(conn, "port_scan", 1, "never expires", "operator")
        removed = retention.prune_expired_suppressions(conn, now)
        self.assertEqual(removed, 1)
        remaining = {r["reason"] for r in conn.execute("SELECT reason FROM suppressions")}
        self.assertEqual(remaining, {"still active", "never expires"})


class RunRetentionIfDueTests(unittest.TestCase):
    def test_does_not_run_twice_in_the_same_day(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, now - 20 * DAY)
        first = retention.run_retention_if_due(conn, now)
        self.assertIsNotNone(first)
        self.assertEqual(first["events"], 1)

        # A second flow event, still old enough to prune, inserted right after.
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, now - 20 * DAY)
        second = retention.run_retention_if_due(conn, now + 60)  # only a minute later
        self.assertIsNone(second, "must not run again until a full day has passed")
        self.assertEqual(conn.execute("SELECT count(*) FROM events").fetchone()[0], 1,
                          "the second old event must still be sitting there, unpruned")

    def test_runs_again_after_a_full_day(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, now - 20 * DAY)
        retention.run_retention_if_due(conn, now)
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, now - 20 * DAY)
        second = retention.run_retention_if_due(conn, now + retention.RUN_INTERVAL_SECONDS + 1)
        self.assertIsNotNone(second)
        self.assertEqual(second["events"], 1)


class DbSizeTests(unittest.TestCase):
    def test_returns_a_nonzero_size_for_a_real_schema(self):
        conn = fixtures.temp_db()
        # An in-memory DB still has real pages once schema.sql has run.
        self.assertGreater(retention.db_size_bytes(conn), 0)


if __name__ == "__main__":
    unittest.main()

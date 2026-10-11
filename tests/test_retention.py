#!/usr/bin/env python3
"""
SecurePi Gateway - retention tests (ENHANCEMENT-PLAN.md step 1.3).

Run via `make test`, or directly: python3 -m unittest tests.test_retention -v
"""

import os
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

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

    def test_a_backlog_bigger_than_one_cycle_is_finished_over_the_next_cycles(self):
        """STAGE8-RECORD.md M-20: one engine cycle deletes at most
        MAX_EVENTS_PER_RUN events, so a big backlog never stops the engine
        for long; the rest goes on the following cycles, and the day's
        pass only counts as done once it has caught up."""
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for _ in range(120):
            fixtures.insert_flow(conn, 1, "1.1.1.1", 443, now - 20 * DAY)
        with mock.patch.object(retention, "MAX_EVENTS_PER_RUN", 50, create=True), \
                mock.patch.object(retention, "EVENT_DELETE_BATCH", 20, create=True), \
                mock.patch.object(retention.time, "sleep"):
            per_cycle = [retention.run_retention_if_due(conn, now + 15 * i) for i in range(4)]
        self.assertEqual([r and r["events"] for r in per_cycle], [50, 50, 20, None],
                         "50 a cycle until caught up, then not again the same day")
        self.assertEqual(conn.execute("SELECT count(*) FROM events").fetchone()[0], 0)

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


class _LockProbe:
    """Wraps the connection retention runs on. Just before every statement
    that deletes events, a second connection tries one write with no wait
    at all. If retention still holds the write lock from its previous
    delete, that write fails - what the privacy canary and the ingest's
    DNS reader hit at boot on 11 Oct 2026 (STAGE8-RECORD.md M-20)."""

    def __init__(self, conn, path, before_delete=None):
        self._conn = conn
        self._other = sqlite3.connect(path, timeout=0)
        self.before_delete = before_delete
        self.deletes = 0
        self.blocked = 0
        self.rows_per_delete = []

    def execute(self, sql, params=()):
        is_event_delete = sql.lstrip().upper().startswith("DELETE FROM EVENTS")
        if is_event_delete:
            if self.before_delete:
                self.before_delete(self._other, self.deletes)
            try:
                self._other.execute("INSERT INTO probe VALUES (1)")
                self._other.commit()
            except sqlite3.OperationalError:
                self._other.rollback()
                self.blocked += 1
            self.deletes += 1
        cur = self._conn.execute(sql, params)
        if is_event_delete:
            self.rows_per_delete.append(cur.rowcount)
        return cur

    def __getattr__(self, name):
        return getattr(self._conn, name)


class RetentionYieldsTheWriteLockTests(unittest.TestCase):
    """STAGE8-RECORD.md M-20: the first pass after the gateway had been
    off for a day held the write lock for about 40 s, longer than any
    other service waits (dbconn.BUSY_TIMEOUT_S). Retention must delete in
    batches and let other writers in between them."""

    BATCH = 50

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "t.db")
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=OFF")  # test speed only
        with open(fixtures.SCHEMA_PATH) as fh:
            conn.executescript(fh.read())
        conn.execute("CREATE TABLE probe (x INTEGER)")
        fixtures.insert_device(conn, 1)
        self.now = time.time()
        # Three batches' worth of old flow events, a few old DNS events
        # (the 30-day bucket), and recent ones of both that must stay.
        for _ in range(self.BATCH * 2 + 20):
            fixtures.insert_flow(conn, 1, "1.1.1.1", 443, self.now - 20 * DAY)
        for _ in range(10):
            fixtures.insert_dns_query(conn, 1, "example.com", self.now - 40 * DAY)
        for _ in range(5):
            fixtures.insert_flow(conn, 1, "1.1.1.1", 443, self.now - 2 * DAY)
            fixtures.insert_dns_query(conn, 1, "example.com", self.now - 2 * DAY)
        self.conn = conn
        patches = [mock.patch.object(retention, "EVENT_DELETE_BATCH", self.BATCH, create=True),
                   mock.patch.object(retention.time, "sleep")]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_another_writer_gets_in_before_every_delete(self):
        probe = _LockProbe(self.conn, self.path)
        removed = retention.run_retention(probe, self.now)
        self.assertGreaterEqual(probe.deletes, 3, "a backlog of three batches is three deletes")
        self.assertEqual(probe.blocked, 0,
                         "another service could not write while retention was running")
        self.assertEqual(removed["events"], self.BATCH * 2 + 30)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM events").fetchone()[0], 10)

    def test_no_single_delete_removes_more_than_one_batch(self):
        probe = _LockProbe(self.conn, self.path)
        retention.run_retention(probe, self.now)
        self.assertTrue(probe.rows_per_delete)
        self.assertLessEqual(max(probe.rows_per_delete), self.BATCH)

    def test_pauses_between_batches_long_enough_for_a_waiting_writer(self):
        # SQLite retries a waiting writer at most 100 ms apart; a shorter
        # pause could let every retry miss the gap between two batches.
        retention.run_retention(self.conn, self.now)
        pauses = [c.args[0] for c in retention.time.sleep.call_args_list]
        self.assertEqual(len(pauses), 2, "three batches, a pause between each pair")
        self.assertTrue(all(p > 0.1 for p in pauses), pauses)

    def test_an_event_linked_to_an_incident_after_the_scan_is_still_kept(self):
        """Evidence-chain safety across the gap between finding the old
        rows and deleting them: an event something links to an incident
        in that gap must survive."""
        oldest = self.conn.execute("SELECT min(id) FROM events").fetchone()[0]

        def link_before_first_delete(other, n):
            if n == 0:
                other.execute(
                    "INSERT INTO incidents (id, device_id, signal_type, severity, title, description,"
                    " status, first_seen, last_seen, created_at, updated_at, evidence_count) VALUES"
                    " (1, 1, 'port_scan', 'high', 't', 'd', 'new', ?, ?, ?, ?, 1)",
                    (self.now, self.now, self.now, self.now))
                other.execute("INSERT INTO incident_events (incident_id, event_id) VALUES (1, ?)",
                              (oldest,))
                other.commit()

        probe = _LockProbe(self.conn, self.path, before_delete=link_before_first_delete)
        retention.run_retention(probe, self.now)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM events WHERE id = ?",
                                           (oldest,)).fetchone()[0], 1)


class DbSizeTests(unittest.TestCase):
    def test_returns_a_nonzero_size_for_a_real_schema(self):
        conn = fixtures.temp_db()
        # An in-memory DB still has real pages once schema.sql has run.
        self.assertGreater(retention.db_size_bytes(conn), 0)


if __name__ == "__main__":
    unittest.main()

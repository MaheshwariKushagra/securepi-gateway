#!/usr/bin/env python3
"""
SecurePi Gateway - correlation signal tests (ENHANCEMENT-PLAN.md step 1.1).

Positive, negative and dedup tests for each of app/correlation.py's six
signals, plus regression tests for the two bugs finding G7 refers to that
were already found and fixed before this step existed (see
EVALUATION-RESULTS.md and correlation.py's own comments):

  - new_device_signal used to use a persisted watermark that advanced past
    a device before its grace period elapsed, silently breaking detection
    for every device. Fixed by recomputing a trailing window every cycle.
  - raise_incident used to increment evidence_count by len(event_ids) on
    every merge, so a signal re-confirming the same events across several
    engine cycles reported far more "evidence" than actually existed.
    Fixed by reading back the real distinct count after each insert.

Run via `make test`, or directly: python3 -m unittest tests.test_correlation -v

Note on malicious_domain_signal: its test below (test_malicious_domain_*)
deliberately documents CURRENT behaviour (thresholding on raw blocked-query
count), not the distinct-domain counting ENHANCEMENT-PLAN.md finding G3 asks
for - that's step 1.6's job, which will update these tests alongside the
fix. Writing a test for not-yet-fixed behaviour here would make `make test`
red, which is exactly what 1.1's own exit criterion says not to do.
"""

import os
import sys
import time
import unittest
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

import correlation  # noqa: E402
import settings  # noqa: E402


class PortScanSignalTests(unittest.TestCase):
    def test_fires_on_enough_distinct_ports_to_one_host(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1, hostname="attacker")
        now = time.time()
        for port in range(1, 9):  # 8 distinct ports - meets the default threshold
            fixtures.insert_flow(conn, 1, "203.0.113.10", port, now - 10)
        fired = correlation.port_scan_signal(conn)
        self.assertEqual(fired, 1)
        row = conn.execute("SELECT * FROM incidents WHERE signal_type='port_scan'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["severity"], "high")
        self.assertIn("203.0.113.10", row["title"])

    def test_does_not_fire_below_threshold(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for port in range(1, 5):  # only 4 distinct ports
            fixtures.insert_flow(conn, 1, "203.0.113.10", port, now - 10)
        self.assertEqual(correlation.port_scan_signal(conn), 0)

    def test_does_not_fire_when_ports_spread_across_hosts(self):
        # 8 total port touches, but each to a DIFFERENT host - normal
        # browsing, not a scan against one host.
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(8):
            fixtures.insert_flow(conn, 1, "203.0.113.%d" % i, 443, now - 10)
        self.assertEqual(correlation.port_scan_signal(conn), 0)

    def test_repeated_firing_merges_into_one_incident(self):
        # A sustained scan re-detected across two engine cycles must extend
        # the same incident, not create a second one - this is the whole
        # point of raise_incident's dedup.
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for port in range(1, 9):
            fixtures.insert_flow(conn, 1, "203.0.113.10", port, now - 10)
        correlation.port_scan_signal(conn)
        for port in range(9, 11):  # scan continues, two more ports
            fixtures.insert_flow(conn, 1, "203.0.113.10", port, now - 5)
        correlation.port_scan_signal(conn)
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='port_scan'").fetchall()
        self.assertEqual(len(rows), 1, "a continuing scan must extend one incident, not create a second")
        self.assertEqual(rows[0]["evidence_count"], 10)


class BruteForceSignalTests(unittest.TestCase):
    def test_fires_on_enough_attempts_to_an_auth_port(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(6):  # meets the default threshold
            fixtures.insert_flow(conn, 1, "203.0.113.20", 22, now - 5)
        fired = correlation.brute_force_signal(conn)
        self.assertEqual(fired, 1)
        row = conn.execute("SELECT * FROM incidents WHERE signal_type='brute_force'").fetchone()
        self.assertIn("SSH", row["title"])

    def test_does_not_fire_below_threshold(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(3):
            fixtures.insert_flow(conn, 1, "203.0.113.20", 22, now - 5)
        self.assertEqual(correlation.brute_force_signal(conn), 0)

    def test_does_not_fire_on_a_non_auth_port(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(10):
            fixtures.insert_flow(conn, 1, "203.0.113.20", 8080, now - 5)
        self.assertEqual(correlation.brute_force_signal(conn), 0)


class MaliciousDomainSignalTests(unittest.TestCase):
    """See the module docstring: this documents CURRENT (raw-count)
    behaviour, not G3's fix - that's step 1.6."""

    def test_fires_on_enough_blocked_lookups(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(15):  # meets the default threshold
            fixtures.insert_dns_query(conn, 1, "ads%d.example.com" % i, now - 5, blocked=True)
        self.assertEqual(correlation.malicious_domain_signal(conn), 1)

    def test_does_not_fire_below_threshold(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(5):
            fixtures.insert_dns_query(conn, 1, "ads%d.example.com" % i, now - 5, blocked=True)
        self.assertEqual(correlation.malicious_domain_signal(conn), 0)

    def test_allowed_queries_do_not_count(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(15):
            fixtures.insert_dns_query(conn, 1, "wikipedia%d.example.com" % i, now - 5, blocked=False)
        self.assertEqual(correlation.malicious_domain_signal(conn), 0)


class NewDeviceSignalTests(unittest.TestCase):
    def test_fires_once_grace_period_elapses(self):
        conn = fixtures.temp_db()
        now = time.time()
        fixtures.insert_device(conn, 1, hostname="new-phone", first_seen=now - 60, last_seen=now - 60)
        self.assertEqual(correlation.new_device_signal(conn), 1)

    def test_does_not_fire_within_grace_period(self):
        conn = fixtures.temp_db()
        now = time.time()
        fixtures.insert_device(conn, 1, hostname="brand-new", first_seen=now - 5, last_seen=now - 5)
        self.assertEqual(correlation.new_device_signal(conn), 0)

    def test_trailing_window_regression_not_a_persisted_watermark(self):
        """Regression test for the watermark bug described in the module
        docstring and EVALUATION-RESULTS.md: a device too new to qualify on
        one engine cycle must still qualify on a LATER cycle once its grace
        period has elapsed. A persisted-watermark implementation fails this
        (the watermark would have already advanced past the device's
        first_seen on the first cycle)."""
        conn = fixtures.temp_db()
        t0 = 1_800_000_000.0
        fixtures.insert_device(conn, 1, hostname="new-phone", first_seen=t0, last_seen=t0)

        with mock.patch("correlation.time.time", return_value=t0 + 10):
            self.assertEqual(correlation.new_device_signal(conn), 0, "still within the 30s grace period")

        with mock.patch("correlation.time.time", return_value=t0 + 45):
            self.assertEqual(correlation.new_device_signal(conn), 1,
                              "grace period has elapsed - must fire on this later cycle")

    def test_repeated_cycles_after_firing_do_not_duplicate(self):
        conn = fixtures.temp_db()
        now = time.time()
        fixtures.insert_device(conn, 1, first_seen=now - 60, last_seen=now - 60)
        correlation.new_device_signal(conn)
        correlation.new_device_signal(conn)  # a second cycle, device still in lookback window
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='new_device'").fetchall()
        self.assertEqual(len(rows), 1)


class AdblockEffectivenessSignalTests(unittest.TestCase):
    def test_fires_when_nothing_is_ever_stripped(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(5):  # meets EFFECTIVENESS_MIN_YOUTUBE_EVENTS
            fixtures.insert_dpi_event(conn, 1, "decrypt", now - 10)
        self.assertEqual(correlation.adblock_effectiveness_signal(conn), 1)

    def test_does_not_fire_when_ads_are_being_stripped(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(4):
            fixtures.insert_dpi_event(conn, 1, "decrypt", now - 10)
        fixtures.insert_dpi_event(conn, 1, "ads_stripped", now - 5, dpi_ads_removed=2)
        self.assertEqual(correlation.adblock_effectiveness_signal(conn), 0)

    def test_does_not_fire_on_too_little_activity(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(2):  # below EFFECTIVENESS_MIN_YOUTUBE_EVENTS
            fixtures.insert_dpi_event(conn, 1, "decrypt", now - 10)
        self.assertEqual(correlation.adblock_effectiveness_signal(conn), 0)


class BehavioralBaselineSignalTests(unittest.TestCase):
    def _seed_history(self, conn, device_id, hour_of_day, now, days, avg_bytes):
        """days rows of device_hourly for the SAME hour-of-day, on past
        days, close to avg_bytes with a small +/-10% jitter - a stable,
        learnable baseline with genuine (nonzero) variance. A perfectly
        flat history would give stdev == 0, which the signal deliberately
        skips ("nothing to compare a deviation against") - real device
        traffic always has some natural variance, so the fixture should too."""
        day_seconds = 86400
        for d in range(1, days + 1):
            hour_start = correlation._hour_start(now) - d * day_seconds
            jitter = 1.0 + (0.1 if d % 2 == 0 else -0.1)
            total = int(avg_bytes * jitter)
            fixtures.insert_device_hourly(conn, device_id, hour_start,
                                           bytes_down=int(total * 0.6), bytes_up=int(total * 0.4))

    def test_fires_on_a_genuine_volume_anomaly(self):
        conn = fixtures.temp_db()
        now = time.time()
        fixtures.insert_device(conn, 1, first_seen=now - 30 * 86400)
        hour_of_day = time.localtime(correlation._hour_start(now)).tm_hour
        self._seed_history(conn, 1, hour_of_day, now, days=10, avg_bytes=10 * 1024 * 1024)
        # Current hour: far above the ~10MB/hour baseline.
        current_hour_start = correlation._hour_start(now)
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, current_hour_start + 60,
                              bytes_toclient=200 * 1024 * 1024, bytes_toserver=1024)
        self.assertEqual(correlation.behavioral_baseline_signal(conn), 1)

    def test_does_not_fire_while_still_learning(self):
        conn = fixtures.temp_db()
        now = time.time()
        fixtures.insert_device(conn, 1, first_seen=now - 30 * 86400)
        hour_of_day = time.localtime(correlation._hour_start(now)).tm_hour
        self._seed_history(conn, 1, hour_of_day, now, days=3, avg_bytes=10 * 1024 * 1024)  # < BASELINE_MIN_SAMPLES
        current_hour_start = correlation._hour_start(now)
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, current_hour_start + 60,
                              bytes_toclient=200 * 1024 * 1024, bytes_toserver=1024)
        self.assertEqual(correlation.behavioral_baseline_signal(conn), 0)

    def test_does_not_fire_below_the_minimum_byte_floor(self):
        conn = fixtures.temp_db()
        now = time.time()
        fixtures.insert_device(conn, 1, first_seen=now - 30 * 86400)
        hour_of_day = time.localtime(correlation._hour_start(now)).tm_hour
        self._seed_history(conn, 1, hour_of_day, now, days=10, avg_bytes=1024)  # tiny baseline
        current_hour_start = correlation._hour_start(now)
        # A big jump relative to baseline, but still under BASELINE_MIN_BYTES_FLOOR overall.
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, current_hour_start + 60,
                              bytes_toclient=2000, bytes_toserver=0)
        self.assertEqual(correlation.behavioral_baseline_signal(conn), 0)

    def test_does_not_fire_on_normal_volume(self):
        conn = fixtures.temp_db()
        now = time.time()
        fixtures.insert_device(conn, 1, first_seen=now - 30 * 86400)
        hour_of_day = time.localtime(correlation._hour_start(now)).tm_hour
        self._seed_history(conn, 1, hour_of_day, now, days=10, avg_bytes=10 * 1024 * 1024)
        current_hour_start = correlation._hour_start(now)
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, current_hour_start + 60,
                              bytes_toclient=6 * 1024 * 1024, bytes_toserver=1024)
        self.assertEqual(correlation.behavioral_baseline_signal(conn), 0)


class RaiseIncidentDedupAndEvidenceTests(unittest.TestCase):
    def _insert_events(self, conn, device_id, n, ts):
        ids = []
        for i in range(n):
            fixtures.insert_flow(conn, device_id, "203.0.113.30", 443, ts)
            ids.append(conn.execute("SELECT max(id) FROM events").fetchone()[0])
        return ids

    def test_within_dedup_window_merges_into_one_incident(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        eids = self._insert_events(conn, 1, 3, now - 100)
        correlation.raise_incident(conn, 1, "port_scan", "high", "t1", "d1", now - 100, now - 100, eids)
        correlation.raise_incident(conn, 1, "port_scan", "high", "t2", "d2", now - 90, now - 90, eids)
        rows = conn.execute("SELECT * FROM incidents WHERE device_id=1").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["description"], "d2")  # the later call's description wins

    def test_outside_dedup_window_creates_a_separate_incident(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        eids1 = self._insert_events(conn, 1, 2, now - 10000)
        eids2 = self._insert_events(conn, 1, 2, now)
        correlation.raise_incident(conn, 1, "port_scan", "high", "t1", "d1",
                                    now - 10000, now - 10000, eids1)
        correlation.raise_incident(conn, 1, "port_scan", "high", "t2", "d2", now, now, eids2)
        rows = conn.execute("SELECT * FROM incidents WHERE device_id=1").fetchall()
        self.assertEqual(len(rows), 2)

    def test_evidence_count_regression_not_cumulative(self):
        """Regression test for the evidence-double-count bug described in
        the module docstring: re-detecting the SAME events across several
        engine cycles must not inflate evidence_count beyond the real
        number of distinct linked events."""
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        eids = self._insert_events(conn, 1, 8, now - 50)
        for cycle in range(7):  # the same 8 events "re-confirmed" 7 times
            correlation.raise_incident(conn, 1, "port_scan", "high", "t", "d",
                                        now - 50, now - 50 + cycle, eids)
        row = conn.execute("SELECT * FROM incidents WHERE device_id=1").fetchone()
        self.assertEqual(row["evidence_count"], 8, "must be the real distinct count, not 8 x 7 = 56")


class WindowSettingsTests(unittest.TestCase):
    """Step 1.2: window durations are console-tunable the same way step
    6.3's thresholds already are. These prove the wiring is real - a
    changed setting genuinely changes what a signal sees - not just that
    the schema entry exists (settings.py's own tests cover that)."""

    def test_all_five_window_settings_have_the_real_hardcoded_defaults(self):
        conn = fixtures.temp_db()
        self.assertEqual(settings.get(conn, "port_scan_window_seconds"), 300)
        self.assertEqual(settings.get(conn, "brute_force_window_seconds"), 120)
        self.assertEqual(settings.get(conn, "malicious_domain_window_seconds"), 600)
        self.assertEqual(settings.get(conn, "new_device_lookback_seconds"), 3600)
        self.assertEqual(settings.get(conn, "dedup_window_seconds"), 600)

    def test_shrinking_the_port_scan_window_excludes_older_events(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for port in range(1, 9):  # 8 ports, spread from 250s ago to ~10s ago
            fixtures.insert_flow(conn, 1, "203.0.113.10", port, now - 250 + port * 5)
        settings.set_value(conn, "port_scan_window_seconds", 60)
        self.assertEqual(correlation.port_scan_signal(conn), 0,
                          "a 60s window must not see ports touched 200+ seconds ago")

    def test_shortening_the_dedup_window_stops_merging_a_later_firing(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        t0 = now - 10000
        eids = []
        for i in range(3):
            fixtures.insert_flow(conn, 1, "203.0.113.30", 443, t0)
            eids.append(conn.execute("SELECT max(id) FROM events").fetchone()[0])
        settings.set_value(conn, "dedup_window_seconds", 60)
        correlation.raise_incident(conn, 1, "port_scan", "high", "t1", "d1", t0, t0, eids)
        correlation.raise_incident(conn, 1, "port_scan", "high", "t2", "d2", t0 + 500, t0 + 500, eids)
        rows = conn.execute("SELECT * FROM incidents WHERE device_id=1").fetchall()
        self.assertEqual(len(rows), 2, "500s apart must not merge under a shortened 60s dedup window")


if __name__ == "__main__":
    unittest.main()

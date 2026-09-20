#!/usr/bin/env python3
"""
SecurePi Gateway - platform health supervisor tests (ENHANCEMENT-PLAN.md
step 3.5).

Every check function is tested against a real temp SQLite DB (the same
fixtures.temp_db() pattern every other signal test uses), with the
actual system calls (systemctl, ping) replaced by simple monkeypatches -
this project has no systemd or network access to test against on the
Mac, the same reason quarantine.py/dpi_enroll.py's nft calls were never
Mac-tested either. What's tested here is the real decision logic: given
a specific system state, does the right incident get raised (or not).

Run via `make test`, or directly: python3 -m unittest tests.test_health -v
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

import health  # noqa: E402


class CheckServicesTests(unittest.TestCase):
    def setUp(self):
        self._orig_services = health._services_to_check
        self._orig_active = health._is_active
        self._orig_usage = health._resource_usage
        health._resource_usage = lambda service: (1024, 0.5)

    def tearDown(self):
        health._services_to_check = self._orig_services
        health._is_active = self._orig_active
        health._resource_usage = self._orig_usage

    def test_no_incident_when_everything_is_active(self):
        conn = fixtures.temp_db()
        health._services_to_check = lambda: ["suricata", "AdGuardHome"]
        health._is_active = lambda s: True
        health.check_services(conn, time.time())
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_service_down'").fetchall()
        self.assertEqual(len(rows), 0)
        health_rows = conn.execute("SELECT * FROM service_health").fetchall()
        self.assertEqual(len(health_rows), 2)

    def test_one_down_service_raises_an_incident_naming_it(self):
        conn = fixtures.temp_db()
        health._services_to_check = lambda: ["suricata", "AdGuardHome"]
        health._is_active = lambda s: s != "suricata"
        health.check_services(conn, time.time())
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_service_down'").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertIn("suricata", rows[0]["title"])
        self.assertIsNone(rows[0]["device_id"])

    def test_multiple_down_services_combine_into_one_incident(self):
        conn = fixtures.temp_db()
        health._services_to_check = lambda: ["suricata", "AdGuardHome", "securepi-dpi"]
        health._is_active = lambda s: s == "securepi-dpi"
        health.check_services(conn, time.time())
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_service_down'").fetchall()
        self.assertEqual(len(rows), 1, "several down services must combine, not create a cascade of incidents")
        self.assertIn("suricata", rows[0]["title"])
        self.assertIn("AdGuardHome", rows[0]["title"])

    def test_repeated_downtime_extends_rather_than_duplicates(self):
        conn = fixtures.temp_db()
        health._services_to_check = lambda: ["suricata"]
        health._is_active = lambda s: False
        now = time.time()
        health.check_services(conn, now)
        health.check_services(conn, now + 30)
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_service_down'").fetchall()
        self.assertEqual(len(rows), 1, "the fix to raise_incident's NULL-device_id dedup must actually work here")

    def test_an_unknown_active_state_is_not_treated_as_down(self):
        # _is_active returns None when systemctl itself couldn't even be
        # asked - that's "unknown", not "confirmed down", and must not
        # raise a false alarm.
        conn = fixtures.temp_db()
        health._services_to_check = lambda: ["suricata"]
        health._is_active = lambda s: None
        health.check_services(conn, time.time())
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_service_down'").fetchall()
        self.assertEqual(len(rows), 0)


class CheckStalenessTests(unittest.TestCase):
    def test_no_incident_when_everything_is_fresh(self):
        conn = fixtures.temp_db()
        now = time.time()
        conn.execute("UPDATE ingest_stats SET last_run=?", (now,))
        conn.execute("INSERT INTO signal_state (signal_type, last_run_ts) VALUES ('port_scan', ?)", (now,))
        fixtures.insert_device(conn, 1)
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, now)
        fixtures.insert_dns_query(conn, 1, "example.com", now)
        conn.commit()
        health.check_staleness(conn, now)
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_stale'").fetchall()
        self.assertEqual(len(rows), 0)

    def test_stale_ingest_raises_an_incident(self):
        conn = fixtures.temp_db()
        now = time.time()
        conn.execute("UPDATE ingest_stats SET last_run=?", (now - 3600,))
        conn.commit()
        health.check_staleness(conn, now)
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_stale'").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertIn("ingest", rows[0]["title"])

    def test_no_events_ever_from_a_source_is_not_flagged_as_stale(self):
        # A fresh install with no Suricata data yet is a startup
        # condition, not staleness - max(ts) returns NULL, which must
        # not be misread as "very stale".
        conn = fixtures.temp_db()
        now = time.time()
        conn.execute("UPDATE ingest_stats SET last_run=?", (now,))
        conn.commit()
        health.check_staleness(conn, now)
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_stale'").fetchall()
        self.assertEqual(len(rows), 0)


class CheckDiskTests(unittest.TestCase):
    def setUp(self):
        self._orig = health.shutil.disk_usage

    def tearDown(self):
        health.shutil.disk_usage = self._orig

    def test_low_free_space_raises_an_incident(self):
        conn = fixtures.temp_db()
        health.shutil.disk_usage = lambda path: (100, 96, 4)  # 4% free
        health.check_disk(conn, time.time())
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_disk_low'").fetchall()
        self.assertEqual(len(rows), 1)

    def test_healthy_free_space_raises_nothing(self):
        conn = fixtures.temp_db()
        health.shutil.disk_usage = lambda path: (100, 50, 50)  # 50% free
        health.check_disk(conn, time.time())
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_disk_low'").fetchall()
        self.assertEqual(len(rows), 0)


class CheckDbSizeTests(unittest.TestCase):
    def setUp(self):
        self._orig = health.retention.db_size_bytes

    def tearDown(self):
        health.retention.db_size_bytes = self._orig

    def test_oversized_database_raises_an_incident(self):
        conn = fixtures.temp_db()
        health.retention.db_size_bytes = lambda c: 600 * 1e6  # above the 500 MB default
        health.check_db_size(conn, time.time())
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_db_size'").fetchall()
        self.assertEqual(len(rows), 1)

    def test_normal_sized_database_raises_nothing(self):
        conn = fixtures.temp_db()
        health.retention.db_size_bytes = lambda c: 10 * 1e6
        health.check_db_size(conn, time.time())
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_db_size'").fetchall()
        self.assertEqual(len(rows), 0)


class CheckWanTests(unittest.TestCase):
    def setUp(self):
        self._orig = health.subprocess.run

    def tearDown(self):
        health.subprocess.run = self._orig

    def test_a_failed_ping_raises_an_incident(self):
        conn = fixtures.temp_db()

        class FakeResult:
            returncode = 1
        health.subprocess.run = lambda *a, **k: FakeResult()
        health.check_wan(conn, time.time())
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_wan_down'").fetchall()
        self.assertEqual(len(rows), 1)

    def test_a_successful_ping_raises_nothing(self):
        conn = fixtures.temp_db()

        class FakeResult:
            returncode = 0
        health.subprocess.run = lambda *a, **k: FakeResult()
        health.check_wan(conn, time.time())
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_wan_down'").fetchall()
        self.assertEqual(len(rows), 0)


class RunIfDueTests(unittest.TestCase):
    def test_does_not_run_again_before_the_interval_elapses(self):
        conn = fixtures.temp_db()
        now = time.time()
        ran = health.run_if_due(conn, now)
        self.assertTrue(ran)
        ran_again = health.run_if_due(conn, now + 1)
        self.assertFalse(ran_again, "must be throttled - ingest.py's own loop runs every 2s")

    def test_runs_again_once_the_interval_has_elapsed(self):
        conn = fixtures.temp_db()
        now = time.time()
        health.run_if_due(conn, now)
        ran = health.run_if_due(conn, now + 999)
        self.assertTrue(ran)


if __name__ == "__main__":
    unittest.main()

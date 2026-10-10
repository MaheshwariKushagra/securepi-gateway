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

import dns_failopen  # noqa: E402
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


class ShortWriteTransactionTests(unittest.TestCase):
    """Audit10Oct H4: the health checks wrote a row, then went on to run
    systemctl, ping and the proxy probe with that write still open -
    holding SQLite's single write lock (and freezing the console's session
    writes) for the whole time. No probe may run with a write open."""

    def setUp(self):
        self._saved = {name: getattr(health, name) for name in
                       ("_services_to_check", "_is_active", "_resource_usage", "check_services",
                        "check_staleness", "check_disk", "check_db_size", "check_wan", "check_dpi_proxy")}

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(health, name, value)

    def test_service_probes_run_with_no_write_open(self):
        conn = fixtures.temp_db()
        seen = []
        health._services_to_check = lambda: ["suricata", "AdGuardHome", "securepi-web"]
        health._is_active = lambda s: seen.append(conn.in_transaction) or True
        health._resource_usage = lambda s: seen.append(conn.in_transaction) or (1, 1.0)
        health.check_services(conn, time.time())
        self.assertEqual(seen, [False] * 6)
        self.assertEqual(conn.execute("SELECT count(*) FROM service_health").fetchone()[0], 3)

    def test_each_check_is_committed_before_the_next_one_runs(self):
        conn = fixtures.temp_db()
        seen = []

        def writes(conn_, now):
            conn_.execute("INSERT INTO signal_state (signal_type, last_run_ts) VALUES ('t', 1)"
                          " ON CONFLICT(signal_type) DO UPDATE SET last_run_ts=2")

        def probes(conn_, now):
            seen.append(conn_.in_transaction)
        health.check_services = writes
        health.check_staleness = probes
        health.check_disk = probes
        health.check_db_size = probes
        health.check_wan = probes
        health.check_dpi_proxy = probes
        health.check_platform_health(conn, time.time())
        self.assertEqual(seen, [False] * 5)


class CheckStalenessTests(unittest.TestCase):
    def test_no_incident_when_everything_is_fresh(self):
        conn = fixtures.temp_db()
        now = time.time()
        conn.execute("UPDATE ingest_stats SET last_run=?", (now,))
        health.record_engine_heartbeat(conn, now)
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

    def test_a_stalled_engine_is_flagged_even_while_ingest_keeps_writing_health_rows(self):
        # Audit.md H9: ingest's own health/fail-open rows in signal_state
        # used to make a hung engine look fresh.
        conn = fixtures.temp_db()
        now = time.time()
        conn.execute("UPDATE ingest_stats SET last_run=?", (now,))
        health.record_engine_heartbeat(conn, now - 3600)
        for sig in ("platform_health", "dns_failopen_check", "privacy_scope"):
            conn.execute("INSERT INTO signal_state (signal_type, last_run_ts) VALUES (?, ?)", (sig, now))
        conn.commit()
        health.check_staleness(conn, now)
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_stale'").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertIn("correlation engine", rows[0]["title"] + rows[0]["description"])

    def test_no_events_ever_from_a_source_is_not_flagged_as_stale(self):
        # A fresh install with no IDS data yet is a startup
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


class DnsResolvesProbeTests(unittest.TestCase):
    """The probe behind DNS fail-open (3 October 2026, CODEBASE_AUDIT.md M2).

    It used to ask the filter for example.com and count an empty answer as
    "the filter is down". With the uplink cut, the filter is alive but can't
    reach its upstream, answers SERVFAIL (empty), and fail-open redirected
    every device's DNS to 1.1.1.1 - filtering off - as seen live in 7.7's
    drop-wan run. The probe now asks for a name the filter answers itself
    (use-application-dns.net, NXDOMAIN from a local rule) and treats ANY
    reply - NXDOMAIN, SERVFAIL, an answer - as alive. Only no reply at all
    (dig exit code 9, or the command hanging) means the filter is down."""

    def _run_with(self, returncode=0, stdout="", raises=None):
        import subprocess
        import unittest.mock as mock
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            if raises is not None:
                raise raises
            return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")

        with mock.patch.object(health.subprocess, "run", fake_run):
            alive = health._dns_resolves("10.10.0.1")
        return alive, calls

    def test_nxdomain_with_empty_output_counts_as_alive(self):
        alive, _ = self._run_with(returncode=0, stdout="")
        self.assertTrue(alive)

    def test_no_reply_counts_as_down(self):
        alive, _ = self._run_with(returncode=9)
        self.assertFalse(alive)

    def test_a_hung_dig_counts_as_down(self):
        import subprocess
        alive, _ = self._run_with(raises=subprocess.TimeoutExpired("dig", 4))
        self.assertFalse(alive)

    def test_probes_a_locally_answered_name_not_an_upstream_one(self):
        _, calls = self._run_with()
        argv = calls[0]
        self.assertIn("use-application-dns.net", argv)
        self.assertIn("@10.10.0.1", argv)
        self.assertNotIn("+short", argv)


class CheckDnsFailopenTests(unittest.TestCase):
    def setUp(self):
        self._orig_resolves = health._dns_resolves
        self._orig_activate = dns_failopen.activate
        self._orig_deactivate = dns_failopen.deactivate
        self._orig_is_active = dns_failopen.is_active
        dns_failopen.is_active = lambda: False   # the live firewall, as these tests set it

    def tearDown(self):
        health._dns_resolves = self._orig_resolves
        dns_failopen.activate = self._orig_activate
        dns_failopen.deactivate = self._orig_deactivate
        dns_failopen.is_active = self._orig_is_active

    # Audit10Oct H8: recovery used to trust the database's `active` flag.
    # An activation that failed half-way left a live bypass rule with the
    # flag still 0, so recovery skipped deactivate() and every device's DNS
    # stayed unfiltered for good.

    def test_recovery_removes_a_leftover_rule_the_database_doesnt_know_about(self):
        conn = fixtures.temp_db()
        health._dns_resolves = lambda host: False

        def half_activate():
            dns_failopen.is_active = lambda: True       # one rule went in...
            raise dns_failopen.DnsFailopenError("could not activate dns fail-open (tcp): boom")
        dns_failopen.activate = half_activate
        now = time.time()
        health.check_dns_failopen(conn, now)
        with self.assertRaises(dns_failopen.DnsFailopenError):
            health.check_dns_failopen(conn, now + 15)
        state = conn.execute("SELECT * FROM dns_failopen_state WHERE id=1").fetchone()
        self.assertEqual(state["active"], 0)                # ...but the flag never said so

        deactivated = []
        dns_failopen.deactivate = lambda: deactivated.append(1)
        health._dns_resolves = lambda host: True
        health.check_dns_failopen(conn, now + 20)
        self.assertEqual(deactivated, [1])
        row = conn.execute("SELECT * FROM audit_log WHERE action='platform.dns_failopen_leftover_removed'").fetchone()
        self.assertIsNotNone(row)

    def test_a_healthy_check_never_touches_the_firewall_when_nothing_is_left(self):
        conn = fixtures.temp_db()
        health._dns_resolves = lambda host: True
        deactivated = []
        dns_failopen.deactivate = lambda: deactivated.append(1)
        health.check_dns_failopen(conn, time.time())
        self.assertEqual(deactivated, [])

    def test_an_unreadable_firewall_does_not_break_the_healthy_path(self):
        conn = fixtures.temp_db()
        health._dns_resolves = lambda host: True

        def cannot_read():
            raise dns_failopen.DnsFailopenError("could not run nft: not found")
        dns_failopen.is_active = cannot_read
        health.check_dns_failopen(conn, time.time())   # must not raise

    def test_no_action_while_resolution_keeps_working(self):
        conn = fixtures.temp_db()
        health._dns_resolves = lambda host: True
        activated = []
        dns_failopen.activate = lambda: activated.append(1)
        health.check_dns_failopen(conn, time.time())
        self.assertEqual(activated, [])
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_dns_failopen'").fetchall()
        self.assertEqual(len(rows), 0)

    def test_a_brief_outage_under_the_grace_period_does_not_fail_open(self):
        conn = fixtures.temp_db()
        health._dns_resolves = lambda host: False
        activated = []
        dns_failopen.activate = lambda: activated.append(1)
        now = time.time()
        health.check_dns_failopen(conn, now)
        health.check_dns_failopen(conn, now + 2)  # well under the 10s default grace
        self.assertEqual(activated, [])
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_dns_failopen'").fetchall()
        self.assertEqual(len(rows), 0)

    def test_outage_past_the_grace_period_fails_open_and_raises_an_incident(self):
        conn = fixtures.temp_db()
        health._dns_resolves = lambda host: False
        activated = []
        dns_failopen.activate = lambda: activated.append(1)
        now = time.time()
        health.check_dns_failopen(conn, now)
        health.check_dns_failopen(conn, now + 15)  # past the 10s default grace
        self.assertEqual(len(activated), 1)
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_dns_failopen'").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["device_id"])
        state = conn.execute("SELECT * FROM dns_failopen_state WHERE id=1").fetchone()
        self.assertEqual(state["active"], 1)

    def test_repeated_outage_extends_rather_than_duplicates_the_incident(self):
        conn = fixtures.temp_db()
        health._dns_resolves = lambda host: False
        dns_failopen.activate = lambda: None
        now = time.time()
        health.check_dns_failopen(conn, now)
        health.check_dns_failopen(conn, now + 15)
        health.check_dns_failopen(conn, now + 25)
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='platform_dns_failopen'").fetchall()
        self.assertEqual(len(rows), 1, "must extend the open incident, not raise a new one every cycle")

    def test_recovery_deactivates_and_clears_state(self):
        conn = fixtures.temp_db()
        health._dns_resolves = lambda host: False
        dns_failopen.activate = lambda: None
        now = time.time()
        health.check_dns_failopen(conn, now)
        health.check_dns_failopen(conn, now + 15)  # now active

        deactivated = []
        dns_failopen.deactivate = lambda: deactivated.append(1)
        health._dns_resolves = lambda host: True
        health.check_dns_failopen(conn, now + 20)

        self.assertEqual(len(deactivated), 1)
        state = conn.execute("SELECT * FROM dns_failopen_state WHERE id=1").fetchone()
        self.assertEqual(state["active"], 0)
        self.assertIsNone(state["down_since"])

    def test_recovery_before_the_grace_period_never_touches_the_firewall(self):
        # A blip that self-heals in a couple of seconds should raise no
        # incident and call neither activate() nor deactivate() - nothing
        # was ever actually redirected, so there's nothing to undo.
        conn = fixtures.temp_db()
        health._dns_resolves = lambda host: False
        activated, deactivated = [], []
        dns_failopen.activate = lambda: activated.append(1)
        now = time.time()
        health.check_dns_failopen(conn, now)

        dns_failopen.deactivate = lambda: deactivated.append(1)
        health._dns_resolves = lambda host: True
        health.check_dns_failopen(conn, now + 2)

        self.assertEqual(activated, [])
        self.assertEqual(deactivated, [], "down_since alone (no activation) needs no deactivate() call")
        state = conn.execute("SELECT * FROM dns_failopen_state WHERE id=1").fetchone()
        self.assertIsNone(state["down_since"])


class RunDnsFailopenIfDueTests(unittest.TestCase):
    def setUp(self):
        # Avoid a real, slow `dig` call against an unreachable 10.10.0.1
        # from the Mac - this class only exercises the throttle gate.
        self._orig_resolves = health._dns_resolves
        health._dns_resolves = lambda host: True

    def tearDown(self):
        health._dns_resolves = self._orig_resolves

    def test_does_not_run_again_before_the_interval_elapses(self):
        conn = fixtures.temp_db()
        now = time.time()
        ran = health.run_dns_failopen_if_due(conn, now)
        self.assertTrue(ran)
        ran_again = health.run_dns_failopen_if_due(conn, now + 1)
        self.assertFalse(ran_again, "must be throttled - ingest.py's own loop runs every 2s")

    def test_runs_again_once_the_interval_has_elapsed(self):
        conn = fixtures.temp_db()
        now = time.time()
        health.run_dns_failopen_if_due(conn, now)
        ran = health.run_dns_failopen_if_due(conn, now + 999)
        self.assertTrue(ran)


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

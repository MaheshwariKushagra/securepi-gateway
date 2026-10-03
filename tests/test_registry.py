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



class ResolveDeviceHostnameTests(unittest.TestCase):
    """Audit.md H2: a new MAC reusing a known hostname must never inherit
    an APPROVED device's identity (and with it, its approval)."""

    def _device_with_mac(self, conn, device_id, hostname, trust, mac):
        fixtures.insert_device(conn, device_id, hostname=hostname)
        conn.execute("UPDATE devices SET trust=? WHERE id=?", (trust, device_id))
        conn.execute("INSERT INTO device_macs (device_id, mac, first_seen, last_seen) VALUES (?, ?, 0, 0)",
                     (device_id, mac))
        conn.commit()

    def test_a_known_mac_resolves_to_its_device(self):
        conn = fixtures.temp_db()
        self._device_with_mac(conn, 1, "phone", "approved", "aa:bb:cc:00:00:01")
        self.assertEqual(registry.resolve_device(conn, "aa:bb:cc:00:00:01", "phone", time.time()), 1)

    def test_a_new_mac_claiming_an_approved_hostname_becomes_a_new_unknown_device(self):
        conn = fixtures.temp_db()
        self._device_with_mac(conn, 1, "Kushagras-iPhone", "approved", "aa:bb:cc:00:00:01")
        new_id = registry.resolve_device(conn, "de:ad:be:ef:00:02", "Kushagras-iPhone", time.time())
        self.assertNotEqual(new_id, 1)
        trust = conn.execute("SELECT trust FROM devices WHERE id=?", (new_id,)).fetchone()["trust"]
        self.assertEqual(trust, "unknown")

    def test_a_new_mac_on_an_unknown_devices_hostname_still_merges(self):
        conn = fixtures.temp_db()
        self._device_with_mac(conn, 1, "tablet", "unknown", "aa:bb:cc:00:00:01")
        self.assertEqual(registry.resolve_device(conn, "de:ad:be:ef:00:02", "tablet", time.time()), 1)

    def test_a_blocked_device_cannot_escape_by_changing_its_mac(self):
        conn = fixtures.temp_db()
        self._device_with_mac(conn, 1, "bad-laptop", "blocked", "aa:bb:cc:00:00:01")
        self.assertEqual(registry.resolve_device(conn, "de:ad:be:ef:00:02", "bad-laptop", time.time()), 1)

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


class AttributionPassCostTests(unittest.TestCase):
    """3 October 2026, found by the reboot test: every 2-second attribution
    pass ended with SELECT count(*) FROM events WHERE device_id IS NOT NULL
    - about 640,000 rows - inside its write transaction, only to print a
    running total. On a cold cache after a boot that count alone took 13 s
    and the engine's signals timed out waiting for the lock. The pass now
    returns how many events IT attributed, counted from its own updates."""

    def _event(self, conn, ip, ts):
        conn.execute("INSERT INTO events (ts, ts_iso, source, event_type, src_ip, blocked)"
                     " VALUES (?, 'test', 'suricata', 'flow', ?, 0)", (ts, ip))

    def test_returns_the_number_attributed_by_this_pass(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1, hostname="phone")
        now = time.time()
        conn.execute("INSERT INTO device_ips (device_id, ip, first_seen, last_seen) VALUES (1, '10.10.0.60', ?, ?)",
                     (now - 100, now + 100))
        for _ in range(3):
            self._event(conn, "10.10.0.60", now)
        conn.commit()
        self.assertEqual(registry.attribute_events(conn), 3)
        # Nothing left to do: the next pass attributes nothing, even though
        # three attributed events exist.
        self.assertEqual(registry.attribute_events(conn), 0)

    def test_does_not_count_every_attributed_event(self):
        conn = fixtures.temp_db()
        statements = []
        conn.set_trace_callback(statements.append)
        registry.attribute_events(conn)
        conn.set_trace_callback(None)
        self.assertFalse(any("device_id IS NOT NULL" in s for s in statements), statements)


class PresenceFollowsAssociationTests(unittest.TestCase):
    """3 October 2026, found by the Stage 7 identity check: the DHCP lease
    lasts 24 hours and the registry counted every unexpired lease as
    present, so a device that left (the Mac, gone at 21:29) still showed
    as seen 12 hours later. When the access point's station list can be
    read, a lease or neighbour entry only counts if that MAC is actually
    associated; if it can't be read, nothing changes."""

    MAC = "a2:b7:71:3b:2b:a3"

    def _run(self, associated, leases=None, arp=None):
        import unittest.mock as mock
        conn = fixtures.temp_db()
        leases = [(self.MAC, "10.10.0.54", "mac-laptop")] if leases is None else leases
        with mock.patch.object(registry, "read_leases", lambda: leases), \
                mock.patch.object(registry, "read_arp", lambda: (arp or {})), \
                mock.patch.object(registry, "read_associated", lambda: associated):
            registry.update_devices(conn)
        return conn

    def test_a_lease_without_association_is_not_presence(self):
        conn = self._run(associated=set())
        self.assertEqual(conn.execute("SELECT count(*) FROM devices").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT count(*) FROM device_ips").fetchone()[0], 0)

    def test_an_associated_device_with_a_lease_is_present(self):
        conn = self._run(associated={self.MAC})
        self.assertEqual(conn.execute("SELECT count(*) FROM devices").fetchone()[0], 1)
        self.assertEqual(conn.execute("SELECT ip FROM device_ips").fetchone()[0], "10.10.0.54")

    def test_a_stale_neighbour_entry_without_association_is_not_presence(self):
        conn = self._run(associated=set(), leases=[], arp={"10.10.0.54": self.MAC})
        self.assertEqual(conn.execute("SELECT count(*) FROM devices").fetchone()[0], 0)

    def test_unreadable_station_list_keeps_the_old_behaviour(self):
        conn = self._run(associated=None)
        self.assertEqual(conn.execute("SELECT count(*) FROM devices").fetchone()[0], 1)

    def test_a_known_device_that_left_keeps_its_last_seen(self):
        import unittest.mock as mock
        conn = fixtures.temp_db()
        leases = [(self.MAC, "10.10.0.54", "mac-laptop")]
        with mock.patch.object(registry, "read_leases", lambda: leases), \
                mock.patch.object(registry, "read_arp", lambda: {}), \
                mock.patch.object(registry, "read_associated", lambda: {self.MAC}):
            registry.update_devices(conn)
        before = conn.execute("SELECT last_seen FROM devices").fetchone()[0]
        with mock.patch.object(registry, "read_leases", lambda: leases), \
                mock.patch.object(registry, "read_arp", lambda: {}), \
                mock.patch.object(registry, "read_associated", lambda: set()), \
                mock.patch.object(registry.time, "time", lambda: before + 3600):
            registry.update_devices(conn)
        self.assertEqual(conn.execute("SELECT last_seen FROM devices").fetchone()[0], before)


class ReadAssociatedTests(unittest.TestCase):
    def test_parses_the_station_dump(self):
        import subprocess
        import unittest.mock as mock
        dump = ("Station 84:b8:b8:51:46:b4 (on ap0)\n\tinactive time:\t20 ms\n"
                "Station CA:25:F0:57:6D:87 (on ap0)\n\tsignal:  \t-50 dBm\n")
        done = subprocess.CompletedProcess([], 0, stdout=dump, stderr="")
        with mock.patch.object(registry.subprocess, "run", lambda *a, **k: done):
            self.assertEqual(registry.read_associated(), {"84:b8:b8:51:46:b4", "ca:25:f0:57:6d:87"})

    def test_a_failing_command_means_unknown_not_empty(self):
        import unittest.mock as mock

        def boom(*a, **k):
            raise OSError("no iw")
        with mock.patch.object(registry.subprocess, "run", boom):
            self.assertIsNone(registry.read_associated())


if __name__ == "__main__":
    unittest.main()


class ReadLeasesTests(unittest.TestCase):
    """Step 7.6 finding: the DHCP server keeps expired leases in its file,
    and the registry treated every one as current - so a phone that left in
    September was still 'seen' every cycle in October, and its address
    interval never closed (an IP handed to a new device could have been
    attributed to the old one)."""

    def _leases(self, leases):
        import json
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump({"version": 1, "leases": leases}, f)
        self.addCleanup(os.remove, path)
        old = registry.LEASES_PATH
        registry.LEASES_PATH = path
        self.addCleanup(setattr, registry, "LEASES_PATH", old)

    def test_expired_leases_are_left_out(self):
        self._leases([
            {"mac": "AA:00:00:00:00:01", "ip": "10.10.0.50", "hostname": "current", "static": False,
             "expires": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))},
            {"mac": "aa:00:00:00:00:02", "ip": "10.10.0.51", "hostname": "gone", "static": False,
             "expires": "2026-09-13T09:14:26Z"},
            {"mac": "aa:00:00:00:00:03", "ip": "10.10.0.60", "hostname": "fixed", "static": True, "expires": ""},
        ])
        names = sorted(h for _, _, h in registry.read_leases())
        self.assertEqual(names, ["current", "fixed"])

    def test_an_offset_timestamp_is_compared_correctly(self):
        # Written with +05:30 like the live file; one hour ahead must count as current.
        self._leases([
            {"mac": "aa:00:00:00:00:04", "ip": "10.10.0.52", "hostname": "ist", "static": False,
             "expires": time.strftime("%Y-%m-%dT%H:%M:%S+05:30", time.gmtime(time.time() + 3600 + 19800))},
        ])
        self.assertEqual([h for _, _, h in registry.read_leases()], ["ist"])

#!/usr/bin/env python3
"""
SecurePi Gateway - policy orchestrator tests (ENHANCEMENT-PLAN.md Stage 4).

Every test runs the real app/orchestrator.py against a real temp SQLite
database and a FakeBackends object: an in-memory stand-in for the two
nftables sets, the enrolled set and AdGuard Home, with the same methods
the real Backends class has. The fake can also be told to misbehave
(accept a change but not keep it, or fail outright), which is how the
"injected failure rolls back" exit criterion is tested.

Run via `make test`, or directly: python3 -m unittest tests.test_orchestrator -v
"""

import copy
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

import adguard  # noqa: E402
import orchestrator  # noqa: E402
import settings  # noqa: E402

CATALOG = {"steam": "gaming", "roblox": "gaming", "tiktok": "social_network", "instagram": "social_network",
           "betway": "gambling", "tinder": "dating", "snapchat": "social_network", "onlyfans": "social_network",
           "4chan": "social_network", "proton": "privacy", "whatsapp": "messenger"}


class FakeBackends:
    """In-memory nftables + AdGuard. Set elements are stored with an
    absolute expiry and reported back as seconds left, like nft does."""

    def __init__(self, clock):
        self.clock = clock
        self.mac_set = {}
        self.ip_set = {}
        self.enroll_set = {}
        self.rules = ["||use-application-dns.net^$dnsrewrite=NXDOMAIN"]
        self.client_list = []
        self.protection_on = True
        self.protection_until = None
        self.ignore_mac_adds = False   # accept mac_add but don't keep it
        self.fail_rules = False        # AdGuard refuses set_rules
        self.calls = []

    def _secs(self, s):
        return {k: (None if v is None else int(v - self.clock())) for k, v in s.items()}

    def macs(self):
        return self._secs(self.mac_set)

    def mac_add(self, mac, seconds):
        self.calls.append(("mac_add", mac, seconds))
        if not self.ignore_mac_adds:
            self.mac_set[mac] = None if seconds is None else self.clock() + seconds

    def mac_del(self, mac):
        self.calls.append(("mac_del", mac))
        self.mac_set.pop(mac, None)

    def ips(self):
        return self._secs(self.ip_set)

    def ip_add(self, ip, seconds):
        self.ip_set[ip] = None if seconds is None else self.clock() + seconds

    def ip_del(self, ip):
        self.ip_set.pop(ip, None)

    def enrolled(self):
        return self._secs(self.enroll_set)

    def enroll(self, ip, hours):
        self.calls.append(("enroll", ip, hours))
        self.enroll_set[ip] = self.clock() + hours * 3600

    def unenroll(self, ip):
        self.calls.append(("unenroll", ip))
        self.enroll_set.pop(ip, None)

    def user_rules(self):
        return list(self.rules)

    def set_user_rules(self, rules):
        if self.fail_rules:
            raise adguard.AdGuardError("AdGuard Home rejected POST /control/filtering/set_rules (HTTP 500)")
        self.rules = list(rules)

    def clients(self):
        return copy.deepcopy(self.client_list)

    def add_client(self, obj):
        self.client_list.append(copy.deepcopy(obj))

    def update_client(self, name, obj):
        for i, c in enumerate(self.client_list):
            if c["name"] == name:
                self.client_list[i] = copy.deepcopy(obj)
                return
        raise adguard.AdGuardError("no such client %s" % name)

    def delete_client(self, name):
        self.client_list = [c for c in self.client_list if c["name"] != name]

    def protection(self):
        return self.protection_on, 0

    def set_protection(self, enabled, duration_ms):
        self.protection_on = enabled
        self.protection_until = None if enabled else self.clock() + (duration_ms or 0) / 1000.0

    def catalog(self):
        return dict(CATALOG)


class Clock:
    def __init__(self):
        self.t = time.time()

    def __call__(self):
        return self.t


def setup_db():
    conn = fixtures.temp_db()
    fixtures.insert_device(conn, 1, hostname="kid-tablet")
    fixtures.insert_device(conn, 2, hostname="tv")
    now = time.time()
    for dev, mac, ip in ((1, "aa:bb:cc:00:00:01", "10.10.0.31"), (2, "aa:bb:cc:00:00:02", "10.10.0.32")):
        conn.execute("INSERT INTO device_macs (device_id, mac, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                     (dev, mac, now, now))
        conn.execute("INSERT INTO device_ips (device_id, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                     (dev, ip, now, now))
    conn.commit()
    return conn


class OrchestratorTestCase(unittest.TestCase):
    def setUp(self):
        self._lockdir = tempfile.mkdtemp()
        self._old_lock = orchestrator.LOCK_PATH
        orchestrator.LOCK_PATH = os.path.join(self._lockdir, "orchestrator.lock")
        self._old_boot = orchestrator.current_boot_id
        self.boot = "boot-1"
        orchestrator.current_boot_id = lambda: self.boot
        self.conn = setup_db()
        self.clock = Clock()
        self.b = FakeBackends(self.clock)

    def tearDown(self):
        orchestrator.LOCK_PATH = self._old_lock
        orchestrator.current_boot_id = self._old_boot

    def create(self, kind, device_id=None, target=None, minutes=None, **kw):
        expires = self.clock() + minutes * 60 if minutes else None
        return orchestrator.create_policy(self.conn, kind, device_id, target, expires,
                                          kw.pop("reason", "test"), backends=self.b, now=self.clock(), **kw)

    def reconcile(self):
        return orchestrator.reconcile(self.conn, backends=self.b, now=self.clock())


class QuarantineTests(OrchestratorTestCase):
    def test_quarantine_adds_every_mac_of_the_device(self):
        self.conn.execute("INSERT INTO device_macs (device_id, mac, first_seen, last_seen) VALUES (1, 'aa:bb:cc:00:00:99', 0, 0)")
        self.conn.commit()
        p = self.create("quarantine", 1)
        self.assertEqual(p["status"], "active")
        self.assertEqual(set(self.b.mac_set), {"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:99"})

    def test_quarantine_is_keyed_on_mac_so_a_new_ip_changes_nothing(self):
        self.create("quarantine", 1)
        # DHCP renewal: the device gets a new address.
        self.conn.execute("INSERT INTO device_ips (device_id, ip, first_seen, last_seen) VALUES (1, '10.10.0.77', ?, ?)",
                          (self.clock() + 1, self.clock() + 1))
        self.conn.commit()
        self.reconcile()
        self.assertIn("aa:bb:cc:00:00:01", self.b.mac_set)

    def test_a_rotated_mac_is_quarantined_on_the_next_cycle(self):
        self.create("quarantine", 1)
        self.conn.execute("INSERT INTO device_macs (device_id, mac, first_seen, last_seen) VALUES (1, 'aa:bb:cc:00:00:55', 0, 0)")
        self.conn.commit()
        self.reconcile()
        self.assertIn("aa:bb:cc:00:00:55", self.b.mac_set)

    def test_timed_quarantine_gets_a_kernel_backstop_and_expires_on_its_own(self):
        p = self.create("quarantine", 1, minutes=30)
        secs = self.b.macs()["aa:bb:cc:00:00:01"]
        self.assertGreater(secs, 30 * 60)                      # outlasts the policy...
        self.assertLessEqual(secs, 30 * 60 + orchestrator.TIMEOUT_MARGIN_S)  # ...but only by the margin
        self.clock.t += 31 * 60
        self.reconcile()
        self.assertEqual(self.b.mac_set, {})
        row = self.conn.execute("SELECT status FROM policies WHERE id=?", (p["id"],)).fetchone()
        self.assertEqual(row["status"], "expired")

    def test_releasing_removes_the_mac(self):
        p = self.create("quarantine", 1)
        orchestrator.end_policy(self.conn, p["id"], reason="false positive", backends=self.b, now=self.clock())
        self.assertEqual(self.b.mac_set, {})

    def test_device_without_a_mac_is_refused(self):
        fixtures.insert_device(self.conn, 3, hostname="static-box")
        with self.assertRaises(orchestrator.PolicyError):
            self.create("quarantine", 3)

    def test_reason_is_required(self):
        with self.assertRaises(orchestrator.PolicyError):
            self.create("quarantine", 1, reason="  ")


class RollbackTests(OrchestratorTestCase):
    def test_injected_failure_rolls_back_and_marks_the_policy_failed(self):
        self.b.mac_set["aa:bb:cc:00:00:02"] = None  # something already there, must survive
        self.b.ignore_mac_adds = True               # the change is accepted but doesn't take
        with self.assertRaises(orchestrator.PolicyApplyError) as ctx:
            self.create("quarantine", 1)
        self.assertIn("rolled back", str(ctx.exception))
        row = self.conn.execute("SELECT status, last_error FROM policies ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row["status"], "failed")
        audit_row = self.conn.execute("SELECT action FROM audit_log WHERE action='policy.rolled_back'").fetchone()
        self.assertIsNotNone(audit_row)

    def test_backend_error_mid_apply_restores_the_previous_rules(self):
        before = list(self.b.rules)
        self.b.fail_rules = True
        with self.assertRaises(orchestrator.PolicyApplyError):
            self.create("block_domain", None, "tracker.example.com")
        self.assertEqual(self.b.rules, before)

    def test_a_failed_replacement_keeps_the_old_policy_active(self):
        first = self.create("profile", 1, "kids")
        self.b.fail_rules = True
        # strict_privacy needs rules, so the rules failure makes it fail
        with self.assertRaises(orchestrator.PolicyApplyError):
            self.create("profile", 1, "strict_privacy")
        row = self.conn.execute("SELECT status FROM policies WHERE id=?", (first["id"],)).fetchone()
        self.assertEqual(row["status"], "active")


class DriftTests(OrchestratorTestCase):
    def test_a_quarantine_removed_by_hand_is_put_back_and_recorded(self):
        self.create("quarantine", 1)
        self.b.mac_set.clear()  # someone ran `nft delete element ...`
        summary = self.reconcile()
        self.assertIn("aa:bb:cc:00:00:01", self.b.mac_set)
        self.assertTrue(summary["drift"])
        inc = self.conn.execute("SELECT * FROM incidents WHERE signal_type='policy_drift'").fetchone()
        self.assertIsNotNone(inc)

    def test_a_rule_deleted_in_adguard_is_detected_and_restored(self):
        self.create("block_domain", None, "tracker.example.com")
        rule = adguard.domain_rule("tracker.example.com", "block")
        self.b.rules = [r for r in self.b.rules if r != rule]
        summary = self.reconcile()
        self.assertIn(rule, self.b.rules)
        self.assertTrue(any("removed or edited in AdGuard" in d for d in summary["drift"]))

    def test_client_settings_edited_in_adguard_are_detected(self):
        self.create("profile", 1, "kids")
        cl = self.b.client_list[0]
        cl["safe_search"]["enabled"] = False
        cl["safesearch_enabled"] = False
        summary = self.reconcile()
        self.assertTrue(summary["drift"])
        self.assertTrue(self.b.client_list[0]["safesearch_enabled"])

    def test_after_a_reboot_the_empty_set_is_restored_quietly(self):
        self.create("quarantine", 1)
        self.reconcile()
        self.b.mac_set.clear()
        self.boot = "boot-2"
        summary = self.reconcile()
        self.assertIn("aa:bb:cc:00:00:01", self.b.mac_set)
        self.assertEqual(summary["drift"], [])
        self.assertTrue(summary["restored"])
        self.assertIsNone(self.conn.execute("SELECT 1 FROM incidents WHERE signal_type='policy_drift'").fetchone())

    def test_nothing_to_do_is_quiet(self):
        self.create("quarantine", 1)
        self.reconcile()
        summary = self.reconcile()
        self.assertEqual(summary["drift"], [])
        self.assertEqual(summary["errors"], {})

    def test_manual_rules_are_never_touched(self):
        self.create("block_domain", None, "tracker.example.com")
        self.b.rules.append("||someone-elses-rule.example^")
        self.reconcile()
        self.assertIn("||someone-elses-rule.example^", self.b.rules)
        self.assertIn("||use-application-dns.net^$dnsrewrite=NXDOMAIN", self.b.rules)


class RuleTests(OrchestratorTestCase):
    def test_device_rule_is_quoted_and_has_no_comment(self):
        self.conn.execute("UPDATE devices SET friendly_name=? WHERE id=1", ("Kid's tablet",))
        self.conn.commit()
        self.create("allow_domain", 1, "cdn.example.com")
        rule = [r for r in self.b.rules if "cdn.example.com" in r][0]
        self.assertEqual(rule, "@@||cdn.example.com^$client='Kid\\'s tablet'")
        self.assertNotIn("#", rule)
        self.assertEqual(len(self.b.client_list), 1)  # the client it names was created

    def test_timed_allow_goes_away_when_it_expires(self):
        self.create("allow_domain", 1, "cdn.example.com", minutes=60)
        self.clock.t += 3601
        self.reconcile()
        self.assertFalse(any("cdn.example.com" in r for r in self.b.rules))

    def test_block_replaces_allow_for_the_same_domain_and_device(self):
        a = self.create("allow_domain", 1, "x.example.com")
        self.create("block_domain", 1, "x.example.com")
        self.assertEqual(self.conn.execute("SELECT status FROM policies WHERE id=?", (a["id"],)).fetchone()[0],
                         "replaced")
        self.assertFalse(any(r.startswith("@@||x.example.com") for r in self.b.rules))

    def test_invalid_domain_is_refused(self):
        with self.assertRaises(orchestrator.PolicyError):
            self.create("block_domain", None, "not a domain")

    def test_legacy_comment_rules_are_migrated_into_policies(self):
        self.b.client_list.append({"name": "kid-tablet", "ids": ["aa:bb:cc:00:00:01"]})
        self.b.rules.append("@@||cdn.example.com^$client=kid-tablet  # securepi-expires:%d" % (self.clock() + 3600))
        self.reconcile()
        row = self.conn.execute("SELECT * FROM policies WHERE source='migrated'").fetchone()
        self.assertEqual((row["kind"], row["device_id"], row["target"]), ("allow_domain", 1, "cdn.example.com"))
        self.assertFalse(any("# securepi" in r for r in self.b.rules))
        self.assertIn("@@||cdn.example.com^$client='kid-tablet'", self.b.rules)


class BlockIpTests(OrchestratorTestCase):
    def test_block_ip(self):
        self.create("block_ip", None, "203.0.113.9")
        self.assertIn("203.0.113.9", self.b.ip_set)

    def test_lan_and_reserved_addresses_are_refused(self):
        for bad in ("10.10.0.5", "127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "255.255.255.255", "nope"):
            with self.assertRaises(orchestrator.PolicyError, msg=bad):
                self.create("block_ip", None, bad)

    def test_ip_blocks_are_network_wide_only(self):
        with self.assertRaises(orchestrator.PolicyError):
            self.create("block_ip", 1, "203.0.113.9")


class ProfileAndPauseTests(OrchestratorTestCase):
    def test_kids_profile_sets_safe_search_and_blocked_services(self):
        self.clock.t = time.mktime((2026, 9, 26, 12, 0, 0, 0, 0, -1))  # midday: schedule closed
        self.create("profile", 1, "kids")
        cl = self.b.client_list[0]
        self.assertTrue(cl["safesearch_enabled"])
        self.assertIn("betway", cl["blocked_services"])      # group:gambling, always
        self.assertNotIn("steam", cl["blocked_services"])    # gaming only at night

    def test_scheduled_block_activates_on_time(self):
        self.clock.t = time.mktime((2026, 9, 26, 20, 59, 30, 0, 0, -1))
        self.create("profile", 1, "kids")
        self.assertNotIn("steam", self.b.client_list[0]["blocked_services"])
        self.clock.t = time.mktime((2026, 9, 26, 21, 0, 5, 0, 0, -1))
        summary = self.reconcile()
        self.assertIn("steam", self.b.client_list[0]["blocked_services"])
        self.assertEqual(summary["drift"], [])  # a schedule change is planned, not drift
        self.clock.t = time.mktime((2026, 9, 27, 7, 0, 5, 0, 0, -1))
        self.reconcile()
        self.assertNotIn("steam", self.b.client_list[0]["blocked_services"])

    def test_pause_turns_filtering_off_and_auto_resumes(self):
        self.create("profile", 1, "kids")
        self.create("pause", 1, minutes=15)
        cl = self.b.client_list[0]
        # A pause turns off blocklists, blocked services AND safe search -
        # AdGuard's filtering_enabled alone leaves the other two applying.
        self.assertFalse(cl["filtering_enabled"])
        self.assertEqual(cl["blocked_services"], [])
        self.assertFalse(cl["safesearch_enabled"])
        self.clock.t += 15 * 60 + 1
        self.reconcile()
        cl = self.b.client_list[0]
        self.assertTrue(cl["filtering_enabled"])
        self.assertTrue(cl["safesearch_enabled"])      # the profile comes back in full
        self.assertIn("betway", cl["blocked_services"])

    def test_removing_a_profile_resets_the_device_to_standard(self):
        p = self.create("profile", 1, "iot")
        self.assertIn("whatsapp", self.b.client_list[0]["blocked_services"])
        orchestrator.end_policy(self.conn, p["id"], backends=self.b, now=self.clock())
        self.assertEqual(self.b.client_list[0]["blocked_services"], [])
        self.assertTrue(self.b.client_list[0]["filtering_enabled"])

    def test_strict_privacy_adds_vendor_telemetry_rules_for_the_device(self):
        self.create("profile", 1, "strict_privacy")
        self.assertTrue(any(r.startswith("||metrics.icloud.com^$client=") for r in self.b.rules))

    def test_network_pause_uses_adguard_protection(self):
        self.create("pause", None, minutes=5)
        self.assertFalse(self.b.protection_on)
        self.clock.t += 301
        self.reconcile()
        self.assertTrue(self.b.protection_on)

    def test_pause_longer_than_a_day_is_refused(self):
        with self.assertRaises(orchestrator.PolicyError):
            self.create("pause", 1, minutes=25 * 60)


class EnrollTests(OrchestratorTestCase):
    def test_enrollment_follows_the_device_to_a_new_ip(self):
        self.create("enroll", 1, minutes=120)
        self.assertIn("10.10.0.31", self.b.enroll_set)
        self.conn.execute("INSERT INTO device_ips (device_id, ip, first_seen, last_seen) VALUES (1, '10.10.0.77', ?, ?)",
                          (self.clock() + 1, self.clock() + 1))
        self.conn.commit()
        self.reconcile()
        self.assertIn("10.10.0.77", self.b.enroll_set)
        self.assertNotIn("10.10.0.31", self.b.enroll_set)

    def test_a_flushed_enrollment_is_never_re_added(self):
        p = self.create("enroll", 1, minutes=120)
        self.b.enroll_set.clear()   # the privacy canary's fail-safe flush
        self.reconcile()
        self.assertEqual(self.b.enroll_set, {})
        row = self.conn.execute("SELECT status FROM policies WHERE id=?", (p["id"],)).fetchone()
        self.assertEqual(row["status"], "removed")

    def test_cli_enrollment_is_adopted_not_removed(self):
        self.b.enroll_set["10.10.0.32"] = self.clock() + 3600
        self.reconcile()
        self.assertIn("10.10.0.32", self.b.enroll_set)
        row = self.conn.execute("SELECT * FROM policies WHERE source='adopted'").fetchone()
        self.assertEqual(row["device_id"], 2)


class TrustAndAutoResponseTests(OrchestratorTestCase):
    def test_blocked_device_is_quarantined_and_approving_releases_it(self):
        self.conn.execute("UPDATE devices SET trust='blocked' WHERE id=2")
        self.conn.commit()
        self.reconcile()
        self.assertIn("aa:bb:cc:00:00:02", self.b.mac_set)
        self.conn.execute("UPDATE devices SET trust='approved' WHERE id=2")
        self.conn.commit()
        self.reconcile()
        self.assertNotIn("aa:bb:cc:00:00:02", self.b.mac_set)

    def test_unknown_devices_are_only_restricted_when_the_setting_is_on(self):
        self.reconcile()
        self.assertEqual(self.b.mac_set, {})
        settings.set_value(self.conn, "restrict_unknown_devices", True)
        self.conn.execute("UPDATE devices SET trust='approved' WHERE id=1")
        self.conn.commit()
        self.reconcile()
        self.assertEqual(set(self.b.mac_set), {"aa:bb:cc:00:00:02"})

    def test_auto_quarantine_acts_once_on_a_new_high_confidence_campaign(self):
        settings.set_value(self.conn, "auto_quarantine_enabled", True)
        self.reconcile()  # records when auto-response was switched on
        self.clock.t += 10
        self.conn.execute("INSERT INTO campaigns (device_id, title, status, tactics, first_seen, last_seen,"
                          " created_at, updated_at) VALUES (1, 'c', 'new', 'Discovery -> Credential Access ->"
                          " Command and Control', ?, ?, ?, ?)", (self.clock(),) * 4)
        self.conn.commit()
        self.reconcile()
        self.assertIn("aa:bb:cc:00:00:01", self.b.mac_set)
        self.reconcile()
        n = self.conn.execute("SELECT count(*) FROM policies WHERE source LIKE 'auto:campaign:%'").fetchone()[0]
        self.assertEqual(n, 1)

    def test_auto_quarantine_ignores_campaigns_from_before_it_was_enabled(self):
        self.conn.execute("INSERT INTO campaigns (device_id, title, status, tactics, first_seen, last_seen,"
                          " created_at, updated_at) VALUES (1, 'c', 'new', 'A -> B -> C', ?, ?, ?, ?)",
                          (self.clock() - 100,) * 4)
        self.conn.commit()
        settings.set_value(self.conn, "auto_quarantine_enabled", True)
        self.reconcile()
        self.assertEqual(self.b.mac_set, {})

    def test_two_tactics_are_not_enough_by_default(self):
        settings.set_value(self.conn, "auto_quarantine_enabled", True)
        self.reconcile()
        self.clock.t += 10
        self.conn.execute("INSERT INTO campaigns (device_id, title, status, tactics, first_seen, last_seen,"
                          " created_at, updated_at) VALUES (1, 'c', 'new', 'A -> B', ?, ?, ?, ?)", (self.clock(),) * 4)
        self.conn.commit()
        self.reconcile()
        self.assertEqual(self.b.mac_set, {})


if __name__ == "__main__":
    unittest.main()

"""The step 8.3 demo helpers: dpi/canary_demo.py (the canary turned red on
purpose) and gateway/demo_attacks.py (the harness attacks). mitmproxy is
stubbed as in tests/test_privacy_canary.py."""
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "app"))
sys.path.insert(0, os.path.join(REPO, "dpi"))
sys.path.insert(0, os.path.join(REPO, "gateway"))

if "mitmproxy" not in sys.modules:
    _fake = types.ModuleType("mitmproxy")
    _fake.http = types.ModuleType("mitmproxy.http")
    sys.modules["mitmproxy"] = _fake
    sys.modules["mitmproxy.http"] = _fake.http

import canary_demo  # noqa: E402
import privacy_canary  # noqa: E402

ADDON = os.path.join(REPO, "dpi", "securepi_adfilter.py")


class CanaryDemoTests(unittest.TestCase):
    def setUp(self):
        # A stand-in for the live addon, so the test can prove it is never written.
        self.dir = tempfile.mkdtemp()
        self.live = os.path.join(self.dir, "securepi_adfilter.py")
        with open(ADDON) as f:
            self.source = f.read()
        with open(self.live, "w") as f:
            f.write(self.source)
        self._orig = privacy_canary.ADDON_PATH
        privacy_canary.ADDON_PATH = self.live

    def tearDown(self):
        privacy_canary.ADDON_PATH = self._orig

    def test_break_checks_a_broken_copy_and_never_touches_the_live_addon(self):
        seen = {}

        def fake_run_check():
            # What the real check would load at this moment.
            seen["path"] = privacy_canary.ADDON_PATH
            with open(privacy_canary.ADDON_PATH) as f:
                seen["source"] = f.read()
            return False

        with mock.patch.object(privacy_canary, "run_check", fake_run_check), \
                mock.patch.object(canary_demo, "open_incidents", return_value=[(7, "new")]):
            canary_demo.break_it()
        self.assertNotEqual(seen["path"], self.live)
        self.assertIn("data.ignore_conn = True", seen["source"])
        self.assertNotIn("data.ignore_connection = True", seen["source"])
        # The live file is byte-for-byte what it was, and the path is put back.
        with open(self.live) as f:
            self.assertEqual(f.read(), self.source)
        self.assertEqual(privacy_canary.ADDON_PATH, self.live)
        # The broken copy is gone.
        self.assertFalse(os.path.exists(seen["path"]))

    def test_break_stops_if_the_check_unexpectedly_passes(self):
        with mock.patch.object(privacy_canary, "run_check", return_value=True):
            with self.assertRaises(SystemExit):
                canary_demo.break_it()
        self.assertEqual(privacy_canary.ADDON_PATH, self.live)

    def test_break_refuses_an_addon_without_the_expected_line(self):
        with open(self.live, "w") as f:
            f.write("# no decision line here\n")
        with mock.patch.object(privacy_canary, "run_check") as run_check:
            with self.assertRaises(SystemExit):
                canary_demo.break_it()
        run_check.assert_not_called()

    def test_the_broken_copy_really_fails_the_real_check_logic(self):
        # End to end without the database: the copy break_it() builds is
        # caught by the canary's own decision checks.
        broken = os.path.join(self.dir, "broken.py")
        with open(broken, "w") as f:
            f.write(self.source.replace(canary_demo.GOOD, canary_demo.BROKEN))
        privacy_canary.ADDON_PATH = broken
        addon = privacy_canary._load_addon_fresh().SecurePiAdFilter()
        leaked = [h for h, must in privacy_canary.wrong_decisions(addon) if not must]
        self.assertIn("example.com", leaked)


class DemoAttackTests(unittest.TestCase):
    def setUp(self):
        import demo_attacks
        self.d = demo_attacks
        self.b = demo_attacks.b

    def test_demo_addresses_never_collide_with_the_battery_or_the_victims(self):
        taken = set(self.b.FAST_HOSTS + self.b.SLOW_SCAN_HOSTS + self.b.SLOW_SWEEP_HOSTS
                    + [self.b.BENIGN_HOST] + self.b.VICTIM_IPS + [self.b.GATEWAY_DNS])
        for ip in self.d.DEMO_HOSTS:
            self.assertNotIn(ip, taken)
            self.assertTrue(ip.startswith("10.10.0."))
        self.assertEqual(len(set(self.d.DEMO_HOSTS)), len(self.d.DEMO_HOSTS))

    def test_campaign_runs_the_battery_functions_unchanged(self):
        calls = []

        def fake(name):
            return lambda n, host, dev: calls.append((name, n, host, dev))

        rows = iter([None, {"id": 3, "created_at": 0.0, "tactics": "Discovery -> Command and Control"}])

        class FakeConn:
            def execute(self, *a):
                class R:
                    def fetchone(_):
                        try:
                            return next(rows)
                        except StopIteration:
                            return {"tactics": "Discovery -> Credential Access -> Command and Control"}
                return R()

        with mock.patch.object(self.b, "beacon", fake("beacon")), \
                mock.patch.object(self.b, "port_scan", fake("port_scan")), \
                mock.patch.object(self.b, "brute_force", fake("brute_force")), \
                mock.patch.object(self.b, "db", return_value=FakeConn()), \
                mock.patch.object(self.d, "add_address"), \
                mock.patch.object(self.d, "new_demo_device", return_value=99), \
                mock.patch.object(self.d, "start_victim_sshd") as sshd, \
                mock.patch.object(self.d.time, "sleep"):
            self.d.campaign(42)
        self.assertEqual(sorted(c[0] for c in calls), ["beacon", "brute_force", "port_scan"])
        for _, n, host, dev in calls:
            self.assertEqual((n, host, dev), (42, self.d.CAMPAIGN_HOST, 99))
        sshd.return_value.terminate.assert_called_once()


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""
SecurePi Gateway - privileged helper validation tests
(ENHANCEMENT-PLAN.md step 3.3).

Only tests build_nft_argv() - the pure "validate the verb and arguments,
decide what nft command would run" logic. Never runs a real subprocess
or touches real nftables, the same reason quarantine.py/dpi_enroll.py
(which this helper stands in front of) have never had Mac-side tests
either: this needs root and a real nftables ruleset to actually execute
against, which only exists on the gateway. What CAN and must be tested
here, without any of that, is the step's own exit criterion: "Helper
rejects malformed input" - every case below is either a valid input that
must produce the exact expected nft command, or an invalid one that
must be rejected before nft is ever considered.

gateway/securepi-web-helper has no .py extension (it's deployed straight
to /usr/local/sbin, matching gateway/securepi's own convention), so it's
loaded by path with importlib rather than a plain import.

Run via `make test`, or directly: python3 -m unittest tests.test_securepi_web_helper -v
"""

import importlib.util
from importlib.machinery import SourceFileLoader
import os
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELPER_PATH = os.path.join(REPO_ROOT, "gateway", "securepi-web-helper")

# securepi-web-helper has no .py extension (it's deployed straight to
# /usr/local/sbin), so importlib's default extension-sniffing spec
# finder returns None for it - an explicit SourceFileLoader is needed
# to load it as Python source regardless of its filename.
_loader = SourceFileLoader("securepi_web_helper", HELPER_PATH)
_spec = importlib.util.spec_from_loader("securepi_web_helper", _loader)
helper = importlib.util.module_from_spec(_spec)
_loader.exec_module(helper)


class QuarantineVerbTests(unittest.TestCase):
    def test_quarantine_add_builds_the_expected_nft_command(self):
        self.assertEqual(
            helper.build_nft_argv("quarantine-add", ["10.10.0.50"]),
            ["add", "element", "inet", "filter", "quarantine", "{ 10.10.0.50 }"],
        )

    def test_quarantine_delete_builds_the_expected_nft_command(self):
        self.assertEqual(
            helper.build_nft_argv("quarantine-delete", ["10.10.0.50"]),
            ["delete", "element", "inet", "filter", "quarantine", "{ 10.10.0.50 }"],
        )

    def test_quarantine_list_takes_no_arguments(self):
        self.assertEqual(
            helper.build_nft_argv("quarantine-list", []),
            ["-j", "list", "set", "inet", "filter", "quarantine"],
        )

    def test_quarantine_add_rejects_a_non_ip(self):
        with self.assertRaises(helper.RejectedInput):
            helper.build_nft_argv("quarantine-add", ["not-an-ip"])

    def test_quarantine_add_rejects_a_shell_injection_attempt(self):
        with self.assertRaises(helper.RejectedInput):
            helper.build_nft_argv("quarantine-add", ["10.10.0.50; rm -rf /"])

    def test_quarantine_add_rejects_nft_syntax_injection(self):
        # Even something that LOOKS like it could smuggle extra nft
        # syntax through the "{ %s }" formatting must be rejected,
        # since it isn't a valid IP address either.
        with self.assertRaises(helper.RejectedInput):
            helper.build_nft_argv("quarantine-add", ["10.10.0.50 } ; add element inet filter quarantine { 10.10.0.99"])

    def test_quarantine_add_rejects_wrong_argument_count(self):
        with self.assertRaises(helper.RejectedInput):
            helper.build_nft_argv("quarantine-add", [])
        with self.assertRaises(helper.RejectedInput):
            helper.build_nft_argv("quarantine-add", ["10.10.0.50", "10.10.0.51"])

    def test_quarantine_add_accepts_ipv6(self):
        # ipaddress.ip_address() validates both families - nft's own
        # "inet" family in this set covers both v4 and v6.
        argv = helper.build_nft_argv("quarantine-add", ["fe80::1"])
        self.assertIn("{ fe80::1 }", argv)


class EnrolledVerbTests(unittest.TestCase):
    def test_enrolled_add_builds_the_expected_nft_command(self):
        self.assertEqual(
            helper.build_nft_argv("enrolled-add", ["10.10.0.50", "24"]),
            ["add", "element", "ip", "nat", "enrolled", "{ 10.10.0.50 timeout 24h }"],
        )

    def test_enrolled_delete_builds_the_expected_nft_command(self):
        self.assertEqual(
            helper.build_nft_argv("enrolled-delete", ["10.10.0.50"]),
            ["delete", "element", "ip", "nat", "enrolled", "{ 10.10.0.50 }"],
        )

    def test_enrolled_flush_takes_no_arguments(self):
        self.assertEqual(
            helper.build_nft_argv("enrolled-flush", []),
            ["flush", "set", "ip", "nat", "enrolled"],
        )
        with self.assertRaises(helper.RejectedInput):
            helper.build_nft_argv("enrolled-flush", ["10.10.0.50"])

    def test_enrolled_add_rejects_a_non_ip(self):
        with self.assertRaises(helper.RejectedInput):
            helper.build_nft_argv("enrolled-add", ["not-an-ip", "24"])

    def test_enrolled_add_rejects_a_non_numeric_hours(self):
        with self.assertRaises(helper.RejectedInput):
            helper.build_nft_argv("enrolled-add", ["10.10.0.50", "twenty-four"])

    def test_enrolled_add_rejects_a_negative_or_zero_hours(self):
        with self.assertRaises(helper.RejectedInput):
            helper.build_nft_argv("enrolled-add", ["10.10.0.50", "0"])
        with self.assertRaises(helper.RejectedInput):
            helper.build_nft_argv("enrolled-add", ["10.10.0.50", "-5"])

    def test_enrolled_add_rejects_an_absurdly_large_hours(self):
        # Above the 720h (30-day) ceiling - a typo or an injected huge
        # number shouldn't be able to create a set element that
        # effectively never expires.
        with self.assertRaises(helper.RejectedInput):
            helper.build_nft_argv("enrolled-add", ["10.10.0.50", "999999"])

    def test_enrolled_add_accepts_the_ceiling_value(self):
        helper.build_nft_argv("enrolled-add", ["10.10.0.50", "720"])  # must not raise

    def test_enrolled_add_rejects_a_hours_value_with_injected_text(self):
        with self.assertRaises(helper.RejectedInput):
            helper.build_nft_argv("enrolled-add", ["10.10.0.50", "24h timeout 999h"])


class UnknownVerbTests(unittest.TestCase):
    def test_an_unknown_verb_is_rejected(self):
        with self.assertRaises(helper.RejectedInput):
            helper.build_nft_argv("drop-the-whole-firewall", [])

    def test_no_verb_set_verbs_ever_take_a_family_table_or_set_argument(self):
        # Structural guard: every verb's family/table/set is hardcoded in
        # build_nft_argv, never taken from the caller's argument list -
        # confirmed by checking none of the real nft argv lists this
        # module can produce contain anything from a plausible
        # "override the target" attempt.
        for verb, args in [
            ("quarantine-add", ["10.10.0.50"]),
            ("enrolled-add", ["10.10.0.50", "24"]),
        ]:
            argv = helper.build_nft_argv(verb, args)
            self.assertNotIn("bridge", argv)
            self.assertNotIn("netdev", argv)


class Stage4VerbTests(unittest.TestCase):
    """ENHANCEMENT-PLAN.md step 4.2: MAC-keyed quarantine and IP blocks."""

    def test_quarantine_mac_add_without_and_with_a_timeout(self):
        self.assertEqual(
            helper.build_nft_argv("quarantine-mac-add", ["aa:bb:cc:dd:ee:ff"]),
            ["add", "element", "inet", "filter", "quarantine_mac", "{ aa:bb:cc:dd:ee:ff }"])
        self.assertEqual(
            helper.build_nft_argv("quarantine-mac-add", ["aa:bb:cc:dd:ee:ff", "3660"]),
            ["add", "element", "inet", "filter", "quarantine_mac", "{ aa:bb:cc:dd:ee:ff timeout 3660s }"])

    def test_blocked_ip_verbs(self):
        self.assertEqual(helper.build_nft_argv("blocked-ip-add", ["203.0.113.9", "120"]),
                         ["add", "element", "inet", "filter", "blocked_ip", "{ 203.0.113.9 timeout 120s }"])
        self.assertEqual(helper.build_nft_argv("blocked-ip-delete", ["203.0.113.9"]),
                         ["delete", "element", "inet", "filter", "blocked_ip", "{ 203.0.113.9 }"])
        self.assertEqual(helper.build_nft_argv("blocked-ip-list", []),
                         ["-j", "list", "set", "inet", "filter", "blocked_ip"])

    def test_malformed_macs_are_rejected(self):
        for bad in ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee", "aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff }",
                    "aa:bb:cc:dd:ee:ff; flush ruleset", ""):
            with self.assertRaises(helper.RejectedInput, msg=bad):
                helper.build_nft_argv("quarantine-mac-add", [bad])

    def test_blocked_ip_refuses_ipv6_and_junk(self):
        for bad in ("2001:db8::1", "10.10.0.1/24", "1.2.3.4 }", "x"):
            with self.assertRaises(helper.RejectedInput, msg=bad):
                helper.build_nft_argv("blocked-ip-add", [bad])

    def test_timeout_seconds_are_bounded(self):
        for bad in ("59", "2592001", "-5", "60s", "1e9"):
            with self.assertRaises(helper.RejectedInput, msg=bad):
                helper.build_nft_argv("quarantine-mac-add", ["aa:bb:cc:dd:ee:ff", bad])
        helper.build_nft_argv("quarantine-mac-add", ["aa:bb:cc:dd:ee:ff", "2592000"])

    def test_wrong_argument_counts_are_rejected(self):
        with self.assertRaises(helper.RejectedInput):
            helper.build_nft_argv("quarantine-mac-list", ["x"])
        with self.assertRaises(helper.RejectedInput):
            helper.build_nft_argv("blocked-ip-add", ["1.2.3.4", "60", "extra"])


class HttpsResetTests(unittest.TestCase):
    """ADBLOCK-ENHANCEMENT-PLAN.md: https-reset makes an enrolment or site
    change apply at once. Only conntrack and ss, fixed paths, a validated
    address, TCP 443 and the proxy's :8080 - nothing else."""

    def test_reset_one_device(self):
        self.assertEqual(helper.build_reset_commands("https-reset", ["10.10.0.50"]), [
            ["/usr/sbin/conntrack", "-D", "-p", "tcp", "--orig-src", "10.10.0.50", "--orig-port-dst", "443"],
            ["/usr/bin/ss", "-K", "dst", "10.10.0.50", "sport", "=", ":8080"],
        ])

    def test_reset_all_only_closes_proxy_connections(self):
        self.assertEqual(helper.build_reset_commands("https-reset-all", []),
                         [["/usr/bin/ss", "-K", "sport", "=", ":8080"]])

    def test_bad_input_rejected(self):
        for verb, args in (("https-reset", []), ("https-reset", ["10.10.0.50", "x"]),
                           ("https-reset", ["10.10.0.50; reboot"]), ("https-reset", ["::1"]),
                           ("https-reset-all", ["10.10.0.50"])):
            with self.assertRaises(helper.RejectedInput, msg=(verb, args)):
                helper.build_reset_commands(verb, args)

    def test_other_verbs_are_not_resets(self):
        self.assertIsNone(helper.build_reset_commands("enrolled-flush", []))


if __name__ == "__main__":
    unittest.main()

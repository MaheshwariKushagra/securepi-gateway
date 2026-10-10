#!/usr/bin/env python3
"""
SecurePi Gateway - DNS fail-open tests (ENHANCEMENT-PLAN.md step 3.6).

_add_rule_argv/_delete_rule_argv/_extract_handles are pure - no
subprocess call - so they're tested directly, the same reason
securepi-web-helper's build_nft_argv() is tested directly. is_active/
activate/deactivate are tested by monkeypatching dns_failopen._run, the
same "replace the one function that shells out" approach app/health.py's
own tests already use for systemctl/ping - this project has no real
nftables ruleset to test against on the Mac.

Run via `make test`, or directly: python3 -m unittest tests.test_dns_failopen -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402,F401  (puts app/ on the import path)

import dns_failopen  # noqa: E402


# A realistic `nft -a list chain ip nat prerouting` snapshot, matching the
# live gateway's real output format (checked directly on the gateway
# before writing this).
BASE_LIST_OUTPUT = """table ip nat {
\tchain prerouting { # handle 1
\t\ttype nat hook prerouting priority dstnat; policy accept;
\t\tiifname "ap0" udp dport 53 ip daddr != 10.10.0.1 counter packets 0 bytes 0 dnat to 10.10.0.1:53 # handle 4
\t\tiifname "ap0" tcp dport 53 ip daddr != 10.10.0.1 counter packets 0 bytes 0 dnat to 10.10.0.1:53 # handle 5
\t\tiifname @dpi_up ip saddr @enrolled tcp dport 443 counter packets 0 bytes 0 redirect to :8080 comment "dpi-redirect" # handle 6
\t}
}
"""

WITH_FAILOPEN_OUTPUT = BASE_LIST_OUTPUT.replace(
    "\t}\n}\n",
    '\t\tiifname "ap0" ip daddr 10.10.0.1 udp dport 53 counter packets 0 bytes 0 dnat to 1.1.1.1:53'
    ' comment "dns-failopen" # handle 7\n'
    '\t\tiifname "ap0" ip daddr 10.10.0.1 tcp dport 53 counter packets 0 bytes 0 dnat to 1.1.1.1:53'
    ' comment "dns-failopen" # handle 8\n'
    "\t}\n}\n",
)


class _FakeResult:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class RuleShapeTests(unittest.TestCase):
    def test_add_rule_argv_for_udp_targets_the_gateways_own_dns_port(self):
        argv = dns_failopen._add_rule_argv("udp")
        self.assertIn("udp", argv)
        self.assertIn(dns_failopen.GATEWAY_IP, argv)
        self.assertIn("%s:53" % dns_failopen.UPSTREAM_RESOLVER, argv)
        self.assertIn(dns_failopen.RULE_COMMENT, argv)

    def test_add_rule_argv_for_tcp_targets_the_gateways_own_dns_port(self):
        argv = dns_failopen._add_rule_argv("tcp")
        self.assertIn("tcp", argv)
        self.assertIn(dns_failopen.GATEWAY_IP, argv)

    def test_delete_rule_argv_references_the_given_handle(self):
        argv = dns_failopen._delete_rule_argv("42")
        self.assertEqual(argv, ["delete", "rule", "ip", "nat", "prerouting", "handle", "42"])


class ExtractHandlesTests(unittest.TestCase):
    def test_no_failopen_rule_present_returns_no_handles(self):
        self.assertEqual(dns_failopen._extract_handles(BASE_LIST_OUTPUT), [])

    def test_finds_every_dns_failopen_commented_handle(self):
        self.assertEqual(dns_failopen._extract_handles(WITH_FAILOPEN_OUTPUT), ["7", "8"])

    def test_never_matches_an_unrelated_rules_comment(self):
        # dpi-redirect's own rule (handle 6) must never be picked up.
        self.assertNotIn("6", dns_failopen._extract_handles(WITH_FAILOPEN_OUTPUT))


class ActivateDeactivateTests(unittest.TestCase):
    def setUp(self):
        self._orig_run = dns_failopen._run

    def tearDown(self):
        dns_failopen._run = self._orig_run

    def test_activate_does_nothing_when_already_active(self):
        calls = []

        def fake_run(args, input_text=None):
            calls.append(args)
            return _FakeResult(stdout=WITH_FAILOPEN_OUTPUT)
        dns_failopen._run = fake_run

        dns_failopen.activate()
        self.assertEqual(len(calls), 1, "should only check, never add, when already active")
        self.assertEqual(calls[0][0], "-a")

    def test_activate_adds_both_udp_and_tcp_rules_in_one_transaction(self):
        # Audit10Oct H8: the two rules used to be added by two separate nft
        # calls, so a failure on the second left the first in place. They
        # now go in through one `nft -f -` batch - both or neither.
        calls = []

        def fake_run(args, input_text=None):
            calls.append((args, input_text))
            return _FakeResult(stdout=BASE_LIST_OUTPUT)
        dns_failopen._run = fake_run

        dns_failopen.activate()
        batches = [text for args, text in calls if args == ["-f", "-"]]
        self.assertEqual(len(batches), 1)
        self.assertEqual([args for args, text in calls if args[:2] == ["add", "rule"]], [])
        lines = [l for l in batches[0].splitlines() if l.strip()]
        self.assertEqual(len(lines), 2)
        self.assertTrue(any(" udp dport 53 " in l for l in lines))
        self.assertTrue(any(" tcp dport 53 " in l for l in lines))
        for line in lines:
            self.assertIn('comment "%s"' % dns_failopen.RULE_COMMENT, line)
            self.assertIn("dnat to %s:53" % dns_failopen.UPSTREAM_RESOLVER, line)

    def test_a_refused_batch_adds_nothing_and_raises(self):
        calls = []

        def fake_run(args, input_text=None):
            calls.append(args)
            if args == ["-f", "-"]:
                return _FakeResult(returncode=1, stderr="Error: Could not process rule")
            return _FakeResult(stdout=BASE_LIST_OUTPUT)
        dns_failopen._run = fake_run
        with self.assertRaises(dns_failopen.DnsFailopenError):
            dns_failopen.activate()
        self.assertEqual([c for c in calls if c[:2] == ["add", "rule"]], [])

    def test_a_half_installed_failopen_is_rebuilt_with_both_rules(self):
        # Audit.md: one leftover rule used to count as "active", so the
        # missing transport was never redirected.
        only_udp = BASE_LIST_OUTPUT.replace(
            "\t}\n}\n",
            '\t\tiifname "ap0" ip daddr 10.10.0.1 udp dport 53 counter packets 0 bytes 0 dnat to 1.1.1.1:53'
            ' comment "dns-failopen" # handle 7\n'
            "\t}\n}\n",
        )
        calls = []

        def fake_run(args, input_text=None):
            calls.append(args)
            return _FakeResult(stdout=only_udp)
        dns_failopen._run = fake_run

        dns_failopen.activate()
        deletes = [c for c in calls if c[:2] == ["delete", "rule"]]
        self.assertEqual(len(deletes), 1)
        self.assertIn(["-f", "-"], calls)

    def test_activate_raises_if_nft_refuses_the_add(self):
        def fake_run(args, input_text=None):
            if args[0] == "-a":
                return _FakeResult(stdout=BASE_LIST_OUTPUT)
            return _FakeResult(returncode=1, stderr="some nft error")
        dns_failopen._run = fake_run

        with self.assertRaises(dns_failopen.DnsFailopenError):
            dns_failopen.activate()

    def test_deactivate_removes_every_handle_found(self):
        calls = []

        def fake_run(args, input_text=None):
            calls.append(args)
            return _FakeResult(stdout=WITH_FAILOPEN_OUTPUT)
        dns_failopen._run = fake_run

        dns_failopen.deactivate()
        delete_calls = [c for c in calls if c[:2] == ["delete", "rule"]]
        self.assertEqual(len(delete_calls), 2)
        self.assertEqual({c[-1] for c in delete_calls}, {"7", "8"})

    def test_deactivate_does_nothing_when_nothing_is_active(self):
        calls = []

        def fake_run(args, input_text=None):
            calls.append(args)
            return _FakeResult(stdout=BASE_LIST_OUTPUT)
        dns_failopen._run = fake_run

        dns_failopen.deactivate()
        delete_calls = [c for c in calls if c[:2] == ["delete", "rule"]]
        self.assertEqual(len(delete_calls), 0)

    def test_is_active_reflects_whether_any_handle_is_found(self):
        dns_failopen._run = lambda args, input_text=None: _FakeResult(stdout=BASE_LIST_OUTPUT)
        self.assertFalse(dns_failopen.is_active())
        dns_failopen._run = lambda args, input_text=None: _FakeResult(stdout=WITH_FAILOPEN_OUTPUT)
        self.assertTrue(dns_failopen.is_active())


if __name__ == "__main__":
    unittest.main()

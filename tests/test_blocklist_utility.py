#!/usr/bin/env python3
"""
SecurePi Gateway - tests for tools/blocklist_utility.py's rule matching
and unique/overlap arithmetic (ENHANCEMENT-PLAN.md step 7.5).

The script's live run also checks itself against the DNS filter's real
decisions; these tests pin down the rule shapes it claims to understand,
so a change to the parser can't quietly change what "unique" means.

Run via `make test`, or directly: python3 -m unittest tests.test_blocklist_utility -v
"""

import importlib.util
import os
import unittest

_spec = importlib.util.spec_from_file_location(
    "blocklist_utility",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "blocklist_utility.py"))
blu = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(blu)


class ParseAndMatchTests(unittest.TestCase):
    def test_adblock_rule_covers_subdomains(self):
        r = blu.parse_list("||ads.example.com^\n")
        self.assertTrue(blu.blocks(r, "ads.example.com"))
        self.assertTrue(blu.blocks(r, "eu.ads.example.com"))
        self.assertFalse(blu.blocks(r, "example.com"))
        self.assertFalse(blu.blocks(r, "notads.example.com"))

    def test_hosts_line_is_exact_only(self):
        r = blu.parse_list("0.0.0.0 tracker.example.net\n127.0.0.1 localhost\n")
        self.assertTrue(blu.blocks(r, "tracker.example.net"))
        self.assertFalse(blu.blocks(r, "a.tracker.example.net"))
        self.assertFalse(blu.blocks(r, "localhost"))

    def test_exception_rule_wins_inside_the_same_list(self):
        r = blu.parse_list("||example.org^\n@@||good.example.org^\n")
        self.assertTrue(blu.blocks(r, "bad.example.org"))
        self.assertFalse(blu.blocks(r, "good.example.org"))
        self.assertFalse(blu.blocks(r, "x.good.example.org"))

    def test_plain_domain_reading_is_selectable(self):
        text = "plain.example.com\n"
        self.assertTrue(blu.blocks(blu.parse_list(text, True), "sub.plain.example.com"))
        self.assertFalse(blu.blocks(blu.parse_list(text, False), "sub.plain.example.com"))

    def test_unsupported_rules_are_counted_not_guessed(self):
        r = blu.parse_list("! comment\n/ads[0-9]+\\./\n||x.example.com^$client=10.10.0.5\n"
                           "||y.example.com^$important\n")
        self.assertEqual(r.skipped, 2)          # the regex and the $client rule
        self.assertEqual(r.parsed, 1)
        self.assertTrue(blu.blocks(r, "y.example.com"))
        self.assertFalse(blu.blocks(r, "x.example.com"))


class GatewayFetchTests(unittest.TestCase):
    """Audit10Oct M17: the list URL went into the remote shell command
    unquoted, and a failed fetch was saved as an empty list."""

    def setUp(self):
        self.orig = blu.subprocess.run
        self.calls = []

    def tearDown(self):
        blu.subprocess.run = self.orig

    def fake(self, returncode=0, stdout=b"||a.example^\n"):
        def run(cmd, **kw):
            self.calls.append(cmd)
            return type("R", (), {"returncode": returncode, "stdout": stdout, "stderr": b"boom"})()
        blu.subprocess.run = run

    def test_the_url_is_quoted_for_the_remote_shell(self):
        self.fake()
        blu.fetch_from_gateway("http://127.0.0.1:8090/list.txt; touch /tmp/x")
        remote = self.calls[0][-1]
        self.assertEqual(remote, "curl -sf 'http://127.0.0.1:8090/list.txt; touch /tmp/x'")

    def test_a_failed_fetch_stops_instead_of_saving_an_empty_list(self):
        self.fake(returncode=7, stdout=b"")
        with self.assertRaises(SystemExit):
            blu.fetch_from_gateway("http://127.0.0.1:8090/list.txt")


class AnalyseTests(unittest.TestCase):
    def test_unique_and_overlap(self):
        lists = [{"id": 1, "name": "A", "rules_count": 2}, {"id": 2, "name": "B", "rules_count": 1}]
        parsed = {1: blu.parse_list("||shared.com^\n||only-a.com^\n"),
                  2: blu.parse_list("||shared.com^\n")}
        domains = {
            "shared.com": {"allowed": 0, "blocked": 10, "blocked_by": {1: 10}},
            "only-a.com": {"allowed": 0, "blocked": 5, "blocked_by": {1: 5}},
            "clean.org": {"allowed": 20, "blocked": 0, "blocked_by": {}},
        }
        res = blu.analyse(lists, parsed, domains)
        a, b = res["per_list"]
        self.assertEqual((a["unique_domains"], a["unique_queries"]), (1, 5))
        self.assertEqual((b["unique_domains"], b["unique_queries"]), (0, 0))
        self.assertAlmostEqual(a["marginal_utility_pct"], 100.0 * 5 / 15, places=2)
        # Everything B blocks, A blocks too; half of A's domains are in B.
        self.assertEqual(res["overlap_pct_row_also_blocked_by_column"]["2"]["1"], 100.0)
        self.assertEqual(res["overlap_pct_row_also_blocked_by_column"]["1"]["2"], 50.0)

        agree = blu.agreement(lists, parsed, domains)
        self.assertEqual(agree["blocked_credited_agree_pct"], 100.0)
        self.assertEqual(agree["allowed_agree_pct"], 100.0)


if __name__ == "__main__":
    unittest.main()

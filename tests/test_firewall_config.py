#!/usr/bin/env python3
"""
SecurePi Gateway - firewall config tests (CODEBASE_AUDIT.md H2).

Not a functional test of nftables - `nft` only runs on Linux, and the
ruleset is checked live on the gateway with `nft -c -f` and a WAN-side
port scan (EVALUATION-RESULTS-2.md, "Audit H2"). These are structural
regression guards, the same shape as test_console_tls_config.py: they read
gateway/nftables.conf as text and fail `make test` if a future edit puts
the gateway's own input chain back to accepting everything, or opens a
service to the uplink.

Run via `make test`, or directly: python3 -m unittest tests.test_firewall_config -v
"""

import os
import re
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NFT_PATH = os.path.join(REPO_ROOT, "gateway", "nftables.conf")


def chain_body(text, name):
    """The rule lines of one chain in the inet filter table, without
    comments or blank lines."""
    start = re.search(r"chain %s \{" % name, text)
    if start is None:
        return []
    lines = []
    depth = 1
    for line in text[start.end():].splitlines():
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            break
        rule = line.split("#", 1)[0].strip()
        if rule:
            lines.append(rule)
    return lines


class InputChainTests(unittest.TestCase):
    def setUp(self):
        with open(NFT_PATH) as fh:
            self.text = fh.read()
        self.rules = chain_body(self.text, "input")

    def test_input_policy_is_drop(self):
        self.assertIn("type filter hook input priority 0; policy drop;", self.rules)

    def test_replies_and_loopback_are_allowed(self):
        self.assertIn("ct state established,related accept", self.rules)
        self.assertIn('iif "lo" accept', self.rules)

    def test_ssh_is_only_open_on_the_management_cable(self):
        ssh = [r for r in self.rules if "dport 22" in r]
        self.assertEqual(len(ssh), 1)
        self.assertIn('iifname "enp1s0"', ssh[0])

    def test_nothing_new_is_accepted_from_the_uplink_except_its_own_dhcp(self):
        wan = [r for r in self.rules if '"wlp2s0"' in r and "accept" in r]
        for rule in wan:
            self.assertRegex(rule, r"dport (68|546) ", rule)

    def test_every_service_rule_names_an_interface(self):
        # An accept on a port with no iifname would open it on the uplink too.
        for rule in self.rules:
            if "dport" in rule and "accept" in rule:
                self.assertIn("iifname", rule, rule)

    def test_the_proxy_port_only_accepts_redirected_connections(self):
        proxy = [r for r in self.rules if "dport 8080" in r and "accept" in r]
        self.assertEqual(len(proxy), 1)
        self.assertIn("ct status dnat", proxy[0])

    def test_proxied_traffic_checks_come_before_the_replies_accept(self):
        # They must also cut connections that are already open.
        accept_at = self.rules.index("ct state established,related accept")
        for comment in ("quarantined-proxied", "quarantined-mac-proxied", "blocked-ip-proxied",
                        "doh-bypass-proxied"):
            at = [i for i, r in enumerate(self.rules) if comment in r]
            self.assertEqual(len(at), 1, comment)
            self.assertLess(at[0], accept_at, comment)


if __name__ == "__main__":
    unittest.main()

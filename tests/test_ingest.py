#!/usr/bin/env python3
"""
SecurePi Gateway - ingest parsing tests (ENHANCEMENT-PLAN.md step 1.1).

Tests app/ingest.py's flattening functions against the synthetic eve.json/
AdGuard querylog fixtures in tests/fixtures.py - the "generator script
creates synthetic eve/querylog fixtures" half of step 1.1's own row. These
exercise the PARSING layer specifically (raw JSON-shaped dict in, a flat
events-table row out), which is a different failure mode than
test_correlation.py's DB-level signal tests: a malformed or renamed
upstream field (Suricata or AdGuard changing their JSON shape) would break
here without ever reaching a signal.

Run via `make test`, or directly: python3 -m unittest tests.test_ingest -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

import ingest  # noqa: E402


class FlattenSuricataTests(unittest.TestCase):
    def test_flow_event(self):
        row = ingest.flatten_suricata(fixtures.make_eve_flow(
            dest_ip="93.184.216.34", dest_port=443,
            bytes_toclient=5000, bytes_toserver=800))
        self.assertEqual(row["event_type"], "flow")
        self.assertEqual(row["source"], "suricata")
        self.assertEqual(row["dest_ip"], "93.184.216.34")
        self.assertEqual(row["dest_port"], 443)
        self.assertEqual(row["bytes_toclient"], 5000)
        self.assertEqual(row["bytes_toserver"], 800)
        self.assertIsInstance(row["ts"], float)

    def test_dns_event(self):
        row = ingest.flatten_suricata(fixtures.make_eve_dns_query(rrname="example.com"))
        self.assertEqual(row["event_type"], "dns")
        self.assertEqual(row["dns_rrname"], "example.com")
        self.assertEqual(row["dns_rrtype"], "A")

    def test_alert_event(self):
        row = ingest.flatten_suricata(fixtures.make_eve_alert(
            signature="ET TEST signature", severity=1))
        self.assertEqual(row["event_type"], "alert")
        self.assertEqual(row["alert_signature"], "ET TEST signature")
        self.assertEqual(row["alert_severity"], 1)

    def test_event_with_no_type_specific_block_has_no_type_specific_fields(self):
        # A bare flow record has no "dns"/"tls"/"alert" key at all - flatten
        # must not crash on the missing keys, and must not invent fields
        # for detail that was never present.
        row = ingest.flatten_suricata(fixtures.make_eve_flow())
        self.assertNotIn("dns_rrname", row)
        self.assertNotIn("alert_signature", row)

    def test_dhcp_params_absent_is_a_silent_no_op(self):
        # No "dhcp" key at all in a flow/dns/alert event - must not crash,
        # and dhcp_params must simply be absent from the row.
        row = ingest.flatten_suricata(fixtures.make_eve_flow())
        self.assertNotIn("dhcp_params", row)


class FlattenAghTests(unittest.TestCase):
    def test_blocked_query(self):
        row = ingest.flatten_agh(fixtures.make_agh_entry(
            client_ip="10.10.0.50", domain="ads.example.com", blocked=True))
        self.assertEqual(row["event_type"], "dns_query")
        self.assertEqual(row["source"], "adguard")
        self.assertEqual(row["src_ip"], "10.10.0.50")
        self.assertEqual(row["dns_rrname"], "ads.example.com")
        self.assertEqual(row["blocked"], 1)
        self.assertEqual(row["dns_filter_list_id"], 1)
        self.assertTrue(row["block_reason"])

    def test_allowed_query_has_no_block_reason(self):
        row = ingest.flatten_agh(fixtures.make_agh_entry(
            domain="wikipedia.org", blocked=False))
        self.assertEqual(row["blocked"], 0)
        self.assertNotIn("block_reason", row)
        self.assertNotIn("dns_filter_list_id", row)

    def test_cache_and_latency_fields(self):
        row = ingest.flatten_agh(fixtures.make_agh_entry(
            domain="example.com", blocked=False, cached=True,
            upstream="tls://1.1.1.1", elapsed_ns=12_000_000))
        self.assertEqual(row["dns_cached"], 1)
        self.assertEqual(row["dns_upstream"], "tls://1.1.1.1")
        self.assertEqual(row["dns_elapsed_ms"], 12.0)

    def test_uncached_answer_still_records_upstream(self):
        row = ingest.flatten_agh(fixtures.make_agh_entry(
            domain="example.com", blocked=False, cached=False, upstream="tls://9.9.9.9"))
        self.assertEqual(row["dns_cached"], 0)
        self.assertEqual(row["dns_upstream"], "tls://9.9.9.9")


if __name__ == "__main__":
    unittest.main()

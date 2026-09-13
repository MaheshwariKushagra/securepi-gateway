#!/usr/bin/env python3
"""
SecurePi Gateway - ingest parsing tests (ENHANCEMENT-PLAN.md steps 1.1
and 1.4).

Tests app/ingest.py's flattening functions against the synthetic eve.json/
AdGuard querylog fixtures in tests/fixtures.py - the "generator script
creates synthetic eve/querylog fixtures" half of step 1.1's own row. These
exercise the PARSING layer specifically (raw JSON-shaped dict in, a flat
events-table row out), which is a different failure mode than
test_correlation.py's DB-level signal tests: a malformed or renamed
upstream field (Suricata or AdGuard changing their JSON shape) would break
here without ever reaching a signal.

ParseRfc3339Tests (added for step 1.4) are regression tests for a real
timestamp bug found while implementing that step - see
parse_rfc3339's own docstring in app/ingest.py.

Run via `make test`, or directly: python3 -m unittest tests.test_ingest -v
"""

import os
import sys
import time
import unittest
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

import adguard  # noqa: E402
import ingest  # noqa: E402


class ParseRfc3339Tests(unittest.TestCase):
    """Regression tests for the real timestamp bug found and fixed in step
    1.4 - see parse_rfc3339's own docstring. Every case below is a real
    timestamp string observed live, either on the gateway's actual
    eve.json/querylog.json files or from AdGuard's real /control/querylog
    API response, not invented."""

    def test_z_suffixed_nanosecond_precision(self):
        # Real AdGuard API entry.
        epoch = ingest.parse_rfc3339("2026-09-12T23:50:11.853451407Z")
        self.assertAlmostEqual(epoch, 1789257011.853451, places=3)

    def test_colon_offset_nanosecond_precision(self):
        # Real AdGuard querylog.json file line AND API entry - the exact
        # case that used to be silently wrong by 5.5 hours.
        epoch = ingest.parse_rfc3339("2026-09-13T14:28:29.571373047+05:30")
        self.assertAlmostEqual(epoch, 1789289909.571373, places=3)

    def test_no_colon_offset_microsecond_precision(self):
        # Real Suricata eve.json line - the format the old to_epoch
        # docstring incorrectly claimed was always '+0000'.
        epoch = ingest.parse_rfc3339("2026-09-14T03:53:12.151693+0530")
        self.assertAlmostEqual(epoch, 1789338192.151693, places=3)

    def test_no_colon_utc_offset(self):
        epoch = ingest.parse_rfc3339("2026-09-12T09:27:53.123456+0000")
        z_equivalent = ingest.parse_rfc3339("2026-09-12T09:27:53.123456Z")
        self.assertAlmostEqual(epoch, z_equivalent, places=3)

    def test_a_negative_offset_is_handled_and_not_mistaken_for_a_date_hyphen(self):
        # Regression guard for the "search from the end" logic: a naive
        # search for the first '+' or '-' would match the date's own
        # hyphens ("2026-09-12...") instead of a real negative offset.
        epoch = ingest.parse_rfc3339("2026-09-12T09:27:53.123456-0500")
        utc_epoch = ingest.parse_rfc3339("2026-09-12T09:27:53.123456Z")
        self.assertAlmostEqual(epoch - utc_epoch, 5 * 3600, places=0)

    def test_malformed_timestamp_falls_back_to_now_rather_than_crashing(self):
        before = time.time()
        epoch = ingest.parse_rfc3339("not a real timestamp")
        after = time.time()
        self.assertTrue(before <= epoch <= after)

    def test_to_epoch_and_to_epoch_agh_both_delegate_to_the_same_parser(self):
        """Also the direct regression guard for the old to_epoch_agh bug:
        confirmed by temporarily reverting to_epoch_agh to its exact old
        body (hardcoded '+00:00', ignoring the real offset) and watching
        this test fail with the real 5.5-hour/19800-second gap, before
        reverting back to a byte-identical file."""
        ts = "2026-09-13T14:28:29.571373047+05:30"
        self.assertEqual(ingest.to_epoch(ts), ingest.parse_rfc3339(ts))
        self.assertEqual(ingest.to_epoch_agh(ts), ingest.parse_rfc3339(ts))


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


class FlattenAghApiTests(unittest.TestCase):
    """Tests app/ingest.py's flatten_agh_api against the REAL
    /control/querylog API shape (confirmed live - see fixtures.py's
    make_agh_api_entry docstring), a genuinely different shape from the
    on-disk file (FlattenAghTests above)."""

    def test_blocked_query(self):
        row = ingest.flatten_agh_api(fixtures.make_agh_api_entry(
            client_ip="10.10.0.50", domain="doubleclick.net", blocked=True))
        self.assertEqual(row["event_type"], "dns_query")
        self.assertEqual(row["source"], "adguard")
        self.assertEqual(row["src_ip"], "10.10.0.50")
        self.assertEqual(row["dns_rrname"], "doubleclick.net")
        self.assertEqual(row["blocked"], 1)
        self.assertEqual(row["dns_filter_list_id"], 1)
        self.assertTrue(row["block_reason"])

    def test_allowed_query_reason_not_filtered_prefix(self):
        row = ingest.flatten_agh_api(fixtures.make_agh_api_entry(
            domain="graph.facebook.com", blocked=False, reason="NotFilteredNotFound"))
        self.assertEqual(row["blocked"], 0)
        self.assertNotIn("block_reason", row)
        self.assertNotIn("dns_filter_list_id", row)

    def test_elapsed_ms_is_a_string_not_nanoseconds(self):
        # The API's elapsedMs is already milliseconds, as a string
        # ("7.459497") - a real, confirmed difference from the file
        # format's Elapsed (nanoseconds, as an int).
        row = ingest.flatten_agh_api(fixtures.make_agh_api_entry(elapsed_ms="12.5"))
        self.assertEqual(row["dns_elapsed_ms"], 12.5)

    def test_cached_and_upstream_fields(self):
        row = ingest.flatten_agh_api(fixtures.make_agh_api_entry(
            cached=True, upstream="tls://1.1.1.1", blocked=False, reason="NotFilteredNotFound"))
        self.assertEqual(row["dns_cached"], 1)
        self.assertEqual(row["dns_upstream"], "tls://1.1.1.1")

    def test_uses_the_real_confirmed_timestamp_field(self):
        row = ingest.flatten_agh_api(fixtures.make_agh_api_entry(
            timestamp="2026-09-13T14:28:29.571373047+05:30"))
        self.assertAlmostEqual(row["ts"], 1789289909.571373, places=3)


class AghWatermarkTests(unittest.TestCase):
    def test_first_call_seeds_a_recent_watermark_not_epoch_zero(self):
        conn = fixtures.temp_db()
        now = time.time()
        watermark = ingest.get_agh_watermark(conn)
        self.assertGreater(watermark, now - 400)
        self.assertLessEqual(watermark, now)

    def test_set_then_get_round_trips(self):
        conn = fixtures.temp_db()
        ingest.get_agh_watermark(conn)  # seed the row
        ingest.set_agh_watermark(conn, 1234567890.5)
        self.assertEqual(ingest.get_agh_watermark(conn), 1234567890.5)


class ReadAghApiTests(unittest.TestCase):
    def test_only_ingests_entries_newer_than_the_watermark(self):
        conn = fixtures.temp_db()
        ingest.get_agh_watermark(conn)  # seed the row
        ingest.set_agh_watermark(conn, ingest.parse_rfc3339("2026-06-01T00:00:00Z"))

        old_entry = fixtures.make_agh_api_entry(domain="old.example.com",
                                                  timestamp="2026-01-01T00:00:00Z")  # before the watermark
        new_entry = fixtures.make_agh_api_entry(domain="new.example.com",
                                                  timestamp="2026-09-14T10:00:00Z")  # after the watermark

        with mock.patch("adguard._request", return_value={"data": [new_entry, old_entry]}):
            ingest.read_agh_api(conn)

        names = {r["dns_rrname"] for r in conn.execute("SELECT dns_rrname FROM events")}
        self.assertIn("new.example.com", names)
        self.assertNotIn("old.example.com", names)

    def test_advances_the_watermark_to_the_newest_ingested_entry(self):
        conn = fixtures.temp_db()
        ingest.get_agh_watermark(conn)
        ingest.set_agh_watermark(conn, 0)
        entry = fixtures.make_agh_api_entry(domain="a.example.com",
                                             timestamp="2026-09-14T10:00:00Z")
        with mock.patch("adguard._request", return_value={"data": [entry]}):
            ingest.read_agh_api(conn)
        new_watermark = ingest.get_agh_watermark(conn)
        self.assertAlmostEqual(new_watermark, ingest.parse_rfc3339("2026-09-14T10:00:00Z"), places=0)

    def test_duplicate_entries_within_one_page_are_not_double_inserted(self):
        conn = fixtures.temp_db()
        ingest.get_agh_watermark(conn)
        ingest.set_agh_watermark(conn, 0)
        entry = fixtures.make_agh_api_entry(domain="dup.example.com",
                                             timestamp="2026-09-14T10:00:00Z")
        with mock.patch("adguard._request", return_value={"data": [entry, dict(entry)]}):
            ingest.read_agh_api(conn)
        n = conn.execute("SELECT count(*) FROM events WHERE dns_rrname='dup.example.com'").fetchone()[0]
        self.assertEqual(n, 1)

    def test_read_agh_falls_back_to_the_file_reader_when_api_unreachable(self):
        conn = fixtures.temp_db()
        with mock.patch("ingest.read_agh_api", side_effect=adguard.AdGuardError("boom")), \
             mock.patch("ingest.read_agh_querylog", return_value=(0, 0, 0)) as m:
            result = ingest.read_agh(conn)
        m.assert_called_once()
        self.assertEqual(result, (0, 0, 0))


if __name__ == "__main__":
    unittest.main()

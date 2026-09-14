#!/usr/bin/env python3
"""
SecurePi Gateway - threat intel feed tests (ENHANCEMENT-PLAN.md step 2.4).

Parser tests use real-shaped sample text captured from each feed's actual
live output (14 September 2026) - the same "confirmed against a live
download, not guessed from documentation" discipline this project applies
elsewhere (see app/adguard.py's add_nxdomain_rule, gateway/refresh-doh-set.sh).
refresh_all()'s own tests mock urllib so no test hits the real network.

Run via `make test`, or directly: python3 -m unittest tests.test_intel -v
"""

import os
import sys
import time
import unittest
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

import intel  # noqa: E402

FEODO_SAMPLE = """\
################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (IPs only)     #
# Last updated: 2026-03-04 14:28:39 UTC                        #
################################################################
#
# DstIP
162.243.103.246
178.62.3.223
# END 2 entries
"""

URLHAUS_SAMPLE = """\
################################################################
# abuse.ch URLhaus Host file                                   #
# Last updated: 2026-09-14 12:29:22 (UTC)                      #
################################################################
#
127.0.0.1\t0following.com
127.0.0.1\tabilityindisabilityindia.org
"""

THREATFOX_SAMPLE = ('################################################################\n'
                     '# ThreatFox IOCs: recent additions - CSV format                #\n'
                     '# Last updated: 2026-09-14 12:33:12 UTC                        #\n'
                     '################################################################\n'
                     '#\n'
                     '# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware",'
                     '"malware_alias","malware_printable","last_seen_utc","confidence_level",'
                     '"is_compromised","reference","tags","anonymous","reporter"\n'
                     '"2026-09-14 12:33:12", "1917764", "158.94.209.216", "ip:port", "botnet_cc", '
                     '"win.remcos", "None", "Remcos", "", "75", "False", "None", "None", "0", "Grim"\n'
                     '"2026-09-14 12:33:12", "1917765", "fl.qq1x.org", "domain", "botnet_cc", '
                     '"win.vidar", "None", "Vidar", "", "75", "False", "None", "None", "0", "Grim"\n'
                     '"2026-09-14 12:33:12", "1917766", "03b1a679e1e40da1f07d88f45d03e651", "md5_hash", '
                     '"payload", "win.gcleaner", "None", "GCleaner", "", "95", "False", "None", "None", '
                     '"0", "Grim"\n')


class FetchFeodoTests(unittest.TestCase):
    def test_parses_bare_ips_skipping_comments(self):
        with mock.patch("intel._fetch_text", return_value=FEODO_SAMPLE):
            result = intel.fetch_feodo()
        self.assertEqual(result, [
            ("162.243.103.246", "ip", "Feodo Tracker botnet C2"),
            ("178.62.3.223", "ip", "Feodo Tracker botnet C2"),
        ])


class FetchUrlhausTests(unittest.TestCase):
    def test_parses_hostfile_format_skipping_comments(self):
        with mock.patch("intel._fetch_text", return_value=URLHAUS_SAMPLE):
            result = intel.fetch_urlhaus()
        self.assertEqual(result, [
            ("0following.com", "domain", "URLhaus malware-hosting host"),
            ("abilityindisabilityindia.org", "domain", "URLhaus malware-hosting host"),
        ])


class FetchThreatfoxTests(unittest.TestCase):
    def test_parses_ip_port_and_domain_rows_only(self):
        with mock.patch("intel._fetch_text", return_value=THREATFOX_SAMPLE):
            result = intel.fetch_threatfox()
        # 3 data rows in the sample: ip:port, domain, md5_hash - only the
        # first two are network-matchable and should survive.
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], ("158.94.209.216", "ip", "ThreatFox: Remcos"))
        self.assertEqual(result[1], ("fl.qq1x.org", "domain", "ThreatFox: Vidar"))

    def test_ip_port_indicator_has_the_port_stripped(self):
        with mock.patch("intel._fetch_text", return_value=THREATFOX_SAMPLE):
            result = intel.fetch_threatfox()
        self.assertNotIn(":", result[0][0])


class RefreshAllTests(unittest.TestCase):
    def test_a_successful_fetch_populates_ioc_and_feed_state(self):
        conn = fixtures.temp_db()
        with mock.patch.dict(intel.FEEDS, {
            "feodo": lambda: [("203.0.113.1", "ip", "test")],
            "urlhaus": lambda: [("evil.example.com", "domain", "test")],
            "threatfox": lambda: [],
        }, clear=True), \
             mock.patch("intel._write_domain_blocklist_file"):
            # threatfox intentionally returns [] here to also exercise the
            # "empty feed treated as a bad fetch" path in the same run.
            results = intel.refresh_all(conn)
        self.assertEqual(results["feodo"], (True, 1))
        self.assertEqual(results["urlhaus"], (True, 1))
        self.assertFalse(results["threatfox"][0])

        rows = conn.execute("SELECT * FROM ioc").fetchall()
        self.assertEqual(len(rows), 2)
        state = {r["source"]: r for r in conn.execute("SELECT * FROM intel_feed_state")}
        self.assertIsNotNone(state["feodo"]["last_fetched"])
        self.assertIsNone(state["feodo"]["last_error"])
        self.assertIsNone(state["threatfox"]["last_fetched"])
        self.assertIsNotNone(state["threatfox"]["last_error"])

    def test_a_failed_fetch_leaves_existing_indicators_untouched(self):
        conn = fixtures.temp_db()
        fixtures.insert_ioc(conn, "203.0.113.1", "ip", source="feodo")
        with mock.patch.dict(intel.FEEDS, {"feodo": mock.Mock(side_effect=OSError("network down")),
                                           "urlhaus": lambda: [], "threatfox": lambda: []},
                              clear=True), \
             mock.patch("intel._write_domain_blocklist_file"):
            intel.refresh_all(conn)
        rows = conn.execute("SELECT * FROM ioc WHERE source='feodo'").fetchall()
        self.assertEqual(len(rows), 1, "a failed refresh must not delete yesterday's indicators")

    def test_re_fetching_the_same_indicator_extends_last_seen_not_duplicates(self):
        conn = fixtures.temp_db()
        with mock.patch.dict(intel.FEEDS, {"feodo": lambda: [("203.0.113.1", "ip", "test")],
                                           "urlhaus": lambda: [], "threatfox": lambda: []},
                              clear=True), \
             mock.patch("intel._write_domain_blocklist_file"):
            intel.refresh_all(conn)
            time.sleep(0.01)
            intel.refresh_all(conn)
        rows = conn.execute("SELECT * FROM ioc WHERE indicator='203.0.113.1'").fetchall()
        self.assertEqual(len(rows), 1, "the same indicator from the same source must not duplicate")


if __name__ == "__main__":
    unittest.main()

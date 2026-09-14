#!/usr/bin/env python3
"""
SecurePi Gateway - correlation signal tests (ENHANCEMENT-PLAN.md step 1.1).

Positive, negative and dedup tests for each of app/correlation.py's six
signals, plus regression tests for the two bugs finding G7 refers to that
were already found and fixed before this step existed (see
EVALUATION-RESULTS.md and correlation.py's own comments):

  - new_device_signal used to use a persisted watermark that advanced past
    a device before its grace period elapsed, silently breaking detection
    for every device. Fixed by recomputing a trailing window every cycle.
  - raise_incident used to increment evidence_count by len(event_ids) on
    every merge, so a signal re-confirming the same events across several
    engine cycles reported far more "evidence" than actually existed.
    Fixed by reading back the real distinct count after each insert.

Run via `make test`, or directly: python3 -m unittest tests.test_correlation -v

Note on malicious_domain_signal: its test below (test_malicious_domain_*)
deliberately documents CURRENT behaviour (thresholding on raw blocked-query
count), not the distinct-domain counting ENHANCEMENT-PLAN.md finding G3 asks
for - that's step 1.6's job, which will update these tests alongside the
fix. Writing a test for not-yet-fixed behaviour here would make `make test`
red, which is exactly what 1.1's own exit criterion says not to do.
"""

import os
import sys
import time
import unittest
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

import correlation  # noqa: E402
import settings  # noqa: E402


class PortScanNamingTests(unittest.TestCase):
    """Regression guard for finding G1: this signal detects many ports on
    ONE host, which is a VERTICAL scan by standard convention, not
    "horizontal" as an earlier comment mislabelled it. A HORIZONTAL scan
    (one port across many hosts) is a different, not-yet-built signal
    (ENHANCEMENT-PLAN.md step 2.1). No behavior changed for this finding -
    only the source's own naming - so this test reads correlation.py's
    source text directly rather than asserting on detection behavior."""

    def test_source_no_longer_calls_this_signal_horizontal(self):
        import os
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app", "correlation.py")
        with open(path) as fh:
            source = fh.read()
        self.assertNotIn("horizontal port scan", source.lower())
        self.assertIn("vertical port scan", source.lower())


class PortScanSignalTests(unittest.TestCase):
    def test_fires_on_enough_distinct_ports_to_one_host(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1, hostname="attacker")
        now = time.time()
        for port in range(1, 9):  # 8 distinct ports - meets the default threshold
            fixtures.insert_flow(conn, 1, "203.0.113.10", port, now - 10)
        fired = correlation.port_scan_signal(conn)
        self.assertEqual(fired, 1)
        row = conn.execute("SELECT * FROM incidents WHERE signal_type='port_scan'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["severity"], "high")
        self.assertIn("203.0.113.10", row["title"])

    def test_does_not_fire_below_threshold(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for port in range(1, 5):  # only 4 distinct ports
            fixtures.insert_flow(conn, 1, "203.0.113.10", port, now - 10)
        self.assertEqual(correlation.port_scan_signal(conn), 0)

    def test_does_not_fire_when_ports_spread_across_hosts(self):
        # 8 total port touches, but each to a DIFFERENT host - normal
        # browsing, not a scan against one host.
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(8):
            fixtures.insert_flow(conn, 1, "203.0.113.%d" % i, 443, now - 10)
        self.assertEqual(correlation.port_scan_signal(conn), 0)

    def test_repeated_firing_merges_into_one_incident(self):
        # A sustained scan re-detected across two engine cycles must extend
        # the same incident, not create a second one - this is the whole
        # point of raise_incident's dedup.
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for port in range(1, 9):
            fixtures.insert_flow(conn, 1, "203.0.113.10", port, now - 10)
        correlation.port_scan_signal(conn)
        for port in range(9, 11):  # scan continues, two more ports
            fixtures.insert_flow(conn, 1, "203.0.113.10", port, now - 5)
        correlation.port_scan_signal(conn)
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='port_scan'").fetchall()
        self.assertEqual(len(rows), 1, "a continuing scan must extend one incident, not create a second")
        self.assertEqual(rows[0]["evidence_count"], 10)


class NetworkSweepSignalTests(unittest.TestCase):
    """ENHANCEMENT-PLAN.md step 2.1: the horizontal mirror of port_scan -
    one port touched on many distinct HOSTS, not many ports on one host."""

    def test_fires_on_enough_distinct_hosts_on_one_port(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1, hostname="attacker")
        now = time.time()
        for i in range(8):  # 8 distinct hosts - meets the default threshold
            fixtures.insert_flow(conn, 1, "203.0.113.%d" % i, 443, now - 10)
        fired = correlation.network_sweep_signal(conn)
        self.assertEqual(fired, 1)
        row = conn.execute("SELECT * FROM incidents WHERE signal_type='network_sweep'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["severity"], "high")
        self.assertIn("443", row["title"])

    def test_does_not_fire_below_threshold(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(4):  # only 4 distinct hosts
            fixtures.insert_flow(conn, 1, "203.0.113.%d" % i, 443, now - 10)
        self.assertEqual(correlation.network_sweep_signal(conn), 0)

    def test_does_not_fire_when_ports_spread_across_one_host(self):
        # 8 total touches, but all to the SAME host on different ports -
        # that's port_scan's pattern (vertical), not network_sweep's
        # (horizontal), and must not double-fire this signal.
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for port in range(1, 9):
            fixtures.insert_flow(conn, 1, "203.0.113.10", port, now - 10)
        self.assertEqual(correlation.network_sweep_signal(conn), 0)

    def test_repeated_firing_merges_into_one_incident(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(8):
            fixtures.insert_flow(conn, 1, "203.0.113.%d" % i, 443, now - 10)
        correlation.network_sweep_signal(conn)
        for i in range(8, 10):  # sweep continues, two more hosts
            fixtures.insert_flow(conn, 1, "203.0.113.%d" % i, 443, now - 5)
        correlation.network_sweep_signal(conn)
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='network_sweep'").fetchall()
        self.assertEqual(len(rows), 1, "a continuing sweep must extend one incident, not create a second")
        self.assertEqual(rows[0]["evidence_count"], 10)


class SlowScanSignalTests(unittest.TestCase):
    """ENHANCEMENT-PLAN.md step 2.1's 'slow-scan variants': the same two
    shapes as port_scan/network_sweep, but over a much longer window - so
    a scan paced too slowly for the fast signals' short window (e.g. an
    nmap -T0/-T1 timing template) still gets caught eventually."""

    def test_fires_on_a_vertical_scan_spread_across_the_long_window(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        # 8 ports, each 800s apart - 5600s total span. Comfortably outside
        # the FAST port_scan_signal's default 300s window (no single 300s
        # slice ever contains more than one of these), but well inside the
        # slow-scan signal's default 7200s window.
        for port in range(1, 9):
            fixtures.insert_flow(conn, 1, "203.0.113.10", port, now - (8 - port) * 800)
        self.assertEqual(correlation.port_scan_signal(conn), 0,
                          "paced this slowly, the FAST signal must not fire")
        fired = correlation.slow_scan_signal(conn)
        self.assertEqual(fired, 1)
        row = conn.execute("SELECT * FROM incidents WHERE signal_type='slow_port_scan'").fetchone()
        self.assertIsNotNone(row)
        self.assertIn("203.0.113.10", row["title"])

    def test_fires_on_a_horizontal_sweep_spread_across_the_long_window(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(8):
            fixtures.insert_flow(conn, 1, "203.0.113.%d" % i, 443, now - (8 - i) * 800)
        self.assertEqual(correlation.network_sweep_signal(conn), 0,
                          "paced this slowly, the FAST signal must not fire")
        fired = correlation.slow_scan_signal(conn)
        self.assertEqual(fired, 1)
        row = conn.execute("SELECT * FROM incidents WHERE signal_type='slow_network_sweep'").fetchone()
        self.assertIsNotNone(row)

    def test_does_not_fire_below_threshold(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for port in range(1, 5):  # only 4 distinct ports, still spread out
            fixtures.insert_flow(conn, 1, "203.0.113.10", port, now - (4 - port) * 800)
        self.assertEqual(correlation.slow_scan_signal(conn), 0)

    def test_does_not_fire_on_activity_older_than_the_slow_window(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for port in range(1, 9):
            fixtures.insert_flow(conn, 1, "203.0.113.10", port, now - 100000)  # far outside 7200s
        self.assertEqual(correlation.slow_scan_signal(conn), 0)


class BruteForceSignalTests(unittest.TestCase):
    def test_fires_on_enough_attempts_to_an_auth_port(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(6):  # meets the default threshold
            fixtures.insert_flow(conn, 1, "203.0.113.20", 22, now - 5)
        fired = correlation.brute_force_signal(conn)
        self.assertEqual(fired, 1)
        row = conn.execute("SELECT * FROM incidents WHERE signal_type='brute_force'").fetchone()
        self.assertIn("SSH", row["title"])

    def test_does_not_fire_below_threshold(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(3):
            fixtures.insert_flow(conn, 1, "203.0.113.20", 22, now - 5)
        self.assertEqual(correlation.brute_force_signal(conn), 0)

    def test_does_not_fire_on_a_non_auth_port(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(10):
            fixtures.insert_flow(conn, 1, "203.0.113.20", 8080, now - 5)
        self.assertEqual(correlation.brute_force_signal(conn), 0)


class DnsBypassSignalTests(unittest.TestCase):
    """ENHANCEMENT-PLAN.md step 2.2: combines nftables reject-rule hits,
    canary-domain queries, and Suricata TLS SNI matches on known DoH
    providers into one per-device count."""

    def test_fires_on_enough_nftables_bypass_attempts_alone(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for _ in range(3):  # meets the default threshold of 3
            fixtures.insert_bypass_attempt(conn, 1, "dot-bypass", now - 10)
        fired = correlation.dns_bypass_signal(conn)
        self.assertEqual(fired, 1)
        row = conn.execute("SELECT * FROM incidents WHERE signal_type='dns_bypass'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["severity"], "medium")
        self.assertIn("dot-bypass", row["description"])

    def test_fires_on_enough_canary_domain_queries_alone(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for _ in range(3):
            fixtures.insert_dns_query(conn, 1, "use-application-dns.net", now - 10, blocked=1)
        self.assertEqual(correlation.dns_bypass_signal(conn), 1)

    def test_fires_on_enough_known_doh_sni_matches_alone(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for _ in range(3):
            fixtures.insert_tls(conn, 1, "dns.google", now - 10)
        self.assertEqual(correlation.dns_bypass_signal(conn), 1)

    def test_combines_different_kinds_of_evidence_toward_one_threshold(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        fixtures.insert_bypass_attempt(conn, 1, "quic-blocked", now - 10)
        fixtures.insert_dns_query(conn, 1, "mask.icloud.com", now - 8, blocked=1)
        fixtures.insert_tls(conn, 1, "cloudflare-dns.com", now - 6)
        fired = correlation.dns_bypass_signal(conn)
        self.assertEqual(fired, 1, "1+1+1 across three kinds of evidence should still meet threshold 3")
        row = conn.execute("SELECT * FROM incidents WHERE signal_type='dns_bypass'").fetchone()
        self.assertEqual(row["evidence_count"], 3)

    def test_does_not_fire_below_threshold(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        fixtures.insert_bypass_attempt(conn, 1, "dot-bypass", now - 10)
        fixtures.insert_dns_query(conn, 1, "mask.icloud.com", now - 8, blocked=1)
        self.assertEqual(correlation.dns_bypass_signal(conn), 0)

    def test_ordinary_dns_and_tls_traffic_does_not_count(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for _ in range(5):
            fixtures.insert_dns_query(conn, 1, "example.com", now - 10, blocked=0)
            fixtures.insert_tls(conn, 1, "example.com", now - 10)
        self.assertEqual(correlation.dns_bypass_signal(conn), 0)

    def test_repeated_firing_merges_into_one_incident(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for _ in range(3):
            fixtures.insert_bypass_attempt(conn, 1, "dot-bypass", now - 10)
        correlation.dns_bypass_signal(conn)
        for _ in range(2):  # bypass attempts continue
            fixtures.insert_bypass_attempt(conn, 1, "dot-bypass", now - 5)
        correlation.dns_bypass_signal(conn)
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='dns_bypass'").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["evidence_count"], 5)


class IdsAlertSignalTests(unittest.TestCase):
    """ENHANCEMENT-PLAN.md step 2.3: turns Suricata/ET alerts into
    incidents via signature_taxonomy.classify()."""

    def test_fires_on_enough_curated_category_alerts(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for _ in range(3):
            fixtures.insert_alert(conn, 1, "A Network Trojan was detected",
                                   now - 10, alert_signature="ET TROJAN Test", alert_severity=1)
        fired = correlation.ids_alert_signal(conn)
        self.assertEqual(fired, 1)
        row = conn.execute("SELECT * FROM incidents WHERE signal_type='ids_trojan'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["severity"], "high")
        self.assertIn("Network trojan", row["title"])
        self.assertIn("ET TROJAN Test", row["description"])

    def test_fires_on_an_uncurated_category_using_the_generic_fallback(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for _ in range(3):
            fixtures.insert_alert(conn, 1, "Misc activity", now - 10, alert_severity=3)
        fired = correlation.ids_alert_signal(conn)
        self.assertEqual(fired, 1)
        row = conn.execute("SELECT * FROM incidents WHERE signal_type='ids_other'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["severity"], "low", "priority 3 in classification.config maps to low")

    def test_does_not_fire_below_threshold(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        fixtures.insert_alert(conn, 1, "Misc activity", now - 10)
        self.assertEqual(correlation.ids_alert_signal(conn), 0)

    def test_different_categories_from_the_same_device_stay_separate_incidents(self):
        # A device with an ongoing burst of low-value "Misc activity"
        # alerts must not have a genuinely severe, unrelated trojan alert
        # quietly merged into that same incident thread.
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for _ in range(3):
            fixtures.insert_alert(conn, 1, "Misc activity", now - 10, alert_severity=3)
            fixtures.insert_alert(conn, 1, "A Network Trojan was detected", now - 10, alert_severity=1)
        correlation.ids_alert_signal(conn)
        rows = conn.execute("SELECT signal_type, severity FROM incidents WHERE device_id=1").fetchall()
        signal_types = {r["signal_type"] for r in rows}
        self.assertEqual(signal_types, {"ids_other", "ids_trojan"})
        severities = {r["signal_type"]: r["severity"] for r in rows}
        self.assertEqual(severities["ids_trojan"], "high")
        self.assertEqual(severities["ids_other"], "low")

    def test_repeated_firing_merges_into_one_incident(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for _ in range(3):
            fixtures.insert_alert(conn, 1, "A Network Trojan was detected", now - 10, alert_severity=1)
        correlation.ids_alert_signal(conn)
        for _ in range(2):
            fixtures.insert_alert(conn, 1, "A Network Trojan was detected", now - 5, alert_severity=1)
        correlation.ids_alert_signal(conn)
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='ids_trojan'").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["evidence_count"], 5)


class ThreatIntelSignalTests(unittest.TestCase):
    """ENHANCEMENT-PLAN.md step 2.4: matches events against the ioc table
    (app/intel.py's daily-refreshed abuse.ch feeds)."""

    def test_fires_on_a_single_malicious_ip_flow_match(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        fixtures.insert_ioc(conn, "203.0.113.99", "ip", source="feodo",
                             description="Feodo Tracker botnet C2")
        now = time.time()
        fixtures.insert_flow(conn, 1, "203.0.113.99", 443, now - 10)
        fired = correlation.threat_intel_signal(conn)
        self.assertEqual(fired, 1, "even ONE confirmed match should fire - default threshold is 1")
        row = conn.execute("SELECT * FROM incidents WHERE signal_type='threat_intel'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["severity"], "high")
        self.assertIn("203.0.113.99", row["title"])
        self.assertIn("feodo", row["description"])

    def test_fires_on_a_malicious_domain_dns_query_match(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        fixtures.insert_ioc(conn, "evil.example.com", "domain", source="urlhaus")
        now = time.time()
        fixtures.insert_dns_query(conn, 1, "evil.example.com", now - 10, blocked=1)
        self.assertEqual(correlation.threat_intel_signal(conn), 1)

    def test_fires_on_a_malicious_domain_tls_sni_match(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        fixtures.insert_ioc(conn, "evil.example.com", "domain", source="threatfox")
        now = time.time()
        fixtures.insert_tls(conn, 1, "evil.example.com", now - 10)
        self.assertEqual(correlation.threat_intel_signal(conn), 1)

    def test_does_not_fire_on_a_clean_destination(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        fixtures.insert_ioc(conn, "203.0.113.99", "ip")
        now = time.time()
        fixtures.insert_flow(conn, 1, "203.0.113.100", 443, now - 10)  # one digit off, not a match
        self.assertEqual(correlation.threat_intel_signal(conn), 0)

    def test_an_ip_indicator_does_not_match_a_domain_field_or_vice_versa(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        fixtures.insert_ioc(conn, "evil.example.com", "domain")
        now = time.time()
        # Same string coincidentally used as a dest_ip on a flow - must
        # not match, since this indicator is type 'domain'.
        fixtures.insert_flow(conn, 1, "evil.example.com", 443, now - 10)
        self.assertEqual(correlation.threat_intel_signal(conn), 0)

    def test_repeated_firing_merges_into_one_incident(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        fixtures.insert_ioc(conn, "203.0.113.99", "ip")
        now = time.time()
        fixtures.insert_flow(conn, 1, "203.0.113.99", 443, now - 10)
        correlation.threat_intel_signal(conn)
        fixtures.insert_flow(conn, 1, "203.0.113.99", 8080, now - 5)
        correlation.threat_intel_signal(conn)
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='threat_intel'").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["evidence_count"], 2)


class DnsTunnelingSignalTests(unittest.TestCase):
    """ENHANCEMENT-PLAN.md step 2.5. High-entropy subdomains generated
    with Python's own random module - deterministic given a fixed seed,
    so these tests don't flake on an unlucky low-entropy draw."""

    @staticmethod
    def _random_label(rng, length=20):
        import string
        alphabet = string.ascii_lowercase + string.digits
        return "".join(rng.choice(alphabet) for _ in range(length))

    def test_fires_on_many_high_entropy_distinct_subdomains(self):
        import random
        rng = random.Random(42)
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(25):  # exceeds the default 20-subdomain threshold
            label = self._random_label(rng)
            fixtures.insert_dns_query(conn, 1, "%s.tunnel.example.com" % label, now - i)
        fired = correlation.dns_tunneling_signal(conn)
        self.assertGreaterEqual(fired, 1)
        row = conn.execute("SELECT * FROM incidents WHERE signal_type='dns_tunneling'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["severity"], "high")
        self.assertIn("example.com", row["title"])

    def test_fires_on_a_high_txt_ratio_even_with_few_distinct_names(self):
        import random
        rng = random.Random(7)
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        # 20 distinct high-entropy subdomains, all TXT queries - crosses
        # both the distinct-count gate AND the TXT-ratio gate.
        for i in range(20):
            label = self._random_label(rng)
            conn.execute(
                "INSERT INTO events (ts, ts_iso, source, event_type, device_id, dns_rrname, dns_rrtype)"
                " VALUES (?, 'test', 'adguard', 'dns_query', 1, ?, 'TXT')",
                (now - i, "%s.tunnel.example.com" % label),
            )
        conn.commit()
        fired = correlation.dns_tunneling_signal(conn)
        self.assertGreaterEqual(fired, 1)

    def test_does_not_fire_on_ordinary_low_entropy_browsing(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        real_names = ["www", "mail", "api", "cdn", "static", "images", "shop", "blog",
                      "support", "docs", "assets", "media", "app", "login", "secure",
                      "m", "news", "help", "forum", "status", "beta", "dev"]
        for i, name in enumerate(real_names):
            fixtures.insert_dns_query(conn, 1, "%s.example.com" % name, now - i)
        self.assertEqual(correlation.dns_tunneling_signal(conn), 0)

    def test_does_not_fire_below_the_distinct_subdomain_floor(self):
        import random
        rng = random.Random(1)
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(5):  # well below the default threshold of 20
            label = self._random_label(rng)
            fixtures.insert_dns_query(conn, 1, "%s.tunnel.example.com" % label, now - i)
        self.assertEqual(correlation.dns_tunneling_signal(conn), 0)

    def test_fires_dga_on_a_genuine_nxdomain_burst_of_high_entropy_names(self):
        import random
        rng = random.Random(99)
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(12):  # exceeds the default 10-NXDOMAIN threshold
            label = self._random_label(rng)
            conn.execute(
                "INSERT INTO events (ts, ts_iso, source, event_type, device_id, dns_rrname,"
                " dns_rrtype, dns_rcode) VALUES (?, 'test', 'adguard', 'dns_query', 1, ?, 'A', 'NXDOMAIN')",
                (now - i, "%s.cnc.example.com" % label),
            )
        conn.commit()
        fired = correlation.dns_tunneling_signal(conn)
        self.assertGreaterEqual(fired, 1)
        row = conn.execute("SELECT * FROM incidents WHERE signal_type='dga'").fetchone()
        self.assertIsNotNone(row)

    def test_a_blocked_query_does_not_count_as_nxdomain_for_dga(self):
        # app/ingest.py's flatten_agh_api docstring: a query THIS gateway
        # blocked still reports dns_rcode NOERROR, not NXDOMAIN - only a
        # genuine upstream NXDOMAIN should count.
        import random
        rng = random.Random(5)
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(12):
            label = self._random_label(rng)
            fixtures.insert_dns_query(conn, 1, "%s.ads.example.com" % label, now - i, blocked=1)
        self.assertEqual(correlation.dns_tunneling_signal(conn), 0)

    def test_repeated_firing_merges_into_one_incident(self):
        import random
        rng = random.Random(3)
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(25):
            label = self._random_label(rng)
            fixtures.insert_dns_query(conn, 1, "%s.tunnel.example.com" % label, now - i)
        correlation.dns_tunneling_signal(conn)
        rows_before = conn.execute("SELECT * FROM incidents WHERE signal_type='dns_tunneling'").fetchall()
        for i in range(25, 28):
            label = self._random_label(rng)
            fixtures.insert_dns_query(conn, 1, "%s.tunnel.example.com" % label, now - i + 100)
        correlation.dns_tunneling_signal(conn)
        rows_after = conn.execute("SELECT * FROM incidents WHERE signal_type='dns_tunneling'").fetchall()
        self.assertEqual(len(rows_before), len(rows_after), "a continuing pattern must extend, not duplicate")


class ShannonEntropyTests(unittest.TestCase):
    def test_a_single_repeated_character_has_zero_entropy(self):
        self.assertEqual(correlation._shannon_entropy("aaaaaa"), 0.0)

    def test_an_empty_string_has_zero_entropy(self):
        self.assertEqual(correlation._shannon_entropy(""), 0.0)

    def test_more_varied_characters_have_higher_entropy(self):
        low = correlation._shannon_entropy("aaaaaabbbbbb")
        high = correlation._shannon_entropy("a1b2c3d4e5f6")
        self.assertGreater(high, low)


class BaseDomainTests(unittest.TestCase):
    def test_takes_the_last_two_labels(self):
        self.assertEqual(correlation._base_domain("random123.tunnel.example.com"), "example.com")
        self.assertEqual(correlation._base_domain("example.com"), "example.com")

    def test_subdomain_part_strips_the_base_domain(self):
        self.assertEqual(correlation._subdomain_part("abc.tunnel.example.com", "example.com"),
                          "abc.tunnel")
        self.assertEqual(correlation._subdomain_part("example.com", "example.com"), "")


class BeaconSignalTests(unittest.TestCase):
    """ENHANCEMENT-PLAN.md step 2.6. Matches the exit criterion's own
    wording: 'harness beacon (60s, 10% jitter) >= 0.8'."""

    @staticmethod
    def _insert_beacon(conn, device_id, dest_ip, dest_port, n, now,
                        rng, interval=60, jitter=0.10, size=500, size_jitter=5):
        ts = now - n * interval
        for _ in range(n):
            ts += interval * (1 + rng.uniform(-jitter, jitter))
            total = size + rng.randint(-size_jitter, size_jitter)
            fixtures.insert_flow(conn, device_id, dest_ip, dest_port, ts,
                                  bytes_toserver=total // 2, bytes_toclient=total - total // 2)

    def test_fires_on_a_60s_10pct_jitter_beacon_with_score_at_least_0_8(self):
        import random
        rng = random.Random(42)
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        self._insert_beacon(conn, 1, "203.0.113.50", 8443, 30, now, rng)
        fired = correlation.beacon_signal(conn)
        self.assertEqual(fired, 1)
        row = conn.execute("SELECT * FROM incidents WHERE signal_type='beacon'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["severity"], "high")
        score = float(row["description"].split("regularity score of ")[1].split(" ")[0])
        self.assertGreaterEqual(score, 0.8, "the exit criterion's own numeric target")

    def test_does_not_fire_on_irregular_human_like_traffic(self):
        import random
        rng = random.Random(7)
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        ts = now - 3000
        for _ in range(30):
            ts += rng.expovariate(1 / 120) + 1  # bursty, irregular gaps
            total = rng.randint(200, 50000)  # wildly varying page/asset sizes
            fixtures.insert_flow(conn, 1, "203.0.113.51", 443, ts,
                                  bytes_toserver=total // 2, bytes_toclient=total - total // 2)
        self.assertEqual(correlation.beacon_signal(conn), 0)

    def test_does_not_fire_below_the_minimum_connection_count(self):
        import random
        rng = random.Random(1)
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        self._insert_beacon(conn, 1, "203.0.113.52", 443, 4, now, rng)  # below default min of 8
        self.assertEqual(correlation.beacon_signal(conn), 0)

    def test_ntp_is_allowlisted_even_though_perfectly_regular(self):
        import random
        rng = random.Random(2)
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        self._insert_beacon(conn, 1, "203.0.113.53", 123, 30, now, rng, jitter=0.0, size_jitter=0)
        self.assertEqual(correlation.beacon_signal(conn), 0)

    def test_repeated_firing_merges_into_one_incident(self):
        import random
        rng = random.Random(9)
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        self._insert_beacon(conn, 1, "203.0.113.54", 8443, 30, now, rng)
        correlation.beacon_signal(conn)
        rows_before = conn.execute("SELECT * FROM incidents WHERE signal_type='beacon'").fetchall()
        self._insert_beacon(conn, 1, "203.0.113.54", 8443, 10, now + 200, rng)
        correlation.beacon_signal(conn)
        rows_after = conn.execute("SELECT * FROM incidents WHERE signal_type='beacon'").fetchall()
        self.assertEqual(len(rows_before), len(rows_after))


class CoefficientOfVariationTests(unittest.TestCase):
    def test_identical_values_have_zero_variation(self):
        self.assertEqual(correlation._coefficient_of_variation([60, 60, 60, 60]), 0.0)

    def test_fewer_than_two_values_is_zero_not_an_error(self):
        self.assertEqual(correlation._coefficient_of_variation([60]), 0.0)
        self.assertEqual(correlation._coefficient_of_variation([]), 0.0)

    def test_a_zero_mean_is_zero_not_a_division_error(self):
        self.assertEqual(correlation._coefficient_of_variation([0, 0, 0]), 0.0)

    def test_more_varied_values_have_higher_variation(self):
        low = correlation._coefficient_of_variation([60, 61, 59, 60])
        high = correlation._coefficient_of_variation([10, 200, 5, 300])
        self.assertGreater(high, low)


class MaliciousDomainSignalTests(unittest.TestCase):
    """Tests the FIXED behaviour: the threshold applies to distinct
    blocked domains, not raw blocked-lookup count (ENHANCEMENT-PLAN.md
    finding G3, fixed in step 1.6). See test_g3_regression_repeated_lookups_to_one_domain_do_not_fire
    below for the exact real-world false positive this fix addresses -
    EVALUATION-RESULTS.md documents it firing on normal Android ad-SDK
    traffic that retries the same domain rapidly."""

    def test_fires_on_enough_distinct_blocked_domains(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(15):  # 15 distinct domains, meets the default threshold
            fixtures.insert_dns_query(conn, 1, "ads%d.example.com" % i, now - 5, blocked=True)
        self.assertEqual(correlation.malicious_domain_signal(conn), 1)

    def test_does_not_fire_below_threshold(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(5):
            fixtures.insert_dns_query(conn, 1, "ads%d.example.com" % i, now - 5, blocked=True)
        self.assertEqual(correlation.malicious_domain_signal(conn), 0)

    def test_g3_regression_repeated_lookups_to_one_domain_do_not_fire(self):
        """The exact real false positive G3 describes: many blocked
        lookups (well above the threshold as a raw count), but all to
        the SAME one or two domains - normal ad-SDK retry behaviour, not
        a device probing many different disallowed destinations. Must
        NOT fire, even though the OLD (buggy) raw-count logic would have."""
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(40):  # 40 blocked lookups, but only 2 distinct domains
            domain = "ads.example.com" if i % 2 == 0 else "tracker.example.com"
            fixtures.insert_dns_query(conn, 1, domain, now - 5, blocked=True)
        self.assertEqual(correlation.malicious_domain_signal(conn), 0,
                          "high raw count against only 2 distinct domains must not fire")

    def test_allowed_queries_do_not_count(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(15):
            fixtures.insert_dns_query(conn, 1, "wikipedia%d.example.com" % i, now - 5, blocked=False)
        self.assertEqual(correlation.malicious_domain_signal(conn), 0)


class NewDeviceSignalTests(unittest.TestCase):
    def test_fires_once_grace_period_elapses(self):
        conn = fixtures.temp_db()
        now = time.time()
        fixtures.insert_device(conn, 1, hostname="new-phone", first_seen=now - 60, last_seen=now - 60)
        self.assertEqual(correlation.new_device_signal(conn), 1)

    def test_does_not_fire_within_grace_period(self):
        conn = fixtures.temp_db()
        now = time.time()
        fixtures.insert_device(conn, 1, hostname="brand-new", first_seen=now - 5, last_seen=now - 5)
        self.assertEqual(correlation.new_device_signal(conn), 0)

    def test_trailing_window_regression_not_a_persisted_watermark(self):
        """Regression test for the watermark bug described in the module
        docstring and EVALUATION-RESULTS.md: a device too new to qualify on
        one engine cycle must still qualify on a LATER cycle once its grace
        period has elapsed. A persisted-watermark implementation fails this
        (the watermark would have already advanced past the device's
        first_seen on the first cycle)."""
        conn = fixtures.temp_db()
        t0 = 1_800_000_000.0
        fixtures.insert_device(conn, 1, hostname="new-phone", first_seen=t0, last_seen=t0)

        with mock.patch("correlation.time.time", return_value=t0 + 10):
            self.assertEqual(correlation.new_device_signal(conn), 0, "still within the 30s grace period")

        with mock.patch("correlation.time.time", return_value=t0 + 45):
            self.assertEqual(correlation.new_device_signal(conn), 1,
                              "grace period has elapsed - must fire on this later cycle")

    def test_repeated_cycles_after_firing_do_not_duplicate(self):
        conn = fixtures.temp_db()
        now = time.time()
        fixtures.insert_device(conn, 1, first_seen=now - 60, last_seen=now - 60)
        correlation.new_device_signal(conn)
        correlation.new_device_signal(conn)  # a second cycle, device still in lookback window
        rows = conn.execute("SELECT * FROM incidents WHERE signal_type='new_device'").fetchall()
        self.assertEqual(len(rows), 1)


class AdblockEffectivenessSignalTests(unittest.TestCase):
    def test_fires_when_nothing_is_ever_stripped(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(5):  # meets EFFECTIVENESS_MIN_YOUTUBE_EVENTS
            fixtures.insert_dpi_event(conn, 1, "decrypt", now - 10)
        self.assertEqual(correlation.adblock_effectiveness_signal(conn), 1)

    def test_does_not_fire_when_ads_are_being_stripped(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(4):
            fixtures.insert_dpi_event(conn, 1, "decrypt", now - 10)
        fixtures.insert_dpi_event(conn, 1, "ads_stripped", now - 5, dpi_ads_removed=2)
        self.assertEqual(correlation.adblock_effectiveness_signal(conn), 0)

    def test_does_not_fire_on_too_little_activity(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for i in range(2):  # below EFFECTIVENESS_MIN_YOUTUBE_EVENTS
            fixtures.insert_dpi_event(conn, 1, "decrypt", now - 10)
        self.assertEqual(correlation.adblock_effectiveness_signal(conn), 0)


class BehavioralBaselineSignalTests(unittest.TestCase):
    def _seed_history(self, conn, device_id, hour_of_day, now, days, avg_bytes):
        """days rows of device_hourly for the SAME hour-of-day, on past
        days, close to avg_bytes with a small +/-10% jitter - a stable,
        learnable baseline with genuine (nonzero) variance. A perfectly
        flat history would give stdev == 0, which the signal deliberately
        skips ("nothing to compare a deviation against") - real device
        traffic always has some natural variance, so the fixture should too."""
        day_seconds = 86400
        for d in range(1, days + 1):
            hour_start = correlation._hour_start(now) - d * day_seconds
            jitter = 1.0 + (0.1 if d % 2 == 0 else -0.1)
            total = int(avg_bytes * jitter)
            fixtures.insert_device_hourly(conn, device_id, hour_start,
                                           bytes_down=int(total * 0.6), bytes_up=int(total * 0.4))

    def test_fires_on_a_genuine_volume_anomaly(self):
        conn = fixtures.temp_db()
        now = time.time()
        fixtures.insert_device(conn, 1, first_seen=now - 30 * 86400)
        hour_of_day = time.localtime(correlation._hour_start(now)).tm_hour
        self._seed_history(conn, 1, hour_of_day, now, days=10, avg_bytes=10 * 1024 * 1024)
        # Current hour: far above the ~10MB/hour baseline.
        current_hour_start = correlation._hour_start(now)
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, current_hour_start + 60,
                              bytes_toclient=200 * 1024 * 1024, bytes_toserver=1024)
        self.assertEqual(correlation.behavioral_baseline_signal(conn), 1)

    def test_does_not_fire_while_still_learning(self):
        conn = fixtures.temp_db()
        now = time.time()
        fixtures.insert_device(conn, 1, first_seen=now - 30 * 86400)
        hour_of_day = time.localtime(correlation._hour_start(now)).tm_hour
        self._seed_history(conn, 1, hour_of_day, now, days=3, avg_bytes=10 * 1024 * 1024)  # < BASELINE_MIN_SAMPLES
        current_hour_start = correlation._hour_start(now)
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, current_hour_start + 60,
                              bytes_toclient=200 * 1024 * 1024, bytes_toserver=1024)
        self.assertEqual(correlation.behavioral_baseline_signal(conn), 0)

    def test_does_not_fire_below_the_minimum_byte_floor(self):
        conn = fixtures.temp_db()
        now = time.time()
        fixtures.insert_device(conn, 1, first_seen=now - 30 * 86400)
        hour_of_day = time.localtime(correlation._hour_start(now)).tm_hour
        self._seed_history(conn, 1, hour_of_day, now, days=10, avg_bytes=1024)  # tiny baseline
        current_hour_start = correlation._hour_start(now)
        # A big jump relative to baseline, but still under BASELINE_MIN_BYTES_FLOOR overall.
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, current_hour_start + 60,
                              bytes_toclient=2000, bytes_toserver=0)
        self.assertEqual(correlation.behavioral_baseline_signal(conn), 0)

    def test_does_not_fire_on_normal_volume(self):
        conn = fixtures.temp_db()
        now = time.time()
        fixtures.insert_device(conn, 1, first_seen=now - 30 * 86400)
        hour_of_day = time.localtime(correlation._hour_start(now)).tm_hour
        self._seed_history(conn, 1, hour_of_day, now, days=10, avg_bytes=10 * 1024 * 1024)
        current_hour_start = correlation._hour_start(now)
        fixtures.insert_flow(conn, 1, "1.1.1.1", 443, current_hour_start + 60,
                              bytes_toclient=6 * 1024 * 1024, bytes_toserver=1024)
        self.assertEqual(correlation.behavioral_baseline_signal(conn), 0)


class RaiseIncidentDedupAndEvidenceTests(unittest.TestCase):
    def _insert_events(self, conn, device_id, n, ts):
        ids = []
        for i in range(n):
            fixtures.insert_flow(conn, device_id, "203.0.113.30", 443, ts)
            ids.append(conn.execute("SELECT max(id) FROM events").fetchone()[0])
        return ids

    def test_within_dedup_window_merges_into_one_incident(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        eids = self._insert_events(conn, 1, 3, now - 100)
        correlation.raise_incident(conn, 1, "port_scan", "high", "t1", "d1", now - 100, now - 100, eids)
        correlation.raise_incident(conn, 1, "port_scan", "high", "t2", "d2", now - 90, now - 90, eids)
        rows = conn.execute("SELECT * FROM incidents WHERE device_id=1").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["description"], "d2")  # the later call's description wins

    def test_g2_regression_merges_into_an_investigating_incident_too(self):
        """Regression test for finding G2: the old code only merged into
        an incident with status 'new', so an operator marking something
        "investigating" made the very next firing open a DUPLICATE
        incident instead of extending the one already being looked at."""
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        eids = self._insert_events(conn, 1, 3, now - 100)
        incident_id = correlation.raise_incident(
            conn, 1, "port_scan", "high", "t1", "d1", now - 100, now - 100, eids)
        conn.execute("UPDATE incidents SET status='investigating' WHERE id=?", (incident_id,))
        conn.commit()

        correlation.raise_incident(conn, 1, "port_scan", "high", "t2", "d2", now - 90, now - 90, eids)

        rows = conn.execute("SELECT * FROM incidents WHERE device_id=1").fetchall()
        self.assertEqual(len(rows), 1, "must extend the investigating incident, not open a duplicate")
        self.assertEqual(rows[0]["status"], "investigating", "merging must not silently revert the status")
        self.assertEqual(rows[0]["description"], "d2")

    def test_g2_does_not_merge_into_a_resolved_incident(self):
        """The other half of G2's fix: 'resolved' and 'false_positive'
        are a genuine operator verdict, so a fresh detection after one
        must start a NEW incident rather than silently reopening the old
        one by merging into it."""
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        eids = self._insert_events(conn, 1, 3, now - 100)
        incident_id = correlation.raise_incident(
            conn, 1, "port_scan", "high", "t1", "d1", now - 100, now - 100, eids)
        conn.execute("UPDATE incidents SET status='resolved' WHERE id=?", (incident_id,))
        conn.commit()

        correlation.raise_incident(conn, 1, "port_scan", "high", "t2", "d2", now - 90, now - 90, eids)

        rows = conn.execute("SELECT * FROM incidents WHERE device_id=1 ORDER BY id").fetchall()
        self.assertEqual(len(rows), 2, "a resolved incident must not be silently reopened by a merge")
        self.assertEqual(rows[0]["status"], "resolved")
        self.assertEqual(rows[1]["status"], "new")

    def test_outside_dedup_window_creates_a_separate_incident(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        eids1 = self._insert_events(conn, 1, 2, now - 10000)
        eids2 = self._insert_events(conn, 1, 2, now)
        correlation.raise_incident(conn, 1, "port_scan", "high", "t1", "d1",
                                    now - 10000, now - 10000, eids1)
        correlation.raise_incident(conn, 1, "port_scan", "high", "t2", "d2", now, now, eids2)
        rows = conn.execute("SELECT * FROM incidents WHERE device_id=1").fetchall()
        self.assertEqual(len(rows), 2)

    def test_evidence_count_regression_not_cumulative(self):
        """Regression test for the evidence-double-count bug described in
        the module docstring: re-detecting the SAME events across several
        engine cycles must not inflate evidence_count beyond the real
        number of distinct linked events."""
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        eids = self._insert_events(conn, 1, 8, now - 50)
        for cycle in range(7):  # the same 8 events "re-confirmed" 7 times
            correlation.raise_incident(conn, 1, "port_scan", "high", "t", "d",
                                        now - 50, now - 50 + cycle, eids)
        row = conn.execute("SELECT * FROM incidents WHERE device_id=1").fetchone()
        self.assertEqual(row["evidence_count"], 8, "must be the real distinct count, not 8 x 7 = 56")


class WindowSettingsTests(unittest.TestCase):
    """Step 1.2: window durations are console-tunable the same way step
    6.3's thresholds already are. These prove the wiring is real - a
    changed setting genuinely changes what a signal sees - not just that
    the schema entry exists (settings.py's own tests cover that)."""

    def test_all_window_settings_have_the_real_hardcoded_defaults(self):
        conn = fixtures.temp_db()
        self.assertEqual(settings.get(conn, "port_scan_window_seconds"), 300)
        self.assertEqual(settings.get(conn, "network_sweep_window_seconds"), 300)
        self.assertEqual(settings.get(conn, "slow_scan_window_seconds"), 7200)
        self.assertEqual(settings.get(conn, "dns_bypass_window_seconds"), 300)
        self.assertEqual(settings.get(conn, "dns_bypass_threshold"), 3)
        self.assertEqual(settings.get(conn, "ids_alert_window_seconds"), 300)
        self.assertEqual(settings.get(conn, "ids_alert_threshold"), 3)
        self.assertEqual(settings.get(conn, "threat_intel_window_seconds"), 3600)
        self.assertEqual(settings.get(conn, "threat_intel_threshold"), 1)
        self.assertEqual(settings.get(conn, "dns_tunneling_window_seconds"), 600)
        self.assertEqual(settings.get(conn, "dns_tunneling_min_distinct_subdomains"), 20)
        self.assertEqual(settings.get(conn, "dns_tunneling_min_entropy"), 3.5)
        self.assertEqual(settings.get(conn, "dns_tunneling_min_txt_ratio"), 0.3)
        self.assertEqual(settings.get(conn, "dga_min_nxdomain_count"), 10)
        self.assertEqual(settings.get(conn, "dga_min_entropy"), 3.3)
        self.assertEqual(settings.get(conn, "beacon_window_seconds"), 3600)
        self.assertEqual(settings.get(conn, "beacon_min_connections"), 8)
        self.assertEqual(settings.get(conn, "beacon_score_threshold"), 0.8)
        self.assertEqual(settings.get(conn, "brute_force_window_seconds"), 120)
        self.assertEqual(settings.get(conn, "malicious_domain_window_seconds"), 600)
        self.assertEqual(settings.get(conn, "new_device_lookback_seconds"), 3600)
        self.assertEqual(settings.get(conn, "dedup_window_seconds"), 600)

    def test_shrinking_the_port_scan_window_excludes_older_events(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        for port in range(1, 9):  # 8 ports, spread from 250s ago to ~10s ago
            fixtures.insert_flow(conn, 1, "203.0.113.10", port, now - 250 + port * 5)
        settings.set_value(conn, "port_scan_window_seconds", 60)
        self.assertEqual(correlation.port_scan_signal(conn), 0,
                          "a 60s window must not see ports touched 200+ seconds ago")

    def test_shortening_the_dedup_window_stops_merging_a_later_firing(self):
        conn = fixtures.temp_db()
        fixtures.insert_device(conn, 1)
        now = time.time()
        t0 = now - 10000
        eids = []
        for i in range(3):
            fixtures.insert_flow(conn, 1, "203.0.113.30", 443, t0)
            eids.append(conn.execute("SELECT max(id) FROM events").fetchone()[0])
        settings.set_value(conn, "dedup_window_seconds", 60)
        correlation.raise_incident(conn, 1, "port_scan", "high", "t1", "d1", t0, t0, eids)
        correlation.raise_incident(conn, 1, "port_scan", "high", "t2", "d2", t0 + 500, t0 + 500, eids)
        rows = conn.execute("SELECT * FROM incidents WHERE device_id=1").fetchall()
        self.assertEqual(len(rows), 2, "500s apart must not merge under a shortened 60s dedup window")


if __name__ == "__main__":
    unittest.main()

"""
Tests for tools/replay.py (ENHANCEMENT-PLAN.md step 7.1).

Suricata itself isn't needed: the tests write small eve.json files by hand
and drive the part of the replay that comes after Suricata - reshaping the
records, timing them, and running the real engine on the simulated clock.
"""

import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402,F401  (puts app/ on the path)

import correlation  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "replay", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "replay.py"))
replay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(replay)

T0 = 1790000000.0  # an arbitrary fixed start, so every run of a test is the same


def iso(epoch):
    return replay.time_iso(epoch)


def flow(src, dst, dport, start, end=None, state="new", proto="TCP", logged=None, flow_id=1, size=120):
    """An eve.json flow record. `logged` is Suricata's own (unreliable)
    logging time; the replay should ignore it."""
    end = start if end is None else end
    return {"timestamp": iso(logged if logged is not None else end + 999), "event_type": "flow",
            "flow_id": flow_id, "src_ip": src, "src_port": 40000, "dest_ip": dst, "dest_port": dport,
            "proto": proto,
            "flow": {"start": iso(start), "end": iso(end), "state": state, "bytes_toserver": size,
                     "bytes_toclient": 0, "pkts_toserver": 2, "pkts_toclient": 0}}


def dns_v3(src, name, ts, kind, rcode="NOERROR", flow_id=7):
    rec = {"timestamp": iso(ts), "event_type": "dns", "flow_id": flow_id, "src_ip": src, "src_port": 5353,
           "dest_ip": "10.10.0.1", "dest_port": 53, "proto": "UDP",
           "dns": {"version": 3, "type": kind, "queries": [{"rrname": name, "rrtype": "A"}]}}
    if kind == "response":
        rec["dns"]["rcode"] = rcode
    return rec


def write_eve(records):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    return path


class ReshapeTests(unittest.TestCase):
    def test_v3_dns_request_becomes_a_v2_query(self):
        e = replay.to_v2_dns(dns_v3("10.10.0.231", "example.com", T0, "request"))
        self.assertEqual(e["dns"], {"type": "query", "rrname": "example.com", "rrtype": "A", "rcode": None})

    def test_v3_dns_response_becomes_a_v2_answer_with_its_rcode(self):
        e = replay.to_v2_dns(dns_v3("10.10.0.231", "nope.example", T0, "response", rcode="NXDOMAIN"))
        self.assertEqual(e["dns"]["type"], "answer")
        self.assertEqual(e["dns"]["rcode"], "NXDOMAIN")

    def test_v2_record_passes_through_unchanged(self):
        rec = {"event_type": "dns", "dns": {"type": "query", "rrname": "a.example", "rrtype": "A"}}
        self.assertIs(replay.to_v2_dns(rec), rec)


class FlowTimingTests(unittest.TestCase):
    """The replay's flow timestamp is when the flow times out, not when
    Suricata's flow manager happened to log it in this particular run."""

    def test_tcp_flow_that_never_got_an_answer_times_out_after_60_s(self):
        self.assertEqual(replay.flow_logged_at({"end": iso(T0), "state": "new"}, "TCP", T0 + 9999), T0 + 60)

    def test_established_udp_flow_times_out_after_300_s(self):
        self.assertEqual(replay.flow_logged_at({"end": iso(T0), "state": "established"}, "UDP", T0 + 9999),
                         T0 + 300)

    def test_other_protocols_use_the_default_timeouts(self):
        self.assertEqual(replay.flow_logged_at({"end": iso(T0), "state": "new"}, "ICMP", T0 + 9999), T0 + 30)

    def test_flow_still_open_at_the_end_of_the_capture_is_logged_then(self):
        self.assertEqual(replay.flow_logged_at({"end": iso(T0), "state": "established"}, "TCP", T0 + 100),
                         T0 + 100)

    def test_time_iso_round_trips_through_ingest(self):
        import ingest
        for t in (T0, T0 + 0.5, T0 + 0.9999996):
            self.assertAlmostEqual(ingest.to_epoch(iso(t)), t, places=5)


class LoadEventsTests(unittest.TestCase):
    def test_flow_timestamp_is_the_modelled_timeout_and_flow_start_is_kept(self):
        path = write_eve([flow("10.10.0.231", "203.0.113.9", 4444, T0, logged=T0 + 7),
                          flow("10.10.0.231", "203.0.113.9", 4444, T0 + 500, logged=T0 + 900)])
        rows = [r for r in replay.load_events(path) if r["event_type"] == "flow"]
        os.remove(path)
        self.assertEqual([r["ts"] for r in rows], [T0 + 60, T0 + 500])  # second one capped at capture end
        self.assertEqual([r["flow_start"] for r in rows], [T0, T0 + 500])

    def test_order_does_not_depend_on_file_order_or_flow_id(self):
        # Two records with the same timestamp: Suricata writes them in
        # either order and gives them random flow_ids from run to run.
        a = flow("10.10.0.231", "203.0.113.9", 22, T0, flow_id=111)
        b = flow("10.10.0.232", "203.0.113.9", 22, T0, flow_id=999)
        p1, p2 = write_eve([a, b]), write_eve([dict(b, flow_id=5), dict(a, flow_id=6)])
        order1 = [r["src_ip"] for r in replay.load_events(p1)]
        order2 = [r["src_ip"] for r in replay.load_events(p2)]
        os.remove(p1)
        os.remove(p2)
        self.assertEqual(order1, order2)

    def test_each_dns_request_becomes_an_adguard_style_query_with_its_rcode(self):
        path = write_eve([dns_v3("10.10.0.231", "nope.example", T0, "request"),
                          dns_v3("10.10.0.231", "nope.example", T0 + 0.01, "response", rcode="NXDOMAIN")])
        rows = [r for r in replay.load_events(path) if r["event_type"] == "dns_query"]
        os.remove(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["dns_rcode"], "NXDOMAIN")
        self.assertEqual(rows[0]["blocked"], 0)

    def test_firefox_canary_is_not_written_as_an_adguard_query(self):
        # The real AdGuard never logs it (step 7.2 finding), so the stand-in
        # mustn't either - correlation.py counts it from Suricata's records.
        canary = next(iter(correlation.CANARY_DOMAINS_NOT_IN_ADGUARD_LOG))
        path = write_eve([dns_v3("10.10.0.231", canary, T0, "request")])
        rows = replay.load_events(path)
        os.remove(path)
        self.assertEqual([r["event_type"] for r in rows], ["dns"])


class RunEngineTests(unittest.TestCase):
    """End to end after Suricata: a beacon host, a benign host, and a label
    for a signal a capture can't drive."""

    LABELS = {
        "hosts": {"10.10.0.231": "beacon host", "10.10.0.240": "benign host"},
        "runs": [
            {"signal": "beacon", "run": 1, "host": "10.10.0.231", "t_start": T0, "t_end": T0 + 600, "expect": True},
            {"signal": "benign", "run": 1, "host": "10.10.0.240", "t_start": T0, "t_end": T0 + 600, "expect": False},
            {"signal": "threat_intel", "run": 1, "host": "10.10.0.231", "t_start": T0, "t_end": T0 + 600,
             "expect": True},
        ],
    }

    def _records(self):
        import random
        rng = random.Random(3)
        records, t = [], T0
        for i in range(12):  # every 50 s, +-10%, same size: a beacon
            t += 50 * (1 + rng.uniform(-0.1, 0.1))
            records.append(flow("10.10.0.231", "203.0.113.9", 4444, t, flow_id=i, logged=t + rng.uniform(0, 400)))
        t = T0
        for i in range(12):  # irregular gaps and sizes: someone browsing
            t += rng.expovariate(1 / 60) + 1
            records.append(flow("10.10.0.240", "198.51.100.%d" % rng.randint(1, 3), 443, t, end=t + 2,
                                state="closed", flow_id=100 + i, size=rng.randint(300, 90000)))
        return records

    def _run(self):
        path = write_eve(self._records())
        rows = replay.load_events(path)
        os.remove(path)
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        with open(os.path.join(replay.REPO, "app", "schema.sql")) as f:
            conn.executescript(f.read())
        return replay.run_engine(conn, rows, self.LABELS)

    def test_beacon_detected_benign_quiet_and_threat_intel_not_scored(self):
        res = self._run()
        runs = {r["signal"]: r for r in res["runs"]}
        self.assertTrue(runs["beacon"]["detected"])
        self.assertTrue(runs["beacon"]["correct"])
        self.assertFalse(runs["benign"]["detected"])
        self.assertTrue(runs["benign"]["correct"])
        self.assertIn("not_replayable", runs["threat_intel"])
        self.assertNotIn("detected", runs["threat_intel"])
        self.assertEqual(res["signal_failures"], {})

    def test_two_runs_give_the_same_result(self):
        self.assertEqual(json.dumps(self._run(), sort_keys=True), json.dumps(self._run(), sort_keys=True))

    def test_the_real_clock_is_put_back_afterwards(self):
        self._run()
        self.assertIs(correlation.time, time)


if __name__ == "__main__":
    unittest.main()

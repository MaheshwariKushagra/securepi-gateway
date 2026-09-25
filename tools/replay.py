#!/usr/bin/env python3
"""
SecurePi Gateway - PCAP replay (ENHANCEMENT-PLAN.md step 7.1).

Runs a packet capture through the same detection pipeline the gateway runs
live, on any machine with Suricata installed (the Mac: `brew install
suricata`), and scores the result against a labels file that says what the
capture contains. The same capture and the same rules always give the same
answer, which is the point: a deterministic ground truth to check the
signals against, without a live attack or a live gateway.

    python3 tools/replay.py CAPTURE.pcap LABELS.json [--out DIR]

The pipeline, step by step
---------------------------
1. `suricata -r CAPTURE` with tools/replay-suricata.yaml and the gateway's
   own rule set (eval/rules/, copied from the gateway - see eval/README.md),
   writing eve.json.
2. Every eve.json record goes through app/ingest.py's real flatten_suricata()
   into a fresh database built from app/schema.sql. Suricata 8 (Homebrew)
   writes DNS in its version-3 layout; the gateway's Suricata 7 writes
   version 2, which is what flatten_suricata() reads - so v3 records are
   reshaped to v2 first. Nothing in app/ is changed for the replay.
   A flow record's timestamp is when Suricata logged it, and in a replay
   that depends on when its flow-manager thread happened to wake: two runs
   of the same capture differed by a median 44 s and up to 6 minutes. So
   the replay sets it to when the flow times out - its last packet plus the
   timeout in tools/replay-suricata.yaml for its protocol and state (the
   live flow manager adds a few seconds on top, which a replay can't
   reproduce). A flow still open when the capture ends is logged then, as
   Suricata does at shutdown.
3. On the gateway, DNS filtering events come from AdGuard, not Suricata.
   There is no AdGuard here, so each DNS request Suricata saw is also
   written as a dns_query event (with the answer's response code), which is
   what the DNS signals read. The Firefox canary is left out, because the
   real AdGuard never logs it either (step 7.2 finding).
4. The labels file names the hosts; each becomes a device, and events from
   its address are attributed to it.
5. app/correlation.py's real run_all() then runs on a simulated clock that
   starts at the first packet and moves forward 15 seconds at a time - the
   engine's own interval - adding each event only once its timestamp has
   been reached. So every signal's trailing window sees exactly what it
   would have seen live, and detection times come out in capture time.
6. Each labelled run is scored: detected or not, and how long after the
   run started. Incidents on a host labelled as benign are false positives.

What a replay can't judge
-------------------------
Five signals read gateway state that a capture doesn't carry (see
NOT_REPLAYABLE below): threat-intel feeds, AdGuard's block decisions, the
device registry's first sighting and the hourly rollups. Labelled runs for
them are reported as "not replayable" rather than scored as misses - the
live battery (gateway/battery.py) is where those are measured.

Same capture, same rules, same result: the replay pins its timezone to UTC
(new_device and the hourly baseline format local time) and prints a
sha256 over the whole result, so two runs can be compared at a glance.

Labels file
-----------
    {"pcap": "...", "source": "...", "licence": "...",
     "hosts": {"10.10.0.231": "battery host 231", ...},
     "runs": [{"signal": "port_scan", "run": 1, "host": "10.10.0.231",
               "t_start": 1790364000.0, "t_end": 1790364010.0, "expect": true}, ...]}

`signal` is an incident signal_type, or "ids_alert" (any ids_* type),
"campaign" (a campaigns row), "benign" (nothing should fire) or "any" (any
incident at all - for public captures labelled only as "this host is
infected"). A run with no t_start covers the whole capture.
"""

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time as real_time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "app"))

import correlation  # noqa: E402
import ingest  # noqa: E402
import suppression  # noqa: E402

STEP_S = 15            # the live engine's cycle (app/engine.py)
DETECT_GRACE_S = 300   # evidence may be up to this long after a run's last packet;
                       # the clock also keeps running this long after the last event

# Signals whose inputs don't exist in a capture, with the reason.
NOT_REPLAYABLE = {
    "threat_intel": "needs the gateway's threat-intel feed (ioc table)",
    "malicious_domain": "needs AdGuard's block decisions",
    "adblock_ineffective": "needs AdGuard's block decisions",
    "new_device": "needs the device registry's first sighting",
    "volume_anomaly": "needs 7 days of hourly rollups (device_hourly)",
}


class SimClock:
    """Stands in for the `time` module inside correlation.py: time() is the
    simulated now, everything else is the real module."""

    def __init__(self, start):
        self.now = start

    def time(self):
        return self.now

    def __getattr__(self, name):
        return getattr(real_time, name)


def run_suricata(pcap, outdir, suricata, rules, classification):
    os.makedirs(outdir, exist_ok=True)
    eve = os.path.join(outdir, "eve.json")
    if os.path.exists(eve):
        os.remove(eve)
    cmd = [suricata, "-c", os.path.join(REPO, "tools", "replay-suricata.yaml"),
           "-S", rules, "--set", "classification-file=%s" % classification,
           # Captures recorded behind checksum offload show every TCP
           # checksum as wrong; checking them only produces decoder alerts
           # about the capture, not about the traffic.
           "--set", "pcap-file.checksum-checks=no", "-k", "none",
           "--runmode", "single", "-r", pcap, "-l", outdir]
    ref = shutil.which(suricata) and os.path.join(os.path.dirname(os.path.dirname(shutil.which(suricata))),
                                                  "etc", "suricata", "reference.config")
    if ref and os.path.exists(ref):
        cmd[cmd.index("-k"):cmd.index("-k")] = ["--set", "reference-config-file=%s" % ref]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("suricata failed:\n%s" % r.stderr[-2000:])
    version = subprocess.run([suricata, "-V"], capture_output=True, text=True).stdout.strip()
    return eve, version


def to_v2_dns(event):
    """Reshape a Suricata 8 (v3) DNS record into the v2 fields
    flatten_suricata() reads: dns.type 'query'/'answer', a flat rrname and
    rrtype, and rcode. A v2 record passes through untouched."""
    dns = event.get("dns") or {}
    if dns.get("version") != 3:
        return event
    q = (dns.get("queries") or [{}])[0]
    event = dict(event)
    event["dns"] = {
        "type": "query" if dns.get("type") == "request" else "answer",
        "rrname": q.get("rrname"), "rrtype": q.get("rrtype"), "rcode": dns.get("rcode"),
    }
    return event


# Suricata's flow timeouts, as set in tools/replay-suricata.yaml (and the
# gateway's defaults). Keep the two in step.
FLOW_TIMEOUTS = {
    "TCP": {"new": 60, "established": 600, "closed": 60},
    "UDP": {"new": 30, "established": 300},
}
DEFAULT_FLOW_TIMEOUTS = {"new": 30, "established": 300, "closed": 0}


def flow_logged_at(flow, proto, capture_end):
    """When Suricata would log this flow: once it has been idle for its
    timeout, or at the end of the capture if that comes first."""
    end = ingest.to_epoch(flow.get("end") or flow.get("start") or "")
    if end is None:
        return None
    timeouts = FLOW_TIMEOUTS.get(proto, DEFAULT_FLOW_TIMEOUTS)
    timeout = timeouts.get(flow.get("state"), DEFAULT_FLOW_TIMEOUTS.get(flow.get("state"), 0))
    return min(end + timeout, capture_end)


def sort_key(row):
    """Time first, then everything else in the row except Suricata's
    flow_id, which is random per run - so ties always sort the same way."""
    rest = {k: v for k, v in row.items() if k != "flow_id"}
    return (row["ts"], json.dumps(rest, sort_keys=True, default=str))


def load_events(eve_path):
    """Every eve record as an events-table row, plus a dns_query row for each
    DNS request (the stand-in for AdGuard's query log)."""
    records = []
    with open(eve_path) as f:
        for line in f:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("event_type") != "stats":
                records.append(e)
    # The capture's last packet: every non-flow record is stamped with a
    # packet's time, and every flow record says when its last packet was.
    capture_end = 0
    for e in records:
        if e.get("event_type") == "flow":
            t = ingest.to_epoch((e.get("flow") or {}).get("end") or "")
        else:
            t = ingest.to_epoch(e.get("timestamp", ""))
        if t is not None and t > capture_end:
            capture_end = t

    rows, requests, rcodes = [], [], {}
    for e in records:
        if e.get("event_type") == "flow":
            logged = flow_logged_at(e.get("flow") or {}, e.get("proto"), capture_end)
            if logged is not None:
                e = dict(e, timestamp=time_iso(logged))
        e = to_v2_dns(e)
        row = ingest.flatten_suricata(e)
        if row["ts"] is None:
            continue
        rows.append(row)
        if row["event_type"] == "dns":
            key = (e.get("flow_id"), row["dns_rrname"])
            if row["dns_type"] == "query":
                requests.append((key, row))
            elif row.get("dns_rcode"):
                rcodes.setdefault(key, row["dns_rcode"])
    for key, q in requests:
        if (q["dns_rrname"] or "") in correlation.CANARY_DOMAINS_NOT_IN_ADGUARD_LOG:
            continue
        rows.append({"ts": q["ts"], "ts_iso": q["ts_iso"], "source": "replay-dns", "event_type": "dns_query",
                     "src_ip": q["src_ip"], "dns_rrname": q["dns_rrname"], "dns_rrtype": q["dns_rrtype"],
                     "dns_rcode": rcodes.get(key), "blocked": 0})
    rows.sort(key=sort_key)
    return rows


def time_iso(epoch):
    """Epoch seconds as an eve.json-style timestamp (UTC, microseconds)."""
    whole, micro = divmod(round(epoch * 1e6), 1000000)
    return "%s.%06d+0000" % (real_time.strftime("%Y-%m-%dT%H:%M:%S", real_time.gmtime(whole)), micro)


def new_db(path):
    if os.path.exists(path):
        os.remove(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    with open(os.path.join(REPO, "app", "schema.sql")) as f:
        conn.executescript(f.read())
    return conn


def detected(conn, run, device, t0, t1):
    sig = run["signal"]
    if sig == "campaign":
        return conn.execute("SELECT 1 FROM campaigns WHERE device_id=? AND created_at >= ?",
                            (device, t0)).fetchone() is not None
    if sig in ("any", "benign"):
        return conn.execute("SELECT 1 FROM incidents WHERE device_id=? AND created_at BETWEEN ? AND ?",
                            (device, t0, t1)).fetchone() is not None
    cond = "i.signal_type LIKE 'ids_%'" if sig == "ids_alert" else "i.signal_type = ?"
    args = () if sig == "ids_alert" else (sig,)
    return conn.execute(
        "SELECT 1 FROM incidents i JOIN incident_events ie ON ie.incident_id = i.id JOIN events e ON e.id = ie.event_id"
        " WHERE %s AND i.device_id = ? AND e.ts BETWEEN ? AND ? LIMIT 1" % cond,
        args + (device, t0 - 1, t1)).fetchone() is not None


def replay(pcap, labels, outdir, suricata, rules, classification):
    name = os.path.splitext(os.path.basename(pcap))[0]
    work = os.path.join(outdir, name)
    eve, sversion = run_suricata(pcap, work, suricata, rules, classification)
    rows = load_events(eve)
    if not rows:
        sys.exit("no events came out of the capture")
    conn = new_db(os.path.join(work, "replay.db"))
    run = run_engine(conn, rows, labels)

    result = {
        "capture": os.path.basename(pcap), "source": labels.get("source"), "licence": labels.get("licence"),
        "suricata": sversion, "rules": os.path.basename(rules),
        "rules_sha256": sha256_file(rules), "capture_sha256": sha256_file(pcap),
        "events": len(rows), "capture_seconds": round(rows[-1]["ts"] - rows[0]["ts"], 1),
    }
    result.update(run)
    canonical = json.dumps(result, sort_keys=True).encode()
    result["result_sha256"] = hashlib.sha256(canonical).hexdigest()
    with open(os.path.join(work, "result.json"), "w") as f:
        json.dump(result, f, indent=1, sort_keys=True)
    return result


def run_engine(conn, rows, labels):
    """Feed the events into the database on the simulated clock, run the
    engine every STEP_S seconds, and score each labelled run. Separate from
    replay() so the tests can drive it without Suricata."""
    first, last = rows[0]["ts"], rows[-1]["ts"]
    devices = {}
    for ip, label in sorted(labels["hosts"].items()):
        cur = conn.execute("INSERT INTO devices (hostname, friendly_name, first_seen, last_seen, trust)"
                           " VALUES (?, ?, ?, ?, 'approved')", (label, label, first - 30 * 86400, last))
        devices[ip] = cur.lastrowid
    conn.commit()

    clock = SimClock(first)
    failures = {}
    pending = []
    for i, r in enumerate(labels["runs"]):
        if r["host"] not in devices:
            continue
        t0 = r.get("t_start") or first
        t1 = (r.get("t_end") or last) + DETECT_GRACE_S
        pending.append({"i": i, "run": r, "device": devices[r["host"]], "t0": t0, "t1": t1, "t_detect": None})

    now = first - (first % STEP_S) + STEP_S
    correlation.time = clock
    suppression.time = clock
    try:
        steps = _step_until(conn, rows, devices, pending, clock, now, last + DETECT_GRACE_S, failures)
    finally:
        correlation.time = real_time
        suppression.time = real_time
    return score(conn, pending, steps, failures)


def _step_until(conn, rows, devices, pending, clock, now, stop, failures):
    """The simulated engine loop. Returns how many cycles ran."""
    idx = 0
    steps = 0
    while now <= stop:
        clock.now = now
        batch = []
        while idx < len(rows) and rows[idx]["ts"] <= now:
            row = dict(rows[idx])
            row["device_id"] = devices.get(row.get("src_ip"))
            batch.append(row)
            idx += 1
        if batch:
            ingest.insert_events(conn, batch)
            # insert_events() doesn't set device_id (the live registry does,
            # afterwards) - apply the labels' host mapping directly.
            conn.executemany("UPDATE events SET device_id=? WHERE device_id IS NULL AND src_ip=?",
                             [(d, ip) for ip, d in devices.items()])
            conn.commit()
        for fn, fired in correlation.run_all(conn).items():
            if fired is None:     # run_all() caught an exception from this signal
                failures[fn] = failures.get(fn, 0) + 1
        steps += 1
        for p in pending:
            if p["t_detect"] is None and now >= p["t0"] and detected(conn, p["run"], p["device"], p["t0"], p["t1"]):
                p["t_detect"] = now
        now += STEP_S
    return steps


def score(conn, pending, steps, failures):
    """Each labelled run: detected or not, correct or not, and how long it
    took. Signals a capture can't drive are listed, not scored."""
    scored = []
    for p in pending:
        r = p["run"]
        expect = r.get("expect", True)
        if r["signal"] in NOT_REPLAYABLE:
            scored.append({"signal": r["signal"], "run": r.get("run", 1), "host": r["host"], "expect": expect,
                           "not_replayable": NOT_REPLAYABLE[r["signal"]]})
            continue
        raised = [row[0] for row in conn.execute(
            "SELECT DISTINCT signal_type FROM incidents WHERE device_id=? AND last_seen >= ? AND first_seen <= ?"
            " ORDER BY 1", (p["device"], p["t0"] - 1, p["t1"]))]
        scored.append({
            "signal": r["signal"], "run": r.get("run", 1), "host": r["host"], "expect": expect,
            "detected": p["t_detect"] is not None,
            "correct": (p["t_detect"] is not None) == expect,
            "ttd_s": round(p["t_detect"] - p["t0"], 1) if p["t_detect"] is not None else None,
            "incidents_on_host": raised,
        })
    incidents = [dict(r) for r in conn.execute(
        "SELECT signal_type, severity, title, device_id, evidence_count, first_seen, created_at FROM incidents ORDER BY id")]
    by_type = {}
    for inc in incidents:
        by_type[inc["signal_type"]] = by_type.get(inc["signal_type"], 0) + 1

    return {
        "engine_steps": steps, "incidents_by_type": dict(sorted(by_type.items())), "runs": scored,
        "signal_failures": dict(sorted(failures.items())), "summary": summarise(scored),
    }


def summarise(scored):
    out = {}
    for s in scored:
        if "not_replayable" in s:
            out.setdefault(s["signal"], {"not_replayable": s["not_replayable"]})
            continue
        o = out.setdefault(s["signal"], {"runs": 0, "detected": 0, "correct": 0, "ttd": []})
        o["runs"] += 1
        o["detected"] += int(s["detected"])
        o["correct"] += int(s["correct"])
        if s["ttd_s"] is not None:
            o["ttd"].append(s["ttd_s"])
    for o in out.values():
        if "not_replayable" in o:
            continue
        t = sorted(o.pop("ttd"))
        o["ttd_median_s"] = t[len(t) // 2] if t else None
        o["ttd_max_s"] = t[-1] if t else None
    return dict(sorted(out.items()))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    os.environ["TZ"] = "UTC"
    real_time.tzset()
    ap = argparse.ArgumentParser(description="Replay a capture through the SecurePi detection pipeline.")
    ap.add_argument("pcap")
    ap.add_argument("labels")
    ap.add_argument("--out", default=os.path.join(REPO, "eval", "replay-out"))
    ap.add_argument("--suricata", default=shutil.which("suricata") or "suricata")
    ap.add_argument("--rules", default=os.path.join(REPO, "eval", "rules", "suricata.rules"))
    ap.add_argument("--classification", default=os.path.join(REPO, "eval", "rules", "classification.config"))
    args = ap.parse_args()
    with open(args.labels) as f:
        labels = json.load(f)
    started = real_time.time()
    res = replay(args.pcap, labels, args.out, args.suricata, args.rules, args.classification)
    print("%s: %d events over %.0f s of capture, %d engine cycles, %.1f s to replay" % (
        res["capture"], res["events"], res["capture_seconds"], res["engine_steps"], real_time.time() - started))
    print("incidents raised: %s" % (res["incidents_by_type"] or "none"))
    print("%-20s %6s %9s %8s %11s" % ("label", "runs", "detected", "correct", "median ttd"))
    for sig, o in res["summary"].items():
        if "not_replayable" in o:
            print("%-20s  not replayable: %s" % (sig, o["not_replayable"]))
        else:
            print("%-20s %6d %9d %8d %11s" % (sig, o["runs"], o["detected"], o["correct"], o["ttd_median_s"]))
    if res["signal_failures"]:
        print("** signals that raised an exception (cycles): %s **" % res["signal_failures"])
    print("result sha256 %s" % res["result_sha256"])


if __name__ == "__main__":
    main()

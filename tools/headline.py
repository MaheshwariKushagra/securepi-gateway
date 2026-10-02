#!/usr/bin/env python3
"""
SecurePi Gateway - step 7.4's headline figures (ENHANCEMENT-PLAN.md).

    python3 tools/headline.py LIVE.db --battery A.json [--battery B.json]
                              [--attack DEVICE:types:START:END] [--out FILE]

Three measurements, each from the real app/ code:

1. Signals vs signatures on scans. For every scan or brute-force run in
   the batteries (and the red-team laptop's attacks), did the IDS's own
   signature rules raise anything about it, and did the behavioural signal?
   Read straight from the live database: the alerts the live IDS wrote
   during each run's window, from that run's device.

2. Beacon jitter curve. How irregular can a C2 beacon's timing get before
   beacon_signal stops seeing it? For each jitter level, TRIALS synthetic
   beacons (one check-in every PERIOD_S seconds, each gap drawn uniformly
   from PERIOD_S * (1 +/- jitter)) go through the real beacon_signal on a
   fresh database. Two cases: constant-size check-ins (a heartbeat), and
   sizes varying by the same jitter. Random but seeded, so repeatable.

3. Ablation: what an operator would face with (a) every signal firing
   shown as its own alert, (b) deduplicated incidents (what the console
   shows), (c) incidents grouped into campaigns. Counted on a replay of the
   live database at the live engine's 15-second cycle (tools/sweep.py's
   simulator), split into attack devices and real devices.
"""

import argparse
import json
import os
import random
import sqlite3
import sys
import tempfile
import time as real_time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "app"))
sys.path.insert(0, os.path.join(REPO, "tools"))

import correlation  # noqa: E402
import sweep  # noqa: E402

SCAN_SIGNALS = ("port_scan", "network_sweep", "slow_port_scan", "slow_network_sweep", "brute_force")
JITTERS = [0.0, 0.05, 0.1, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.7, 0.8, 1.0]
TRIALS = 50
PERIOD_S = 60
SEED = 7


# ------------------------------------------------------- 1. vs signatures --

SCAN_WORDS = ("SCAN", "BRUTE", "BRUTEFORCE", "NMAP", "PORTSCAN")
SCAN_CATEGORIES = ("Detection of a Network Scan", "Attempted Information Leak", "Attempted Denial of Service")


def is_scan_alert(name, category):
    upper = (name or "").upper()
    return any(word in upper for word in SCAN_WORDS) or category in SCAN_CATEGORIES


def signatures_vs_signals(live_path, positives, sweep_table):
    """Per scan signal: runs, how many the IDS's own rules alerted on, and
    how many the behavioural signal detected (from the sweep's default run)."""
    live = sqlite3.connect("file:%s?mode=ro" % live_path, uri=True)
    out = {}
    for signal in SCAN_SIGNALS:
        runs = [r for r in positives if r["signal"] == signal]
        with_alert = 0
        alert_names = set()
        for r in runs:
            # Every alert from the run's device in its window is listed, but a
            # run only counts as caught by signatures if an alert is ABOUT
            # scanning or brute force (by its name or its rule class) - the
            # battery's own ids_alert test and a laptop's connectivity checks
            # fall in the same minutes and say nothing about the scan.
            rows = live.execute(
                "SELECT DISTINCT alert_signature, alert_category FROM events WHERE event_type='alert'"
                " AND device_id=? AND ts BETWEEN ? AND ?",
                (r["device_id"], r["t_start"] - 1, r["t_end"] + sweep.DETECT_GRACE_S)).fetchall()
            alert_names.update(x[0] for x in rows)
            if any(is_scan_alert(name, category) for name, category in rows):
                with_alert += 1
        row = sweep_table.get(signal, {})
        out[signal] = {"runs": len(runs), "signature_alerted": with_alert, "signatures_seen": sorted(alert_names),
                       "signal_detected": row.get("tp")}
    live.close()
    return out


# ----------------------------------------------------- 2. beacon jitter --

def one_beacon(jitter, vary_size, rng, workdir):
    """True if beacon_signal flags one synthetic beacon."""
    path = os.path.join(workdir, "beacon.db")
    if os.path.exists(path):
        os.remove(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    with open(os.path.join(REPO, "app", "schema.sql")) as f:
        conn.executescript(f.read())
    conn.execute("INSERT INTO devices (id, hostname, first_seen, last_seen) VALUES (1, 'beacon-test', 0, 0)")
    window = 3600
    end = 1790000000.0
    t = end - window + 30
    rows = []
    while t < end - 30:
        size = 1200
        if vary_size:
            size = int(1200 * (1 + rng.uniform(-jitter, jitter)))
        rows.append((t, "synthetic", "flow", "suricata", "10.10.0.50", "203.0.113.77", 8443, 1, size // 2,
                     size - size // 2, t))
        t += PERIOD_S * (1 + rng.uniform(-jitter, jitter))
    conn.executemany(
        "INSERT INTO events (ts, ts_iso, event_type, source, src_ip, dest_ip, dest_port, device_id, bytes_toserver,"
        " bytes_toclient, flow_start) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
    conn.commit()
    clock = sweep.SimClock(end)
    correlation.time = clock
    try:
        fired = correlation.beacon_signal(conn)
    finally:
        correlation.time = real_time
    conn.close()
    return fired > 0


def jitter_curve(workdir):
    rng = random.Random(SEED)
    curve = []
    for jitter in JITTERS:
        point = {"jitter": jitter}
        for vary_size in (False, True):
            hits = sum(1 for _ in range(TRIALS) if one_beacon(jitter, vary_size, rng, workdir))
            point["size_varies" if vary_size else "constant_size"] = hits / TRIALS
        curve.append(point)
        print("  jitter %3d%%  constant size %.2f  size varies too %.2f" % (
            jitter * 100, point["constant_size"], point["size_varies"]))
    return curve


# ----------------------------------------------------------- 3. ablation --

def ablation(live_path, cols, rows, attack_devices, real_devices, workdir, iocs):
    """Raw firings, incidents and campaign-grouped incidents, per device group."""
    base = os.path.join(workdir, "ablation-base.db")
    sweep.build_base(live_path, base, iocs)
    path = os.path.join(workdir, "ablation.db")
    import shutil
    shutil.copyfile(base, path)

    raw = {}
    original = correlation.raise_incident

    def counting(conn, device_id, *args, **kwargs):
        raw[device_id] = raw.get(device_id, 0) + 1
        return original(conn, device_id, *args, **kwargs)

    correlation.raise_incident = counting
    saved_step = sweep.STEP_S
    sweep.STEP_S = 15
    try:
        conn, steps, failures = sweep.simulate(path, cols, rows, {}, None)
    finally:
        correlation.raise_incident = original
        sweep.STEP_S = saved_step

    def group(devices):
        devices = set(devices)
        firings = sum(n for d, n in raw.items() if d in devices)
        incidents = conn.execute("SELECT id, campaign_id, device_id FROM incidents").fetchall()
        mine = [i for i in incidents if i["device_id"] in devices]
        campaigns = {i["campaign_id"] for i in mine if i["campaign_id"] is not None}
        loose = sum(1 for i in mine if i["campaign_id"] is None)
        alerts = conn.execute("SELECT count(*) FROM events WHERE event_type='alert' AND device_id IN (%s)"
                              % ",".join("?" * len(devices)), sorted(devices)).fetchone()[0] if devices else 0
        return {"raw_signal_firings": firings, "incidents": len(mine),
                "after_campaign_grouping": loose + len(campaigns), "campaigns": len(campaigns),
                "raw_ids_alerts": alerts}

    result = {"steps": steps, "attack_devices": group(attack_devices), "real_devices": group(real_devices)}
    conn.close()
    return result


def main():
    os.environ["TZ"] = "Asia/Kolkata"
    real_time.tzset()
    ap = argparse.ArgumentParser(description="Step 7.4 headline figures.")
    ap.add_argument("live_db")
    ap.add_argument("--battery", action="append", required=True)
    ap.add_argument("--attack", action="append", default=[])
    ap.add_argument("--exclude", action="append", default=[])
    ap.add_argument("--negative-device", action="append", type=int, default=[])
    ap.add_argument("--sweep-result", required=True, help="tools/sweep.py output (for the signal side of 1.)")
    ap.add_argument("--out", default=os.path.join(REPO, "eval", "results", "headline.json"))
    args = ap.parse_args()

    positives, iocs = sweep.load_positives(args.battery)
    attacks = [sweep.parse_attack(s) for s in args.attack]
    positives = positives + sweep.attack_runs(attacks)
    excludes = [sweep.parse_exclude(s) for s in args.exclude]
    with open(args.sweep_result) as f:
        sweep_table = json.load(f)["default"]["table"]
    workdir = tempfile.mkdtemp(prefix="headline-")

    print("1. signals vs signatures on scans")
    sig = signatures_vs_signals(args.live_db, positives, sweep_table)
    for s, row in sig.items():
        print("  %-20s runs %2d  signature alerted %2d  signal detected %s" % (
            s, row["runs"], row["signature_alerted"], row["signal_detected"]))

    print("2. beacon jitter curve (%d trials per point, %d s period)" % (TRIALS, PERIOD_S))
    curve = jitter_curve(workdir)

    print("3. ablation (15 s cycle)")
    cols, rows = sweep.load_events(args.live_db)
    rows = sweep.drop_excluded(cols, rows, excludes)
    attack_devices = {r["device_id"] for r in positives} - set(args.negative_device)
    abl = ablation(args.live_db, cols, rows, attack_devices, args.negative_device, workdir, iocs)
    for k in ("attack_devices", "real_devices"):
        print("  %-15s %s" % (k, abl[k]))

    with open(args.out, "w") as f:
        json.dump({"signatures_vs_signals": sig, "beacon_jitter": {"trials": TRIALS, "period_s": PERIOD_S,
                   "seed": SEED, "curve": curve}, "ablation": abl}, f, indent=1, sort_keys=True)
    print("written to %s" % args.out)


if __name__ == "__main__":
    main()

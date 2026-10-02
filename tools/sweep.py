#!/usr/bin/env python3
"""
SecurePi Gateway - precision / recall and threshold sweeps (ENHANCEMENT-PLAN.md
steps 7.3 and 7.4).

Replays a copy of the LIVE database's events through app/correlation.py's
real signals, on a simulated clock, as many times as needed with different
settings - and scores every run against ground truth:

  positives  the step 7.2 battery runs on the live gateway (every signal,
             5 runs each per battery). Their results files say which device
             ran which attack, and when.
  negatives  the real devices' own traffic (the household's phones and PCs),
             with their deliberate test windows cut out. Nothing on those
             devices is an attack, so every incident there is a false
             positive.

    python3 tools/sweep.py LIVE.db --battery eval/results/battery-A.json [--battery ...]
                           [--negative-device 2 --negative-device 13 ...]
                           [--exclude 2:2026-09-26T07:00:00:2026-09-26T10:00:00 ...]
                           [--out eval/results/sweep.json] [--only-default]

Why the live database rather than the captures: four signals read gateway
state that a capture doesn't carry - the DNS filter's block decisions, the
threat-intel feed, the device registry, the hourly rollups (tools/replay.py,
NOT_REPLAYABLE). Their events and tables are in the live database, so here
every signal can be scored. The live IDS (version 7) wrote these events, so
this also isn't affected by the Mac's IDS version.

What is copied from the live database: the events (with the device each was
attributed to live), devices, their addresses and MACs, the hourly rollups
and the threat-intel table. The battery deletes its own test indicators
when it finishes; they are put back from the results file (each run's
`target`), with the same source and time the battery used.

Simulated clock: one engine cycle every STEP_S seconds of event time,
skipping minutes with no new events (no signal can change its mind without
new data except the campaign signal, which only reads incidents). The live
engine runs every 15 s; with this coarser step a detection can land up to a
minute later, so this tool scores WHETHER something is detected, not how
fast - the battery itself measured time to detect.

Scoring one signal s:
  TP  labelled s-runs detected (an s-incident on that run's device, with
      evidence inside the run's window plus DETECT_GRACE_S)
  FN  labelled s-runs not detected
  FP  s-incidents on the negative devices outside the excluded windows,
      plus s-incidents on the battery's benign host
  precision = TP / (TP + FP), recall = TP / (TP + FN), F1 their harmonic mean
FP is counted in incidents (after dedup), the unit an operator sees.
"""

import argparse
import calendar
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time as real_time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "app"))

import correlation  # noqa: E402
import settings  # noqa: E402
import suppression  # noqa: E402

STEP_S = 60
DETECT_GRACE_S = 300
COPIED_TABLES = ("devices", "device_ips", "device_macs", "device_hourly", "ioc")
IOC_SOURCE = "battery-test"   # gateway/battery.py's own value

# Which signal function produces which incident types. ids_alert stands for
# every ids_* type, as in the battery and the replay.
SIGNAL_FUNCTIONS = {
    "port_scan": ["port_scan_signal"],
    "network_sweep": ["network_sweep_signal"],
    "slow_port_scan": ["slow_scan_signal"],
    "slow_network_sweep": ["slow_scan_signal"],
    "dns_bypass": ["dns_bypass_signal"],
    "ids_alert": ["ids_alert_signal"],
    "threat_intel": ["threat_intel_signal"],
    "dns_tunneling": ["dns_tunneling_signal"],
    "dga": ["dns_tunneling_signal"],
    "beacon": ["beacon_signal"],
    "brute_force": ["brute_force_signal"],
    "malicious_domain": ["malicious_domain_signal"],
    "new_device": ["new_device_signal"],
    "volume_anomaly": ["behavioral_baseline_signal"],
}

# The thresholds each sweep varies, one at a time, everything else at its
# default. Grids straddle the default on both sides.
SWEEPS = {
    "port_scan": ("port_scan_threshold", [3, 4, 6, 8, 10, 12, 16, 24]),
    "network_sweep": ("network_sweep_threshold", [3, 4, 6, 8, 10, 12, 16, 24]),
    "slow_port_scan": ("slow_scan_threshold", [3, 4, 6, 8, 10, 12, 16]),
    "slow_network_sweep": ("slow_scan_threshold", [3, 4, 6, 8, 10, 12, 16]),
    "brute_force": ("brute_force_threshold", [2, 3, 4, 6, 8, 10, 15, 20]),
    "dns_bypass": ("dns_bypass_threshold", [1, 2, 3, 4, 5, 8, 12]),
    "ids_alert": ("ids_alert_threshold", [1, 2, 3, 4, 5, 8]),
    "malicious_domain": ("malicious_domain_threshold", [5, 10, 15, 20, 25, 30, 50]),
    "dns_tunneling": ("dns_tunneling_min_distinct_subdomains", [5, 10, 15, 20, 25, 30, 50]),
    "dga": ("dga_min_nxdomain_count", [3, 5, 8, 10, 12, 15, 20]),
    "beacon": ("beacon_score_threshold", [0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95]),
    "volume_anomaly": ("baseline_z_threshold", [1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0]),
}

# Secondary knobs worth a curve of their own.
EXTRA_SWEEPS = {
    "dns_tunneling_entropy": ("dns_tunneling", "dns_tunneling_min_entropy", [2.5, 3.0, 3.25, 3.5, 3.75, 4.0, 4.5]),
    "dga_entropy": ("dga", "dga_min_entropy", [2.5, 2.8, 3.0, 3.3, 3.6, 3.9, 4.2]),
    "beacon_min_connections": ("beacon", "beacon_min_connections", [4, 6, 8, 10, 12, 16]),
    "slow_scan_window": ("slow_port_scan", "slow_scan_window_seconds", [1800, 3600, 7200, 14400, 28800]),
}


class SimClock:
    """Stands in for the `time` module inside correlation.py."""

    def __init__(self, start):
        self.now = start

    def time(self):
        return self.now

    def __getattr__(self, name):
        return getattr(real_time, name)


def parse_local(value):
    """'2026-09-26T07:00:00' in the gateway's local time (IST) -> epoch."""
    t = real_time.strptime(value, "%Y-%m-%dT%H:%M:%S")
    return calendar.timegm(t) - (5 * 3600 + 30 * 60)


def parse_attack(spec):
    """'DEVICE:type1,type2:START:END' (local times) -> (device, {types}, start, end).
    A deliberate attack run from a negative device (the red-team simulator):
    those incident types in that window are true detections, and each type
    is also scored as one extra positive run."""
    device, types, rest = spec.split(":", 2)
    return int(device), set(types.split(",")), parse_local(rest[:19]), parse_local(rest[20:])


def attack_runs(attacks):
    runs = []
    for device, types, start, end in attacks:
        for signal in sorted(types):
            runs.append({"signal": signal, "run": 1, "device_id": device, "t_start": start, "t_end": end,
                         "expect": True, "battery": "red-team simulator (redteam/securepi_attack.py)"})
    return runs


def parse_exclude(spec):
    """'DEVICE:START:END' (local times) -> (device, start, end)."""
    device, rest = spec.split(":", 1)
    # Times contain colons too: split on the 'T' of the second timestamp.
    start_text = rest[:19]
    end_text = rest[20:]
    return int(device), parse_local(start_text), parse_local(end_text)


# ------------------------------------------------------------ ground truth --

def load_positives(battery_paths):
    """Every labelled battery run, plus the test indicators the battery
    deleted when it finished."""
    runs = []
    iocs = []
    for path in battery_paths:
        with open(path) as f:
            battery = json.load(f)
        name = os.path.basename(path)
        for r in battery["runs"]:
            run = dict(r)
            run["battery"] = name
            runs.append(run)
            if r["signal"] == "threat_intel":
                iocs.append((r["target"], r["t_start"]))
    return runs, iocs


# -------------------------------------------------------------- databases --

def build_base(live_path, base_path, iocs):
    """A fresh database from app/schema.sql with the live tables the signals
    read copied in (not the events - those are added on the clock)."""
    if os.path.exists(base_path):
        os.remove(base_path)
    conn = sqlite3.connect(base_path)
    with open(os.path.join(REPO, "app", "schema.sql")) as f:
        conn.executescript(f.read())
    live =sqlite3.connect("file:%s?mode=ro" % live_path, uri=True)
    for table in COPIED_TABLES:
        mine = [r[1] for r in conn.execute("PRAGMA table_info(%s)" % table)]
        theirs = [r[1] for r in live.execute("PRAGMA table_info(%s)" % table)]
        cols = [c for c in mine if c in theirs]
        rows = live.execute("SELECT %s FROM %s" % (", ".join(cols), table)).fetchall()
        conn.executemany("INSERT INTO %s (%s) VALUES (%s)" % (table, ", ".join(cols), ", ".join("?" * len(cols))), rows)
    for indicator, t in iocs:
        conn.execute("INSERT INTO ioc (indicator, ioc_type, source, description, first_seen, last_seen)"
                     " VALUES (?, 'domain', ?, 'step 7.2 test indicator (re-added by sweep.py)', ?, ?)",
                     (indicator, IOC_SOURCE, t - 1, t - 1))
    conn.commit()
    conn.close()
    live.close()


def load_events(live_path, start=None, end=None):
    """Every live event as a row tuple, oldest first, with the column list."""
    live = sqlite3.connect("file:%s?mode=ro" % live_path, uri=True)
    cols = [r[1] for r in live.execute("PRAGMA table_info(events)") if r[1] != "id"]
    where, args = [], []
    if start is not None:
        where.append("ts >= ?")
        args.append(start)
    if end is not None:
        where.append("ts <= ?")
        args.append(end)
    sql = "SELECT %s FROM events %s ORDER BY ts, id" % (", ".join(cols), ("WHERE " + " AND ".join(where)) if where else "")
    rows = live.execute(sql, args).fetchall()
    live.close()
    return cols, rows


def drop_excluded(cols, rows, excludes):
    """Leave a device's deliberate test windows out of the replay entirely,
    so test traffic can neither raise an incident nor feed one."""
    if not excludes:
        return rows
    ts_index = cols.index("ts")
    device_index = cols.index("device_id")
    kept = []
    for row in rows:
        excluded = False
        for device, start, end in excludes:
            if row[device_index] == device and start <= row[ts_index] <= end:
                excluded = True
                break
        if not excluded:
            kept.append(row)
    return kept


def simulate(db_path, cols, rows, overrides, function_names):
    """Feed the events in on the simulated clock and run the chosen signal
    functions (all of them, in run_all's order, when function_names is None)."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    mine = [r[1] for r in conn.execute("PRAGMA table_info(events)")]
    keep = [i for i, c in enumerate(cols) if c in mine]
    insert_cols = [cols[i] for i in keep]
    insert_sql = "INSERT INTO events (%s) VALUES (%s)" % (", ".join(insert_cols), ", ".join("?" * len(insert_cols)))
    for key, value in overrides.items():
        settings.set_value(conn, key, value)
    if function_names is None:
        functions = list(correlation.SIGNALS)
    else:
        functions = [fn for fn in correlation.SIGNALS if fn.__name__ in function_names]
    ts_index = cols.index("ts")

    clock = SimClock(rows[0][ts_index])
    correlation.time = clock
    suppression.time = clock
    failures = {}
    steps = 0
    try:
        i = 0
        while i < len(rows):
            # The next cycle is the first STEP_S boundary at or after the
            # next pending event.
            now = (int(rows[i][ts_index]) // STEP_S + 1) * STEP_S
            batch = []
            while i < len(rows) and rows[i][ts_index] <= now:
                batch.append(tuple(rows[i][k] for k in keep))
                i += 1
            conn.executemany(insert_sql, batch)
            conn.commit()
            clock.now = now
            for fn in functions:
                try:
                    fn(conn)
                    conn.commit()
                except Exception as exc:
                    conn.rollback()
                    failures[fn.__name__] = failures.get(fn.__name__, 0) + 1
                    if failures[fn.__name__] == 1:
                        print("  %s failed: %s" % (fn.__name__, exc), file=sys.stderr)
            steps += 1
    finally:
        correlation.time = real_time
        suppression.time = real_time
    return conn, steps, failures


# ---------------------------------------------------------------- scoring --

def run_detected(conn, run):
    """Did this labelled battery run get detected?"""
    signal = run["signal"]
    device = run["device_id"]
    t0 = run["t_start"] - 1
    t1 = run["t_end"] + DETECT_GRACE_S
    if signal == "campaign":
        return conn.execute("SELECT 1 FROM campaigns WHERE device_id=? AND created_at BETWEEN ? AND ?",
                            (device, t0, t1 + 600)).fetchone() is not None
    if signal == "new_device":
        return conn.execute("SELECT 1 FROM incidents WHERE device_id=? AND signal_type='new_device'"
                            " AND created_at BETWEEN ? AND ?", (device, t0, t1)).fetchone() is not None
    if signal == "volume_anomaly":
        # behavioral_baseline_signal links no evidence events (event_ids=[]),
        # so match on the incident's own time span instead.
        return conn.execute("SELECT 1 FROM incidents WHERE device_id=? AND signal_type='volume_anomaly'"
                            " AND first_seen <= ? AND last_seen >= ?", (device, t1, t0)).fetchone() is not None
    if signal == "benign":
        return conn.execute("SELECT 1 FROM incidents WHERE device_id=? AND created_at BETWEEN ? AND ?",
                            (device, t0, t1)).fetchone() is not None
    cond = "i.signal_type LIKE 'ids_%'" if signal == "ids_alert" else "i.signal_type = ?"
    args = () if signal == "ids_alert" else (signal,)
    # The battery's DNS tests all run on one device, seconds apart, so the
    # tunnelling test's NXDOMAIN lookups fall inside the DGA run's window.
    # A DNS run only counts when the evidence involves ITS OWN target
    # domain (from the results file), or it would be credited with another
    # run's detection.
    domain = run_domain(run)
    if domain is not None:
        cond += " AND (e.dns_rrname = ? OR e.dns_rrname LIKE ?)"
        args = args + (domain, "%." + domain)
    return conn.execute(
        "SELECT 1 FROM incidents i JOIN incident_events ie ON ie.incident_id = i.id"
        " JOIN events e ON e.id = ie.event_id WHERE %s AND i.device_id = ? AND e.ts BETWEEN ? AND ? LIMIT 1" % cond,
        args + (device, t0, t1)).fetchone() is not None


def run_domain(run):
    """The domain a battery DNS run queried, from its `target` text:
    "12 NXDOMAIN lookups under sp-dga1.invalid" -> sp-dga1.invalid,
    "mask.icloud.com x4 (...)" -> mask.icloud.com, an IOC name as is.
    None for runs that aren't about one domain (scans, beacons, ...)."""
    signal = run["signal"]
    target = run.get("target") or ""
    if signal in ("dga", "dns_tunneling") and " under " in target:
        return target.split(" under ", 1)[1].split()[0]
    if signal in ("dns_bypass", "threat_intel") and target:
        return target.split()[0]
    return None


def incident_type_matches(signal, signal_type):
    if signal == "ids_alert":
        return signal_type.startswith("ids_")
    return signal == signal_type


def is_genuine_join(conn, inc):
    """A new_device incident raised when the device really did first join
    (within the signal's own lookback of its first sighting) is a correct
    detection, not a false positive."""
    if inc["signal_type"] != "new_device":
        return False
    row = conn.execute("SELECT first_seen FROM devices WHERE id=?", (inc["device_id"],)).fetchone()
    lookback = settings.get(conn, "new_device_lookback_seconds")
    return row is not None and inc["first_seen"] - row[0] <= lookback


def in_attack(inc, attacks):
    """Is this incident one of the attacks a negative device deliberately ran
    (the red-team simulator), so not a false positive?"""
    for device, signal_types, start, end in attacks:
        if inc["device_id"] == device and inc["signal_type"] in signal_types and start <= inc["first_seen"] <= end:
            return True
    return False


def false_positives(conn, negative_devices, excludes, benign_devices, attacks=()):
    """Incidents on the negative devices (outside excluded windows, not a
    genuine new-device join, not a deliberate attack) and on the battery's
    benign hosts, as a list of dicts."""
    out = []
    if not negative_devices and not benign_devices:
        return out
    devices = sorted(set(negative_devices) | set(benign_devices))
    rows = conn.execute("SELECT * FROM incidents WHERE device_id IN (%s)" % ",".join("?" * len(devices)),
                        devices).fetchall()
    for inc in rows:
        if inc["device_id"] in negative_devices:
            # (Deliberate test windows never get here: their events are
            # left out of the replay altogether - see drop_excluded.)
            if is_genuine_join(conn, inc) or in_attack(inc, attacks):
                continue
        out.append({"device_id": inc["device_id"], "signal_type": inc["signal_type"],
                    "first_seen": inc["first_seen"], "evidence_count": inc["evidence_count"],
                    "title": inc["title"]})
    return out


def score(conn, positives, negative_devices, excludes, signals, attacks=()):
    benign = sorted({r["device_id"] for r in positives if r["signal"] == "benign"})
    fps = false_positives(conn, negative_devices, excludes, benign, attacks)
    table = {}
    for signal in signals:
        runs = [r for r in positives if r["signal"] == signal]
        tp = sum(1 for r in runs if run_detected(conn, r))
        fn = len(runs) - tp
        fp_list = [f for f in fps if incident_type_matches(signal, f["signal_type"])]
        fp = len(fp_list)
        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / (tp + fn) if (tp + fn) else None
        f1 = (2 * precision * recall / (precision + recall)) if precision and recall else (0.0 if precision == 0 or recall == 0 else None)
        table[signal] = {"tp": tp, "fn": fn, "fp": fp, "precision": precision, "recall": recall, "f1": f1,
                         "fp_by_device": count_by(fp_list, "device_id")}
    return table, fps


def count_by(items, key):
    out = {}
    for item in items:
        out[str(item[key])] = out.get(str(item[key]), 0) + 1
    return out


def negative_device_days(live_path, negative_devices, excludes):
    """How much benign traffic each negative device contributed: distinct
    days with events, and event counts (excluded windows left out)."""
    live = sqlite3.connect("file:%s?mode=ro" % live_path, uri=True)
    out = {}
    for d in negative_devices:
        rows = live.execute("SELECT ts FROM events WHERE device_id=?", (d,)).fetchall()
        windows = [(s, e) for dev, s, e in excludes if dev == d]
        kept = [t for (t,) in rows if not any(s <= t <= e for s, e in windows)]
        days = {real_time.strftime("%Y-%m-%d", real_time.gmtime(t + 19800)) for t in kept}
        out[str(d)] = {"events": len(kept), "days_with_events": len(days)}
    live.close()
    return out


# -------------------------------------------------------------------- main --

def one_config(base_path, workdir, cols, rows, overrides, function_names, positives, negatives, excludes, signals,
               attacks=(), keep=None):
    path = keep or os.path.join(workdir, "run.db")
    shutil.copyfile(base_path, path)
    started = real_time.time()
    conn, steps, failures = simulate(path, cols, rows, overrides, function_names)
    table, fps = score(conn, positives, negatives, excludes, signals, attacks)
    extra = {
        "incidents": conn.execute("SELECT count(*) FROM incidents").fetchone()[0],
        "campaigns": conn.execute("SELECT count(*) FROM campaigns").fetchone()[0],
    }
    conn.close()
    return {"overrides": overrides, "steps": steps, "failures": failures, "seconds": round(real_time.time() - started, 1),
            "table": table, "false_positives": fps, **extra}


def main():
    os.environ["TZ"] = "Asia/Kolkata"   # the gateway's own zone: hour-of-day baselines match live
    real_time.tzset()
    ap = argparse.ArgumentParser(description="Precision/recall and threshold sweeps over a live database copy.")
    ap.add_argument("live_db")
    ap.add_argument("--battery", action="append", required=True)
    ap.add_argument("--negative-device", action="append", type=int, default=[])
    ap.add_argument("--exclude", action="append", default=[], help="DEVICE:YYYY-MM-DDTHH:MM:SS:YYYY-MM-DDTHH:MM:SS (local)")
    ap.add_argument("--attack", action="append", default=[], help="DEVICE:type1,type2:START:END (local) - deliberate attacks from a negative device")
    ap.add_argument("--keep-db", help="keep the default run's database at this path, for inspection")
    ap.add_argument("--out", default=os.path.join(REPO, "eval", "results", "sweep.json"))
    ap.add_argument("--only-default", action="store_true")
    ap.add_argument("--only", action="append", default=[], help="run only these sweeps (names from SWEEPS/EXTRA_SWEEPS)")
    args = ap.parse_args()

    positives, iocs = load_positives(args.battery)
    excludes = [parse_exclude(s) for s in args.exclude]
    attacks = [parse_attack(s) for s in args.attack]
    positives = positives + attack_runs(attacks)
    signals = sorted({r["signal"] for r in positives if r["signal"] not in ("benign",)})
    workdir = tempfile.mkdtemp(prefix="sweep-")
    base = os.path.join(workdir, "base.db")
    build_base(args.live_db, base, iocs)
    cols, rows = load_events(args.live_db)
    before = len(rows)
    rows = drop_excluded(cols, rows, excludes)
    print("%d events left out of the replay (deliberate test windows)" % (before - len(rows)))
    print("%d events, %d labelled runs, negatives %s" % (len(rows), len(positives), args.negative_device))

    result = {"live_db": os.path.basename(args.live_db), "batteries": [os.path.basename(b) for b in args.battery],
              "negative_devices": args.negative_device, "excludes": args.exclude, "attacks": args.attack, "step_s": STEP_S,
              "grace_s": DETECT_GRACE_S, "negative_data": negative_device_days(args.live_db, args.negative_device, excludes)}

    if not args.only:
        print("default settings, every signal ...")
        result["default"] = one_config(base, workdir, cols, rows, {}, None, positives, args.negative_device, excludes,
                                       signals + ["campaign"], attacks, args.keep_db)
        print("  done in %ss, %d incidents" % (result["default"]["seconds"], result["default"]["incidents"]))
        for s, row in sorted(result["default"]["table"].items()):
            print("  %-20s TP %2d FN %2d FP %3d  P %s R %s" % (s, row["tp"], row["fn"], row["fp"],
                                                              fmt(row["precision"]), fmt(row["recall"])))
    if not args.only_default:
        result["sweeps"] = {}
        all_sweeps = {name: (name, key, grid) for name, (key, grid) in SWEEPS.items()}
        all_sweeps.update(EXTRA_SWEEPS)
        for name, (signal, key, grid) in sorted(all_sweeps.items()):
            if args.only and name not in args.only:
                continue
            points = []
            for value in grid:
                r = one_config(base, workdir, cols, rows, {key: value}, SIGNAL_FUNCTIONS[signal], positives,
                               args.negative_device, excludes, [signal], attacks)
                row = r["table"][signal]
                points.append({"value": value, "tp": row["tp"], "fn": row["fn"], "fp": row["fp"],
                               "precision": row["precision"], "recall": row["recall"], "f1": row["f1"],
                               "fp_by_device": row["fp_by_device"], "seconds": r["seconds"]})
                print("  %-24s %-38s %8s  TP %2d FN %2d FP %3d" % (name, key, value, row["tp"], row["fn"], row["fp"]))
            result["sweeps"][name] = {"signal": signal, "setting": key,
                                      "default": settings.SETTINGS_SCHEMA[key]["default"], "points": points}
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(result, f, indent=1, sort_keys=True, default=str)
    shutil.rmtree(workdir, ignore_errors=True)
    print("written to %s" % args.out)


def fmt(x):
    return "-" if x is None else "%.2f" % x


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
SecurePi Gateway - step 7.0's continuous-run report (ENHANCEMENT-PLAN.md).

    python3 tools/run_report.py DB --start 2026-10-02T19:00:00 --end 2026-10-09T19:00:00
                                [--monitor DIR] [--boots FILE] [--out FILE]

DB is a copy of the gateway's database; --monitor is a copy of
/var/lib/securepi-eval/monitor (gateway/run_monitor.py's JSONL files);
--boots is the output of `journalctl --list-boots --no-pager` on the
gateway. Times are the gateway's local time (IST).

The metrics, and where each comes from:

  false-positive incidents / 24 h   incidents created in the window on real
      devices (anything not named "[TEST HARNESS] ..."). Nobody attacks this
      network, so each one is a false positive unless a person says
      otherwise - every one is listed for that review. Not counted: a
      new_device incident raised when the device really did first join
      (that is a correct detection), and platform/policy incidents (counted
      separately: they are about the gateway, not a device).
  uptime                            the share of the window the gateway was
      running (from the boot list), and each service's share of the
      monitor's 60-second snapshots in which it was active.
  storage growth / day              the slope of the database's size over the
      monitor's snapshots (least squares), and the free disk at the end.
  ingest lag p95                    from the monitor's per-minute lag records,
      weighted by how many events each minute had.
  reduction ratio                   events ingested in the window, per
      incident raised.
  block % per device                blocked / all DNS queries per device in the
      window, from the DNS filter's own decisions (dns_query events).
"""

import argparse
import calendar
import glob
import json
import os
import re
import sqlite3
import sys
import time

# The app's own settings module: beside this file's repo when run on the Mac,
# the gateway's code directory when run there (from /opt/securepi-eval).
sys.path.insert(0, "/opt/securepi")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app"))
import settings  # noqa: E402

IST_OFFSET = 5 * 3600 + 30 * 60


def parse_local(value):
    return calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%S")) - IST_OFFSET


def fmt(epoch):
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(epoch + IST_OFFSET))


# ------------------------------------------------------------------ uptime --

BOOT_LINE = re.compile(r"^\s*-?\d+\s+\S+\s+\w{3} (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \S+\s+\w{3} (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")


def gateway_uptime(boots_path, start, end):
    """Seconds the gateway was running inside [start, end], from
    `journalctl --list-boots` (each boot's first and last journal entry)."""
    if not boots_path:
        return None
    up = 0.0
    boots = []
    with open(boots_path) as f:
        for line in f:
            m = BOOT_LINE.match(line)
            if not m:
                continue
            b0 = parse_local(m.group(1).replace(" ", "T"))
            b1 = parse_local(m.group(2).replace(" ", "T"))
            boots.append((b0, b1))
            overlap = min(b1, end) - max(b0, start)
            if overlap > 0:
                up += overlap
    return {"seconds_up": round(up), "window_seconds": round(end - start), "fraction": up / (end - start),
            "boots_in_window": sum(1 for b0, b1 in boots if start <= b0 <= end)}


# ----------------------------------------------------------------- monitor --

def read_monitor(monitor_dir, start, end):
    lags, snaps = [], []
    if not monitor_dir:
        return lags, snaps
    for path in sorted(glob.glob(os.path.join(monitor_dir, "*.jsonl"))):
        with open(path) as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not start <= rec.get("t", 0) <= end:
                    continue
                if rec.get("kind") == "lag":
                    lags.append(rec)
                elif rec.get("kind") == "snapshot":
                    snaps.append(rec)
    return lags, snaps


def lag_summary(lags):
    """Event-weighted p50/p95 per source: each minute's p95 stands for its
    events. An approximation (the minute's own percentiles, not every
    event's lag) - stated in the output."""
    out = {}
    by_source = {}
    for rec in lags:
        by_source.setdefault(rec["source"], []).append(rec)
    for source, recs in by_source.items():
        total = sum(r["n"] for r in recs)
        weighted = []
        for r in recs:
            weighted.append((r["p95"], r["n"]))
        weighted.sort()
        running = 0
        p95 = None
        for value, n in weighted:
            running += n
            if running >= 0.95 * total:
                p95 = value
                break
        out[source] = {"events": total, "minutes": len(recs), "p95_s": p95,
                       "worst_minute_max_s": max(r["max"] for r in recs)}
    return out


def storage_summary(snaps):
    if len(snaps) < 2:
        return None
    xs = [s["t"] for s in snaps]
    ys = [s["db_bytes"] + s.get("wal_bytes", 0) for s in snaps]
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx if sxx else 0
    return {"db_bytes_first": ys[0], "db_bytes_last": ys[-1], "growth_bytes_per_day": slope * 86400,
            "disk_free_last": snaps[-1]["disk_free"], "disk_total": snaps[-1]["disk_total"],
            "snapshots": n}


def service_uptime(snaps):
    counts = {}
    for s in snaps:
        for name, st in (s.get("services") or {}).items():
            c = counts.setdefault(name, [0, 0])
            c[1] += 1
            if st.get("active"):
                c[0] += 1
    return {name: {"active_samples": a, "samples": n, "fraction": a / n} for name, (a, n) in sorted(counts.items())}


def resources(snaps):
    """Peak memory per service and load average over the window."""
    if not snaps:
        return None
    peak = {}
    for s in snaps:
        for name, st in (s.get("services") or {}).items():
            if st.get("mem"):
                peak[name] = max(peak.get(name, 0), st["mem"])
    loads = [s["load"][0] for s in snaps if s.get("load")]
    return {"peak_service_memory_bytes": dict(sorted(peak.items())),
            "load1_mean": sum(loads) / len(loads) if loads else None, "load1_max": max(loads) if loads else None}


# -------------------------------------------------------------- database --

def in_excluded(device_id, ts, excludes):
    for device, s0, s1 in excludes:
        if device == device_id and s0 <= ts <= s1:
            return True
    return False


def database_metrics(db_path, start, end, excludes=()):
    conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    conn.row_factory = sqlite3.Row
    harness = {r[0] for r in conn.execute(
        "SELECT id FROM devices WHERE coalesce(friendly_name, hostname) LIKE '[TEST HARNESS]%'")}
    lookback = settings.get(conn, "new_device_lookback_seconds")

    incidents = conn.execute("SELECT * FROM incidents WHERE created_at BETWEEN ? AND ? ORDER BY created_at",
                             (start, end)).fetchall()
    fps, platform, harness_inc, joins = [], [], 0, 0
    for inc in incidents:
        st = inc["signal_type"]
        if st.startswith("platform_") or st.startswith("policy_"):
            platform.append({"type": st, "created": fmt(inc["created_at"]), "title": inc["title"]})
            continue
        if inc["device_id"] in harness:
            harness_inc += 1
            continue
        if st == "new_device":
            dev = conn.execute("SELECT first_seen FROM devices WHERE id=?", (inc["device_id"],)).fetchone()
            if dev and inc["first_seen"] - dev[0] <= lookback:
                joins += 1
                continue
        if in_excluded(inc["device_id"], inc["first_seen"], excludes):
            continue   # raised during a deliberate test on this device
        name = conn.execute("SELECT coalesce(friendly_name, hostname) FROM devices WHERE id=?",
                            (inc["device_id"],)).fetchone()
        fps.append({"id": inc["id"], "device_id": inc["device_id"], "device": name[0] if name else None,
                    "type": st, "created": fmt(inc["created_at"]), "status": inc["status"],
                    "title": inc["title"]})
    days = (end - start) / 86400
    by_type = {}
    for f in fps:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1

    events = conn.execute("SELECT count(*) FROM events WHERE ts BETWEEN ? AND ?", (start, end)).fetchone()[0]
    real_events = conn.execute(
        "SELECT count(*) FROM events WHERE ts BETWEEN ? AND ? AND device_id IS NOT NULL AND device_id NOT IN (%s)"
        % ",".join(str(h) for h in harness or [-1]), (start, end)).fetchone()[0]

    blocks = []
    for r in conn.execute(
            "SELECT e.device_id, coalesce(d.friendly_name, d.hostname) name, count(*) queries,"
            " sum(e.blocked) blocked FROM events e LEFT JOIN devices d ON d.id = e.device_id"
            " WHERE e.event_type='dns_query' AND e.source='adguard' AND e.ts BETWEEN ? AND ?"
            " AND e.device_id IS NOT NULL GROUP BY e.device_id ORDER BY queries DESC", (start, end)):
        if r["device_id"] in harness:
            continue
        blocks.append({"device_id": r["device_id"], "device": r["name"], "queries": r["queries"],
                       "blocked": r["blocked"], "block_pct": 100.0 * r["blocked"] / r["queries"] if r["queries"] else None})
    conn.close()
    real_incidents = len(fps) + joins
    return {
        "false_positives": {"count": len(fps), "per_24h": len(fps) / days if days else None, "by_type": by_type,
                            "list": fps},
        "genuine_new_device_joins": joins,
        "harness_incidents": harness_inc,
        "platform_and_policy_incidents": {"count": len(platform), "list": platform},
        "events_in_window": events,
        "events_from_real_devices": real_events,
        "reduction_real_devices": {"events": real_events, "incidents": real_incidents,
                                   "events_per_incident": real_events / real_incidents if real_incidents else None},
        "block_pct_per_device": blocks,
    }


def main():
    ap = argparse.ArgumentParser(description="Step 7.0 continuous-run report.")
    ap.add_argument("db")
    ap.add_argument("--start", required=True, help="local (IST) YYYY-MM-DDTHH:MM:SS")
    ap.add_argument("--end", required=True)
    ap.add_argument("--monitor")
    ap.add_argument("--boots")
    ap.add_argument("--exclude", action="append", default=[],
                    help="DEVICE:START:END (local) - a deliberate test on a real device; incidents it raised are not false positives")
    ap.add_argument("--out")
    args = ap.parse_args()
    excludes = []
    for spec in args.exclude:
        device, rest = spec.split(":", 1)
        excludes.append((int(device), parse_local(rest[:19]), parse_local(rest[20:])))
    start, end = parse_local(args.start), parse_local(args.end)
    lags, snaps = read_monitor(args.monitor, start, end)
    report = {
        "window": {"start": args.start, "end": args.end, "days": (end - start) / 86400},
        "gateway_uptime": gateway_uptime(args.boots, start, end),
        "service_uptime": service_uptime(snaps) if snaps else None,
        "ingest_lag": lag_summary(lags) if lags else None,
        "ingest_lag_note": "event-weighted over per-minute p95s (gateway/run_monitor.py, 2 s polling)",
        "storage": storage_summary(snaps),
        "resources": resources(snaps),
    }
    report["excluded_test_windows"] = args.exclude
    report.update(database_metrics(args.db, start, end, excludes))
    text = json.dumps(report, indent=1, sort_keys=True)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")
    print(text)


if __name__ == "__main__":
    main()

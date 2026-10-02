#!/usr/bin/env python3
"""
SecurePi Gateway - evaluation run monitor (ENHANCEMENT-PLAN.md step 7.0).

Records what step 7.0's continuous run is measured on, because the
platform itself doesn't keep these over time:

  * ingest lag - how long an event takes from its own timestamp to being
    in the database. Every 2 s this reads the rows added since the last
    look; `now - ts` is each one's lag (to within the 2 s poll). Written
    once a minute per source as count / p50 / p95 / max.
  * a system snapshot every 60 s - database and disk size (storage growth
    per day), memory and CPU of every service in services.list, whether
    each is active (service uptime), the IDS's kernel packet/drop counters,
    load average and free memory.

Read-only: it opens the database with `mode=ro` and never writes to it,
so it can't disturb what it measures. Output is one JSON object per line
in /var/lib/securepi-eval/monitor/<date>.jsonl, read by tools/run_report.py.

Runs as `securepi-web` (it only needs to read the database) from
securepi-run-monitor.service. Not part of services.list: it is an
evaluation instrument, not part of the gateway.
"""

import json
import os
import sqlite3
import subprocess
import time

DB_PATH = "/var/lib/securepi/securepi.db"
OUT_DIR = "/var/lib/securepi-eval/monitor"
SERVICES_LIST = "/opt/securepi/services.list"
LAG_POLL_S = 2
SNAPSHOT_EVERY_S = 60


def percentile(values, p):
    """Nearest-rank percentile of a list of numbers (p in 0-100)."""
    if not values:
        return None
    ordered = sorted(values)
    rank = int(round(p / 100.0 * (len(ordered) - 1)))
    return ordered[rank]


def write_record(record):
    day = time.strftime("%Y-%m-%d", time.localtime(record["t"]))
    path = os.path.join(OUT_DIR, day + ".jsonl")
    with open(path, "a") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def read_services():
    names = []
    try:
        with open(SERVICES_LIST) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    names.append(line)
    except OSError:
        pass
    return names


def service_state(name):
    """ActiveState, memory and CPU of one systemd unit, without root."""
    unit = name if "." in name else name + ".service"
    out = subprocess.run(
        ["systemctl", "show", unit, "--property=ActiveState,MemoryCurrent,CPUUsageNSec,NRestarts"],
        capture_output=True, text=True, timeout=10).stdout
    props = {}
    for line in out.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            props[key] = value
    def number(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None  # "[not set]" for timers and some units
    return {
        "active": props.get("ActiveState") == "active",
        "state": props.get("ActiveState"),
        "mem": number(props.get("MemoryCurrent")),
        "cpu_ns": number(props.get("CPUUsageNSec")),
        "restarts": number(props.get("NRestarts")),
    }


def meminfo():
    values = {}
    with open("/proc/meminfo") as f:
        for line in f:
            key, rest = line.split(":", 1)
            values[key] = int(rest.split()[0]) * 1024
    return {"total": values.get("MemTotal"), "available": values.get("MemAvailable")}


def file_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def snapshot(conn):
    st = os.statvfs("/")
    sensor = conn.execute("SELECT ts, kernel_packets, kernel_drops, capture_errors FROM sensor_stats WHERE id=1").fetchone()
    services = {}
    for name in read_services():
        try:
            services[name] = service_state(name)
        except (OSError, subprocess.SubprocessError) as e:
            services[name] = {"error": str(e)}
    with open("/proc/loadavg") as f:
        load = [float(x) for x in f.read().split()[:3]]
    return {
        "kind": "snapshot",
        "t": time.time(),
        "db_bytes": file_size(DB_PATH),
        "wal_bytes": file_size(DB_PATH + "-wal"),
        "disk_free": st.f_bavail * st.f_frsize,
        "disk_total": st.f_blocks * st.f_frsize,
        "events": conn.execute("SELECT count(*) FROM events").fetchone()[0],
        "open_incidents": conn.execute("SELECT count(*) FROM incidents WHERE status NOT IN ('resolved','false_positive')").fetchone()[0],
        "sensor": list(sensor) if sensor else None,
        "load": load,
        "mem": meminfo(),
        "services": services,
    }


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    conn = sqlite3.connect("file:%s?mode=ro" % DB_PATH, uri=True, timeout=30)
    last_id = conn.execute("SELECT coalesce(max(id), 0) FROM events").fetchone()[0]
    lags = {}            # source -> list of lags this minute
    minute_start = time.time()
    next_snapshot = 0
    write_record({"kind": "start", "t": time.time(), "last_event_id": last_id})
    while True:
        now = time.time()
        try:
            rows = conn.execute("SELECT id, ts, source FROM events WHERE id > ? ORDER BY id", (last_id,)).fetchall()
            for event_id, ts, source in rows:
                last_id = max(last_id, event_id)
                lags.setdefault(source, []).append(now - ts)
            if now - minute_start >= 60:
                for source, values in lags.items():
                    write_record({"kind": "lag", "t": now, "source": source, "n": len(values),
                                  "p50": percentile(values, 50), "p95": percentile(values, 95),
                                  "max": max(values)})
                lags = {}
                minute_start = now
            if now >= next_snapshot:
                write_record(snapshot(conn))
                next_snapshot = now + SNAPSHOT_EVERY_S
        except sqlite3.Error as e:
            write_record({"kind": "error", "t": now, "error": str(e)})
        time.sleep(LAG_POLL_S)


if __name__ == "__main__":
    main()

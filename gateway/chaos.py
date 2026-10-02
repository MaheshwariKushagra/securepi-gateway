#!/usr/bin/env python3
"""
SecurePi Gateway - chaos tests (ENHANCEMENT-PLAN.md step 7.7).

Run on the gateway as root, one scenario at a time:

    sudo python3 chaos.py SCENARIO [--watch SECONDS] > result.json

Scenarios: kill-ids, kill-dns, kill-ingest, kill-engine, kill-proxy,
stop-dns (the DNS filter down for 60 s - longer than its own restart, so
fail-open has to act), fill-disk, drop-wan.

Each one breaks one thing on purpose, then watches once a second, for
--watch seconds, what the gateway does about it. Before anything is broken
an independent undo is scheduled with systemd-run, so the gateway recovers
even if this script dies half-way. Output is one JSON object: the action
time, and a timeline of every change observed -

  service state      ActiveState of the unit (kill-*)
  data flowing       the newest event per source in the database, read-only
                     (how long the IDS / DNS filter / proxy went quiet)
  health incidents   new platform_* incidents and when they were raised
  dns fail-open      whether the dns-failopen DNAT rules are in place
  inspection gate    whether `ip nat dpi_up` holds ap0 (kill-proxy)
  disk / WAN         free space; whether 1.1.1.1 answers a ping

What a device on the LAN experiences is measured separately, from the
phone (tools/chaos_run.sh), and joined to this timeline on the clock.
"""

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time

DB = "file:/var/lib/securepi/securepi.db?mode=ro"
FILL_PATH = "/var/tmp/securepi-chaos-fill"
WAN_IF = "wlp2s0"

UNITS = {"kill-ids": "suricata", "kill-dns": "AdGuardHome", "kill-ingest": "securepi-ingest",
         "kill-engine": "securepi-engine", "kill-proxy": "securepi-dpi", "stop-dns": "AdGuardHome"}
STOP_DNS_S = 60   # stop-dns: the DNS filter stays down this long (a kill comes back in ~10 s)


def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def unit_state(unit):
    return sh(["systemctl", "show", unit, "--property=ActiveState", "--value"]).stdout.strip()


def newest_event(conn, source):
    row = conn.execute("SELECT max(ts) FROM events WHERE source=?", (source,)).fetchone()
    return row[0]


def platform_incidents(conn, since):
    return [dict(r) for r in conn.execute(
        "SELECT id, signal_type, created_at, last_seen, title FROM incidents"
        " WHERE signal_type LIKE 'platform_%' AND created_at >= ? ORDER BY id", (since,))]


def failopen_active():
    out = sh(["nft", "-a", "list", "chain", "ip", "nat", "prerouting"]).stdout
    return "dns-failopen" in out


def gate_open():
    out = sh(["nft", "list", "set", "ip", "nat", "dpi_up"]).stdout
    return '"ap0"' in out


def wan_up():
    return sh(["ping", "-c", "1", "-W", "1", "1.1.1.1"]).returncode == 0


def disk_free_pct():
    st = os.statvfs("/")
    return round(100.0 * st.f_bavail / st.f_blocks, 1)


def schedule_undo(name, seconds, command):
    """An undo that runs whatever happens to this script."""
    sh(["systemctl", "stop", name + ".timer"])
    sh(["systemctl", "reset-failed", name + ".service"])
    sh(["systemd-run", "--quiet", "--unit", name, "--on-active=%d" % seconds] + command)


def cancel_undo(name):
    sh(["systemctl", "stop", name + ".timer"])


def observe(conn, scenario, since):
    obs = {"t": round(time.time(), 2)}
    if scenario in UNITS:
        obs["service"] = unit_state(UNITS[scenario])
    obs["ids_newest"] = newest_event(conn, "suricata")
    obs["dns_newest"] = newest_event(conn, "adguard")
    obs["dpi_newest"] = newest_event(conn, "dpi")
    obs["failopen"] = failopen_active()
    obs["gate_open"] = gate_open()
    obs["wan"] = wan_up() if scenario == "drop-wan" else None
    obs["disk_free_pct"] = disk_free_pct() if scenario == "fill-disk" else None
    obs["incidents"] = [(i["id"], i["signal_type"]) for i in platform_incidents(conn, since)]
    return obs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", choices=sorted(list(UNITS) + ["fill-disk", "drop-wan"]))
    ap.add_argument("--watch", type=int, default=150)
    ap.add_argument("--wan-down-s", type=int, default=120)
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root")
    conn = sqlite3.connect(DB, uri=True, timeout=30)
    conn.row_factory = sqlite3.Row
    s = args.scenario
    before = observe(conn, s, time.time())

    # --- break it (with the undo armed first) ---------------------------
    if s == "stop-dns":
        # A DNS filter that stays down - what fail-open exists for. The undo
        # timer IS the planned restart, so it runs whatever happens here.
        unit = UNITS[s]
        schedule_undo("securepi-chaos-undo", STOP_DNS_S, ["/usr/bin/systemctl", "start", unit])
        t_action = time.time()
        sh(["systemctl", "stop", unit])
    elif s in UNITS:
        unit = UNITS[s]
        schedule_undo("securepi-chaos-undo", 300, ["/usr/bin/systemctl", "start", unit])
        t_action = time.time()
        sh(["systemctl", "kill", "-s", "SIGKILL", unit])
    elif s == "fill-disk":
        st = os.statvfs("/")
        # Leave 8% free: under the supervisor's 10% line, well clear of full.
        target_free = int(st.f_blocks * st.f_frsize * 0.08)
        size = st.f_bavail * st.f_frsize - target_free
        schedule_undo("securepi-chaos-undo", 300, ["/usr/bin/rm", "-f", FILL_PATH])
        t_action = time.time()
        sh(["fallocate", "-l", str(size), FILL_PATH])
    elif s == "drop-wan":
        # Drop everything leaving through the uplink (gateway's own and
        # forwarded), in its own table so removing it is one command.
        rules = ("table inet securepi_chaos {\n"
                 " chain out { type filter hook output priority -10; oifname \"%s\" drop; }\n"
                 " chain fwd { type filter hook forward priority -10; oifname \"%s\" drop; }\n}\n" % (WAN_IF, WAN_IF))
        with open("/var/tmp/securepi-chaos.nft", "w") as f:
            f.write(rules)
        schedule_undo("securepi-chaos-undo", args.wan_down_s,
                      ["/usr/sbin/nft", "delete", "table", "inet", "securepi_chaos"])
        t_action = time.time()
        sh(["nft", "-f", "/var/tmp/securepi-chaos.nft"])
    timeline = []
    end = t_action + args.watch
    while time.time() < end:
        timeline.append(observe(conn, s, t_action - 1))
        if s == "fill-disk" and time.time() - t_action > 90 and os.path.exists(FILL_PATH):
            os.remove(FILL_PATH)          # restore after the supervisor has had 3 checks
            cancel_undo("securepi-chaos-undo")
            timeline.append({"t": round(time.time(), 2), "note": "fill file removed"})
        time.sleep(1)
    cancel_undo("securepi-chaos-undo")
    if s in UNITS and unit_state(UNITS[s]) != "active":
        sh(["systemctl", "start", UNITS[s]])
    if s == "drop-wan":
        sh(["nft", "delete", "table", "inet", "securepi_chaos"])
    if os.path.exists(FILL_PATH):
        os.remove(FILL_PATH)
    after = observe(conn, s, t_action - 1)
    print(json.dumps({"scenario": s, "t_action": t_action, "before": before, "timeline": timeline,
                      "after": after, "incidents": platform_incidents(conn, t_action - 1)}))


if __name__ == "__main__":
    main()

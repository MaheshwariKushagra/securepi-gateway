#!/bin/bash
# SecurePi Gateway - freeze manifest and collection for Stage 7's soak
# (the one-session replacement for the seven-day run; ENHANCEMENT-PLAN.md 7.0).
#
#   sudo /opt/securepi-eval/collect_run.sh mark START
#   sudo /opt/securepi-eval/collect_run.sh collect START END [run_report.py options ...]
#
# START and END are local times, YYYY-MM-DDTHH:MM:SS. Everything lands in
# /var/lib/securepi-eval/soak-<START>/{mark,collect}/ (root-only; the
# database copies hold session tokens, so they are mode 600).
#
# mark    - run just before the soak starts. Records what is frozen (checksums
#           of every deployed file, the IDS rule set, the DNS filter's config
#           and lists, the settings rows, the enrolled/quarantine sets),
#           start-stats.json (database page counts, event count), a start copy
#           of the database, the boot list with how each boot ended, systemd's
#           lifecycle lines for every gateway unit since 12 September, and
#           every privacy-canary line so far. These history extracts are also
#           what the retrospective reliability table is built from, so the
#           journal can be purged afterwards (NEXT-SESSION.md, Day 15 item).
# collect - run when the soak ends (a transient timer runs it as a safety
#           net). Records the same manifest again and reports any drift from
#           the mark, end-stats.json, an end copy of the database, the run
#           monitor's files, the canary and unit lines for the window. If
#           run_report.py is installed next to this script it is run with
#           any extra options given; the full analysis is done on the Mac.
set -euo pipefail
MODE="${1:?usage: collect_run.sh mark START | collect START END [run_report options]}"
START="${2:?START missing}"
BASE="/var/lib/securepi-eval/soak-${START//:/}"
DB=/var/lib/securepi/securepi.db
HERE=$(cd "$(dirname "$0")" && pwd)
UNITS="hostapd securepi-ap-follow-uplink securepi-ap0 AdGuardHome nftables securepi-dpi securepi-ca-server securepi-test-harness suricata securepi-ingest securepi-engine securepi-web securepi-static securepi-privacy-canary securepi-run-monitor securepi-doh-refresh securepi-intel-refresh securepi-ids-logrotate"

copy_db() {   # copy_db DEST - a consistent copy through SQLite's backup API
    python3 - "$1" <<'PY'
import sqlite3, sys
src = sqlite3.connect("file:/var/lib/securepi/securepi.db?mode=ro", uri=True, timeout=30)
dst = sqlite3.connect(sys.argv[1])
src.backup(dst)
dst.close()
PY
    chmod 600 "$1"
}

db_stats() {  # db_stats DEST.json - logical size, for storage growth
    python3 - "$1" <<'PY'
import json, os, sqlite3, sys, time
c = sqlite3.connect("file:/var/lib/securepi/securepi.db?mode=ro", uri=True, timeout=30)
one = lambda sql: c.execute(sql).fetchone()[0]
stats = {
    "t": time.time(),
    "page_size": one("PRAGMA page_size"),
    "page_count": one("PRAGMA page_count"),
    "freelist_count": one("PRAGMA freelist_count"),
    "events": one("SELECT count(*) FROM events"),
    "max_event_id": one("SELECT max(id) FROM events"),
    "incidents": one("SELECT count(*) FROM incidents"),
    "db_bytes": os.path.getsize("/var/lib/securepi/securepi.db"),
    "wal_bytes": os.path.getsize("/var/lib/securepi/securepi.db-wal")
                 if os.path.exists("/var/lib/securepi/securepi.db-wal") else 0,
}
stats["logical_bytes"] = (stats["page_count"] - stats["freelist_count"]) * stats["page_size"]
json.dump(stats, open(sys.argv[1], "w"), indent=1)
PY
}

manifest() {  # manifest DIR - what is frozen
    local d="$1"
    find /opt/securepi -type f ! -path "*__pycache__*" ! -name "*.bak*" -print0 | sort -z | xargs -0 sha256sum > "$d/sha256-opt-securepi.txt"
    sha256sum /opt/securepi-dpi/*.py /opt/securepi-dpi/dpi-gate.sh /etc/nftables.conf \
        /etc/securepi/logrotate-suricata.conf /etc/systemd/system/securepi-*.service \
        /etc/systemd/system/securepi-*.timer /var/lib/suricata/rules/suricata.rules > "$d/sha256-other.txt" 2>/dev/null || true
    dpkg-query -W adb suricata 2>/dev/null > "$d/packages.txt" || true
    python3 - "$d" <<'PY'
import json, sqlite3, sys
sys.path.insert(0, "/opt/securepi")
import adguard
out = sys.argv[1]
cfg = adguard.dns_config()
keep = ("upstream_dns", "fallback_dns", "upstream_mode", "cache_enabled", "cache_optimistic", "dnssec_enabled", "blocking_mode")
json.dump({k: cfg.get(k) for k in keep}, open(out + "/dns-config.json", "w"), indent=1, sort_keys=True)
lists = adguard.filtering_status().get("filters", [])
json.dump([{k: f.get(k) for k in ("name", "url", "enabled", "rules_count")} for f in lists],
          open(out + "/dns-lists.json", "w"), indent=1, sort_keys=True)
c = sqlite3.connect("file:/var/lib/securepi/securepi.db?mode=ro", uri=True, timeout=30)
json.dump({k: json.loads(v) for k, v in c.execute("SELECT key, value FROM settings")},
          open(out + "/settings.json", "w"), indent=1, sort_keys=True)
PY
    { nft list set ip nat enrolled; nft list set inet filter quarantine_mac; nft list set ip nat dpi_up; } > "$d/nft-sets.txt" 2>&1 || true
}

unit_lines() {  # unit_lines SINCE UNTIL DEST - systemd's own lifecycle lines for the gateway's units
    local pattern
    pattern=$(echo "$UNITS" | tr ' ' '|')
    journalctl --no-pager -o short-iso _PID=1 --since "$1" ${2:+--until "$2"} \
        | grep -E "($pattern)(\.service|\.timer)?" \
        | grep -E "Started|Stopped|Failed|Main process exited|Control process exited|Scheduled restart|Consumed|Deactivated" > "$3" || true
}

boot_ends() {  # boot_ends DEST - for each finished boot: did it end with a clean shutdown?
    journalctl --list-boots --no-pager | awk 'NR>1 && $1 != "0" {print $1, $2}' | while read -r idx id; do
        if journalctl -b "$id" -n 200 -o cat --no-pager 2>/dev/null \
                | grep -qE "Reached target (poweroff|reboot|halt|kexec)|System is (powering down|rebooting)|Shutting down\.|Power key pressed"; then
            echo "$idx $id clean"
        else
            echo "$idx $id abrupt"
        fi
    done > "$1"
}

case "$MODE" in
    mark)
        OUT="$BASE/mark"
        mkdir -p "$OUT"; chmod 750 "$BASE" "$OUT"
        manifest "$OUT"
        db_stats "$OUT/start-stats.json"
        copy_db "$OUT/securepi-start.db"
        journalctl --list-boots --no-pager > "$OUT/boots.txt"
        boot_ends "$OUT/boot-ends.txt"
        unit_lines "2026-09-12 00:00:00" "" "$OUT/unit-lines-history.txt"
        journalctl --no-pager -u securepi-privacy-canary -o short-iso | grep "securepi-privacy-canary:" > "$OUT/canary-history.log" || true
        echo "$START" > "$OUT/start.txt"
        echo "marked in $OUT"
        ;;
    collect)
        END="${3:?END missing}"
        shift 3
        OUT="$BASE/collect"
        mkdir -p "$OUT"; chmod 750 "$BASE" "$OUT"
        manifest "$OUT"
        # Drift: anything frozen at the mark that differs now.
        for f in sha256-opt-securepi.txt sha256-other.txt dns-config.json dns-lists.json settings.json packages.txt; do
            if [ -f "$BASE/mark/$f" ] && ! diff -q "$BASE/mark/$f" "$OUT/$f" > /dev/null; then
                echo "== $f changed since the mark"; diff "$BASE/mark/$f" "$OUT/$f" || true
            fi
        done > "$OUT/drift.txt"
        db_stats "$OUT/end-stats.json"
        copy_db "$OUT/securepi-end.db"
        journalctl --list-boots --no-pager > "$OUT/boots.txt"
        rm -rf "$OUT/monitor"; mkdir -p "$OUT/monitor"
        cp /var/lib/securepi-eval/monitor/*.jsonl "$OUT/monitor/"
        unit_lines "${START/T/ }" "${END/T/ }" "$OUT/unit-lines-window.txt"
        journalctl --no-pager -u securepi-privacy-canary --since "${START/T/ }" --until "${END/T/ }" -o short-iso \
            | grep "securepi-privacy-canary:" > "$OUT/canary.log" || true
        if [ -f "$HERE/run_report.py" ]; then
            python3 "$HERE/run_report.py" "$OUT/securepi-end.db" --start "$START" --end "$END" \
                --monitor "$OUT/monitor" --boots "$OUT/boots.txt" --out "$OUT/report.json" "$@" > /dev/null \
                || echo "run_report.py failed - analyse on the Mac" > "$OUT/report-error.txt"
        fi
        echo "collected in $OUT ($(wc -l < "$OUT/drift.txt") drift lines)"
        ;;
    *)
        echo "usage: collect_run.sh mark START | collect START END [run_report options]" >&2
        exit 2
        ;;
esac

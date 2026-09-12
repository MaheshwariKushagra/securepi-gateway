#!/usr/bin/env python3
"""
SecurePi Gateway - event ingest service.

Reads Suricata's eve.json and the DNS resolver's query log, converts every
record into the one shared event shape defined in schema.sql, and stores it.

Design notes worth knowing:

  * It remembers its position in each file (see the ingest_state table), so a
    restart neither re-reads old events nor skips new ones.

  * It watches for log rotation by inode, not by size. Suricata replaces
    eve.json periodically; the file path stays the same but the inode changes,
    and a byte offset into the old file means nothing in the new one.

  * Nothing is dropped silently. Records that cannot be parsed are counted in
    ingest_stats so a broken source shows up as a number rather than as
    mysteriously missing data.

Run it as a service; it polls, sleeps, and repeats.
"""

import json
import os
import sqlite3
import sys
import time

import registry

DB_PATH = "/opt/securepi/securepi.db"
SCHEMA_PATH = "/opt/securepi/schema.sql"
EVE_PATH = "/var/log/suricata/eve.json"
AGH_QUERYLOG_PATH = "/opt/AdGuardHome/data/querylog.json"

# How long to wait between passes over the log files. Two seconds keeps the
# console feeling live without spinning the CPU on an idle network.
POLL_SECONDS = 2

# Suricata emits a 'stats' record every few seconds. They are useful for
# monitoring Suricata itself but they are not network events, so they do not
# belong in the events table.
SKIP_TYPES = {"stats"}


def open_db():
    """Open the database, creating it from schema.sql if it does not exist."""
    first_time = not os.path.exists(DB_PATH)
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    if first_time or conn.execute(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='events'"
    ).fetchone()[0] == 0:
        with open(SCHEMA_PATH) as fh:
            conn.executescript(fh.read())
        conn.commit()
        print("created database at %s" % DB_PATH, flush=True)
    return conn


def to_epoch(timestamp):
    """
    Convert Suricata's timestamp to epoch seconds.

    Suricata writes e.g. '2026-09-12T09:27:53.123456+0000'. Python's fromisoformat
    handles this in 3.11+, but we fall back to a manual parse rather than lose
    the event if the format ever shifts.
    """
    from datetime import datetime
    try:
        return datetime.fromisoformat(timestamp).timestamp()
    except Exception:
        try:
            head = timestamp[:26]
            return datetime.strptime(head, "%Y-%m-%dT%H:%M:%S.%f").timestamp()
        except Exception:
            return time.time()


def flatten_suricata(event):
    """
    Turn one Suricata record into a flat dictionary matching the events table.

    Every event type shares the same outer fields; the type-specific detail
    lives in a nested object named after the type. We pull out the parts the
    correlation engine will need and leave the rest behind - storing the raw
    JSON as well would roughly triple the database size for data we would
    never query.
    """
    row = {
        "ts": to_epoch(event.get("timestamp", "")),
        "ts_iso": event.get("timestamp"),
        "source": "suricata",
        "event_type": event.get("event_type"),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "proto": event.get("proto"),
        "app_proto": event.get("app_proto"),
        "flow_id": event.get("flow_id"),
        "community_id": event.get("community_id"),
    }

    flow = event.get("flow") or {}
    if flow:
        row["bytes_toserver"] = flow.get("bytes_toserver")
        row["bytes_toclient"] = flow.get("bytes_toclient")
        row["pkts_toserver"] = flow.get("pkts_toserver")
        row["pkts_toclient"] = flow.get("pkts_toclient")
        row["flow_state"] = flow.get("state")
        row["flow_age"] = flow.get("age")

    dns = event.get("dns") or {}
    if dns:
        row["dns_type"] = dns.get("type")
        row["dns_rrname"] = dns.get("rrname")
        row["dns_rrtype"] = dns.get("rrtype")
        row["dns_rcode"] = dns.get("rcode")

    tls = event.get("tls") or {}
    if tls:
        row["tls_sni"] = tls.get("sni")
        row["tls_version"] = tls.get("version")
        row["tls_ja3"] = (tls.get("ja3") or {}).get("hash") if isinstance(tls.get("ja3"), dict) else tls.get("ja3")

    alert = event.get("alert") or {}
    if alert:
        row["alert_signature"] = alert.get("signature")
        row["alert_category"] = alert.get("category")
        row["alert_severity"] = alert.get("severity")
        row["alert_signature_id"] = alert.get("signature_id")

    return row


def insert_events(conn, rows):
    """Insert a batch of rows. Batching matters: one transaction per event
    would make ingest roughly an order of magnitude slower."""
    if not rows:
        return 0
    columns = [
        "ts", "ts_iso", "source", "event_type",
        "src_ip", "src_port", "dest_ip", "dest_port", "proto", "app_proto",
        "flow_id", "community_id",
        "bytes_toserver", "bytes_toclient", "pkts_toserver", "pkts_toclient",
        "flow_state", "flow_age",
        "dns_type", "dns_rrname", "dns_rrtype", "dns_rcode",
        "tls_sni", "tls_version", "tls_ja3",
        "alert_signature", "alert_category", "alert_severity", "alert_signature_id",
        "blocked", "block_reason",
    ]
    placeholders = ",".join("?" for _ in columns)
    sql = "INSERT INTO events (%s) VALUES (%s)" % (",".join(columns), placeholders)
    values = [tuple(r.get(c) for c in columns) for r in rows]
    conn.executemany(sql, values)
    return len(values)


def get_state(conn, source, path):
    row = conn.execute(
        "SELECT file_inode, byte_offset FROM ingest_state WHERE source = ?", (source,)
    ).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO ingest_state (source, file_path, file_inode, byte_offset, updated_at)"
            " VALUES (?, ?, NULL, 0, ?)",
            (source, path, time.time()),
        )
        conn.commit()
        return None, 0
    return row["file_inode"], row["byte_offset"]


def save_state(conn, source, path, inode, offset):
    conn.execute(
        "UPDATE ingest_state SET file_path = ?, file_inode = ?, byte_offset = ?,"
        " updated_at = ? WHERE source = ?",
        (path, inode, offset, time.time(), source),
    )


def read_eve(conn):
    """Read whatever is new in eve.json and store it. Returns (read, saved, errors)."""
    if not os.path.exists(EVE_PATH):
        return 0, 0, 0

    stat = os.stat(EVE_PATH)
    saved_inode, offset = get_state(conn, "suricata", EVE_PATH)

    # A different inode means the file was rotated: start from the beginning.
    # A smaller file at the same inode means it was truncated: same response.
    if saved_inode is not None and saved_inode != stat.st_ino:
        print("eve.json rotated - restarting from the beginning", flush=True)
        offset = 0
    elif offset > stat.st_size:
        print("eve.json truncated - restarting from the beginning", flush=True)
        offset = 0

    read = errors = 0
    rows = []
    with open(EVE_PATH, "r") as fh:
        fh.seek(offset)
        for line in fh:
            # A partial final line means Suricata is mid-write. Stop here and
            # pick it up next pass rather than storing a corrupt record.
            if not line.endswith("\n"):
                break
            read += 1
            try:
                event = json.loads(line)
            except Exception:
                errors += 1
                continue
            if event.get("event_type") in SKIP_TYPES:
                continue
            rows.append(flatten_suricata(event))
        offset = fh.tell()

    saved = insert_events(conn, rows)
    save_state(conn, "suricata", EVE_PATH, stat.st_ino, offset)
    conn.execute(
        "UPDATE ingest_stats SET events_read = events_read + ?,"
        " events_saved = events_saved + ?, parse_errors = parse_errors + ?,"
        " last_run = ? WHERE id = 1",
        (read, saved, errors, time.time()),
    )
    conn.commit()
    return read, saved, errors



def to_epoch_agh(timestamp):
    """AdGuard timestamps look like '2026-09-12T00:37:50.376866267Z' - RFC3339
    with nanosecond precision, which Python's fromisoformat cannot parse
    directly (it wants microseconds, and a real +00:00 offset, not 'Z')."""
    from datetime import datetime
    try:
        # Truncate sub-second digits to 6 (microseconds) and normalise 'Z'.
        head, _, frac_and_zone = timestamp.partition(".")
        frac = frac_and_zone.rstrip("Z")[:6].ljust(6, "0")
        return datetime.fromisoformat(head + "." + frac + "+00:00").timestamp()
    except Exception:
        return time.time()


def flatten_agh(entry):
    """
    Turn one AdGuard Home querylog line into a flat event row.

    This is a genuinely different signal from Suricata's own 'dns' event type:
    Suricata sees that a query was made; AdGuard reports whether its own
    filtering decision blocked it. Keeping event_type='dns_query' (source=
    'adguard') separate from Suricata's 'dns' (source='suricata') avoids
    conflating "a query happened" with "a query was blocked".
    """
    result = entry.get("Result") or {}
    row = {
        "ts": to_epoch_agh(entry.get("T", "")),
        "ts_iso": entry.get("T"),
        "source": "adguard",
        "event_type": "dns_query",
        "src_ip": entry.get("IP"),
        "proto": "udp",
        "dns_type": "query",
        "dns_rrname": entry.get("QH"),
        "dns_rrtype": entry.get("QT"),
        "blocked": 1 if result.get("IsFiltered") else 0,
    }
    rules = result.get("Rules") or []
    if rules:
        row["block_reason"] = rules[0].get("Text")
    return row


def read_agh_querylog(conn):
    """Read whatever is new in AdGuard's querylog.json. Same watermark and
    rotation-by-inode approach as read_eve - see its docstring."""
    if not os.path.exists(AGH_QUERYLOG_PATH):
        return 0, 0, 0

    stat = os.stat(AGH_QUERYLOG_PATH)
    saved_inode, offset = get_state(conn, "adguard", AGH_QUERYLOG_PATH)

    if saved_inode is not None and saved_inode != stat.st_ino:
        print("querylog.json rotated - restarting from the beginning", flush=True)
        offset = 0
    elif offset > stat.st_size:
        offset = 0

    read = errors = 0
    rows = []
    with open(AGH_QUERYLOG_PATH, "r") as fh:
        fh.seek(offset)
        for line in fh:
            if not line.endswith("\n"):
                break
            read += 1
            try:
                entry = json.loads(line)
            except Exception:
                errors += 1
                continue
            rows.append(flatten_agh(entry))
        offset = fh.tell()

    saved = insert_events(conn, rows)
    save_state(conn, "adguard", AGH_QUERYLOG_PATH, stat.st_ino, offset)
    conn.execute(
        "UPDATE ingest_stats SET events_read = events_read + ?,"
        " events_saved = events_saved + ?, parse_errors = parse_errors + ?,"
        " last_run = ? WHERE id = 1",
        (read, saved, errors, time.time()),
    )
    conn.commit()
    return read, saved, errors


def main():
    conn = open_db()
    print("ingest started, polling every %ds" % POLL_SECONDS, flush=True)
    total = 0
    cycle = 0
    while True:
        try:
            # Refresh the device registry before reading events, so a device
            # that just got a lease is already known when its events arrive.
            # Leases change slowly, so this runs every fifth pass rather than
            # re-reading the same file every two seconds.
            if cycle % 5 == 0:
                registry.update_devices(conn)
            cycle += 1

            read, saved, errors = read_eve(conn)
            a_read, a_saved, a_errors = read_agh_querylog(conn)
            saved += a_saved
            errors += a_errors
            total += saved

            # Attach events to devices. Done after insertion rather than
            # during it, because an event may arrive fractionally before the
            # lease that explains it - this way it gets picked up next pass
            # instead of being permanently unattributed.
            attributed = registry.attribute_events(conn)

            if saved:
                print("stored %d events (total %d), attributed %d%s" % (
                    saved, total, attributed,
                    ", %d parse errors" % errors if errors else ""
                ), flush=True)
        except Exception as exc:
            # Never let one bad pass kill the service; report and carry on.
            print("ingest error: %s" % exc, file=sys.stderr, flush=True)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()

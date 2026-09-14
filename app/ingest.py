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
import re
import sqlite3
import subprocess
import sys
import time

import adguard
import registry

DB_PATH = "/opt/securepi/securepi.db"
SCHEMA_PATH = "/opt/securepi/schema.sql"
EVE_PATH = "/var/log/suricata/eve.json"
AGH_QUERYLOG_PATH = "/opt/AdGuardHome/data/querylog.json"
AGH_API_PAGE_SIZE = 500  # comfortably covers real accumulation between 2s polls - see read_agh_api's docstring
AGH_WATERMARK_STARTUP_LOOKBACK_SECONDS = 300  # first-ever run: start 5 minutes back, not from epoch 0
DPI_EVENTS_PATH = "/var/log/securepi/dpi-events.jsonl"
NFT_LOG_STARTUP_LOOKBACK_SECONDS = 300  # same first-run convention as AdGuard's watermark above

# Schema changes made after the Day 14 database was already created on the
# gateway. schema.sql already lists these for a FRESH install (open_db()
# below runs it in full when the events table doesn't exist yet), but the
# live gateway's existing database needs each one applied by hand.
#
# ALTER TABLE statements are wrapped in try/except because SQLite has no
# "ADD COLUMN IF NOT EXISTS" - only the "duplicate column" error (meaning
# it was already applied, on a later run of this same code) is swallowed;
# any other error still surfaces. CREATE TABLE/INDEX IF NOT EXISTS
# statements (step 6.1's device_hourly) need no such handling - they are
# already idempotent by construction, so a plain execute() is enough.
SCHEMA_MIGRATIONS = [
    "ALTER TABLE events ADD COLUMN dns_filter_list_id INTEGER",
    "ALTER TABLE events ADD COLUMN dns_cached INTEGER",
    "ALTER TABLE events ADD COLUMN dns_upstream TEXT",
    "ALTER TABLE events ADD COLUMN dns_elapsed_ms REAL",
    "ALTER TABLE events ADD COLUMN dpi_action TEXT",
    "ALTER TABLE events ADD COLUMN dpi_ads_removed INTEGER",
    """CREATE TABLE IF NOT EXISTS device_hourly (
           device_id   INTEGER NOT NULL REFERENCES devices(id),
           hour_start  INTEGER NOT NULL,
           bytes_down  INTEGER NOT NULL DEFAULT 0,
           bytes_up    INTEGER NOT NULL DEFAULT 0,
           dns_queries INTEGER NOT NULL DEFAULT 0,
           dns_blocked INTEGER NOT NULL DEFAULT 0,
           flows       INTEGER NOT NULL DEFAULT 0,
           PRIMARY KEY (device_id, hour_start)
       )""",
    "CREATE INDEX IF NOT EXISTS idx_device_hourly_hour ON device_hourly(hour_start)",
    "ALTER TABLE events ADD COLUMN dhcp_params TEXT",
    """CREATE TABLE IF NOT EXISTS settings (
           key        TEXT PRIMARY KEY,
           value      TEXT NOT NULL,
           updated_at REAL NOT NULL
       )""",
    """CREATE TABLE IF NOT EXISTS audit_log (
           id     INTEGER PRIMARY KEY,
           ts     REAL NOT NULL,
           actor  TEXT NOT NULL,
           action TEXT NOT NULL,
           target TEXT,
           detail TEXT
       )""",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts)",
    """CREATE TABLE IF NOT EXISTS incident_notes (
           id          INTEGER PRIMARY KEY,
           incident_id INTEGER NOT NULL REFERENCES incidents(id),
           ts          REAL NOT NULL,
           author      TEXT NOT NULL,
           note        TEXT NOT NULL
       )""",
    "CREATE INDEX IF NOT EXISTS idx_incident_notes_incident ON incident_notes(incident_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_dest_ip ON events(dest_ip)",
    "ALTER TABLE ingest_state ADD COLUMN watermark_ts REAL",
    """CREATE TABLE IF NOT EXISTS saved_searches (
           id         INTEGER PRIMARY KEY,
           name       TEXT NOT NULL,
           filters    TEXT NOT NULL,
           created_at REAL NOT NULL
       )""",
    """CREATE TABLE IF NOT EXISTS ioc (
           id          INTEGER PRIMARY KEY,
           indicator   TEXT NOT NULL,
           ioc_type    TEXT NOT NULL,
           source      TEXT NOT NULL,
           description TEXT,
           first_seen  REAL NOT NULL,
           last_seen   REAL NOT NULL,
           UNIQUE (indicator, ioc_type, source)
       )""",
    "CREATE INDEX IF NOT EXISTS idx_ioc_indicator ON ioc(indicator, ioc_type)",
    """CREATE TABLE IF NOT EXISTS intel_feed_state (
           source          TEXT PRIMARY KEY,
           last_fetched    REAL,
           last_error      TEXT,
           indicator_count INTEGER
       )""",
]

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
    apply_migrations(conn)
    return conn


def apply_migrations(conn):
    """Bring an existing database up to date with columns schema.sql has
    grown since it was created. Safe to call every startup: an already-
    applied statement fails with 'duplicate column name', which is the one
    error this deliberately ignores."""
    for stmt in SCHEMA_MIGRATIONS:
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError as e:
            if "duplicate column" not in str(e):
                raise
    conn.commit()


def parse_rfc3339(timestamp):
    """
    Parse an RFC3339 timestamp with nanosecond-or-fewer fractional precision
    and either a 'Z' suffix or an explicit +/-HH:MM offset (colon optional),
    returning epoch seconds.

    A real bug, found and fixed as part of step 1.4: this project's two
    timestamp parsers previously disagreed about what format they'd even
    see, and one of them was silently wrong as a result.

    - Suricata's own eve.json docstring example claimed '+0000' (UTC).
      Checked live against this gateway's real eve.json: it is actually
      '2026-09-14T03:53:12.151693+0530' - the system's local IST offset,
      not UTC, and without a colon. `datetime.fromisoformat()` rejects
      that (no colon) on any Python version, so every event was silently
      falling through to a fallback that discarded the offset entirely
      and treated the naive wall-clock value as system-local time. That
      happened to produce the right answer ONLY because this gateway's
      own system timezone is also Asia/Kolkata (+05:30) - confirmed live
      via `timedatectl` - a coincidence any future redeploy in a
      different timezone would silently break.
    - AdGuard's querylog (both the on-disk file AND the /control/querylog
      API - checked both live) returns a MIX of 'Z' and explicit-offset
      timestamps in the same response/file, not always 'Z' as the old
      code assumed. The old `to_epoch_agh` built its own string with a
      HARDCODED '+00:00' regardless of the source timestamp's real
      offset - for a '+05:30' entry, that is a genuine, deterministic
      5.5-hour error, confirmed by computing both the buggy and correct
      epoch for the same real timestamp and comparing.

    One shared, tested parser now backs both Suricata and AdGuard
    ingestion, handling any offset form rather than assuming one.
    """
    from datetime import datetime
    try:
        if timestamp.endswith("Z"):
            body, offset = timestamp[:-1], "+00:00"
        else:
            # The offset's sign is the LAST +/- in the string - searching
            # from the end avoids matching the date portion's own hyphens
            # ("2026-09-14T..."), which always precede any real offset.
            sign_pos = max(timestamp.rfind("+"), timestamp.rfind("-"))
            body, offset = timestamp[:sign_pos], timestamp[sign_pos:]
            if ":" not in offset:  # "+0530" -> "+05:30"
                offset = offset[:3] + ":" + offset[3:]
        head, _, frac = body.partition(".")
        frac = (frac[:6] if frac else "").ljust(6, "0")
        return datetime.fromisoformat("%s.%s%s" % (head, frac, offset)).timestamp()
    except Exception:
        return time.time()


def to_epoch(timestamp):
    """Convert Suricata's eve.json timestamp to epoch seconds. See
    parse_rfc3339's own docstring for the real bug this used to have."""
    return parse_rfc3339(timestamp)


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

    # DHCP option 55 (the Parameter Request List) - step 6.2 device
    # fingerprinting evidence. Only present once suricata.yaml's dhcp
    # logger is in "extended" mode (enabled this step; confirmed live via
    # `suricata -T` before the restart). `.get("params")` is Suricata's
    # documented field name for this list, but NOT yet confirmed against
    # a real extended-mode event on this gateway - no device has renewed
    # its DHCP lease since extended mode was turned on, and forcing one
    # would mean disconnecting a real device mid-session. Written
    # defensively so a wrong field name is a silent no-op (column stays
    # NULL), never an ingest crash - see ENHANCEMENT-PLAN.md step 6.2 for
    # what still needs confirming next time a real lease renews.
    dhcp = event.get("dhcp") or {}
    if dhcp and dhcp.get("params"):
        params = dhcp["params"]
        row["dhcp_params"] = ",".join(str(p) for p in params) if isinstance(params, list) else str(params)

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
        "dns_filter_list_id", "dns_cached", "dns_upstream", "dns_elapsed_ms",
        "dpi_action", "dpi_ads_removed",
        "dhcp_params",
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
    """Convert an AdGuard Home timestamp (file querylog or the
    /control/querylog API - both seen live to return a MIX of 'Z' and
    explicit-offset forms) to epoch seconds. See parse_rfc3339's own
    docstring for the real 5.5-hour bug this function used to have."""
    return parse_rfc3339(timestamp)


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
        # Telemetry for the ad-blocking analytics and list-health pages
        # (ENHANCEMENT-PLAN.md 5.3, 5.4): which list matched, whether the
        # answer came from AdGuard's cache, which upstream resolver
        # answered (only meaningful when not cached), and how long that
        # took. "Elapsed" arrives in nanoseconds; we store milliseconds,
        # which is the unit every other latency figure in this project uses.
        "dns_cached": 1 if entry.get("Cached") else 0,
        "dns_upstream": entry.get("Upstream") or None,
        "dns_elapsed_ms": (entry.get("Elapsed") or 0) / 1_000_000.0 or None,
    }
    rules = result.get("Rules") or []
    if rules:
        row["block_reason"] = rules[0].get("Text")
        row["dns_filter_list_id"] = rules[0].get("FilterListID")
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


def flatten_agh_api(entry, ts=None):
    """Turn one /control/querylog API entry into a flat events-table row -
    a DIFFERENT shape from the on-disk file's own format (flatten_agh
    above), confirmed live against the real API (both a blocked and an
    allowed real entry fetched and inspected directly, not guessed):
    'client'/'question.name'/'question.type' instead of 'IP'/'QH'/'QT',
    a top-level 'rule' string plus a 'rules' array instead of nested
    'Result.Rules', 'elapsedMs' as a MILLISECOND STRING ('7.459497')
    instead of 'Elapsed' nanoseconds, and 'cached'/'upstream' at the top
    level instead of nested under 'Result'.

    Blocked-vs-allowed comes from 'reason': AdGuard's own documented
    naming convention is that every 'Filtered*' reason means blocked and
    every 'NotFiltered*' reason means allowed. Confirmed live against
    the two reasons this gateway actually produces
    (FilteredBlackList, NotFilteredNotFound) - the fuller reason enum
    (safe browsing, parental control, safe search, custom rule,
    rewrite...) was not each individually exercised live, since none of
    those features are enabled on this gateway. Followed here as a
    stated interpretation of AdGuard's own convention, not a guess."""
    question = entry.get("question") or {}
    rules = entry.get("rules") or []
    reason = entry.get("reason") or ""
    row = {
        "ts": ts if ts is not None else parse_rfc3339(entry.get("time", "")),
        "ts_iso": entry.get("time"),
        "source": "adguard",
        "event_type": "dns_query",
        "src_ip": entry.get("client"),
        "proto": "udp",
        "dns_type": "query",
        "dns_rrname": question.get("name"),
        "dns_rrtype": question.get("type"),
        "blocked": 1 if reason.startswith("Filtered") else 0,
        "dns_cached": 1 if entry.get("cached") else 0,
        "dns_upstream": entry.get("upstream") or None,
    }
    try:
        elapsed_ms = float(entry.get("elapsedMs") or 0)
        if elapsed_ms:
            row["dns_elapsed_ms"] = elapsed_ms
    except (TypeError, ValueError):
        pass
    if rules:
        row["block_reason"] = rules[0].get("text")
        row["dns_filter_list_id"] = rules[0].get("filter_list_id")
    return row


def get_agh_watermark(conn):
    row = conn.execute(
        "SELECT watermark_ts FROM ingest_state WHERE source='adguard_api'"
    ).fetchone()
    if row is not None and row["watermark_ts"] is not None:
        return row["watermark_ts"]
    start = time.time() - AGH_WATERMARK_STARTUP_LOOKBACK_SECONDS
    conn.execute(
        "INSERT INTO ingest_state (source, file_path, file_inode, byte_offset, watermark_ts, updated_at)"
        " VALUES ('adguard_api', '(control API)', NULL, 0, ?, ?)"
        " ON CONFLICT(source) DO UPDATE SET watermark_ts=excluded.watermark_ts",
        (start, time.time()),
    )
    conn.commit()
    return start


def set_agh_watermark(conn, ts):
    conn.execute(
        "UPDATE ingest_state SET watermark_ts=?, updated_at=? WHERE source='adguard_api'",
        (ts, time.time()),
    )


def read_agh_api(conn):
    """Poll AdGuard's /control/querylog API - real-time, not gated on
    AdGuard's own flush-to-disk cadence the way tailing querylog.json is
    (confirmed live in EVALUATION-RESULTS.md: the on-disk file can sit
    unwritten for 7+ hours under real traffic, because AdGuard only
    flushes when its 1000-entry in-memory buffer rotates - the exact gap
    this step exists to close). Raises adguard.AdGuardError if the admin
    API can't be reached; read_agh() below catches that and falls back
    to the file reader for that cycle, per this step's own "file reader
    kept as fallback".

    No cursor/pagination beyond one page per poll: at this project's
    real event volume (measured live - see ENHANCEMENT-PLAN.md step
    6.6's note: roughly 950 DNS queries/day network-wide, under 1/minute
    on average) one page of AGH_API_PAGE_SIZE entries per 2-second poll
    comfortably covers what actually accumulates between polls. A gap
    larger than one page between polls (the service down for a while, or
    a genuine traffic spike) would silently skip the overflow rather
    than page forward to catch up - a real, stated limitation, not a
    silent one; the fallback-to-file path would separately still pick up
    what the API poll missed, subject to the file's OWN latency
    characteristics.
    """
    watermark = get_agh_watermark(conn)
    resp = adguard._request("GET", "/control/querylog?limit=%d" % AGH_API_PAGE_SIZE)
    data = (resp or {}).get("data") or []

    rows = []
    newest = watermark
    seen_this_page = set()
    for entry in data:
        ts = parse_rfc3339(entry.get("time", ""))
        if ts <= watermark:
            continue
        # A defensive duplicate guard within one fetched page - the API
        # has no stable per-entry id to key on, so this is the best
        # available "have I already queued this exact entry" check.
        dedup_key = (ts, entry.get("client"), (entry.get("question") or {}).get("name"))
        if dedup_key in seen_this_page:
            continue
        seen_this_page.add(dedup_key)
        rows.append(flatten_agh_api(entry, ts))
        if ts > newest:
            newest = ts

    saved = insert_events(conn, rows)
    if newest > watermark:
        set_agh_watermark(conn, newest)
    conn.execute(
        "UPDATE ingest_stats SET events_read = events_read + ?,"
        " events_saved = events_saved + ?, last_run = ? WHERE id = 1",
        (len(data), saved, time.time()),
    )
    conn.commit()
    return len(data), saved, 0


def read_agh(conn):
    """Try the real-time /control/querylog API first; fall back to
    tailing the on-disk file if AdGuard's admin API can't be reached
    right now (e.g. AdGuard itself restarting) - step 1.4's own "file
    reader kept as fallback"."""
    try:
        return read_agh_api(conn)
    except adguard.AdGuardError as e:
        print("AdGuard API unreachable (%s) - falling back to file tailing this cycle" % e, flush=True)
        return read_agh_querylog(conn)


def flatten_dpi(entry):
    """Turn one structured line from the DPI addon's telemetry log (see
    dpi/securepi_adfilter.py's _log_event) into an events row. Reuses the
    generic events shape - source='dpi', event_type='dpi_decision' - rather
    than a bespoke table, the same reasoning schema.sql's header gives for
    keeping Suricata and AdGuard on one table."""
    return {
        "ts": entry.get("ts") or time.time(),
        "ts_iso": entry.get("ts_iso"),
        "source": "dpi",
        "event_type": "dpi_decision",
        "src_ip": entry.get("src_ip"),
        "tls_sni": entry.get("sni"),
        "dpi_action": entry.get("decision"),
        "dpi_ads_removed": entry.get("ads_removed"),
        "block_reason": entry.get("blocked_path"),
    }


def read_dpi_events(conn):
    """Read whatever is new in the DPI addon's telemetry log. Same
    watermark and rotation-by-inode approach as read_eve and
    read_agh_querylog - see read_eve's docstring. The file may not exist at
    all when Tier 2 (selective HTTPS inspection) has never been deployed on
    this gateway, which is the normal, expected case for most of this
    project's life - that's a quiet no-op here, not an error."""
    if not os.path.exists(DPI_EVENTS_PATH):
        return 0, 0, 0

    stat = os.stat(DPI_EVENTS_PATH)
    saved_inode, offset = get_state(conn, "dpi", DPI_EVENTS_PATH)

    if saved_inode is not None and saved_inode != stat.st_ino:
        offset = 0
    elif offset > stat.st_size:
        offset = 0

    read = errors = 0
    rows = []
    with open(DPI_EVENTS_PATH, "r") as fh:
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
            rows.append(flatten_dpi(entry))
        offset = fh.tell()

    saved = insert_events(conn, rows)
    save_state(conn, "dpi", DPI_EVENTS_PATH, stat.st_ino, offset)
    conn.execute(
        "UPDATE ingest_stats SET events_read = events_read + ?,"
        " events_saved = events_saved + ?, parse_errors = parse_errors + ?,"
        " last_run = ? WHERE id = 1",
        (read, saved, errors, time.time()),
    )
    conn.commit()
    return read, saved, errors


# ------------------------------------------------------------- nftables log
# ENHANCEMENT-PLAN.md step 2.2: the DNS-bypass reject rules in
# gateway/nftables.conf's forward chain (dot-bypass, doh-bypass,
# quic-blocked) now each carry a `log prefix` - see that file. nftables'
# `log` statement with no `group` writes straight to the kernel ring
# buffer (`dmesg`), which journald already captures as the kernel's own
# log stream - no new daemon, no nflog socket, no extra dependency, in
# keeping with this project's "plain Python, minimal moving parts"
# design. Read via `journalctl -k`, the same "poll by watermark, not by
# tailing a growing file" shape as read_agh_api - journalctl isn't a
# plain file with a stable inode to seek in, so a timestamp watermark is
# the natural fit here too, not the inode-and-offset approach read_eve
# and read_dpi_events use.
NFT_LOG_PREFIXES = ("dot-bypass: ", "doh-bypass: ", "quic-blocked: ")
# A standard iptables/nftables kernel log line, e.g.:
#   dot-bypass: IN=ap0 OUT=wlp2s0 ... SRC=10.10.0.50 DST=1.1.1.1 ...
#   PROTO=TCP SPT=51000 DPT=853 ...
NFT_LOG_FIELD_RE = re.compile(r"\b(SRC|DST|PROTO|SPT|DPT)=(\S+)")


def flatten_nft_log(message):
    """Parse one kernel log line from the reject rules above into an
    events row, or None if this line isn't one of ours (journalctl -k
    carries every kernel message, not just nftables') or doesn't parse.
    source='nftables', event_type='bypass_attempt' - a new combination on
    the existing generic events shape, not a bespoke table (this file's
    own header/schema.sql's own header give the same reasoning for
    dpi_decision rows). block_reason carries which rule matched
    ('dot-bypass' etc.) - the same field's existing job (Tier 1's "why
    was this blocked?") extended to a second, related meaning: why was
    this connection attempt rejected."""
    prefix = next((p for p in NFT_LOG_PREFIXES if p in message), None)
    if prefix is None:
        return None
    fields = dict(NFT_LOG_FIELD_RE.findall(message))
    if "SRC" not in fields:
        return None  # not a real match for our rules' expected shape
    dest_port = fields.get("DPT")
    return {
        "ts": time.time(),  # overwritten by the real journal timestamp by the caller
        "ts_iso": None,
        "source": "nftables",
        "event_type": "bypass_attempt",
        "src_ip": fields["SRC"],
        "dest_ip": fields.get("DST"),
        "dest_port": int(dest_port) if dest_port and dest_port.isdigit() else None,
        "proto": fields.get("PROTO"),
        "block_reason": prefix.rstrip(": "),
    }


def get_nft_log_watermark(conn):
    row = conn.execute(
        "SELECT watermark_ts FROM ingest_state WHERE source='nftables'"
    ).fetchone()
    if row is not None and row["watermark_ts"] is not None:
        return row["watermark_ts"]
    start = time.time() - NFT_LOG_STARTUP_LOOKBACK_SECONDS
    conn.execute(
        "INSERT INTO ingest_state (source, file_path, file_inode, byte_offset, watermark_ts, updated_at)"
        " VALUES ('nftables', '(journalctl -k)', NULL, 0, ?, ?)"
        " ON CONFLICT(source) DO UPDATE SET watermark_ts=excluded.watermark_ts",
        (start, time.time()),
    )
    conn.commit()
    return start


def set_nft_log_watermark(conn, ts):
    conn.execute(
        "UPDATE ingest_state SET watermark_ts=?, updated_at=? WHERE source='nftables'",
        (ts, time.time()),
    )


def read_nft_log(conn):
    """Poll the kernel log for new DNS-bypass reject-rule hits since the
    last watermark. Returns (0, 0, 0) rather than raising if journalctl
    itself fails (e.g. permissions, or running somewhere without a
    journal at all, like a test sandbox) - a missing detection source for
    one cycle should never take the whole ingest loop down, the same
    principle main()'s own try/except already applies at the top level."""
    watermark = get_nft_log_watermark(conn)
    try:
        result = subprocess.run(
            ["journalctl", "-k", "-o", "json", "--no-pager", "--since=@%d" % int(watermark)],
            capture_output=True, text=True, timeout=10,
        )
    except Exception as exc:
        print("read_nft_log: journalctl failed: %s" % exc, file=sys.stderr, flush=True)
        return 0, 0, 0

    read = errors = 0
    rows = []
    newest = watermark
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            errors += 1
            continue
        message = rec.get("MESSAGE")
        if not isinstance(message, str):
            continue
        # __REALTIME_TIMESTAMP is microseconds-since-epoch, as a string.
        try:
            ts = int(rec.get("__REALTIME_TIMESTAMP", 0)) / 1_000_000.0
        except (TypeError, ValueError):
            continue
        if ts <= watermark:
            continue  # journalctl's --since is second-granularity; re-filter precisely
        read += 1
        row = flatten_nft_log(message)
        if row is None:
            continue
        row["ts"] = ts
        row["ts_iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
        rows.append(row)
        if ts > newest:
            newest = ts

    saved = insert_events(conn, rows)
    if newest > watermark:
        set_nft_log_watermark(conn, newest)
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
            a_read, a_saved, a_errors = read_agh(conn)
            d_read, d_saved, d_errors = read_dpi_events(conn)
            saved += a_saved + d_saved
            errors += a_errors + d_errors
            # read_nft_log spawns a journalctl subprocess, unlike every other
            # reader here (a pure Python file read or HTTP call) - real but
            # small overhead that a bypass attempt's own rarity doesn't need
            # paid every 2s. Every fifth cycle (~10s), the same cadence as
            # the lease refresh just above, keeps detection latency well
            # under dns_bypass_signal's own window while cutting the
            # subprocess spawn rate by 5x.
            if cycle % 5 == 0:
                n_read, n_saved, n_errors = read_nft_log(conn)
                saved += n_saved
                errors += n_errors
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

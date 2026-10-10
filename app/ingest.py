#!/usr/bin/env python3
"""
SecurePi Gateway - event ingest service.

Reads the IDS's eve.json and the DNS resolver's query log, converts every
record into the one shared event shape defined in schema.sql, and stores it.

Design notes worth knowing:

  * It remembers its position in each file (see the ingest_state table), so a
    restart neither re-reads old events nor skips new ones.

  * It watches for log rotation by inode, not by size. The IDS replaces
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
import urllib.parse

import adguard
import dbconn
import health
import registry

DB_PATH = "/var/lib/securepi/securepi.db"
SCHEMA_PATH = "/opt/securepi/schema.sql"
EVE_PATH = "/var/log/suricata/eve.json"
AGH_QUERYLOG_PATH = "/opt/AdGuardHome/data/querylog.json"
AGH_API_PAGE_SIZE = 500  # comfortably covers real accumulation between 2s polls - see read_agh_api's docstring
AGH_API_MAX_PAGES = 20   # up to 10,000 entries per poll when catching up after a gap (restart, outage)
# A backlog bigger than AGH_API_MAX_PAGES pages is drained over the next
# polls, this many older pages per poll (Audit10Oct H2) - see read_agh_api.
AGH_CATCHUP_PAGES_PER_POLL = 10
AGH_WATERMARK_STARTUP_LOOKBACK_SECONDS = 300  # first-ever run: start 5 minutes back, not from epoch 0
DPI_EVENTS_PATH = "/var/log/securepi/dpi-events.jsonl"
NFT_LOG_STARTUP_LOOKBACK_SECONDS = 300  # same first-run convention as the DNS filter's watermark above

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
    # Audit10Oct H2: an unfinished DNS backlog - see read_agh_api.
    "ALTER TABLE ingest_state ADD COLUMN catchup_cursor TEXT",
    "ALTER TABLE ingest_state ADD COLUMN catchup_floor REAL",
    "ALTER TABLE ingest_state ADD COLUMN catchup_ceiling REAL",
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
    """CREATE TABLE IF NOT EXISTS suppressions (
           id          INTEGER PRIMARY KEY,
           signal_type TEXT NOT NULL,
           device_id   INTEGER REFERENCES devices(id),
           reason      TEXT NOT NULL,
           created_by  TEXT NOT NULL,
           created_at  REAL NOT NULL,
           expires_at  REAL
       )""",
    "CREATE INDEX IF NOT EXISTS idx_suppressions_signal_device ON suppressions(signal_type, device_id)",
    """CREATE TABLE IF NOT EXISTS campaigns (
           id         INTEGER PRIMARY KEY,
           device_id  INTEGER NOT NULL REFERENCES devices(id),
           title      TEXT NOT NULL,
           status     TEXT NOT NULL DEFAULT 'new',
           tactics    TEXT NOT NULL,
           first_seen REAL NOT NULL,
           last_seen  REAL NOT NULL,
           created_at REAL NOT NULL,
           updated_at REAL NOT NULL
       )""",
    "CREATE INDEX IF NOT EXISTS idx_campaigns_device ON campaigns(device_id)",
    "ALTER TABLE incidents ADD COLUMN campaign_id INTEGER REFERENCES campaigns(id)",
    """CREATE TABLE IF NOT EXISTS sessions (
           token       TEXT PRIMARY KEY,
           username    TEXT NOT NULL,
           created_at  REAL NOT NULL,
           last_active REAL NOT NULL,
           expires_at  REAL NOT NULL
       )""",
    "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)",
    """CREATE TABLE IF NOT EXISTS login_attempts (
           id INTEGER PRIMARY KEY,
           ip TEXT NOT NULL,
           ts REAL NOT NULL
       )""",
    "CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_ts ON login_attempts(ip, ts)",
    """CREATE TABLE IF NOT EXISTS sensor_stats (
           id             INTEGER PRIMARY KEY,
           ts             REAL NOT NULL,
           kernel_packets INTEGER,
           kernel_drops   INTEGER,
           capture_errors INTEGER
       )""",
    """CREATE TABLE IF NOT EXISTS service_health (
           service      TEXT PRIMARY KEY,
           checked_at   REAL NOT NULL,
           is_active    INTEGER,
           memory_bytes INTEGER,
           cpu_seconds  REAL
       )""",
    """CREATE TABLE IF NOT EXISTS dns_failopen_state (
           id         INTEGER PRIMARY KEY CHECK (id = 1),
           active     INTEGER NOT NULL DEFAULT 0,
           down_since REAL,
           changed_at REAL
       )""",
    "INSERT OR IGNORE INTO dns_failopen_state (id, active, down_since, changed_at) VALUES (1, 0, NULL, NULL)",
    # ENHANCEMENT-PLAN.md Stage 4. The trust column's DEFAULT here is
    # 'approved', not schema.sql's 'unknown', on purpose: this ALTER only
    # ever runs once, against a database that already has devices, and
    # those devices were on the network before trust states existed - so
    # they're grandfathered in rather than suddenly treated as strangers.
    # registry.py sets 'unknown' explicitly for every device it creates
    # from now on, so this default never applies to a new device.
    "ALTER TABLE devices ADD COLUMN trust TEXT NOT NULL DEFAULT 'approved'",
    """CREATE TABLE IF NOT EXISTS policies (
           id               INTEGER PRIMARY KEY,
           kind             TEXT NOT NULL,
           device_id        INTEGER REFERENCES devices(id),
           target           TEXT,
           reason           TEXT NOT NULL,
           source           TEXT NOT NULL,
           created_by       TEXT NOT NULL,
           created_at       REAL NOT NULL,
           expires_at       REAL,
           status           TEXT NOT NULL,
           ended_at         REAL,
           ended_by         TEXT,
           ended_reason     TEXT,
           applied_state    TEXT,
           last_verified_at REAL,
           last_error       TEXT
       )""",
    "CREATE INDEX IF NOT EXISTS idx_policies_status ON policies(status, kind)",
    "CREATE INDEX IF NOT EXISTS idx_policies_device ON policies(device_id)",
    """CREATE TABLE IF NOT EXISTS orchestrator_state (
           id         INTEGER PRIMARY KEY CHECK (id = 1),
           applied    TEXT NOT NULL DEFAULT '{}',
           boot_id    TEXT,
           last_run   REAL,
           last_ok    REAL,
           last_error TEXT,
           domains    TEXT NOT NULL DEFAULT '{}',
           extra      TEXT NOT NULL DEFAULT '{}'
       )""",
    "INSERT OR IGNORE INTO orchestrator_state (id) VALUES (1)",
    """CREATE TABLE IF NOT EXISTS filter_profiles (
           key        TEXT PRIMARY KEY,
           config     TEXT NOT NULL,
           updated_at REAL NOT NULL
       )""",
    """CREATE TABLE IF NOT EXISTS notification_channels (
           id            INTEGER PRIMARY KEY,
           kind          TEXT NOT NULL,
           name          TEXT NOT NULL,
           config        TEXT NOT NULL,
           min_severity  TEXT NOT NULL DEFAULT 'medium',
           enabled       INTEGER NOT NULL DEFAULT 1,
           created_at    REAL NOT NULL,
           updated_at    REAL NOT NULL,
           last_sent_at  REAL,
           last_error    TEXT,
           last_error_at REAL
       )""",
    """CREATE TABLE IF NOT EXISTS notifications (
           id          INTEGER PRIMARY KEY,
           channel_id  INTEGER NOT NULL REFERENCES notification_channels(id),
           incident_id INTEGER REFERENCES incidents(id),
           ts          REAL NOT NULL,
           status      TEXT NOT NULL,
           attempts    INTEGER NOT NULL DEFAULT 0,
           title       TEXT,
           detail      TEXT,
           UNIQUE (channel_id, incident_id)
       )""",
    "CREATE INDEX IF NOT EXISTS idx_notifications_channel_ts ON notifications(channel_id, ts)",
    """CREATE TABLE IF NOT EXISTS notify_state (
           id               INTEGER PRIMARY KEY CHECK (id = 1),
           last_incident_id INTEGER,
           last_digest_at   REAL
       )""",
    "INSERT OR IGNORE INTO notify_state (id, last_incident_id, last_digest_at) VALUES (1, NULL, NULL)",
    # Step 7.2: when a flow STARTED. `ts` on a flow record is when the IDS
    # logged it - after the flow timed out, in batches whenever its flow
    # manager wakes - so the gaps between ts values aren't the gaps between
    # connections. beacon_signal() needs the real ones.
    "ALTER TABLE events ADD COLUMN flow_start REAL",
    # ADBLOCK-ENHANCEMENT-PLAN.md B5: which site module a Tier 2 decision
    # belongs to, now that the rules hold more than one site.
    "ALTER TABLE events ADD COLUMN dpi_module TEXT",
]

# How long to wait between passes over the log files. Two seconds keeps the
# console feeling live without spinning the CPU on an idle network.
POLL_SECONDS = 2

# The most lines one pass reads from any one log file (3 October 2026).
# Everything a pass reads is written in a single transaction, and on
# 2 October one pass swallowed ~245,000 harness alerts at once - that one
# write grew the database's write-ahead log to 137 MB, which the next boot
# then had to recover (see app/dbconn.py). 5,000 lines every 2-second poll
# is still 2,500 lines a second, far above anything this network produces;
# a backlog simply drains over a few passes instead of all at once.
MAX_LINES_PER_PASS = 5000

# Event types that are not network events and so do not belong in the
# events table. 'stats' USED to be skipped entirely here - as of step 3.5
# it gets its own handling (save_sensor_stats) instead, since the health
# supervisor needs the IDS's own capture-drop count. Kept as an empty-
# but-present set rather than removed outright, so a genuinely new
# non-network event type has an obvious place to go without having to
# rediscover this exact reasoning.
SKIP_TYPES = set()


def open_db():
    """Open the database, creating it from schema.sql if it does not exist.

    The schema check and migrations are the first things to touch the
    database after a boot, so they run under dbconn.retry_while_locked:
    on 3 October 2026 this exact step crashed ingest with "database is
    locked" while the disk was busy at boot (see app/dbconn.py)."""
    first_time = not os.path.exists(DB_PATH)
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = dbconn.connect(DB_PATH)

    def prepare():
        if first_time or conn.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='events'"
        ).fetchone()[0] == 0:
            with open(SCHEMA_PATH) as fh:
                conn.executescript(fh.read())
            conn.commit()
            print("created database at %s" % DB_PATH, flush=True)
        apply_migrations(conn)

    dbconn.retry_while_locked(prepare, what="ingest start-up")
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

    - The IDS's own eve.json docstring example claimed '+0000' (UTC).
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
    - The DNS filter's querylog (both the on-disk file AND the /control/querylog
      API - checked both live) returns a MIX of 'Z' and explicit-offset
      timestamps in the same response/file, not always 'Z' as the old
      code assumed. The old `to_epoch_agh` built its own string with a
      HARDCODED '+00:00' regardless of the source timestamp's real
      offset - for a '+05:30' entry, that is a genuine, deterministic
      5.5-hour error, confirmed by computing both the buggy and correct
      epoch for the same real timestamp and comparing.

    One shared, tested parser now backs both the IDS and DNS filter
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
        # None, not "now" (Audit10Oct H3): a made-up time gave a broken
        # record a plausible-looking place in the timeline, and could move
        # the DNS watermark past entries not yet imported. Every caller
        # skips a record whose time is None and counts it as a parse error.
        return None


def to_epoch(timestamp):
    """Convert the IDS's eve.json timestamp to epoch seconds. See
    parse_rfc3339's own docstring for the real bug this used to have."""
    return parse_rfc3339(timestamp)


def save_sensor_stats(conn, event):
    """The IDS emits a 'stats' record periodically (every 8s by default) -
    previously discarded entirely via SKIP_TYPES. ENHANCEMENT-PLAN.md step
    3.5 (health supervisor) needs the capture drop count to tell "packets
    are arriving but the kernel is dropping some" apart from "nothing is
    arriving at all" - a single upserted row (matching the ingest_stats/
    signal_state pattern: one current snapshot, not a growing history) is
    all that check needs. capture.kernel_packets/kernel_drops/errors are
    the IDS's own documented stats.capture fields, confirmed against a
    real record on the live gateway before writing this, not guessed."""
    capture = event.get("stats", {}).get("capture", {})
    ts = to_epoch(event["timestamp"])
    if ts is None:
        raise ValueError("stats record with no usable timestamp")
    conn.execute(
        "INSERT INTO sensor_stats (id, ts, kernel_packets, kernel_drops, capture_errors)"
        " VALUES (1, ?, ?, ?, ?)"
        " ON CONFLICT(id) DO UPDATE SET ts=excluded.ts, kernel_packets=excluded.kernel_packets,"
        " kernel_drops=excluded.kernel_drops, capture_errors=excluded.capture_errors",
        (ts, capture.get("kernel_packets"),
         capture.get("kernel_drops"), capture.get("errors")),
    )


def flatten_suricata(event):
    """
    Turn one IDS record into a flat dictionary matching the events table.

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
        if flow.get("start"):
            row["flow_start"] = to_epoch(flow["start"])

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
    # `suricata -T` before the restart). `.get("params")` is the IDS's
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
        "flow_state", "flow_age", "flow_start",
        "dns_type", "dns_rrname", "dns_rrtype", "dns_rcode",
        "tls_sni", "tls_version", "tls_ja3",
        "alert_signature", "alert_category", "alert_severity", "alert_signature_id",
        "blocked", "block_reason",
        "dns_filter_list_id", "dns_cached", "dns_upstream", "dns_elapsed_ms",
        "dpi_action", "dpi_ads_removed", "dpi_module",
        "dhcp_params",
    ]
    # A row missing a column the table requires would make the whole batch
    # fail - and the caller's cursor not move, so the same batch failed on
    # every pass after (Audit10Oct H3). Such a row is dropped on its own.
    required = ("ts", "ts_iso", "source", "event_type")
    complete = [r for r in rows if all(r.get(c) is not None for c in required)]
    if len(complete) != len(rows):
        print("ingest: dropped %d event(s) missing a required field" % (len(rows) - len(complete)),
              file=sys.stderr, flush=True)
    placeholders = ",".join("?" for _ in columns)
    sql = "INSERT INTO events (%s) VALUES (%s)" % (",".join(columns), placeholders)
    values = [tuple(r.get(c) for c in columns) for r in complete]
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


def read_complete_lines(path, offset, max_lines):
    """Read up to `max_lines` complete lines from `path`, starting at byte
    `offset`. Returns (lines, new_offset), where new_offset is just after
    the last complete line read - the place to resume next time.

    Binary mode + readline(), not `for line in fh` in text mode: after
    leaving a text-mode `for` loop early, fh.tell() raises "telling
    position disabled by next() call" - so a half-written last line
    crashed the whole ingest pass (Audit.md H4). Counting the bytes of
    each complete line gives the exact offset to resume from instead."""
    lines = []
    with open(path, "rb") as fh:
        fh.seek(offset)
        while len(lines) < max_lines:
            line = fh.readline()
            # Empty = end of file. No trailing newline = the writer is still
            # writing this line. Either way stop, with `offset` still at
            # the start of the unfinished line, and read it whole next pass.
            if not line.endswith(b"\n"):
                break
            offset += len(line)
            lines.append(line)
    return lines, offset


def read_eve(conn):
    """Read whatever is new in eve.json and store it. Returns (read, saved, errors).

    Rotation. The IDS log is rotated by renaming it to eve.json.1 and
    starting a fresh eve.json; the IDS is then told (HUP) to reopen, and
    until it does it keeps writing to the renamed file. So when the inode
    changes and eve.json.1 is the file we were reading, we first finish
    that file from where we stopped, and only move to the new eve.json once
    the IDS has visibly switched (the new file has something in it).
    Before 3 October 2026 ingest jumped straight to the new file and the
    old file's last lines were lost. A copy-and-truncate rotation (same
    inode, smaller file) still simply restarts at the beginning."""
    if not os.path.exists(EVE_PATH):
        return 0, 0, 0

    stat = os.stat(EVE_PATH)
    saved_inode, offset = get_state(conn, "suricata", EVE_PATH)
    rotated_path = EVE_PATH + ".1"
    draining_rotated_file = False

    if saved_inode is not None and saved_inode != stat.st_ino:
        rotated_stat = os.stat(rotated_path) if os.path.exists(rotated_path) else None
        if rotated_stat is not None and rotated_stat.st_ino == saved_inode:
            draining_rotated_file = True
        else:
            print("eve.json rotated - restarting from the beginning", flush=True)
            offset = 0
    elif offset > stat.st_size:
        print("eve.json truncated - restarting from the beginning", flush=True)
        offset = 0

    read_path = rotated_path if draining_rotated_file else EVE_PATH
    lines, offset = read_complete_lines(read_path, offset, MAX_LINES_PER_PASS)

    read = errors = 0
    rows = []
    for line in lines:
        read += 1
        # Everything about one line is inside this try, not only the JSON
        # decoding (Audit10Oct H3). A line that is valid JSON but not an
        # event - a bare list, a field of the wrong type, no usable time -
        # used to raise further on, roll the whole pass back without moving
        # the cursor, and so fail again on every pass after: one bad line
        # stopped this source for good. Now it is counted and passed over.
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("not a JSON object")
            if event.get("event_type") == "stats":
                save_sensor_stats(conn, event)
                continue
            if event.get("event_type") in SKIP_TYPES:
                continue
            row = flatten_suricata(event)
            if row["ts"] is None:
                raise ValueError("no usable timestamp")
        except Exception:
            errors += 1
            continue
        rows.append(row)

    saved = insert_events(conn, rows)
    if not draining_rotated_file:
        save_state(conn, "suricata", EVE_PATH, stat.st_ino, offset)
    elif len(lines) < MAX_LINES_PER_PASS and stat.st_size > 0:
        # The old file is read to its end, and the IDS is already writing
        # the new one (checked before reading, so nothing can still be on
        # its way into the old file): switch to the new file, from the top.
        print("eve.json rotated - finished the rotated file, moving to the new one", flush=True)
        save_state(conn, "suricata", EVE_PATH, stat.st_ino, 0)
    else:
        # More of the old file to read, or the IDS hasn't switched yet:
        # keep our place in the old file for the next pass.
        save_state(conn, "suricata", EVE_PATH, saved_inode, offset)
    conn.execute(
        "UPDATE ingest_stats SET events_read = events_read + ?,"
        " events_saved = events_saved + ?, parse_errors = parse_errors + ?,"
        " last_run = ? WHERE id = 1",
        (read, saved, errors, time.time()),
    )
    conn.commit()
    return read, saved, errors



def to_epoch_agh(timestamp):
    """Convert a DNS-filter timestamp (file querylog or the
    /control/querylog API - both seen live to return a MIX of 'Z' and
    explicit-offset forms) to epoch seconds. See parse_rfc3339's own
    docstring for the real 5.5-hour bug this function used to have."""
    return parse_rfc3339(timestamp)


def flatten_agh(entry):
    """
    Turn one DNS-filter querylog line into a flat event row.

    This is a genuinely different signal from the IDS's own 'dns' event type:
    the IDS sees that a query was made; the DNS filter reports whether its own
    filtering decision blocked it. Keeping event_type='dns_query' (source=
    'adguard') separate from the IDS's 'dns' (source='suricata') avoids
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
        # answer came from the DNS filter's cache, which upstream resolver
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
    """Read whatever is new in the DNS filter's querylog.json. Same watermark and
    rotation-by-inode approach as read_eve - see its docstring.

    Only runs when the API is unreachable (read_agh below), and the API
    reader is what normally imports the DNS filter's queries. So entries at or
    before the API reader's watermark are skipped - they're already in
    the database - and the watermark moves forward past whatever this
    reader imports, so the API doesn't import them a second time once it
    is back. Previously the file reader kept its own separate position,
    untouched while the API worked, and re-imported all of that history
    on the first API outage (Audit.md H5)."""
    already_imported_up_to = get_agh_watermark(conn)
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
    lines, offset = read_complete_lines(AGH_QUERYLOG_PATH, offset, MAX_LINES_PER_PASS)
    for line in lines:
        read += 1
        try:
            entry = json.loads(line)
            if not isinstance(entry, dict):
                raise ValueError("not a JSON object")
            row = flatten_agh(entry)
            if row["ts"] is None:
                raise ValueError("no usable timestamp")
        except Exception:
            errors += 1   # see read_eve: counted and passed over (Audit10Oct H3)
            continue
        if row["ts"] > already_imported_up_to:
            rows.append(row)

    saved = insert_events(conn, rows)
    save_state(conn, "adguard", AGH_QUERYLOG_PATH, stat.st_ino, offset)
    newest = max([r["ts"] for r in rows], default=None)
    if newest is not None and newest > already_imported_up_to:
        set_agh_watermark(conn, newest)
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

    Blocked-vs-allowed comes from 'reason': the DNS filter's own documented
    naming convention is that every 'Filtered*' reason means blocked and
    every 'NotFiltered*' reason means allowed. Confirmed live against
    the two reasons this gateway actually produces
    (FilteredBlackList, NotFilteredNotFound) - the fuller reason enum
    (safe browsing, parental control, safe search, custom rule,
    rewrite...) was not each individually exercised live, since none of
    those features are enabled on this gateway. Followed here as a
    stated interpretation of the DNS filter's own convention, not a guess."""
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
        # 'status' is the response code the DNS filter itself answered with, not
        # necessarily what the real upstream would say for a NON-blocked
        # query - confirmed live (14 September 2026) that a query this
        # gateway's filtering blocks still reports status NOERROR (the
        # "default" blocking_mode's 0.0.0.0 answer IS a real, if bogus,
        # NOERROR response - see app/adguard.py's add_nxdomain_rule for
        # the same fact used elsewhere). That's exactly what step 2.5's
        # DGA detection needs: a genuine NXDOMAIN here means the query
        # reached the real upstream and the domain doesn't actually
        # exist anywhere - not that the DNS filter chose to block it.
        "dns_rcode": entry.get("status"),
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


def get_agh_catchup(conn):
    """An unfinished DNS backlog (Audit10Oct H2), as (cursor, floor,
    ceiling), or None. `cursor` is the DNS filter's own older_than value
    for the next page still to read; entries with floor < time < ceiling
    are the ones still to import."""
    row = conn.execute(
        "SELECT catchup_cursor, catchup_floor, catchup_ceiling FROM ingest_state WHERE source='adguard_api'"
    ).fetchone()
    if row is None or row["catchup_cursor"] is None:
        return None
    return row["catchup_cursor"], row["catchup_floor"], row["catchup_ceiling"]


def set_agh_catchup(conn, catchup):
    cursor, floor, ceiling = catchup if catchup is not None else (None, None, None)
    conn.execute(
        "UPDATE ingest_state SET catchup_cursor=?, catchup_floor=?, catchup_ceiling=? WHERE source='adguard_api'",
        (cursor, floor, ceiling),
    )


def _fetch_agh_pages(older_than, stop_at, max_pages):
    """Ask the DNS filter for pages of its query log, newest first, starting
    just below `older_than` (None: from the very newest). Stops when a page
    reaches back to `stop_at`, when there is nothing older, or after
    `max_pages` pages. Returns (entries, next_cursor): next_cursor is None
    when it stopped because it was finished, or the older_than value for
    the next page when it stopped at the page limit."""
    entries = []
    for _ in range(max_pages):
        path = "/control/querylog?limit=%d" % AGH_API_PAGE_SIZE
        if older_than:
            path += "&older_than=%s" % urllib.parse.quote(older_than)
        resp = adguard._request("GET", path) or {}
        page = resp.get("data") or []
        entries.extend(page)
        # Newest first, so the page's last entry is its oldest.
        if len(page) < AGH_API_PAGE_SIZE or not resp.get("oldest"):
            return entries, None
        last = parse_rfc3339(page[-1].get("time", ""))
        if last is not None and last <= stop_at:
            return entries, None
        older_than = resp["oldest"]
    return entries, older_than


def _agh_rows(entries, after, before, seen):
    """Event rows for the entries timed strictly between `after` and
    `before` (None: no upper limit). `seen` is the poll's duplicate guard -
    the API has no stable per-entry id, so (time, client, name, type) is the
    best available key; query type is part of it because a device asks for
    A and AAAA records of the same name at the same instant, and those are
    two queries, not one. Returns (rows, newest time, entries with no usable
    time)."""
    rows = []
    newest = None
    bad = 0
    for entry in entries:
        ts = parse_rfc3339(entry.get("time", "")) if isinstance(entry, dict) else None
        if ts is None:
            bad += 1   # never imported, never moves the watermark (Audit10Oct H3)
            continue
        if ts <= after or (before is not None and ts >= before):
            continue
        question = entry.get("question") or {}
        key = (ts, entry.get("client"), question.get("name"), question.get("type"))
        if key in seen:
            continue
        seen.add(key)
        try:
            rows.append(flatten_agh_api(entry, ts))
        except Exception:
            bad += 1
            continue
        if newest is None or ts > newest:
            newest = ts
    return rows, newest, bad


def read_agh_api(conn):
    """Poll the DNS filter's /control/querylog API - real-time, not gated on
    the DNS filter's own flush-to-disk cadence the way tailing querylog.json is
    (confirmed live in EVALUATION-RESULTS.md: the on-disk file can sit
    unwritten for 7+ hours under real traffic, because the DNS filter only
    flushes when its 1000-entry in-memory buffer rotates - the exact gap
    this step exists to close). Raises adguard.AdGuardError if the admin
    API can't be reached; read_agh() below catches that and falls back
    to the file reader for that cycle, per this step's own "file reader
    kept as fallback".

    Normally one page of AGH_API_PAGE_SIZE entries per 2-second poll is
    plenty (measured live - ENHANCEMENT-PLAN.md step 6.6: roughly 950 DNS
    queries/day network-wide). After a gap - this service restarted or
    down for a while, or a real traffic spike - more than one page can
    pile up, so this keeps asking for the next-older page (the DNS filter's
    `older_than` cursor, which each reply supplies as "oldest") until a
    page reaches back to entries already imported (Audit.md H5).

    Up to AGH_API_MAX_PAGES pages per poll. If even that doesn't reach
    back to the watermark, the watermark still moves to the newest entry -
    but the range left behind (from the old watermark up to the oldest
    entry fetched) is remembered as a "catch-up" and drained over the
    following polls, AGH_CATCHUP_PAGES_PER_POLL pages at a time. Before
    Audit10Oct H2 that range was simply never imported."""
    watermark = get_agh_watermark(conn)
    catchup = get_agh_catchup(conn)
    seen = set()

    # 1. Everything new since the last poll, down to the watermark.
    data, cursor = _fetch_agh_pages(None, watermark, AGH_API_MAX_PAGES)
    rows, newest, bad = _agh_rows(data, watermark, None, seen)
    read = len(data)
    if cursor is not None:
        fetched = [parse_rfc3339(e.get("time", "")) for e in data if isinstance(e, dict)]
        ceiling = min([t for t in fetched if t is not None], default=None)
        if ceiling is not None and catchup is None:
            catchup = (cursor, watermark, ceiling)
            print("DNS-filter backlog beyond %d pages - the older entries will be caught up over the "
                  "next polls" % AGH_API_MAX_PAGES, flush=True)
        elif ceiling is not None:
            # A second backlog while the first is still draining needs more
            # than 10,000 queries in one 2-second poll, twice over. Say so
            # rather than pretend: this range is not imported.
            print("DNS-filter backlog: a second gap opened while an earlier one is still draining - "
                  "entries between %.3f and %.3f are not imported" % (watermark, ceiling), flush=True)

    # 2. A few more pages of an earlier backlog, if there is one.
    if catchup is not None:
        c_cursor, floor, ceiling = catchup
        older, next_cursor = _fetch_agh_pages(c_cursor, floor, AGH_CATCHUP_PAGES_PER_POLL)
        more, _, more_bad = _agh_rows(older, floor, ceiling, seen)
        rows += more
        bad += more_bad
        read += len(older)
        catchup = None if next_cursor is None else (next_cursor, floor, ceiling)
        if catchup is None:
            print("DNS-filter backlog caught up", flush=True)

    saved = insert_events(conn, rows)
    set_agh_catchup(conn, catchup)
    if newest is not None and newest > watermark:
        set_agh_watermark(conn, newest)
    conn.execute(
        "UPDATE ingest_stats SET events_read = events_read + ?,"
        " events_saved = events_saved + ?, parse_errors = parse_errors + ?, last_run = ? WHERE id = 1",
        (read, saved, bad, time.time()),
    )
    conn.commit()
    return read, saved, bad


def read_agh(conn):
    """Try the real-time /control/querylog API first; fall back to
    tailing the on-disk file if the DNS filter's admin API can't be reached
    right now (e.g. the DNS filter itself restarting) - step 1.4's own "file
    reader kept as fallback"."""
    try:
        return read_agh_api(conn)
    except adguard.AdGuardError as e:
        print("DNS-filter API unreachable (%s) - falling back to file tailing this cycle" % e, flush=True)
        return read_agh_querylog(conn)


def flatten_dpi(entry):
    """Turn one structured line from the DPI addon's telemetry log (see
    dpi/securepi_adfilter.py's _log_event) into an events row. Reuses the
    generic events shape - source='dpi', event_type='dpi_decision' - rather
    than a bespoke table, the same reasoning schema.sql's header gives for
    keeping the IDS and DNS filter on one table."""
    return {
        # The addon always writes a numeric ts. A line without one is
        # broken, not "now" (Audit10Oct H3) - read_dpi_events skips it.
        "ts": entry.get("ts") if isinstance(entry.get("ts"), (int, float)) else None,
        "ts_iso": entry.get("ts_iso") or (
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(entry["ts"]))
            if isinstance(entry.get("ts"), (int, float)) else None),
        "source": "dpi",
        "event_type": "dpi_decision",
        "src_ip": entry.get("src_ip"),
        "tls_sni": entry.get("sni"),
        "dpi_action": entry.get("decision"),
        "dpi_ads_removed": entry.get("ads_removed"),
        "block_reason": entry.get("blocked_path"),
        "dpi_module": entry.get("module") or (
            "youtube" if entry.get("decision") in _PRE_MODULE_SITE_DECISIONS else None),
    }


# Lines written before the addon recorded a module (schema 2 rules,
# ADBLOCK-ENHANCEMENT-PLAN.md B5) can only be YouTube's: it was the one
# site the addon decrypted. Passthrough lines have no site.
_PRE_MODULE_SITE_DECISIONS = ("decrypt", "ads_stripped", "path_blocked", "cosmetic_injected",
                              "pin_bypass", "tls_failed")


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
    lines, offset = read_complete_lines(DPI_EVENTS_PATH, offset, MAX_LINES_PER_PASS)
    for line in lines:
        read += 1
        try:
            entry = json.loads(line)
            if not isinstance(entry, dict):
                raise ValueError("not a JSON object")
            row = flatten_dpi(entry)
            if row["ts"] is None:
                raise ValueError("no usable timestamp")
        except Exception:
            errors += 1   # see read_eve: counted and passed over (Audit10Oct H3)
            continue
        rows.append(row)

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
# doq-bypass: DNS-over-QUIC on UDP 853 (Audit10Oct M8). dns_bypass_signal
# counts it like dot-bypass - every bypass reason except quic-blocked.
NFT_LOG_PREFIXES = ("dot-bypass: ", "doq-bypass: ", "doh-bypass: ", "quic-blocked: ")
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
    if result.returncode != 0:
        # e.g. no permission to read the kernel journal - say so, rather
        # than quietly treating it as "no bypass attempts".
        print("read_nft_log: journalctl exited %d: %s" % (result.returncode, (result.stderr or "").strip()[:200]),
              file=sys.stderr, flush=True)
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
        # The watermark moves past EVERY kernel line read, not only the
        # ones that are ours. Otherwise, during a quiet spell with no
        # bypass attempts, it stayed put and every poll re-read (and
        # re-parsed) the whole kernel log since the last attempt - more
        # and more work the longer the network stayed clean (Audit.md).
        if ts > newest:
            newest = ts
        row = flatten_nft_log(message)
        if row is None:
            continue
        row["ts"] = ts
        row["ts_iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
        rows.append(row)

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


def run_step(conn, name, fn, default):
    """Run one piece of an ingest pass on its own: if it fails, report it,
    undo whatever half-finished database work it left behind, and return
    `default` so the rest of the pass still runs.

    Every step used to share one try/except around the whole pass, so a
    single failing reader (a bad line, the DNS filter restarting) also skipped
    every step after it - including the DNS fail-open check, whose whole
    job is keeping the network usable when something is broken
    (Audit.md H4). The rollback matters too: without it, a step's
    partly-written rows were committed by whichever later step next
    called commit(), without the matching offset/watermark update.
    """
    try:
        return fn(conn)
    except Exception as exc:
        print("ingest: %s failed: %s" % (name, exc), file=sys.stderr, flush=True)
        try:
            conn.rollback()
        except Exception:
            pass
        return default


def main():
    conn = open_db()
    print("ingest started, polling every %ds" % POLL_SECONDS, flush=True)
    total = 0
    cycle = 0
    nothing = (0, 0, 0)  # (read, saved, errors) for a reader that failed
    while True:
        # Refresh the device registry before reading events, so a device
        # that just got a lease is already known when its events arrive.
        # Leases change slowly, so this runs every fifth pass rather than
        # re-reading the same file every two seconds.
        if cycle % 5 == 0:
            run_step(conn, "device registry", registry.update_devices, None)
        cycle += 1

        read, saved, errors = run_step(conn, "IDS reader", read_eve, nothing)
        a_read, a_saved, a_errors = run_step(conn, "DNS-filter reader", read_agh, nothing)
        d_read, d_saved, d_errors = run_step(conn, "DPI reader", read_dpi_events, nothing)
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
            n_read, n_saved, n_errors = run_step(conn, "nftables log reader", read_nft_log, nothing)
            saved += n_saved
            errors += n_errors
        total += saved

        # Attach events to devices. Done after insertion rather than
        # during it, because an event may arrive fractionally before the
        # lease that explains it - this way it gets picked up next pass
        # instead of being permanently unattributed.
        attributed = run_step(conn, "event attribution", registry.attribute_events, 0)

        if saved:
            print("stored %d events (total %d), %d attributed to devices this pass%s" % (
                saved, total, attributed,
                ", %d parse errors" % errors if errors else ""
            ), flush=True)

        # step 3.5's health supervisor rides this loop, not
        # engine.py's - a process can't reliably detect its own
        # death, and securepi-ingest is a genuinely separate systemd
        # unit from securepi-engine, so it can correctly report "the
        # engine hasn't run recently" even if the engine crashed.
        # Throttled internally (run_if_due) to health_check_interval_
        # seconds, since most of these checks are too costly to
        # repeat every 2s.
        run_step(conn, "platform health check", health.run_if_due, False)

        # step 3.6's DNS fail-open check needs a tighter, dedicated
        # cadence than the general platform checks above - the ~30s
        # "clients still resolve" exit criterion has no room for
        # waiting out a full health_check_interval_seconds cycle
        # first. Same root/same-loop reasoning as run_if_due(), just
        # its own faster throttle. Its own step, so it runs even when
        # every reader above has failed.
        run_step(conn, "DNS fail-open check", health.run_dns_failopen_if_due, False)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()

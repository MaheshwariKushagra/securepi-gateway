#!/usr/bin/env python3
"""
SecurePi Gateway - hourly device activity rollups.

ENHANCEMENT-PLAN.md step 6.1 (behavioural baselines) needs to compare
"this hour" against the same hour-of-day on past days. A windowed SQL
query over raw `events` - the pattern every other signal in
app/correlation.py uses - can't do that cheaply once there are weeks of
history to scan for every device on every cycle. `device_hourly`
(schema.sql) and this rollup are the answer: one pre-aggregated row per
device per hour, so the baseline signal only ever reads a handful of
rows per device instead of re-summing raw events every 15 seconds.

This is the minimal prerequisite 6.1 actually needs - not the full
Stage 1 F3 feature ("Retention + hourly rollups"), which also prunes old
raw events and keeps rollups for 180 days. rollup_closed_hours() below
only ever ADDS rows; nothing here deletes anything. That's F3's job,
still to come - see ENHANCEMENT-PLAN.md.

No new systemd service: called from engine.py's existing 15-second loop,
alongside correlation.run_all(). It is naturally cheap on every cycle
where there is nothing new to roll up (it only re-checks the last two
closed hours - see the docstring below), so it does not need its own
timer or throttle.
"""

import time

# How many of the most recently closed hours are recomputed on every call,
# even if they were rolled up already. Events can land in an hour after
# it closed: an event attributed to its device a few seconds late (the
# registry refreshes every ~10s), or AdGuard's file fallback delivering
# queries late. Re-rolling is safe - INSERT OR REPLACE simply overwrites
# the same (device, hour) row with the corrected totals.
REPAIR_HOURS = 2


def _hour_start(ts):
    return int(ts // 3600) * 3600


def rollup_closed_hours(conn, now=None):
    """
    Aggregate every device's activity for each hour that has fully closed
    (i.e. ended before `now`) and hasn't been rolled up yet - plus the
    last REPAIR_HOURS closed hours again, to catch events that arrived
    late.

    Resumes from its own progress row in signal_state ('rollup'). On a
    cycle where nothing new has closed, it only recomputes those
    REPAIR_HOURS hours - two small grouped queries over an hour of events
    each - which is still cheap enough to call unconditionally from
    engine.py's own loop rather than needing a timer.

    A device with zero events in some hour gets no row for that hour, not
    a zero-value row - the baseline signal (correlation.py) treats a
    missing row as "no data for that hour", which is what it is; writing
    an explicit zero would not be wrong, just needless rows for a device
    that was simply offline.

    Returns the number of (device, hour) rows written.
    """
    now = now if now is not None else time.time()
    last_closed_hour = _hour_start(now) - 3600  # the most recent FULLY closed hour
    if last_closed_hour < 0:
        return 0

    # Where the last call got to. Kept in its own signal_state row
    # ('rollup'), not read back as MAX(hour_start) from device_hourly as it
    # used to be: an hour with no events writes no rows, so that marker
    # never moved past a quiet spell, and every 15-second cycle re-scanned
    # every empty hour since (Audit.md). MAX(hour_start) is still the
    # starting point the first time, for a database from before this row.
    progress = conn.execute("SELECT last_run_ts FROM signal_state WHERE signal_type='rollup'").fetchone()
    if progress is not None:
        start_hour = int(progress["last_run_ts"]) + 3600
    else:
        watermark = conn.execute("SELECT max(hour_start) FROM device_hourly").fetchone()[0]
        if watermark is None:
            earliest = conn.execute("SELECT min(ts) FROM events").fetchone()[0]
            if earliest is None:
                return 0  # no events at all yet - nothing to roll up
            start_hour = _hour_start(earliest)
        else:
            start_hour = watermark + 3600
    # Always redo the last REPAIR_HOURS closed hours, to pick up late data.
    start_hour = min(start_hour, last_closed_hour - (REPAIR_HOURS - 1) * 3600)

    written = 0
    hour = start_hour
    while hour <= last_closed_hour:
        rows = conn.execute(
            """
            SELECT device_id,
                   COALESCE(sum(CASE WHEN event_type='flow' THEN bytes_toclient END),0) bytes_down,
                   COALESCE(sum(CASE WHEN event_type='flow' THEN bytes_toserver END),0) bytes_up,
                   sum(event_type='dns_query') dns_queries,
                   sum(event_type='dns_query' AND blocked=1) dns_blocked,
                   sum(event_type='flow') flows
              FROM events
             WHERE device_id IS NOT NULL AND ts >= ? AND ts < ?
             GROUP BY device_id
            """,
            (hour, hour + 3600),
        ).fetchall()
        for r in rows:
            conn.execute(
                "INSERT OR REPLACE INTO device_hourly"
                " (device_id, hour_start, bytes_down, bytes_up, dns_queries, dns_blocked, flows)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (r["device_id"], hour, r["bytes_down"], r["bytes_up"],
                 r["dns_queries"] or 0, r["dns_blocked"] or 0, r["flows"] or 0),
            )
            written += 1
        hour += 3600

    conn.execute(
        "INSERT INTO signal_state (signal_type, last_run_ts) VALUES ('rollup', ?)"
        " ON CONFLICT(signal_type) DO UPDATE SET last_run_ts=excluded.last_run_ts",
        (last_closed_hour,),
    )
    conn.commit()
    return written

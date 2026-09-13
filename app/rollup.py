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
where there is nothing new to roll up (see the docstring below for why),
so it does not need its own timer or throttle.
"""

import time


def _hour_start(ts):
    return int(ts // 3600) * 3600


def rollup_closed_hours(conn, now=None):
    """
    Aggregate every device's activity for each hour that has fully closed
    (i.e. ended before `now`) and doesn't have a device_hourly row yet.

    Resumes from device_hourly's own high-water mark (MAX(hour_start)),
    the same "read state back from the data itself" approach
    ingest_state/signal_state use elsewhere in this project - no separate
    watermark table. On a cycle where the most recent closed hour is
    already rolled up, the loop body never executes: this is what makes
    it cheap enough to call unconditionally from engine.py's own loop
    rather than needing a timer.

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

    watermark = conn.execute("SELECT max(hour_start) FROM device_hourly").fetchone()[0]
    if watermark is None:
        earliest = conn.execute("SELECT min(ts) FROM events").fetchone()[0]
        if earliest is None:
            return 0  # no events at all yet - nothing to roll up
        start_hour = _hour_start(earliest)
    else:
        start_hour = watermark + 3600

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

    conn.commit()
    return written

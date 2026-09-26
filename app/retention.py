#!/usr/bin/env python3
"""
SecurePi Gateway - data retention (ENHANCEMENT-PLAN.md step 1.3).

Nothing in this project deleted a row before this step - `events`,
`incidents` and `device_hourly` all grew forever (finding C1/G10). This
prunes them: flow/TLS/QUIC events 14 days, everything else in `events`
(DNS, alerts, and every other event_type) 30 days, incidents 365 days,
`device_hourly` rollups 180 days. `audit_log` is deliberately never
pruned here - an audit trail that silently forgets its own history
after some retention window would defeat the point of having one.

Evidence-chain safety, the one subtlety here: an event still linked to
an incident via `incident_events` is NEVER pruned by its own age, for
as long as the incident itself survives (up to 365 days). Deleting a
5-day-old flow/TLS event that a 200-day-old still-open incident cites
as evidence would silently break "why was this raised" for that
incident - directly against this project's own evidence-chain design
principle (see correlation.py's module docstring: "the incident is not
a verdict on its own, it is a claim backed by the evidence chain").
`run_retention()` therefore prunes incidents FIRST (which also deletes
their `incident_events` links), so only events genuinely unlinked from
any surviving incident become eligible for event-level pruning.

Runs from engine.py's own 15-second loop, the same pattern step 6.1
established for rollup.py, rather than a separate systemd timer:
`run_retention_if_due()` is a cheap no-op on every cycle except the
~1-in-5760 that's actually due, gated on a stored last-run timestamp in
the existing `signal_state` table (reused as "retention" is not one of
webapp.py's SIGNALS, so this never appears in the pipeline-health
panel - it's bookkeeping, not a detection signal).

DNS's 30-day retention (vs. flow/TLS's 14) is NOT explicitly split out
from "everything else" in the plan's own wording ("flow/TLS 14 days,
DNS 30 days") - alerts, DHCP records and every other event_type this
project's events table holds land in the same 30-day bucket as DNS
here, an explicit interpretation of an unstated case rather than a
third invented category.
"""

import time

EVENT_RETENTION_DAYS = {
    "flow": 14,
    "tls": 14,
    "quic": 14,
}
DEFAULT_EVENT_RETENTION_DAYS = 30  # dns_query, dns, alert, http, anomaly, dhcp, fileinfo, ssh, dpi_decision, ...
INCIDENT_RETENTION_DAYS = 365
DEVICE_HOURLY_RETENTION_DAYS = 180
RUN_INTERVAL_SECONDS = 86400  # once a day


def prune_incidents(conn, now=None):
    now = now if now is not None else time.time()
    cutoff = now - INCIDENT_RETENTION_DAYS * 86400
    ids = [r["id"] for r in conn.execute("SELECT id FROM incidents WHERE last_seen < ?", (cutoff,))]
    if not ids:
        return 0
    placeholders = ",".join("?" * len(ids))
    conn.execute("DELETE FROM incident_events WHERE incident_id IN (%s)" % placeholders, ids)
    conn.execute("DELETE FROM incident_notes WHERE incident_id IN (%s)" % placeholders, ids)
    # Notification history for these incidents too - otherwise those rows
    # outlive the incident they describe and pile up for ever (Audit.md).
    conn.execute("DELETE FROM notifications WHERE incident_id IN (%s)" % placeholders, ids)
    conn.execute("DELETE FROM incidents WHERE id IN (%s)" % placeholders, ids)
    return len(ids)


def prune_events(conn, now=None):
    """Must run AFTER prune_incidents - see the module docstring's
    evidence-chain safety note. Every DELETE excludes events still
    linked via incident_events, regardless of how old they are."""
    now = now if now is not None else time.time()
    total = 0
    for event_type, days in EVENT_RETENTION_DAYS.items():
        cutoff = now - days * 86400
        cur = conn.execute(
            """DELETE FROM events WHERE event_type = ? AND ts < ?
                 AND id NOT IN (SELECT event_id FROM incident_events)""",
            (event_type, cutoff),
        )
        total += cur.rowcount

    default_cutoff = now - DEFAULT_EVENT_RETENTION_DAYS * 86400
    listed_types = tuple(EVENT_RETENTION_DAYS.keys())
    placeholders = ",".join("?" * len(listed_types))
    cur = conn.execute(
        "DELETE FROM events WHERE event_type NOT IN (%s) AND ts < ?"
        "  AND id NOT IN (SELECT event_id FROM incident_events)" % placeholders,
        listed_types + (default_cutoff,),
    )
    total += cur.rowcount
    return total


def prune_device_hourly(conn, now=None):
    now = now if now is not None else time.time()
    cutoff = now - DEVICE_HOURLY_RETENTION_DAYS * 86400
    cur = conn.execute("DELETE FROM device_hourly WHERE hour_start < ?", (cutoff,))
    return cur.rowcount


def prune_expired_suppressions(conn, now=None):
    """ENHANCEMENT-PLAN.md step 2.7: a suppression past its own expires_at
    is already inert (app/suppression.py's is_suppressed() checks the
    same condition), so this is pure housekeeping, not a correctness
    fix - deleting it a day late changes nothing about whether it was
    still being honored."""
    now = now if now is not None else time.time()
    cur = conn.execute(
        "DELETE FROM suppressions WHERE expires_at IS NOT NULL AND expires_at < ?", (now,)
    )
    return cur.rowcount


def run_retention(conn, now=None):
    """Prune incidents, then events, then old device_hourly rollups -
    that order matters, see the module docstring. Returns what was
    removed; does not print or track last-run itself, so it can be
    called directly (e.g. from a test) without those side effects."""
    now = now if now is not None else time.time()
    removed = {
        "incidents": prune_incidents(conn, now),
        "events": prune_events(conn, now),
        "device_hourly": prune_device_hourly(conn, now),
        "suppressions": prune_expired_suppressions(conn, now),
    }
    conn.commit()
    return removed


def db_size_bytes(conn):
    """The live database file's size, for the "DB size logged daily"
    exit criterion. PRAGMA page_count * page_size - works for any
    connection; returns 0 for :memory:, which is fine, since this is
    only ever meaningful against a real file."""
    page_count = conn.execute("PRAGMA page_count").fetchone()[0]
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    return page_count * page_size


def run_retention_if_due(conn, now=None):
    """Called from engine.py's own loop every cycle. A cheap SELECT on
    every cycle except the ~1-in-5760 that's actually due, the same
    'ride the existing loop, gate on a stored timestamp' pattern
    rollup.py already established. Returns the removed-counts dict on a
    day it actually ran, None otherwise."""
    now = now if now is not None else time.time()
    row = conn.execute(
        "SELECT last_run_ts FROM signal_state WHERE signal_type='retention'"
    ).fetchone()
    last_run = row["last_run_ts"] if row else 0
    if now - last_run < RUN_INTERVAL_SECONDS:
        return None

    removed = run_retention(conn, now)
    size = db_size_bytes(conn)
    print(
        "retention: removed %d incidents, %d events, %d device_hourly rows, %d expired "
        "suppressions - db size %.1f MB"
        % (removed["incidents"], removed["events"], removed["device_hourly"],
           removed["suppressions"], size / 1e6),
        flush=True,
    )
    conn.execute(
        "INSERT INTO signal_state (signal_type, last_run_ts) VALUES ('retention', ?)"
        " ON CONFLICT(signal_type) DO UPDATE SET last_run_ts = excluded.last_run_ts",
        (now,),
    )
    conn.commit()
    return removed

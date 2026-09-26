#!/usr/bin/env python3
"""
SecurePi Gateway - audit log.

ENHANCEMENT-PLAN.md step 1.5 ("Audit log: audit_log table and an
audit() helper on every write endpoint"), built here as the minimal
prerequisite step 6.3's "audit viewer" needs - the same "build only the
piece the current step actually needs" pattern steps 6.1 and 6.2 already
used for device_hourly and dhcp_params.

Several endpoints in app/webapp.py already print() an audit-shaped line
to the journal as a stopgap, each one commented "until step 1.5 exists".
This module is that step: those call sites now call log() as well as
print() - both stay, since the journal remains useful to someone
watching live (`journalctl -f`), while this table is what makes the
history queryable and displayable in the console itself, which a
scrolling log file cannot do.
"""

import time


def log(conn, actor, action, target=None, detail=None):
    """Record one audited action. Commits - callers don't need to."""
    conn.execute(
        "INSERT INTO audit_log (ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
        (time.time(), actor, action, target, detail),
    )
    conn.commit()


def recent(conn, limit=200):
    """Newest-first audit rows, for the console's audit viewer."""
    return conn.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (max(1, min(limit, 1000)),)
    ).fetchall()


def for_target(conn, target, limit=50):
    """Newest-first audit rows for one target - step 6.4's incident
    status-change timeline reads this with target=str(incident_id)."""
    return conn.execute(
        "SELECT * FROM audit_log WHERE target = ? ORDER BY id DESC LIMIT ?",
        (target, max(1, min(limit, 200))),
    ).fetchall()

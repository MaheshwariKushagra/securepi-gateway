#!/usr/bin/env python3
"""
SecurePi Gateway - suppression rules (ENHANCEMENT-PLAN.md step 2.7).

An operator's false-positive verdict on a real incident is the only way
a suppression rule comes into being here - there is deliberately no way
to pre-emptively suppress a signal that hasn't fired yet, which would be
guessing at future false positives rather than acting on a confirmed one.

Scoped to (signal_type, device_id) - see schema.sql's own comment on the
`suppressions` table for why this is coarser than per-destination
suppression, and a real, stated boundary rather than an oversight.
`device_id=None` means network-wide for that signal_type.

Every create/remove call is expected to be wrapped in an app.audit.log()
call by its caller (app/webapp.py's endpoints) - this module doesn't
audit itself, the same separation app/adguard.py's write functions and
their webapp.py callers already use.
"""

import time


def is_suppressed(conn, signal_type, device_id):
    """True if an active (non-expired) rule matches this signal_type for
    this device OR network-wide. Checked by correlation.py's
    raise_incident() before it ever inserts or extends an incident."""
    now = time.time()
    row = conn.execute(
        """SELECT 1 FROM suppressions
            WHERE signal_type = ?
              AND (device_id = ? OR device_id IS NULL)
              AND (expires_at IS NULL OR expires_at > ?)
            LIMIT 1""",
        (signal_type, device_id, now),
    ).fetchone()
    return row is not None


def add_suppression(conn, signal_type, device_id, reason, created_by, expires_at=None):
    """Create a suppression rule. Commits - callers don't need to.
    Returns the new row's id."""
    now = time.time()
    cur = conn.execute(
        """INSERT INTO suppressions (signal_type, device_id, reason, created_by, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
        (signal_type, device_id, reason, created_by, now, expires_at),
    )
    conn.commit()
    return cur.lastrowid


def remove_suppression(conn, suppression_id):
    """Delete a rule. Returns True if a row was actually removed."""
    cur = conn.execute("DELETE FROM suppressions WHERE id = ?", (suppression_id,))
    conn.commit()
    return cur.rowcount > 0


def list_suppressions(conn):
    """Newest-first, for the console. Each row's `active` field applies
    the same not-expired check is_suppressed() uses, so the console
    doesn't need to reimplement it."""
    now = time.time()
    rows = conn.execute("SELECT * FROM suppressions ORDER BY id DESC").fetchall()
    return [dict(r, active=(r["expires_at"] is None or r["expires_at"] > now)) for r in rows]

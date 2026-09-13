#!/usr/bin/env python3
"""
SecurePi Gateway - correlation engine.

Design: windowed SQL queries, not an in-memory stream processor
-----------------------------------------------------------------
Each signal is a SQL query over a trailing time window of stored events,
run on a timer. This is a deliberate choice over a streaming/stateful engine
that maintains counters in memory as events arrive:

  - Every detection is a query you can run by hand and get the same answer.
    That matters for a system a single person has to explain and defend.
  - "Bounded state" falls out for free: the window is bounded by the SQL
    query's time range, not by an unbounded in-memory dictionary that has to
    be manually evicted.
  - At this event volume (order of thousands/day) a full-table windowed scan
    completes in milliseconds; the complexity of incremental state tracking
    would buy nothing here.

The trade-off, stated plainly: a signal cannot see "unusually spread out"
patterns that span longer than its window in one look, and very high volume
would eventually make repeated table scans too slow. Neither applies at this
scale. If event rates grew by two orders of magnitude, incremental counters
would be the right next step.

Pipeline: Events (already in the DB) -> Signals (this file) -> Incidents
--------------------------------------------------------------------------
A signal firing is a candidate detection. It becomes (or extends) an
INCIDENT via raise_incident(), which deduplicates: a signal that keeps firing
for the same device within a short gap extends the existing open incident
rather than creating a new one every cycle. This is what produces a small
number of incidents from a large number of raw events - the reduction ratio
that is the point of having a correlation layer at all.
"""

import sqlite3
import time

DB_PATH = "/opt/securepi/securepi.db"

# How far apart two firings of the SAME signal for the SAME device can be
# while still counting as "the same incident continuing" rather than a new
# one. Chosen to merge a sustained scan or a flurry of blocked lookups into
# one incident, without merging genuinely separate events hours apart.
DEDUP_WINDOW_SECONDS = 600

# Ports commonly targeted by credential brute-forcing. Not exhaustive by
# design - see brute_force_signal for why a short, defensible list beats a
# large opaque one here.
AUTH_PORTS = {22: "SSH", 21: "FTP", 23: "Telnet", 3389: "RDP", 25: "SMTP"}


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_window_start(conn, signal_type, default_lookback):
    """Where this signal last left off. First run looks back `default_lookback`
    seconds so a fresh install does not have to wait for history to build up."""
    row = conn.execute(
        "SELECT last_run_ts FROM signal_state WHERE signal_type = ?", (signal_type,)
    ).fetchone()
    if row is None:
        return time.time() - default_lookback
    return row["last_run_ts"]


def set_window_start(conn, signal_type, ts):
    conn.execute(
        "INSERT INTO signal_state (signal_type, last_run_ts) VALUES (?, ?)"
        " ON CONFLICT(signal_type) DO UPDATE SET last_run_ts = excluded.last_run_ts",
        (signal_type, ts),
    )


def raise_incident(conn, device_id, signal_type, severity, title, description,
                    first_seen, last_seen, event_ids):
    """
    Record a detection as an incident, merging into a recent open incident of
    the same type for the same device rather than always creating a new row.

    This dedup step is where the alert-to-incident reduction actually happens:
    without it, a signal that fires once per cycle while a scan is in progress
    would produce one incident per cycle instead of one incident per scan.
    """
    existing = conn.execute(
        """SELECT id, evidence_count FROM incidents
            WHERE device_id = ? AND signal_type = ? AND status = 'new'
              AND last_seen >= ?
            ORDER BY last_seen DESC LIMIT 1""",
        (device_id, signal_type, last_seen - DEDUP_WINDOW_SECONDS),
    ).fetchone()

    now = time.time()
    if existing:
        incident_id = existing["id"]
        conn.execute(
            """UPDATE incidents SET last_seen = ?, updated_at = ?, description = ?
               WHERE id = ?""",
            (last_seen, now, description, incident_id),
        )
    else:
        cur = conn.execute(
            """INSERT INTO incidents
                   (device_id, signal_type, severity, title, description, status,
                    first_seen, last_seen, created_at, updated_at, evidence_count)
               VALUES (?, ?, ?, ?, ?, 'new', ?, ?, ?, ?, 0)""",
            (device_id, signal_type, severity, title, description,
             first_seen, last_seen, now, now),
        )
        incident_id = cur.lastrowid

    conn.executemany(
        "INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?, ?)",
        [(incident_id, eid) for eid in event_ids],
    )
    # evidence_count is the ACTUAL number of distinct linked events, read back
    # after the insert - not a running sum. A signal that keeps re-detecting
    # the same underlying data every cycle (entirely normal: a pattern stays
    # inside its trailing window for as long as the window is wide) must not
    # make the count climb just because it was checked again. An earlier
    # version incremented by len(event_ids) on every merge, so a signal
    # re-confirming the same 8 events across 7 engine cycles reported 56
    # "pieces of evidence" for what was actually 8 - a real bug, since this
    # figure is meant to tell a security operator how much data supports the
    # incident, not how many times the engine happened to look.
    n = conn.execute(
        "SELECT count(*) FROM incident_events WHERE incident_id = ?", (incident_id,)
    ).fetchone()[0]
    conn.execute("UPDATE incidents SET evidence_count = ? WHERE id = ?", (n, incident_id))
    return incident_id


# --------------------------------------------------------------------------
# Signal 1: horizontal port scan
#
# One device contacting many distinct destination ports. Grouped by
# (device, dest_ip) so a scan of one host is distinguished from a device that
# legitimately uses many ports across many different destinations (normal
# browsing does this constantly - one destination, one or two ports).
#
# Threshold chosen deliberately low (8 ports / 5 minutes) because this signal
# is meant to catch the slow scan that a per-packet IDS signature misses, not
# just to duplicate what Suricata's own scan rules already flag.
# --------------------------------------------------------------------------
PORT_SCAN_THRESHOLD = 8
PORT_SCAN_WINDOW_SECONDS = 300


def port_scan_signal(conn):
    # A proper trailing window, re-evaluated in full every cycle - NOT "since
    # the last run". An earlier version used the last-run watermark as the
    # scan boundary, which meant a slow scan spread across several short
    # polling cycles would never accumulate enough hits in any single window
    # to cross the threshold - exactly defeating the point of this signal.
    # Incident-level dedup (in raise_incident) is what prevents the repeated
    # overlapping scans from creating duplicate incidents.
    now = time.time()
    since = now - PORT_SCAN_WINDOW_SECONDS

    rows = conn.execute(
        """
        SELECT device_id, dest_ip,
               count(DISTINCT dest_port) n_ports,
               min(ts) first_seen, max(ts) last_seen,
               group_concat(DISTINCT dest_port) ports
          FROM events
         WHERE event_type = 'flow'
           AND device_id IS NOT NULL
           AND ts > ?
         GROUP BY device_id, dest_ip
        HAVING n_ports >= ?
        """,
        (since, PORT_SCAN_THRESHOLD),
    ).fetchall()

    fired = 0
    for r in rows:
        event_ids = [
            e["id"] for e in conn.execute(
                """SELECT id FROM events WHERE event_type='flow' AND device_id=?
                     AND dest_ip=? AND ts > ? ORDER BY ts""",
                (r["device_id"], r["dest_ip"], since),
            )
        ]
        raise_incident(
            conn, r["device_id"], "port_scan", "high",
            title="Port scan detected against %s" % r["dest_ip"],
            description=(
                "%d distinct ports contacted on %s within %d seconds "
                "(ports: %s)." % (r["n_ports"], r["dest_ip"],
                                   PORT_SCAN_WINDOW_SECONDS, r["ports"])
            ),
            first_seen=r["first_seen"], last_seen=r["last_seen"],
            event_ids=event_ids,
        )
        fired += 1

    set_window_start(conn, "port_scan", now)  # bookkeeping only; see note above
    return fired


# --------------------------------------------------------------------------
# Signal 2: brute force
#
# Many short connections from one device to one auth-service port on one
# destination. "Short" and "many" together are what separates this from a
# single legitimate SSH session: a real login is one flow; a brute-force
# attempt is dozens of separate, quick ones.
# --------------------------------------------------------------------------
BRUTE_FORCE_THRESHOLD = 6
BRUTE_FORCE_WINDOW_SECONDS = 120


def brute_force_signal(conn):
    # Trailing window every cycle - see port_scan_signal for why this must
    # not be gated by "since the engine last ran".
    now = time.time()
    since = now - BRUTE_FORCE_WINDOW_SECONDS

    placeholders = ",".join("?" for _ in AUTH_PORTS)
    rows = conn.execute(
        f"""
        SELECT device_id, dest_ip, dest_port,
               count(*) n_attempts, min(ts) first_seen, max(ts) last_seen
          FROM events
         WHERE event_type = 'flow'
           AND device_id IS NOT NULL
           AND dest_port IN ({placeholders})
           AND ts > ?
         GROUP BY device_id, dest_ip, dest_port
        HAVING n_attempts >= ?
        """,
        (*AUTH_PORTS.keys(), since, BRUTE_FORCE_THRESHOLD),
    ).fetchall()

    fired = 0
    for r in rows:
        service = AUTH_PORTS.get(r["dest_port"], str(r["dest_port"]))
        event_ids = [
            e["id"] for e in conn.execute(
                """SELECT id FROM events WHERE event_type='flow' AND device_id=?
                     AND dest_ip=? AND dest_port=? AND ts > ? ORDER BY ts""",
                (r["device_id"], r["dest_ip"], r["dest_port"], since),
            )
        ]
        raise_incident(
            conn, r["device_id"], "brute_force", "high",
            title="Possible brute-force attempt against %s (%s)" % (r["dest_ip"], service),
            description=(
                "%d connection attempts to %s port %d (%s) within a short window."
                % (r["n_attempts"], r["dest_ip"], r["dest_port"], service)
            ),
            first_seen=r["first_seen"], last_seen=r["last_seen"],
            event_ids=event_ids,
        )
        fired += 1

    set_window_start(conn, "brute_force", now)
    return fired


# --------------------------------------------------------------------------
# Signal 3: malicious/blocked-domain repeat offender
#
# Fires on a device whose DNS queries are being blocked repeatedly, not on
# any single blocked lookup - one blocked ad domain is normal background
# noise on any modern device; a device that is repeatedly trying blocked
# domains, especially many DISTINCT ones, is the more interesting signal
# (an app or process persistently trying to reach something disallowed).
# --------------------------------------------------------------------------
MALICIOUS_DOMAIN_THRESHOLD = 15
MALICIOUS_DOMAIN_WINDOW_SECONDS = 600


def malicious_domain_signal(conn):
    # Trailing window every cycle - same reasoning as port_scan_signal.
    now = time.time()
    since = now - MALICIOUS_DOMAIN_WINDOW_SECONDS

    rows = conn.execute(
        """
        SELECT device_id,
               count(*) n_blocked,
               count(DISTINCT dns_rrname) n_distinct,
               min(ts) first_seen, max(ts) last_seen
          FROM events
         WHERE event_type = 'dns_query'
           AND blocked = 1
           AND device_id IS NOT NULL
           AND ts > ?
         GROUP BY device_id
        HAVING n_blocked >= ?
        """,
        (since, MALICIOUS_DOMAIN_THRESHOLD),
    ).fetchall()

    fired = 0
    for r in rows:
        top = conn.execute(
            """SELECT dns_rrname, count(*) n FROM events
                WHERE event_type='dns_query' AND blocked=1 AND device_id=? AND ts > ?
                GROUP BY dns_rrname ORDER BY n DESC LIMIT 5""",
            (r["device_id"], since),
        ).fetchall()
        event_ids = [
            e["id"] for e in conn.execute(
                """SELECT id FROM events WHERE event_type='dns_query' AND blocked=1
                     AND device_id=? AND ts > ? ORDER BY ts""",
                (r["device_id"], since),
            )
        ]
        raise_incident(
            conn, r["device_id"], "malicious_domain", "medium",
            title="Repeated blocked-domain lookups (%d in %ds)"
                  % (r["n_blocked"], MALICIOUS_DOMAIN_WINDOW_SECONDS),
            description=(
                "%d blocked DNS queries across %d distinct domains. Top domains: %s."
                % (r["n_blocked"], r["n_distinct"],
                   ", ".join("%s (x%d)" % (t["dns_rrname"], t["n"]) for t in top))
            ),
            first_seen=r["first_seen"], last_seen=r["last_seen"],
            event_ids=event_ids,
        )
        fired += 1

    set_window_start(conn, "malicious_domain", now)
    return fired


# --------------------------------------------------------------------------
# Signal 4: new device
#
# The cheapest signal to compute - devices.first_seen already IS the
# detection - but a real security signal in its own right: an unrecognised
# device joining the network is exactly what a small-network operator wants
# to know about immediately, independent of anything it does afterwards.
# --------------------------------------------------------------------------
NEW_DEVICE_GRACE_SECONDS = 30  # let the registry finish resolving identity first
NEW_DEVICE_LOOKBACK_SECONDS = 3600  # trailing window; raise_incident's own
# dedup (same device/signal within DEDUP_WINDOW_SECONDS) is what stops a
# still-recent device from getting re-raised every cycle - see below for why
# this can't be a persisted watermark instead.


def new_device_signal(conn):
    # A trailing window every cycle, like the other three signals - NOT a
    # persisted "since we last ran" watermark. An earlier version used one,
    # and it silently broke detection for every device: the watermark
    # advanced to the CURRENT cycle's time regardless of whether the grace
    # period had elapsed, so a device still too new to qualify on cycle 1 had
    # already been watermarked past by cycle 2, and could never match again.
    # Confirmed by direct testing - a device created and then left running
    # past the grace period never fired, on any later cycle, under the old
    # code.
    now = time.time()
    since = now - NEW_DEVICE_LOOKBACK_SECONDS

    rows = conn.execute(
        """SELECT id, hostname, friendly_name, first_seen FROM devices
            WHERE first_seen > ? AND first_seen <= ?""",
        (since, now - NEW_DEVICE_GRACE_SECONDS),
    ).fetchall()

    fired = 0
    for r in rows:
        name = r["friendly_name"] or r["hostname"] or ("device %d" % r["id"])
        raise_incident(
            conn, r["id"], "new_device", "low",
            title="New device joined the network: %s" % name,
            description="First seen at %s; not previously known to the registry."
                         % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["first_seen"])),
            first_seen=r["first_seen"], last_seen=r["first_seen"],
            event_ids=[],
        )
        fired += 1

    set_window_start(conn, "new_device", now)
    return fired


# --------------------------------------------------------------------------
# Signal 5: ad-blocking effectiveness watchdog (ENHANCEMENT-PLAN.md step
# 5.10)
#
# A different kind of signal from the four above: not a security threat,
# a PRODUCT one. If a device is actively decrypting YouTube traffic (Tier
# 2 is doing its job of inspecting) but nothing is ever being stripped
# from any of it, ad removal has stopped working - most likely because
# YouTube changed its response format, or moved to server-side ad
# insertion (SSAI). SSAI is documented here as this feature's expected
# long-term end state: it splices ads into the same video stream the
# real content comes from, so there is no longer a separate
# ad-scheduling field to delete, and no rule-based fix (step 5.9's
# console-editable rules included) can restore removal once that
# happens. This signal cannot fix that day - it exists to make it
# visible the moment it happens, instead of ad-blocking silently
# degrading with nobody noticing.
#
# Reuses source='dpi' events from the SAME events table every other
# signal reads, exactly the way step 5.1 built this telemetry to be used
# - not a bespoke table, and not a second, DPI-specific engine.
# --------------------------------------------------------------------------
EFFECTIVENESS_WINDOW_SECONDS = 3600   # "a configured period", per the plan
EFFECTIVENESS_MIN_YOUTUBE_EVENTS = 5  # enough real activity to judge by, not one stray handshake


def adblock_effectiveness_signal(conn):
    now = time.time()
    since = now - EFFECTIVENESS_WINDOW_SECONDS

    rows = conn.execute(
        """
        SELECT device_id, count(*) n_youtube, sum(dpi_action='ads_stripped') n_stripped,
               min(ts) first_seen, max(ts) last_seen
          FROM events
         WHERE source='dpi' AND device_id IS NOT NULL AND ts > ?
           AND dpi_action IN ('decrypt', 'ads_stripped')
         GROUP BY device_id
        HAVING n_youtube >= ? AND n_stripped = 0
        """,
        (since, EFFECTIVENESS_MIN_YOUTUBE_EVENTS),
    ).fetchall()

    fired = 0
    for r in rows:
        event_ids = [
            e["id"] for e in conn.execute(
                """SELECT id FROM events WHERE source='dpi' AND device_id=? AND ts > ?
                     AND dpi_action IN ('decrypt', 'ads_stripped') ORDER BY ts""",
                (r["device_id"], since),
            )
        ]
        raise_incident(
            conn, r["device_id"], "adblock_ineffective", "medium",
            title="YouTube ad removal may no longer be effective",
            description=(
                "%d YouTube connection(s) decrypted in the last %d minutes with zero ads "
                "stripped from any of them - likely a YouTube format change, or server-side "
                "ad insertion (SSAI), which this feature cannot remove by design."
                % (r["n_youtube"], EFFECTIVENESS_WINDOW_SECONDS // 60)
            ),
            first_seen=r["first_seen"], last_seen=r["last_seen"],
            event_ids=event_ids,
        )
        fired += 1

    set_window_start(conn, "adblock_ineffective", now)
    return fired


SIGNALS = [port_scan_signal, brute_force_signal, malicious_domain_signal, new_device_signal,
           adblock_effectiveness_signal]


def run_all(conn):
    """Run every signal once. Returns {signal_name: incidents_fired}."""
    results = {}
    for fn in SIGNALS:
        try:
            results[fn.__name__] = fn(conn)
        except Exception as exc:
            print("correlation: %s failed: %s" % (fn.__name__, exc), flush=True)
            results[fn.__name__] = None
    conn.commit()
    return results


if __name__ == "__main__":
    c = connect()
    print(run_all(c))

# --------------------------------------------------------------------------
# Known edge case, found during testing: device_ips intervals for the SAME
# address that overlap in time are not deterministically resolved by the
# attribution query in registry.py (whichever row SQLite's correlated
# subquery returns first wins, with no defined tie-break). This surfaced when
# two manually-inserted test-harness mappings for the same test IP
# overlapped; it cannot occur through the normal DHCP-driven path, because
# touch_interval() always extends an existing interval for the same device
# rather than opening a second one, and only opens a new interval when the
# device differs. Recorded here as a known limitation rather than a bug in
# the signals themselves - not fixed given the project timeline, but worth
# a defensive tie-break (e.g. prefer the most recently opened interval) if
# revisited.
# --------------------------------------------------------------------------

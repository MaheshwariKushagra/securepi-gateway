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

import settings

DB_PATH = "/opt/securepi/securepi.db"

# How far apart two firings of the SAME signal for the SAME device can be
# while still counting as "the same incident continuing" rather than a new
# one. Chosen to merge a sustained scan or a flurry of blocked lookups into
# one incident, without merging genuinely separate events hours apart.
# Lives in app/settings.py (step 1.2) - queried fresh on every call below,
# same as every other window/threshold this file reads from there.

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

    Merges into an incident with status 'new' OR 'investigating' - an
    operator marking something "investigating" is not the same as closing
    it out, and the pattern that raised it may well still be ongoing
    (ENHANCEMENT-PLAN.md finding G2: the old code merged into 'new' only,
    so marking an incident "investigating" made the very next firing open
    a duplicate). Deliberately does NOT merge into 'resolved' or
    'false_positive' - those are a genuine operator verdict, and silently
    reopening one by merging a new detection into it would undermine that
    decision; a fresh detection after a real resolution correctly starts
    a new incident instead.
    """
    dedup_window = settings.get(conn, "dedup_window_seconds")
    existing = conn.execute(
        """SELECT id, evidence_count FROM incidents
            WHERE device_id = ? AND signal_type = ? AND status IN ('new', 'investigating')
              AND last_seen >= ?
            ORDER BY last_seen DESC LIMIT 1""",
        (device_id, signal_type, last_seen - dedup_window),
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
# Signal 1: vertical port scan (ENHANCEMENT-PLAN.md finding G1)
#
# One device contacting many distinct destination PORTS on ONE host - a
# vertical scan by standard convention (many ports, one host). Grouped by
# (device, dest_ip) so a scan of one host is distinguished from a device that
# legitimately uses many ports across many different destinations (normal
# browsing does this constantly - one destination, one or two ports).
#
# This was previously mislabelled "horizontal" in this comment - the
# opposite of standard usage, where a HORIZONTAL scan is one port probed
# across many HOSTS (a network sweep), not what this signal detects. Fixed
# as G1; no behavior changed, only the name - a network-sweep signal of
# the standard-horizontal kind is a separate, not-yet-built item
# (ENHANCEMENT-PLAN.md step 2.1).
#
# Threshold chosen deliberately low (8 ports / 5 minutes) because this signal
# is meant to catch the slow scan that a per-packet IDS signature misses, not
# just to duplicate what Suricata's own scan rules already flag.
# --------------------------------------------------------------------------
# Window and threshold both live in app/settings.py (steps 1.2 and 6.3) -
# queried fresh every cycle below, the same "no cached state" design this
# signal's own trailing-window re-evaluation already follows.


def port_scan_signal(conn):
    # A proper trailing window, re-evaluated in full every cycle - NOT "since
    # the last run". An earlier version used the last-run watermark as the
    # scan boundary, which meant a slow scan spread across several short
    # polling cycles would never accumulate enough hits in any single window
    # to cross the threshold - exactly defeating the point of this signal.
    # Incident-level dedup (in raise_incident) is what prevents the repeated
    # overlapping scans from creating duplicate incidents.
    now = time.time()
    window = settings.get(conn, "port_scan_window_seconds")
    since = now - window
    threshold = settings.get(conn, "port_scan_threshold")

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
        (since, threshold),
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
                "(ports: %s)." % (r["n_ports"], r["dest_ip"], window, r["ports"])
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
# Window and threshold both live in app/settings.py - see port_scan_signal's
# own note above.


def brute_force_signal(conn):
    # Trailing window every cycle - see port_scan_signal for why this must
    # not be gated by "since the engine last ran".
    now = time.time()
    since = now - settings.get(conn, "brute_force_window_seconds")
    threshold = settings.get(conn, "brute_force_threshold")

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
        (*AUTH_PORTS.keys(), since, threshold),
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
# Fires on a device whose DNS queries are being blocked across many
# DISTINCT domains, not on raw blocked-lookup volume (ENHANCEMENT-PLAN.md
# finding G3, and a real false positive documented in
# EVALUATION-RESULTS.md: this signal used to threshold on raw count and
# fired on normal Android ad-SDK traffic, which retries the SAME handful
# of ad/tracker domains rapidly - high raw volume, low distinct-domain
# count). One blocked ad domain, even hit repeatedly, is normal
# background noise on any modern device; a device repeatedly trying many
# DIFFERENT blocked domains is the more interesting signal (an app or
# process persistently trying to reach a range of disallowed
# destinations, not just retrying one ad slot).
# --------------------------------------------------------------------------
# Window and threshold both live in app/settings.py - see port_scan_signal's
# own note above. The threshold applies to DISTINCT domains (n_distinct
# below), not raw lookup count (n_blocked) - see the fix note above.


def malicious_domain_signal(conn):
    # Trailing window every cycle - same reasoning as port_scan_signal.
    now = time.time()
    window = settings.get(conn, "malicious_domain_window_seconds")
    since = now - window
    threshold = settings.get(conn, "malicious_domain_threshold")

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
        HAVING n_distinct >= ?
        """,
        (since, threshold),
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
            title="Blocked lookups against %d distinct domains (%ds window)"
                  % (r["n_distinct"], window),
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
# The lookback window lives in app/settings.py (step 1.2) - see
# port_scan_signal's own note above. raise_incident's own dedup (same
# device/signal within the dedup window) is what stops a still-recent
# device from getting re-raised every cycle - see below for why this
# can't be a persisted watermark instead.


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
    since = now - settings.get(conn, "new_device_lookback_seconds")

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


# --------------------------------------------------------------------------
# Signal 6: behavioural baseline / volume anomaly (ENHANCEMENT-PLAN.md
# step 6.1)
#
# Every other signal here looks for a specific KNOWN bad pattern (a scan,
# repeated auth failures, blocked-domain bursts). This one is different:
# it has no fixed threshold for "too much traffic" at all, because there
# isn't one - a smart TV streaming 4K and a text sensor pinging once an
# hour are both normal, for THAT device. Instead it asks whether THIS
# device is doing something unusual for ITSELF, at THIS hour of day,
# compared to its own history - the EWMA-per-hour-of-day approach F§12.3
# describes, computed fresh from device_hourly (app/rollup.py) each cycle
# rather than maintained as running state, the same "recompute from a
# windowed query, not an incremental stream processor" philosophy this
# whole file states up top.
#
# "Learning" isn't a separate mode - it falls out of the sample-count
# gate below. A device younger than BASELINE_MIN_SAMPLES hours of history
# AT THIS SPECIFIC HOUR OF DAY is simply never judged, full stop, not
# judged against a thin or default baseline. See webapp.py's
# api_device_baseline for the console's "still learning" badge, which
# uses a simpler days-since-first-seen approximation of this same idea
# for display purposes.
# --------------------------------------------------------------------------
BASELINE_MIN_SAMPLES = 7            # "learning badge until 7 days of data exist", per the plan
BASELINE_MIN_BYTES_FLOOR = 5 * 1024 * 1024  # 5 MB - below this, a z-score alone is just noise
# The z-score threshold lives in app/settings.py (step 6.3) - see
# port_scan_signal's own note above for why only this one of this
# signal's three constants is console-tunable.


def _hour_start(ts):
    return int(ts // 3600) * 3600


def behavioral_baseline_signal(conn):
    now = time.time()
    current_hour_start = _hour_start(now)
    current_hour_of_day = time.localtime(current_hour_start).tm_hour
    z_threshold = settings.get(conn, "baseline_z_threshold")

    # The current hour is still open, so it has no device_hourly row yet
    # (rollup.py only ever rolls up FULLY closed hours) - summed directly
    # from raw events instead, so an ongoing burst can be judged within
    # the same hour it's happening, not only after it closes.
    current_totals = conn.execute(
        """
        SELECT device_id,
               COALESCE(sum(CASE WHEN event_type='flow' THEN bytes_toclient END),0)
             + COALESCE(sum(CASE WHEN event_type='flow' THEN bytes_toserver END),0) total_bytes
          FROM events
         WHERE device_id IS NOT NULL AND ts >= ? AND ts < ?
         GROUP BY device_id
        """,
        (current_hour_start, now),
    ).fetchall()

    fired = 0
    for row in current_totals:
        device_id, current_bytes = row["device_id"], row["total_bytes"]
        if current_bytes < BASELINE_MIN_BYTES_FLOOR:
            continue  # too small to mean anything either way

        history = conn.execute(
            """
            SELECT bytes_down + bytes_up total FROM device_hourly
             WHERE device_id = ? AND hour_start < ?
               AND CAST(strftime('%H', hour_start, 'unixepoch', 'localtime') AS INTEGER) = ?
            """,
            (device_id, current_hour_start, current_hour_of_day),
        ).fetchall()

        if len(history) < BASELINE_MIN_SAMPLES:
            continue  # still learning this device's pattern for this hour of day

        values = [h["total"] for h in history]
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
        stdev = variance ** 0.5
        if stdev == 0:
            continue  # perfectly flat history - nothing to compare a deviation against

        z = (current_bytes - mean) / stdev
        if z > z_threshold:
            raise_incident(
                conn, device_id, "volume_anomaly", "medium",
                title="Unusual data volume for this device at this time of day",
                description=(
                    "%.1f MB so far this hour, vs. a %d-day average of %.1f MB at %02d:00 "
                    "(z=%.1f) - could be a large upload/exfiltration, or just an unusually "
                    "heavy session." % (current_bytes / 1e6, len(values), mean / 1e6,
                                         current_hour_of_day, z)
                ),
                first_seen=current_hour_start, last_seen=now, event_ids=[],
            )
            fired += 1

    set_window_start(conn, "volume_anomaly", now)
    return fired


SIGNALS = [port_scan_signal, brute_force_signal, malicious_domain_signal, new_device_signal,
           adblock_effectiveness_signal, behavioral_baseline_signal]


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
# Finding G6 (device_ips intervals for the same address that overlap in
# time having no defined tie-break) is fixed - see registry.py's
# attribute_events(), Pass 1's own comment, for the fix and the reasoning
# behind it (prefer the most recently opened interval).
# --------------------------------------------------------------------------

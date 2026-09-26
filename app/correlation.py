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

import math
import sqlite3
import statistics
import time
from collections import Counter, defaultdict

import playbooks
import settings
import signature_taxonomy
import suppression

DB_PATH = "/var/lib/securepi/securepi.db"

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

    Step 2.7: checked against app/suppression.py FIRST, before any of the
    above - an operator's false-positive verdict, turned into a
    suppression rule, means this signal/device (or this signal
    network-wide) writes NOTHING here at all, not even a merged-and-
    ignored incident. Returns None in that case. Every caller's own
    `fired += 1` still runs regardless (this function's return value
    isn't checked at any of the 13 call sites) - a deliberate, honest
    trade-off: `fired` counts "this signal's pattern was detected this
    cycle", not "an incident row was written", and touching all 13 call
    sites just to keep a debug log line's count exact wasn't worth the
    diff. The one thing that actually matters for this step - no
    incident is created or extended while suppressed - is real.
    """
    if suppression.is_suppressed(conn, signal_type, device_id):
        return None

    dedup_window = settings.get(conn, "dedup_window_seconds")
    existing = conn.execute(
        # `device_id IS ?`, not `= ?` (step 3.5 finding, found before it
        # could bite): SQLite's `=` never matches NULL, even against
        # another NULL, so a platform-wide incident (device_id=None, new
        # in step 3.5's health supervisor) would never dedup against its
        # own earlier firing under `=` - every cycle would raise a brand
        # new incident instead of extending the open one. `IS` matches
        # NULL-to-NULL correctly and behaves identically to `=` for every
        # real (non-NULL) device_id, confirmed with a quick sqlite3
        # check before relying on it, not assumed from general SQL rules.
        """SELECT id, evidence_count FROM incidents
            WHERE device_id IS ? AND signal_type = ? AND status IN ('new', 'investigating')
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
# just to duplicate what the IDS's own scan rules already flag.
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
# Signal 1b: network sweep (ENHANCEMENT-PLAN.md step 2.1, F§12.3)
#
# One device touching one PORT across many distinct HOSTS - a horizontal
# scan by standard convention, the mirror image of port_scan_signal's
# vertical one. This is the discovery step that typically comes BEFORE a
# vertical scan in a real reconnaissance sequence (find which hosts are
# alive, then probe one interesting host's ports) - Stage 2.8's campaign
# correlation is what will eventually link the two into one story; this
# signal only needs to raise the sweep on its own.
#
# Same trailing-window-every-cycle design as every other signal in this
# file - see port_scan_signal's own comment for why a persisted watermark
# would silently break this the same way it did for new_device_signal.
# --------------------------------------------------------------------------
# Window and threshold both live in app/settings.py - see port_scan_signal's
# own note above.


def network_sweep_signal(conn):
    now = time.time()
    window = settings.get(conn, "network_sweep_window_seconds")
    since = now - window
    threshold = settings.get(conn, "network_sweep_threshold")

    rows = conn.execute(
        """
        SELECT device_id, dest_port,
               count(DISTINCT dest_ip) n_hosts,
               min(ts) first_seen, max(ts) last_seen,
               group_concat(DISTINCT dest_ip) hosts
          FROM events
         WHERE event_type = 'flow'
           AND device_id IS NOT NULL
           AND ts > ?
         GROUP BY device_id, dest_port
        HAVING n_hosts >= ?
        """,
        (since, threshold),
    ).fetchall()

    fired = 0
    for r in rows:
        event_ids = [
            e["id"] for e in conn.execute(
                """SELECT id FROM events WHERE event_type='flow' AND device_id=?
                     AND dest_port=? AND ts > ? ORDER BY ts""",
                (r["device_id"], r["dest_port"], since),
            )
        ]
        raise_incident(
            conn, r["device_id"], "network_sweep", "high",
            title="Network sweep detected on port %d" % r["dest_port"],
            description=(
                "%d distinct hosts contacted on port %d within %d seconds "
                "(hosts: %s)." % (r["n_hosts"], r["dest_port"], window, r["hosts"])
            ),
            first_seen=r["first_seen"], last_seen=r["last_seen"],
            event_ids=event_ids,
        )
        fired += 1

    set_window_start(conn, "network_sweep", now)
    return fired


# --------------------------------------------------------------------------
# Signal 1c: slow scan - the vertical and horizontal scan patterns above,
# re-checked over a much longer window (ENHANCEMENT-PLAN.md step 2.1's
# "slow-scan variants").
#
# port_scan_signal's own comment already explains its 8-ports/300s
# threshold is deliberately low to catch scans a per-packet IDS signature
# misses. But because both signals above use a genuine SLIDING window
# (re-evaluated in full every cycle, not "since we last looked"), a scan
# paced slower than window/threshold - for port_scan_signal, slower than
# one new port every 300/8 = 37.5s - can cross the distinct-count
# threshold at EVERY cycle's check and still never have 8 of them fall
# inside any single trailing 300-second slice. nmap's slower timing
# templates (-T0 "paranoid", -T1 "sneaky") are built to pace exactly like
# this, specifically to stay under fast-window detection thresholds. This
# signal re-runs both queries with a much longer window so a scan that
# outlasts the fast signals' window still gets caught, just later -
# "detected eventually" beats "never detected" for a pattern this
# deliberate.
#
# Reuses port_scan_signal/network_sweep_signal's own SQL shape rather than
# introducing a third query style - only the window/threshold differ, and
# duplicating the query here (instead of calling those functions with a
# parameter) keeps each signal's incident bookkeeping and signal_type
# independent, exactly as raise_incident's own dedup-by-(device,
# signal_type) design expects.
# --------------------------------------------------------------------------
# Window and threshold both live in app/settings.py - see port_scan_signal's
# own note above.


def slow_scan_signal(conn):
    now = time.time()
    window = settings.get(conn, "slow_scan_window_seconds")
    since = now - window
    threshold = settings.get(conn, "slow_scan_threshold")
    fired = 0

    vertical = conn.execute(
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
    for r in vertical:
        event_ids = [
            e["id"] for e in conn.execute(
                """SELECT id FROM events WHERE event_type='flow' AND device_id=?
                     AND dest_ip=? AND ts > ? ORDER BY ts""",
                (r["device_id"], r["dest_ip"], since),
            )
        ]
        raise_incident(
            conn, r["device_id"], "slow_port_scan", "high",
            title="Slow port scan detected against %s" % r["dest_ip"],
            description=(
                "%d distinct ports contacted on %s over %d minutes (ports: %s) - too "
                "slowly paced for the fast port-scan signal's shorter window to catch."
                % (r["n_ports"], r["dest_ip"], window // 60, r["ports"])
            ),
            first_seen=r["first_seen"], last_seen=r["last_seen"],
            event_ids=event_ids,
        )
        fired += 1

    horizontal = conn.execute(
        """
        SELECT device_id, dest_port,
               count(DISTINCT dest_ip) n_hosts,
               min(ts) first_seen, max(ts) last_seen,
               group_concat(DISTINCT dest_ip) hosts
          FROM events
         WHERE event_type = 'flow'
           AND device_id IS NOT NULL
           AND ts > ?
         GROUP BY device_id, dest_port
        HAVING n_hosts >= ?
        """,
        (since, threshold),
    ).fetchall()
    for r in horizontal:
        event_ids = [
            e["id"] for e in conn.execute(
                """SELECT id FROM events WHERE event_type='flow' AND device_id=?
                     AND dest_port=? AND ts > ? ORDER BY ts""",
                (r["device_id"], r["dest_port"], since),
            )
        ]
        raise_incident(
            conn, r["device_id"], "slow_network_sweep", "high",
            title="Slow network sweep detected on port %d" % r["dest_port"],
            description=(
                "%d distinct hosts contacted on port %d over %d minutes (hosts: %s) - too "
                "slowly paced for the fast network-sweep signal's shorter window to catch."
                % (r["n_hosts"], r["dest_port"], window // 60, r["hosts"])
            ),
            first_seen=r["first_seen"], last_seen=r["last_seen"],
            event_ids=event_ids,
        )
        fired += 1

    set_window_start(conn, "slow_scan", now)
    return fired


# --------------------------------------------------------------------------
# Signal 1d: DNS-filtering bypass (ENHANCEMENT-PLAN.md step 2.2)
#
# Combines three independent kinds of evidence that a device is routing
# its DNS around DNS-filter rather than through it, into one count per
# device:
#   1. nftables reject-rule hits (source='nftables', event_type=
#      'bypass_attempt') - a device that actually tried DoT (port 853),
#      a known-IP DoH resolver, or QUIC on 443 and got rejected. See
#      gateway/nftables.conf's `log prefix` additions and
#      app/ingest.py's read_nft_log.
#   2. Canary-domain queries (event_type='dns_query') for
#      use-application-dns.net (Firefox's own DoH auto-enable check) or
#      mask.icloud.com / mask-h2.icloud.com (Apple's documented iCloud
#      Private Relay opt-out signal) - the DNS filter now answers all three with
#      a genuine NXDOMAIN (app/adguard.py's add_nxdomain_rule), so seeing
#      the QUERY at all means the client-side mechanism ran, independent
#      of whether the nftables layer ever saw a rejected connection.
#   3. IDS TLS SNI matches (event_type='tls') against known DoH
#      provider hostnames - catches a provider's IP the moment it
#      changes, before the doh_resolvers nft set's next daily refresh
#      (gateway/refresh-doh-set.sh) would.
#
# Deliberately NOT ATT&CK-tagged at the technique level - see
# app/playbooks.py's own docstring for the full reasoning, but the short
# version: modern OSes and browsers increasingly auto-enable encrypted
# DNS by default for ordinary privacy reasons (iOS Private Relay, recent
# Firefox DoH rollouts), so one device tripping this signal is real
# evidence of evaded DNS filtering, not reliable evidence of malicious
# intent - the same caution malicious_domain_signal's own docstring
# already applies to blocklist-hit volume.
# --------------------------------------------------------------------------
# Window and threshold both live in app/settings.py - see port_scan_signal's
# own note above.

CANARY_DOMAINS = ("use-application-dns.net", "mask.icloud.com", "mask-h2.icloud.com")
# Checked live (26 September 2026, step 7.2): the DNS filter answers the
# Firefox canary through our $dnsrewrite rule but never writes it to its
# query log (the iCloud canaries ARE logged, reason "RewriteRule"), so an
# DNS-filter-sourced dns_query event for it can never exist. The IDS captures
# ap0 and logs every DNS request a device sends the gateway, so for this
# one domain the signal counts the IDS's own DNS records instead - only
# this one, so the logged canaries aren't counted twice.
CANARY_DOMAINS_NOT_IN_ADGUARD_LOG = ("use-application-dns.net",)
# Curated, not exhaustive - the same "short, defensible list beats a large
# opaque one" reasoning brute_force_signal's AUTH_PORTS gives. Widening
# this is cheap (just add a hostname) and doesn't need a redeploy of
# anything else, since it's only read here.
KNOWN_DOH_PROVIDER_SNIS = (
    "dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
    "dns.quad9.net", "doh.opendns.com", "dns.adguard.com", "dns.nextdns.io",
)


def dns_bypass_signal(conn):
    now = time.time()
    window = settings.get(conn, "dns_bypass_window_seconds")
    since = now - window
    threshold = settings.get(conn, "dns_bypass_threshold")

    canary_placeholders = ",".join("?" for _ in CANARY_DOMAINS)
    suricata_placeholders = ",".join("?" for _ in CANARY_DOMAINS_NOT_IN_ADGUARD_LOG)
    sni_placeholders = ",".join("?" for _ in KNOWN_DOH_PROVIDER_SNIS)
    rows = conn.execute(
        f"""
        SELECT device_id, count(*) n, min(ts) first_seen, max(ts) last_seen
          FROM events
         WHERE device_id IS NOT NULL AND ts > ?
           AND (
                (source='nftables' AND event_type='bypass_attempt')
             OR (event_type='dns_query' AND dns_rrname IN ({canary_placeholders}))
             OR (source='suricata' AND event_type='dns' AND dns_type IN ('query','request')
                 AND dns_rrname IN ({suricata_placeholders}))
             OR (event_type='tls' AND tls_sni IN ({sni_placeholders}))
           )
         GROUP BY device_id
        HAVING n >= ?
        """,
        (since, *CANARY_DOMAINS, *CANARY_DOMAINS_NOT_IN_ADGUARD_LOG, *KNOWN_DOH_PROVIDER_SNIS, threshold),
    ).fetchall()

    fired = 0
    for r in rows:
        event_ids = [
            e["id"] for e in conn.execute(
                f"""SELECT id FROM events WHERE device_id=? AND ts > ?
                     AND (
                          (source='nftables' AND event_type='bypass_attempt')
                       OR (event_type='dns_query' AND dns_rrname IN ({canary_placeholders}))
                       OR (source='suricata' AND event_type='dns' AND dns_type IN ('query','request')
                           AND dns_rrname IN ({suricata_placeholders}))
                       OR (event_type='tls' AND tls_sni IN ({sni_placeholders}))
                     )
                     ORDER BY ts""",
                (r["device_id"], since, *CANARY_DOMAINS, *CANARY_DOMAINS_NOT_IN_ADGUARD_LOG, *KNOWN_DOH_PROVIDER_SNIS),
            )
        ]
        # A short breakdown by kind, so the incident says WHICH mechanism
        # was seen rather than just a bare count - "3 DoT attempts" reads
        # very differently to an analyst than "3 canary-domain queries".
        by_reason = conn.execute(
            """SELECT block_reason reason, count(*) n FROM events
                WHERE device_id=? AND ts > ? AND source='nftables' AND event_type='bypass_attempt'
                GROUP BY block_reason""",
            (r["device_id"], since),
        ).fetchall()
        by_canary = conn.execute(
            f"""SELECT dns_rrname reason, count(*) n FROM events
                 WHERE device_id=? AND ts > ?
                   AND ((event_type='dns_query' AND dns_rrname IN ({canary_placeholders}))
                     OR (source='suricata' AND event_type='dns' AND dns_type IN ('query','request')
                         AND dns_rrname IN ({suricata_placeholders})))
                 GROUP BY dns_rrname""",
            (r["device_id"], since, *CANARY_DOMAINS, *CANARY_DOMAINS_NOT_IN_ADGUARD_LOG),
        ).fetchall()
        by_sni = conn.execute(
            f"""SELECT tls_sni reason, count(*) n FROM events
                 WHERE device_id=? AND ts > ? AND event_type='tls' AND tls_sni IN ({sni_placeholders})
                 GROUP BY tls_sni""",
            (r["device_id"], since, *KNOWN_DOH_PROVIDER_SNIS),
        ).fetchall()
        parts = ["%s x%d" % (b["reason"], b["n"]) for b in list(by_reason) + list(by_canary) + list(by_sni)]

        raise_incident(
            conn, r["device_id"], "dns_bypass", "medium",
            title="Device tried to bypass DNS filtering %d times" % r["n"],
            description=(
                "%d DoH/DoT/QUIC/Private-Relay bypass indicators in %d seconds: %s. Modern "
                "devices increasingly enable encrypted DNS by default for privacy, so this is "
                "evidence of evaded filtering, not necessarily malicious intent - see the "
                "evidence chain for exactly what was attempted."
                % (r["n"], window, ", ".join(parts) or "no breakdown available")
            ),
            first_seen=r["first_seen"], last_seen=r["last_seen"],
            event_ids=event_ids,
        )
        fired += 1

    set_window_start(conn, "dns_bypass", now)
    return fired


# --------------------------------------------------------------------------
# Signal 1e: IDS alerts -> incidents (ENHANCEMENT-PLAN.md step 2.3)
#
# IDS/ET Open alerts have been ingested since day one (source=
# 'suricata', event_type='alert') but never turned into anything the
# console shows - the exact gap ENHANCEMENT-PLAN.md §1.1 names ("Alerts
# ingested but never used"). This signal closes it, using
# signature_taxonomy.classify() to turn alert_category into a plain name,
# our own severity, and (only where genuinely warranted) an ATT&CK tag.
#
# Grouped by (device_id, alert_category), NOT just device_id: a device
# with an ongoing burst of low-value "Misc activity" alerts (confirmed
# live on this gateway's own real traffic - see signature_taxonomy.py's
# docstring) must not have a genuinely severe, unrelated trojan alert
# quietly merged into that same incident thread by raise_incident's own
# dedup (which merges on device_id + signal_type only). Each curated
# category in signature_taxonomy.TAXONOMY gets its own signal_type for
# exactly this reason - the same reasoning slow_scan_signal above already
# uses to keep its two shapes as separate incident types, just applied to
# a larger, still bounded and fully known set (signature_taxonomy.
# ALL_SIGNAL_TYPES) rather than two.
# --------------------------------------------------------------------------
# Window and threshold both live in app/settings.py - see port_scan_signal's
# own note above.


def ids_alert_signal(conn):
    now = time.time()
    window = settings.get(conn, "ids_alert_window_seconds")
    since = now - window
    threshold = settings.get(conn, "ids_alert_threshold")

    rows = conn.execute(
        """
        SELECT device_id, alert_category, count(*) n,
               min(ts) first_seen, max(ts) last_seen,
               max(alert_severity) alert_severity
          FROM events
         WHERE event_type = 'alert'
           AND device_id IS NOT NULL
           AND ts > ?
         GROUP BY device_id, alert_category
        HAVING n >= ?
        """,
        (since, threshold),
    ).fetchall()

    fired = 0
    for r in rows:
        # max() only because alert_severity is 1:1 with alert_category in
        # the IDS's own classification.config - it never actually varies
        # within a group, so which aggregate wins doesn't matter (the same
        # reasoning app/webapp.py's signal_mix query already documents for
        # incidents.severity).
        signal_type, plain_name, severity, attack = signature_taxonomy.classify(
            r["alert_category"], r["alert_severity"])
        top = conn.execute(
            """SELECT alert_signature, count(*) n FROM events
                WHERE event_type='alert' AND device_id=? AND alert_category=? AND ts > ?
                GROUP BY alert_signature ORDER BY n DESC LIMIT 5""",
            (r["device_id"], r["alert_category"], since),
        ).fetchall()
        event_ids = [
            e["id"] for e in conn.execute(
                """SELECT id FROM events WHERE event_type='alert' AND device_id=?
                     AND alert_category=? AND ts > ? ORDER BY ts""",
                (r["device_id"], r["alert_category"], since),
            )
        ]
        attack_note = ""
        if attack:
            tactic, tactic_id, technique, technique_id, _url = attack
            attack_note = " ATT&CK: %s (%s)%s." % (
                tactic, tactic_id, " / %s (%s)" % (technique, technique_id) if technique else "")
        raise_incident(
            conn, r["device_id"], signal_type, severity,
            title="%s (%d alerts)" % (plain_name, r["n"]),
            description=(
                "%d IDS alerts in category \"%s\" over %d seconds. Top signatures: %s.%s"
                % (r["n"], r["alert_category"], window,
                   ", ".join("%s (x%d)" % (t["alert_signature"], t["n"]) for t in top),
                   attack_note)
            ),
            first_seen=r["first_seen"], last_seen=r["last_seen"],
            event_ids=event_ids,
        )
        fired += 1

    set_window_start(conn, "ids_alert", now)
    return fired


# --------------------------------------------------------------------------
# Signal 1f: offline threat intelligence (ENHANCEMENT-PLAN.md step 2.4)
#
# Matches recent events against app/intel.py's daily-refreshed `ioc`
# table (abuse.ch Feodo Tracker / URLhaus / ThreatFox): flow destination
# IPs against ip-type indicators, and DNS queries / TLS SNI against
# domain-type ones. Domain-type indicators are ALSO pushed to the DNS filter as
# a real blocklist (intel.py's own job) - this signal is what turns a
# match into an INCIDENT, on top of intel.py's blocklist turning it into
# a block. The three UNION ALL branches (rather than one query with OR'd
# join conditions across mismatched columns) keep each branch using a
# single, obvious index and stay readable - this is the one signal in
# this file that joins against another table at all, so leaning toward
# clarity here mattered more than a single denser query.
#
# threshold defaults to 1 (app/settings.py) - unlike a hit-VOLUME signal
# like malicious_domain, contact with even ONE confirmed-malicious
# indicator is significant on its own; these aren't ad/tracker
# blocklists, they're curated indicators of actual compromise
# infrastructure.
# --------------------------------------------------------------------------
# Window and threshold both live in app/settings.py - see port_scan_signal's
# own note above.


def _threat_intel_matches(conn, since):
    return conn.execute(
        """
        SELECT device_id, indicator, ioc_type, source, description, ts
          FROM (
            SELECT e.device_id device_id, i.indicator indicator, i.ioc_type ioc_type,
                   i.source source, i.description description, e.ts ts
              FROM events e JOIN ioc i ON i.ioc_type='ip' AND e.dest_ip = i.indicator
             WHERE e.event_type='flow' AND e.device_id IS NOT NULL AND e.ts > ?
            UNION ALL
            SELECT e.device_id, i.indicator, i.ioc_type, i.source, i.description, e.ts
              FROM events e JOIN ioc i ON i.ioc_type='domain' AND e.dns_rrname = i.indicator
             WHERE e.event_type='dns_query' AND e.device_id IS NOT NULL AND e.ts > ?
            UNION ALL
            SELECT e.device_id, i.indicator, i.ioc_type, i.source, i.description, e.ts
              FROM events e JOIN ioc i ON i.ioc_type='domain' AND e.tls_sni = i.indicator
             WHERE e.event_type='tls' AND e.device_id IS NOT NULL AND e.ts > ?
          )
        """,
        (since, since, since),
    ).fetchall()


def threat_intel_signal(conn):
    now = time.time()
    window = settings.get(conn, "threat_intel_window_seconds")
    since = now - window
    threshold = settings.get(conn, "threat_intel_threshold")

    matches = _threat_intel_matches(conn, since)
    by_key = {}
    for m in matches:
        key = (m["device_id"], m["indicator"])
        by_key.setdefault(key, []).append(m)

    fired = 0
    for (device_id, indicator), group in by_key.items():
        if len(group) < threshold:
            continue
        ioc_type = group[0]["ioc_type"]
        sources = sorted({g["source"] for g in group})
        description_text = group[0]["description"] or ""
        first_seen = min(g["ts"] for g in group)
        last_seen = max(g["ts"] for g in group)

        # Evidence: the actual matching events, re-queried directly rather
        # than carried through the grouping above - same "look it up
        # again by the real predicate" approach every other signal here
        # uses for its own event_ids.
        if ioc_type == "ip":
            event_ids = [e["id"] for e in conn.execute(
                """SELECT id FROM events WHERE event_type='flow' AND device_id=?
                     AND dest_ip=? AND ts > ? ORDER BY ts""",
                (device_id, indicator, since))]
        else:
            event_ids = [e["id"] for e in conn.execute(
                """SELECT id FROM events WHERE device_id=? AND ts > ?
                     AND ((event_type='dns_query' AND dns_rrname=?)
                       OR (event_type='tls' AND tls_sni=?))
                     ORDER BY ts""",
                (device_id, since, indicator, indicator))]

        raise_incident(
            conn, device_id, "threat_intel", "high",
            title="Contact with known-malicious %s: %s" % (
                "IP" if ioc_type == "ip" else "domain", indicator),
            description=(
                "%d event(s) involving %s, listed by %s (%s) over %d seconds."
                % (len(group), indicator, " and ".join(sources), description_text, window)
            ),
            first_seen=first_seen, last_seen=last_seen,
            event_ids=event_ids,
        )
        fired += 1

    set_window_start(conn, "threat_intel", now)
    return fired


# --------------------------------------------------------------------------
# Signal 1g: DNS tunnelling + DGA (ENHANCEMENT-PLAN.md step 2.5)
#
# Both patterns share the same underlying shape - many algorithmically-
# generated-looking subdomains under one base domain - and are computed
# from the same grouped query below, splitting into two incident types
# only when raising (the same one-function-two-signal_types pattern
# slow_scan_signal already established in step 2.1):
#
#   - dns_tunneling: malware carrying data OUT via DNS, encoded into
#     subdomain labels and/or TXT record lookups (a common tunnelling
#     carrier - TXT records hold more data per query than A/AAAA). Looks
#     for many DISTINCT high-entropy subdomains, or an unusually high
#     TXT-query ratio, under one base domain.
#   - dga: malware trying to find its command-and-control server by
#     querying algorithmically-generated domain names until one
#     resolves. Looks for a burst of GENUINE NXDOMAIN responses (the
#     domain doesn't exist anywhere - see app/ingest.py's
#     flatten_agh_api docstring on why a blocked query does NOT count as
#     NXDOMAIN here) with high-entropy labels.
#
# "Base domain" here is a simplified last-two-labels heuristic
# (_base_domain below), not a real Public Suffix List lookup - documented
# as a real, stated limitation rather than a maintained-dependency this
# project doesn't need for its own traffic volume: it would misgroup a
# multi-part suffix like "example.co.uk" (treating "co.uk" as the base
# domain), but every domain this gateway has actually seen live is a
# plain second-level one, and getting this wrong only under-flags a
# tunnelling pattern that happens to sit under a two-part-suffix
# registrar, not over-flag normal traffic.
# --------------------------------------------------------------------------
# All five thresholds and the shared window live in app/settings.py - see
# port_scan_signal's own note above.


def _shannon_entropy(s):
    """Bits of entropy per character - 0 for a single repeated character,
    up to log2(len(alphabet)) for a uniformly random string over that
    alphabet. Standard textbook Shannon entropy; used here (rather than a
    trained classifier) because it's the same "a query anyone can run by
    hand" property this whole file's design favors - see the module
    docstring."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _base_domain(fqdn):
    """Simplified registrable-domain heuristic (last two labels) - see
    this signal's own header comment for why a real Public Suffix List
    isn't used here."""
    parts = (fqdn or "").rstrip(".").split(".")
    if len(parts) < 2:
        return fqdn or ""
    return ".".join(parts[-2:])


def _subdomain_part(fqdn, base_domain):
    """Everything before the base domain - the part a DGA/tunnel actually
    randomizes. Empty string for a query against the apex domain itself."""
    if fqdn == base_domain:
        return ""
    suffix = "." + base_domain
    return fqdn[: -len(suffix)] if fqdn.endswith(suffix) else fqdn


def dns_tunneling_signal(conn):
    now = time.time()
    window = settings.get(conn, "dns_tunneling_window_seconds")
    since = now - window

    rows = conn.execute(
        """SELECT id, device_id, dns_rrname, dns_rrtype, dns_rcode, ts FROM events
            WHERE event_type='dns_query' AND device_id IS NOT NULL
              AND dns_rrname IS NOT NULL AND ts > ?""",
        (since,),
    ).fetchall()

    # Group in Python, not SQL: the entropy/subdomain-splitting logic
    # above has no clean SQL equivalent, and event volume in one window
    # is small enough (this file's own header explains why a full scan
    # is fine at this project's scale) that this costs nothing measurable.
    groups = defaultdict(list)
    for r in rows:
        base = _base_domain(r["dns_rrname"])
        groups[(r["device_id"], base)].append(r)

    fired = 0
    for (device_id, base), group in groups.items():
        subdomains = {r["dns_rrname"] for r in group}
        non_apex = [_subdomain_part(r["dns_rrname"], base) for r in group if r["dns_rrname"] != base]
        entropies = [_shannon_entropy(s) for s in non_apex if s]
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        txt_ratio = sum(1 for r in group if r["dns_rrtype"] == "TXT") / len(group)
        nxdomain_rows = [r for r in group if r["dns_rcode"] == "NXDOMAIN"]

        event_ids_all = [r["id"] for r in group]
        first_seen = min(r["ts"] for r in group)
        last_seen = max(r["ts"] for r in group)

        if (len(subdomains) >= settings.get(conn, "dns_tunneling_min_distinct_subdomains")
                and (avg_entropy >= settings.get(conn, "dns_tunneling_min_entropy")
                     or txt_ratio >= settings.get(conn, "dns_tunneling_min_txt_ratio"))):
            raise_incident(
                conn, device_id, "dns_tunneling", "high",
                title="Possible DNS tunnelling under %s" % base,
                description=(
                    "%d distinct subdomains under %s in %d seconds (avg subdomain entropy "
                    "%.1f bits/char, %.0f%% TXT queries) - looks encoded rather than typed."
                    % (len(subdomains), base, window, avg_entropy, txt_ratio * 100)
                ),
                first_seen=first_seen, last_seen=last_seen, event_ids=event_ids_all,
            )
            fired += 1

        if nxdomain_rows:
            nx_entropies = [_shannon_entropy(_subdomain_part(r["dns_rrname"], base))
                             for r in nxdomain_rows if r["dns_rrname"] != base]
            nx_avg_entropy = sum(nx_entropies) / len(nx_entropies) if nx_entropies else 0.0
            if (len(nxdomain_rows) >= settings.get(conn, "dga_min_nxdomain_count")
                    and nx_avg_entropy >= settings.get(conn, "dga_min_entropy")):
                raise_incident(
                    conn, device_id, "dga", "high",
                    title="Possible domain-generation-algorithm activity under %s" % base,
                    description=(
                        "%d genuine NXDOMAIN lookups under %s in %d seconds (avg entropy %.1f "
                        "bits/char) - a pattern consistent with malware searching for its "
                        "command-and-control server by trying algorithmically generated names."
                        % (len(nxdomain_rows), base, window, nx_avg_entropy)
                    ),
                    first_seen=min(r["ts"] for r in nxdomain_rows),
                    last_seen=max(r["ts"] for r in nxdomain_rows),
                    event_ids=[r["id"] for r in nxdomain_rows],
                )
                fired += 1

    # Pass 2 - generated APEX domains (Audit.md H11). The pass above groups
    # by base domain and scores only what sits IN FRONT of it, so it
    # catches "x7fq2k.evil.com, p0zr8w.evil.com, ..." - but many DGA
    # families generate the registrable name itself: "x7fq2kp0zr.com,
    # q9vbn3mwxt.net, ...". Each of those is its own one-row group above,
    # with nothing in front of the base domain to score, so a device
    # trying hundreds of them never fired. Here all of a device's
    # NXDOMAIN lookups of bare apex names are pooled, and the generated
    # part - the label before the suffix ("x7fq2kp0zr") - is scored.
    # Same thresholds as the pass above. Note: per-character entropy of
    # a label can't exceed log2(its length), so with the default 3.3-bit
    # threshold only labels of 10+ characters can qualify - which is also
    # what keeps ordinary mistyped names ("gooogle.com") from counting.
    apex_nxdomain = defaultdict(list)
    for r in rows:
        if r["dns_rcode"] == "NXDOMAIN" and r["dns_rrname"] == _base_domain(r["dns_rrname"]):
            apex_nxdomain[r["device_id"]].append(r)
    for device_id, nx_rows in apex_nxdomain.items():
        names = {r["dns_rrname"] for r in nx_rows}
        if len(names) < settings.get(conn, "dga_min_nxdomain_count"):
            continue
        entropies = [_shannon_entropy(name.split(".")[0]) for name in names]
        avg_entropy = sum(entropies) / len(entropies)
        if avg_entropy < settings.get(conn, "dga_min_entropy"):
            continue
        raise_incident(
            conn, device_id, "dga", "high",
            title="Possible domain-generation-algorithm activity (%d random-looking domains)" % len(names),
            description=(
                "%d genuine NXDOMAIN lookups of %d different, random-looking domain names in %d "
                "seconds (avg entropy %.1f bits/char) - a pattern consistent with malware searching "
                "for its command-and-control server by trying algorithmically generated names."
                % (len(nx_rows), len(names), window, avg_entropy)
            ),
            first_seen=min(r["ts"] for r in nx_rows),
            last_seen=max(r["ts"] for r in nx_rows),
            event_ids=[r["id"] for r in nx_rows],
        )
        fired += 1

    set_window_start(conn, "dns_tunneling", now)
    return fired


# --------------------------------------------------------------------------
# Signal 1h: C2 beaconing (ENHANCEMENT-PLAN.md step 2.6)
#
# A RITA-style regularity score, not a full port of RITA itself (that
# tool's actual scoring code wasn't available to verify against in this
# environment, and this project's own standard - "a query anyone can run
# by hand" - favors a formula simple enough to state plainly over one
# copied without being able to confirm it matches). The idea RITA
# popularized, and the one implemented here: real malware C2 beacons
# check in on a near-fixed timer with near-identical "I'm still here"
# payloads, which is a MUCH more regular pattern than anything a human
# browsing, streaming, or an app polling on its own irregular schedule
# produces. Scored with the coefficient of variation (stdev / mean) of
# the intervals BETWEEN connections and of the connection SIZES, to the
# same (device, dest_ip, dest_port) - CV near 0 means "every gap and
# every payload was almost identical", the beacon signature; CV near or
# above 1 means "wildly irregular", ordinary traffic.
#
# ALLOWLIST_BEACON_PORTS covers NTP (123/udp) specifically - a
# legitimate, extremely regular periodic check-in that would otherwise
# score high on timing alone. A broader push-notification allowlist
# (Apple APNs, Google FCM keep-alives, which are also fairly regular)
# is NOT included: those need vendor-specific IP ranges this project has
# no way to confirm live without an enrolled device actively using them,
# and this project's own standard is to state that gap rather than guess
# at ranges. In practice, real push payloads tend to vary enough in size
# to keep their size_score down even when timing alone looks regular -
# untested here, but worth recording as the reasoning, not a guess
# presented as a verified mitigation.
# --------------------------------------------------------------------------
# Window, minimum connection count and score threshold all live in
# app/settings.py - see port_scan_signal's own note above.

ALLOWLIST_BEACON_PORTS = {123}  # NTP - see the header comment above


def _coefficient_of_variation(values):
    """stdev/mean, or 0.0 for a mean of zero or fewer than two values -
    statistics.stdev needs at least two data points, and a CV against a
    zero mean is undefined, not "maximally regular"."""
    if len(values) < 2:
        return 0.0
    mean = statistics.mean(values)
    if mean == 0:
        return 0.0
    return statistics.stdev(values) / mean


def _beacon_score(timestamps, sizes):
    """0.0 (no pattern at all) to 1.0 (perfectly regular timing AND
    perfectly uniform size). Timing weighted higher (0.7) than size
    (0.3): a C2 channel's payload size can legitimately vary a little
    more than its check-in timer does, so size alone shouldn't be able
    to sink an otherwise clearly-periodic pattern's score, but it still
    corroborates."""
    intervals = [b - a for a, b in zip(sorted(timestamps), sorted(timestamps)[1:])]
    timing_score = max(0.0, 1.0 - _coefficient_of_variation(intervals))
    size_score = max(0.0, 1.0 - _coefficient_of_variation(sizes))
    return 0.7 * timing_score + 0.3 * size_score


def beacon_signal(conn):
    now = time.time()
    window = settings.get(conn, "beacon_window_seconds")
    since = now - window
    min_connections = settings.get(conn, "beacon_min_connections")
    threshold = settings.get(conn, "beacon_score_threshold")

    # The window is on ts (when the flow was logged), so a flow logged late
    # is still picked up; the timing is judged on flow_start (when the
    # connection began). The IDS logs flows in batches after they time
    # out, so ts gaps are the flow manager's rhythm, not the beacon's - a
    # 10 s beacon's logged gaps ran 5-15 s and it scored 0.73 against the
    # 0.8 threshold (step 7.2 finding, measured live). Rows from before
    # flow_start existed fall back to ts.
    rows = conn.execute(
        """SELECT id, device_id, dest_ip, dest_port, COALESCE(flow_start, ts) started,
                  COALESCE(bytes_toserver, 0) + COALESCE(bytes_toclient, 0) total_bytes
             FROM events
            WHERE event_type='flow' AND device_id IS NOT NULL AND ts > ?""",
        (since,),
    ).fetchall()

    groups = defaultdict(list)
    for r in rows:
        if r["dest_port"] in ALLOWLIST_BEACON_PORTS:
            continue
        groups[(r["device_id"], r["dest_ip"], r["dest_port"])].append(r)

    fired = 0
    for (device_id, dest_ip, dest_port), group in groups.items():
        if len(group) < min_connections:
            continue
        timestamps = [r["started"] for r in group]
        sizes = [r["total_bytes"] for r in group]
        score = _beacon_score(timestamps, sizes)
        if score < threshold:
            continue

        event_ids = [r["id"] for r in group]
        raise_incident(
            conn, device_id, "beacon", "high",
            title="Possible C2 beacon to %s:%d" % (dest_ip, dest_port),
            description=(
                "%d connections to %s:%d over %d seconds with a regularity score of %.2f "
                "(0=no pattern, 1=perfectly regular timing and size) - consistent with malware "
                "checking in with a command-and-control server on a fixed timer."
                % (len(group), dest_ip, dest_port, window, score)
            ),
            first_seen=min(timestamps), last_seen=max(timestamps),
            event_ids=event_ids,
        )
        fired += 1

    set_window_start(conn, "beacon", now)
    return fired


# --------------------------------------------------------------------------
# Campaign correlation + MITRE ATT&CK kill chain (ENHANCEMENT-PLAN.md
# step 2.8) - the closing piece of Stage 2, the "never cut" detection
# core.
#
# Different in kind from every signal above: it reads INCIDENTS, not raw
# events, and doesn't go through raise_incident() at all - a campaign is
# a different sort of object (it tracks which of a device's incidents
# belong to one unfolding multi-stage attack, not a fresh detection),
# with its own table and its own status lifecycle (mirroring incidents'
# new/investigating/resolved/false_positive so it triages the same way).
#
# A device's OPEN incidents (status new/investigating, within a much
# longer window than any individual signal's own - a real multi-stage
# attack can unfold over hours) are grouped by device, then filtered to
# just the ones with a RECOGNIZED ATT&CK tactic (app/playbooks.py's own
# mapping - malicious_domain, new_device, ids_other and
# adblock_ineffective have none, on purpose, and can't be a kill-chain
# stage). If the DISTINCT tactic count meets the threshold (default 2 -
# two incidents of the SAME tactic, like two scan variants, are one
# stage, not a multi-stage pattern), they're linked into one campaign.
# `tactics` records the kill chain itself: the distinct tactics in the
# order their first incident actually started - "Discovery -> Credential
# Access -> Command and Control" for the plan's own scan -> brute-force
# -> beacon example.
#
# Re-evaluated in full every cycle, the same trailing-window philosophy
# as every signal above: an existing open campaign for a device is
# extended (not duplicated) when a later incident adds a new tactic,
# recomputing the whole tactic sequence from every qualifying incident
# currently in the window rather than trying to patch it incrementally.
# --------------------------------------------------------------------------
# Window and minimum-tactic-count both live in app/settings.py - see
# port_scan_signal's own note above.

CAMPAIGN_LIVE_STATUSES = ("new", "investigating")


def campaign_signal(conn):
    now = time.time()
    window = settings.get(conn, "campaign_window_seconds")
    since = now - window
    min_tactics = settings.get(conn, "campaign_min_distinct_tactics")

    device_ids = [r["device_id"] for r in conn.execute(
        """SELECT DISTINCT device_id FROM incidents
            WHERE status IN ('new','investigating') AND last_seen > ? AND device_id IS NOT NULL""",
        (since,)).fetchall()]

    fired = 0
    for device_id in device_ids:
        incidents = conn.execute(
            """SELECT id, signal_type, first_seen, last_seen, campaign_id FROM incidents
                WHERE device_id=? AND status IN ('new','investigating') AND last_seen > ?""",
            (device_id, since)).fetchall()

        tagged = []
        for inc in incidents:
            attack = playbooks.get_attack(inc["signal_type"])
            if attack:
                tagged.append((inc, attack["tactic"]))

        distinct_tactics = {tactic for _, tactic in tagged}
        already_has_campaign = any(inc["campaign_id"] is not None for inc in incidents)
        if len(distinct_tactics) < min_tactics and not already_has_campaign:
            continue  # not enough for a new campaign, and none exists to extend

        # The kill chain: distinct tactics in the order their first
        # incident actually started, collapsing immediate repeats (two
        # incidents of the same tactic back to back stay one entry, not
        # two) so it reads as a sequence of STAGES, not a raw incident list.
        tagged.sort(key=lambda pair: pair[0]["first_seen"])
        tactic_sequence = []
        for _, tactic in tagged:
            if not tactic_sequence or tactic_sequence[-1] != tactic:
                tactic_sequence.append(tactic)
        tactics_str = " -> ".join(tactic_sequence)

        first_seen = min(inc["first_seen"] for inc, _ in tagged)
        last_seen = max(inc["last_seen"] for inc, _ in tagged)
        unattached_ids = [inc["id"] for inc, _ in tagged if inc["campaign_id"] is None]

        existing = conn.execute(
            """SELECT id FROM campaigns WHERE device_id=? AND status IN ('new','investigating')
                ORDER BY last_seen DESC LIMIT 1""",
            (device_id,)).fetchone()

        if existing:
            campaign_id = existing["id"]
            conn.execute(
                "UPDATE campaigns SET tactics=?, last_seen=?, updated_at=? WHERE id=?",
                (tactics_str, last_seen, now, campaign_id))
        else:
            device = conn.execute(
                "SELECT hostname, friendly_name FROM devices WHERE id=?", (device_id,)).fetchone()
            name = (device["friendly_name"] or device["hostname"]) if device else None
            name = name or ("device %d" % device_id)
            cur = conn.execute(
                """INSERT INTO campaigns
                       (device_id, title, status, tactics, first_seen, last_seen, created_at, updated_at)
                   VALUES (?, ?, 'new', ?, ?, ?, ?, ?)""",
                (device_id, "Multi-stage attack pattern on %s" % name, tactics_str,
                 first_seen, last_seen, now, now))
            campaign_id = cur.lastrowid

        if unattached_ids:
            conn.executemany(
                "UPDATE incidents SET campaign_id=? WHERE id=?",
                [(campaign_id, iid) for iid in unattached_ids])
        fired += 1

    conn.commit()
    set_window_start(conn, "campaign", now)
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
BASELINE_FLAT_STDEV_FRACTION = 0.25  # spread assumed for a perfectly flat history - see behavioral_baseline_signal
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
            # A perfectly flat history (every day the same, e.g. a camera
            # that always sends 0 bytes or exactly the same amount at this
            # hour) used to be skipped entirely - so even a sudden 500 MB
            # upload from it never fired (Audit.md). Instead, assume a
            # modest natural spread: a quarter of the usual amount, and at
            # least BASELINE_MIN_BYTES_FLOOR, so a device that normally
            # sends nothing at all fires only on a real amount of data.
            stdev = max(mean * BASELINE_FLAT_STDEV_FRACTION, BASELINE_MIN_BYTES_FLOOR)

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


SIGNALS = [port_scan_signal, network_sweep_signal, slow_scan_signal, dns_bypass_signal,
           ids_alert_signal, threat_intel_signal, dns_tunneling_signal, beacon_signal,
           brute_force_signal, malicious_domain_signal, new_device_signal,
           adblock_effectiveness_signal, behavioral_baseline_signal, campaign_signal]


def run_all(conn):
    """Run every signal once. Returns {signal_name: incidents_fired}.

    Each signal's work is committed as soon as that signal finishes, and
    thrown away (rolled back) if it fails part-way. Previously one commit
    at the very end saved everything - including whatever a failed signal
    had half-written (say, an incident raised but its window position not
    yet moved on), which then made it process the same events again."""
    results = {}
    for fn in SIGNALS:
        try:
            results[fn.__name__] = fn(conn)
            conn.commit()
        except Exception as exc:
            conn.rollback()
            print("correlation: %s failed: %s" % (fn.__name__, exc), flush=True)
            results[fn.__name__] = None
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

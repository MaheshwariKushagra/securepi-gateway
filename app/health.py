#!/usr/bin/env python3
"""
SecurePi Gateway - platform health supervisor (ENHANCEMENT-PLAN.md steps
3.5 and 3.6).

Every signal in app/correlation.py asks "is a DEVICE doing something
suspicious"; this asks "is the GATEWAY ITSELF healthy enough to trust
what those signals are telling you". A stopped IDS means silent,
undetected blind spots, not a quiet network - the operator needs to
know the difference, and needs to know it the same way as any other
incident (in the queue, audited, not buried in a log file).

Run from app/ingest.py's loop, not app/engine.py's - deliberately.
app/engine.py IS one of the things this module needs to be able to say
is unhealthy, and a process cannot reliably detect its own death;
app/ingest.py is a genuinely separate systemd unit, so it keeps
checking (and can correctly report "the engine hasn't run recently")
even if the engine itself has crashed. Throttled to
`health_check_interval_seconds` (default 30s, well under the 60s the
plan's own exit criterion allows) via the same "gate on a stored
timestamp" pattern app/retention.py already uses for its own
once-a-day job, since ingest's own loop runs every 2s and most of these
checks (systemctl calls, a WAN ping) are too costly to repeat that
often.

Platform incidents are ordinary rows in the incidents table
(device_id=NULL, a signal_type not present in app/playbooks.py's
ATTACK_MAPPING, since infrastructure health is not an adversary
technique - the same "no tactic, on purpose" treatment
malicious_domain/new_device/ids_other/adblock_ineffective already get)
- they show up in the same Incidents queue, get the same audit
treatment, and clear the same way: an operator resolves one once the
underlying problem is actually fixed. This module never marks one
resolved itself, matching every other signal's own behavior - it only
ever raises/extends an incident while a problem is real, never closes
one out from underneath an operator.

check_dns_failopen() (step 3.6) is the one exception to "this module
only observes and reports": when the DNS filter stops answering DNS, it
actively redirects plaintext DNS to a public upstream resolver via
app/dns_failopen.py, so the network keeps working while the incident
above is still open. That firewall change - not the incident - is what
reverts itself automatically once the DNS filter recovers.
"""

import os
import shutil
import subprocess
import time

import audit
import correlation
import dns_failopen
import dpi_gate
import retention
import settings

SERVICES_LIST_PATH = "/opt/securepi/services.list"
DB_PATH = "/var/lib/securepi/securepi.db"
DB_DIR = os.path.dirname(DB_PATH)
WAN_PROBE_HOST = "1.1.1.1"
# The name the DNS fail-open probe asks for. The DNS filter answers it
# itself (NXDOMAIN, from the `use-application-dns.net` rule adguard.py's
# add_nxdomain_rule installs - Firefox's DoH canary), without asking any
# upstream resolver. So the probe tests "is the filter answering", not "is
# the internet up" - see _dns_resolves. It was example.com until 3 October
# 2026, which also put a lookup every 5 s into the filter's query log.
DNS_PROBE_DOMAIN = "use-application-dns.net"
DNS_PROBE_TIMEOUT_S = 2


def _services_to_check():
    if not os.path.exists(SERVICES_LIST_PATH):
        return []
    out = []
    with open(SERVICES_LIST_PATH) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def _is_active(service):
    """True/False, or None if systemctl itself couldn't be asked - never
    conflated with "known inactive", which would be a false alarm."""
    try:
        result = subprocess.run(["systemctl", "is-active", service],
                                 capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() == "active"


def _resource_usage(service):
    """Current memory (bytes) and CPU time (seconds) for one systemd
    unit, read from systemd's own cgroup accounting - no psutil, no
    /proc parsing, matching ENHANCEMENT-PLAN.md §1.6's decision against
    adding a system-monitor dependency for this."""
    try:
        result = subprocess.run(
            ["systemctl", "show", service, "-p", "MemoryCurrent", "-p", "CPUUsageNSec"],
            capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    mem = values.get("MemoryCurrent")
    cpu = values.get("CPUUsageNSec")
    # systemd prints "[not set]" for a unit with accounting disabled, and
    # "18446744073709551615" (uint64 max) for "never measured yet" -
    # neither is a real number, and .isdigit() alone would still accept
    # the second, so both need excluding explicitly.
    mem_bytes = int(mem) if mem and mem.isdigit() and mem != "18446744073709551615" else None
    cpu_seconds = (int(cpu) / 1e9) if cpu and cpu.isdigit() and cpu != "18446744073709551615" else None
    return mem_bytes, cpu_seconds


def check_services(conn, now):
    """Refreshes service_health for every service in services.list, and
    raises/extends ONE combined 'platform_service_down' incident naming
    every currently-inactive service - not one incident per service,
    since several going down at once (e.g. a reboot) is one platform
    event to triage, not a cascade of separate rows."""
    down = []
    for service in _services_to_check():
        active = _is_active(service)
        mem, cpu = _resource_usage(service)
        conn.execute(
            "INSERT INTO service_health (service, checked_at, is_active, memory_bytes, cpu_seconds)"
            " VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT(service) DO UPDATE SET checked_at=excluded.checked_at,"
            " is_active=excluded.is_active, memory_bytes=excluded.memory_bytes,"
            " cpu_seconds=excluded.cpu_seconds",
            (service, now, active, mem, cpu),
        )
        if active is False:
            down.append(service)

    if down:
        title = "%d service%s not running: %s" % (
            len(down), "" if len(down) == 1 else "s", ", ".join(down))
        correlation.raise_incident(
            conn, None, "platform_service_down", "high", title,
            "Stopped: %s. Every signal that depends on this service is blind while it's down." % ", ".join(down),
            now, now, [],
        )


# The signal_state row app/engine.py stamps once per completed cycle (and
# once at start-up). It is the engine's own heartbeat and nothing else.
ENGINE_HEARTBEAT = "engine_cycle"


def record_engine_heartbeat(conn, now=None):
    """Called by app/engine.py when it starts and after every completed
    cycle - see check_staleness() for why it has a row of its own."""
    now = now if now is not None else time.time()
    conn.execute(
        "INSERT INTO signal_state (signal_type, last_run_ts) VALUES (?, ?)"
        " ON CONFLICT(signal_type) DO UPDATE SET last_run_ts=excluded.last_run_ts",
        (ENGINE_HEARTBEAT, now),
    )
    conn.commit()


def check_staleness(conn, now):
    """Catches a process that's still 'active' per systemd but has
    stopped actually doing anything - a hang, not a crash - which
    check_services() alone would miss. Reuses the ingest_stats/
    signal_state tables step 1.1 onward already maintain, plus the
    events table's own source column for the IDS and DNS filter specifically."""
    stale_after = settings.get(conn, "health_stale_after_seconds")
    stale = []

    row = conn.execute("SELECT last_run FROM ingest_stats WHERE id=1").fetchone()
    if row and row["last_run"] and now - row["last_run"] > stale_after:
        stale.append("ingest")

    # The engine's own heartbeat row only. This used to take the newest
    # timestamp of ANY signal_state row - but this very process (ingest)
    # stamps rows there too, for these health checks and the DNS
    # fail-open check, so a hung engine always looked fresh (Audit.md H9).
    # No row yet means an engine that predates the heartbeat or hasn't
    # started once - a start-up condition, like the event sources below.
    engine_row = conn.execute("SELECT last_run_ts FROM signal_state WHERE signal_type=?",
                              (ENGINE_HEARTBEAT,)).fetchone()
    if engine_row and engine_row["last_run_ts"] and now - engine_row["last_run_ts"] > stale_after:
        stale.append("correlation engine")

    for label, source in (("IDS", "suricata"), ("DNS filter", "adguard")):
        r = conn.execute("SELECT max(ts) m FROM events WHERE source=?", (source,)).fetchone()
        if r and r["m"] and now - r["m"] > stale_after:
            stale.append(label)
        # No row at all (never seen a single event from this source) is
        # a startup condition, not staleness - not flagged here.

    if stale:
        title = "No recent activity from: %s" % ", ".join(stale)
        correlation.raise_incident(
            conn, None, "platform_stale", "medium", title,
            "No fresh output in over %ds from: %s. The systemd unit(s) may still show "
            "'active' - this is a hang, not necessarily a crash." % (stale_after, ", ".join(stale)),
            now, now, [],
        )


def check_disk(conn, now):
    min_free_pct = settings.get(conn, "health_disk_min_free_pct")
    total, _used, free = shutil.disk_usage(DB_DIR if os.path.isdir(DB_DIR) else "/")
    free_pct = (free / total * 100) if total else 100
    if free_pct < min_free_pct:
        correlation.raise_incident(
            conn, None, "platform_disk_low", "high",
            "Disk %.1f%% free (below %d%% threshold)" % (free_pct, min_free_pct),
            "Only %.1f%% of disk space remains free on the volume holding the database. "
            "Retention (step 1.3) may not be keeping up, or something else is filling the disk."
            % free_pct,
            now, now, [],
        )


def check_db_size(conn, now):
    max_mb = settings.get(conn, "health_db_max_size_mb")
    size_mb = retention.db_size_bytes(conn) / 1e6
    if size_mb > max_mb:
        correlation.raise_incident(
            conn, None, "platform_db_size", "medium",
            "Database is %.0f MB (above the %d MB threshold)" % (size_mb, max_mb),
            "The live database is larger than expected. Most likely cause: step 1.3's nightly "
            "retention job has stopped running - check securepi-engine's own journal.",
            now, now, [],
        )


def check_wan(conn, now):
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "3", WAN_PROBE_HOST],
                                 capture_output=True, timeout=6)
        reachable = result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        reachable = False
    if not reachable:
        correlation.raise_incident(
            conn, None, "platform_wan_down", "high",
            "WAN uplink unreachable",
            "A single ping to %s failed. DNS filtering and threat-intel updates depend on "
            "internet access; local network monitoring and the console itself are unaffected."
            % WAN_PROBE_HOST,
            now, now, [],
        )


DPI_SERVICE = "securepi-dpi"


def check_dpi_proxy(conn, now):
    """Stage 7.7: keep the HTTPS inspection gate (app/dpi_gate.py) in step
    with whether the proxy is actually answering.

    The proxy's own unit already opens the gate when it starts and closes
    it when it stops, so a stopped or crashed proxy never needs this. What
    systemd can't see is a proxy that is running but hung: every enrolled
    device's HTTPS would hang with it. So, while the unit is active:

      - proxy answering, gate closed -> reopen it (it was closed by an
        earlier hang, or a reload of nftables.conf emptied the set)
      - proxy not answering          -> close the gate (enrolled devices
        browse undecrypted) and raise an incident saying so

    When the unit isn't active the gate should already be closed; it is
    closed again here in case the unit's own ExecStopPost never ran. The
    'service not running' incident itself is check_services' job."""
    active = _is_active(DPI_SERVICE)
    if active is None:
        return
    if not active:
        if dpi_gate.is_open():
            dpi_gate.close_gate()
        return

    state = dpi_gate.probe()
    if state != dpi_gate.ANSWERING:
        # One retry, so a single slow moment doesn't bypass inspection.
        state = dpi_gate.probe()
    gate_open = dpi_gate.is_open()

    if state == dpi_gate.ANSWERING:
        if not gate_open:
            dpi_gate.open_gate()
            print("health: inspection proxy answering again - inspection gate reopened", flush=True)
        return

    if gate_open:
        dpi_gate.close_gate()
        print("health: inspection proxy %s - inspection gate closed (fail open)" % state, flush=True)
    correlation.raise_incident(
        conn, None, "platform_dpi_unresponsive", "high",
        "HTTPS inspection bypassed: proxy not answering",
        "%s is running but its listener was %s on two probes, so the inspection gate is "
        "closed: enrolled devices' HTTPS now goes out undecrypted instead of hanging. "
        "Inspection resumes by itself once the proxy answers again." % (DPI_SERVICE, state),
        now, now, [],
    )


def check_platform_health(conn, now=None):
    """Runs every check above. Never lets one check's failure stop the
    rest - the same 'never let one bad pass kill the service' principle
    app/ingest.py's own main loop already applies at the outer level."""
    now = now if now is not None else time.time()
    for check in (check_services, check_staleness, check_disk, check_db_size, check_wan, check_dpi_proxy):
        try:
            check(conn, now)
        except Exception as exc:
            print("health check %s failed: %s" % (check.__name__, exc), flush=True)
    conn.commit()


def run_if_due(conn, now=None):
    """Gate on a stored timestamp, the same pattern app/retention.py's
    run_retention_if_due() already uses - ingest.py's own loop runs
    every 2s, far more often than these checks need to repeat."""
    now = now if now is not None else time.time()
    interval = settings.get(conn, "health_check_interval_seconds")
    row = conn.execute("SELECT last_run_ts FROM signal_state WHERE signal_type='platform_health'").fetchone()
    last_run = row["last_run_ts"] if row else 0
    if now - last_run < interval:
        return False
    check_platform_health(conn, now)
    conn.execute(
        "INSERT INTO signal_state (signal_type, last_run_ts) VALUES ('platform_health', ?)"
        " ON CONFLICT(signal_type) DO UPDATE SET last_run_ts=excluded.last_run_ts",
        (now,),
    )
    conn.commit()
    return True


def _dns_resolves(host):
    """A real query, not just 'is the DNS filter's process active' - a hung-
    but-still-running DNS filter would pass systemctl's own is-active check
    (check_services above) but not actually answer anything, exactly
    the same 'active is not the same as working' distinction
    check_staleness already draws. Uses `dig`, already installed on the
    gateway (bind9-dnsutils) - the same 'shell out to a standard system
    tool rather than add a Python package' approach check_wan's own
    ping call already takes.

    Alive means "the filter replied at all", whatever the reply: dig exits
    0 for an answer, NXDOMAIN and SERVFAIL alike, and 9 when no reply came
    back. Before 3 October 2026 this asked for example.com and required a
    non-empty answer, so an uplink outage - the filter alive, but its
    upstream unreachable, so SERVFAIL - looked like a dead filter and
    switched fail-open on, i.e. sent every device's DNS to 1.1.1.1
    unfiltered (seen live in 7.7's drop-wan run; CODEBASE_AUDIT.md M2).
    The probe name is answered by the filter itself (DNS_PROBE_DOMAIN), so
    an outage upstream can no longer be mistaken for one in the filter."""
    try:
        result = subprocess.run(
            ["dig", "+time=%d" % DNS_PROBE_TIMEOUT_S, "+tries=1",
             "@%s" % host, DNS_PROBE_DOMAIN],
            capture_output=True, text=True, timeout=DNS_PROBE_TIMEOUT_S + 2)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _leftover_failopen_rule():
    """True if the firewall holds a fail-open rule right now. If nft can't
    be read, say so and answer False: nothing could be removed anyway."""
    try:
        return dns_failopen.is_active()
    except dns_failopen.DnsFailopenError as exc:
        print("health: could not check for a leftover dns fail-open rule: %s" % exc, flush=True)
        return False


def check_dns_failopen(conn, now):
    """ENHANCEMENT-PLAN.md step 3.6 (F§8.4): if the DNS filter stops actually
    answering DNS queries, redirect plaintext DNS to a public upstream
    resolver after a short grace period - long enough that the DNS filter's
    own `Restart=always` (10s) usually fixes a simple crash on its own
    first - so LAN clients keep resolving names (unfiltered, but
    working) instead of the whole network going dark. Reverts itself
    the moment the DNS filter is confirmed answering again: DNS service itself
    needs no operator action to come back, even though the incident
    this raises still needs a manual resolve like every other platform
    incident (see this module's own docstring on why none of these
    auto-resolve) - "automatic recovery" in the plan's own wording means
    the network, not the audit trail.

    `down_since` and `active` are deliberately two different things: a
    brief outage under the grace period sets `down_since` (tracking how
    long it's been going on) without ever setting `active` (nothing has
    actually been redirected yet) - so a blip that self-heals in a
    couple of seconds raises no incident and touches no firewall rule
    at all."""
    row = conn.execute("SELECT * FROM dns_failopen_state WHERE id=1").fetchone()
    resolving = _dns_resolves(dns_failopen.GATEWAY_IP)

    if resolving:
        if row["down_since"] is not None:
            conn.execute("UPDATE dns_failopen_state SET down_since=NULL WHERE id=1")
        if row["active"]:
            dns_failopen.deactivate()
            conn.execute("UPDATE dns_failopen_state SET active=0, changed_at=? WHERE id=1", (now,))
        elif _leftover_failopen_rule():
            # The database says fail-open is off, but the firewall still has
            # a redirect rule - an activation that failed part-way, or a
            # rule added by hand. Recovery used to trust the flag and leave
            # it, so every device's DNS stayed unfiltered (Audit10Oct H8).
            dns_failopen.deactivate()
            print("health: removed a dns fail-open rule the database didn't know about", flush=True)
            audit.log(conn, "health", "platform.dns_failopen_leftover_removed", target="dns-failopen",
                      detail="the DNS filter answers, but a fail-open redirect rule was still in the "
                             "firewall with fail-open recorded as off - removed")
        if row["down_since"] is not None or row["active"]:
            conn.commit()
        return

    down_since = row["down_since"]
    if down_since is None:
        conn.execute("UPDATE dns_failopen_state SET down_since=? WHERE id=1", (now,))
        conn.commit()
        return

    grace = settings.get(conn, "dns_failopen_after_seconds")
    if now - down_since < grace:
        return

    dns_failopen.activate()
    if not row["active"]:
        conn.execute("UPDATE dns_failopen_state SET active=1, changed_at=? WHERE id=1", (now,))
    correlation.raise_incident(
        conn, None, "platform_dns_failopen", "high",
        "DNS fail-open active - the DNS filter not answering queries",
        "The DNS filter has not answered a real DNS query in over %ds. Plaintext DNS for the "
        "project LAN is being redirected to a public upstream resolver (%s) so devices keep "
        "resolving names - unfiltered - until the DNS filter recovers." % (int(grace), dns_failopen.UPSTREAM_RESOLVER),
        now, now, [],
    )
    conn.commit()


def run_dns_failopen_if_due(conn, now=None):
    """Its own throttle, deliberately faster than run_if_due()'s general
    health_check_interval_seconds - the ~30s 'clients still resolve'
    exit criterion has no room to wait out a slower shared cycle."""
    now = now if now is not None else time.time()
    interval = settings.get(conn, "dns_failopen_check_interval_seconds")
    row = conn.execute("SELECT last_run_ts FROM signal_state WHERE signal_type='dns_failopen_check'").fetchone()
    last_run = row["last_run_ts"] if row else 0
    if now - last_run < interval:
        return False
    try:
        check_dns_failopen(conn, now)
    except Exception as exc:
        print("dns failopen check failed: %s" % exc, flush=True)
    conn.execute(
        "INSERT INTO signal_state (signal_type, last_run_ts) VALUES ('dns_failopen_check', ?)"
        " ON CONFLICT(signal_type) DO UPDATE SET last_run_ts=excluded.last_run_ts",
        (now,),
    )
    conn.commit()
    return True

#!/usr/bin/env python3
"""
SecurePi Gateway - web console.

Architecture: FastAPI serves a thin HTML shell plus JSON APIs; the browser
polls those APIs and updates the DOM in place. This replaced an earlier
meta-refresh design, which reloaded the whole page every 15 seconds - it
worked, but a console that visibly blinks and loses your scroll position
every few seconds is not something anyone would want to watch during an
incident.

Routes:
  /                  dashboard shell
  /devices           device inventory
  /devices/{id}      per-device detail
  /incidents         incident queue
  /incidents/{id}    incident detail with evidence chain
  /filtering         DNS filtering: blocklists, custom rules, query log

  /api/overview      everything the dashboard needs, one round trip
  /api/devices       device inventory
  /api/incidents     incident queue, filterable
  /api/events        recent event stream
  /api/filtering/*   AdGuard Home blocklists, rules and per-device policy
  /api/filtering/check              "why is this blocked?" - test a domain
  /api/filtering/analytics          network-wide ad-blocking analytics
  /api/filtering/lists/health       blocklist staleness and per-list contribution
  /api/native-profiles              vendor telemetry profiles a device can be assigned
  /api/devices/{id}/filtering/profile(s)  apply/remove/list a device's native-tracker profiles
  /api/filtering/resolver           resolver quality: config + measured DNS latency
  /api/filtering/resolver/apply     apply recommended resolver tuning (needs confirm=true)
  /api/filtering/ca                 Tier 2 CA fingerprint, validity, download URL
  /api/filtering/dpi/enrolled       every enrolled device, expiry, and a CA-trust check
  /api/devices/{id}/dpi             enroll/unenroll one device for Tier 2 (replaces the CLI)
  /api/devices/{id}/blocked         recently blocked domains for one device
  /api/devices/{id}/filtering/rules allow/block rules scoped to one device
  /api/devices/{id}/filtering/allow one-click unbreak, optionally temporary
  /api/devices/{id}/filtering/block block one domain for one device only
  /api/devices/{id}/privacy         per-device tracker/privacy report
  /api/devices/{id}/quarantine   quarantine a device via nftables, or undo it
"""

import base64
import datetime
import secrets
import sqlite3
import subprocess
import time

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.requests import Request

import adguard
import dpi_enroll
import native_trackers
import quarantine
import risk
import tracker_entities

DB_PATH = "/opt/securepi/securepi.db"
CONSOLE_USERNAME = "securepi"
CONSOLE_PASSWORD_FILE = "/root/.securepi-console-password"

# Static assets are versioned by service start time. Without this, a browser
# holding a cached stylesheet shows the old console after a deploy, which is
# indistinguishable from "the change did not work".
ASSET_V = str(int(time.time()))

app = FastAPI(title="SecurePi Gateway")
app.mount("/static", StaticFiles(directory="/opt/securepi/static"), name="static")
templates = Jinja2Templates(directory="/opt/securepi/templates")
templates.env.globals["asset_v"] = ASSET_V


def _console_password():
    with open(CONSOLE_PASSWORD_FILE) as f:
        return f.read().strip()


# Plain HTTP Basic Auth as ASGI middleware rather than a FastAPI dependency:
# it runs ahead of routing, so it also covers the /static mount, and it keeps
# auth as one linear function instead of a dependency wired onto every route
# (see SECUREPI-15-DAY-PLAN.md 4.5 - no dependency-injection patterns).
# Fails closed: if the password file is missing, every request is rejected
# rather than the console silently running open.
@app.middleware("http")
async def basic_auth(request: Request, call_next):
    scheme, _, creds = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() == "basic":
        try:
            username, password = base64.b64decode(creds).decode().split(":", 1)
        except Exception:
            username, password = "", ""
        try:
            correct_password = _console_password()
        except FileNotFoundError:
            correct_password = None
        if (correct_password is not None
                and secrets.compare_digest(username, CONSOLE_USERNAME)
                and secrets.compare_digest(password, correct_password)):
            return await call_next(request)
    return PlainTextResponse("Authentication required", status_code=401,
                              headers={"WWW-Authenticate": 'Basic realm="SecurePi Gateway"'})

# Time ranges offered by the dashboard's selector. Bucket widths are chosen so
# every range produces a similar number of points (~24-30): enough shape to
# read a trend, few enough that the chart stays legible.
RANGES = {
    "1h":  {"seconds": 3600,    "bucket": 300,   "label": "1 hour"},
    "6h":  {"seconds": 21600,   "bucket": 900,   "label": "6 hours"},
    "24h": {"seconds": 86400,   "bucket": 3600,  "label": "24 hours"},
    "7d":  {"seconds": 604800,  "bucket": 21600, "label": "7 days"},
}

# The correlation engine's signals, and how stale a signal's last run has to
# be before the console calls it unhealthy rather than just "hasn't found
# anything lately". Engine cycles every 15s (see engine.py); 4 missed cycles
# is a real problem, not noise.
SIGNALS = ["port_scan", "brute_force", "malicious_domain", "new_device"]
SIGNAL_STALE_AFTER = 60
INGEST_STALE_AFTER = 30  # ingest.py polls every 2s

INCIDENT_STATUSES = ("new", "investigating", "resolved", "false_positive")

# Bandwidth/requests "saved" by blocking is an estimate, not a measurement:
# we know how many DNS lookups were blocked, but not the size of the request
# each one would have made. 2 KB/request is a commonly cited rough figure
# for a blocked ad or tracker call (a small image, pixel or JSON beacon,
# not a full ad creative). ENHANCEMENT-PLAN.md step 7.5 replaces this
# constant with a value measured from this project's own benchmark; until
# that lands, the console names this figure so nobody mistakes it for one.
AVG_BLOCKED_REQUEST_BYTES = 2048

# A blocklist that hasn't synced in this long is either offline or its
# source URL has gone stale - either way, the operator should know rather
# than assume it's still doing its job. See step 5.4.
LIST_STALE_AFTER_HOURS = 48
# Below this share of all attributed blocks, an enabled list is flagged as
# "low contribution" in case it isn't earning its place. This is a share of
# *observed* blocks, not a true unique-blocks count (that needs the overlap
# experiment step 5.4 deferred to Stage 7 - see api_filtering_lists_health).
LIST_LOW_CONTRIBUTION_SHARE = 0.01

# Where deploy-dpi.sh installs the Tier 2 inspection CA (see step 5.6d) and
# the plain-HTTP URL it's already served from for devices to download -
# both fixed by that script, not discovered at runtime.
DPI_CA_PATH = "/opt/securepi-dpi/ca/mitmproxy-ca-cert.pem"
DPI_CA_DOWNLOAD_URL = "http://10.10.0.1:8081/securepi-ca.crt"


class IncidentUpdate(BaseModel):
    status: str


class DeviceUpdate(BaseModel):
    friendly_name: str


class DeviceFilterUpdate(BaseModel):
    enabled: bool


class DeviceRuleRequest(BaseModel):
    domain: str
    reason: str
    temporary: bool = False
    hours: int = 1


class DeviceBlockRequest(BaseModel):
    domain: str
    reason: str


class NativeProfileRequest(BaseModel):
    vendor: str


class ResolverTuningRequest(BaseModel):
    confirm: bool = False


class DpiEnrollRequest(BaseModel):
    enrolled: bool
    hours: int = dpi_enroll.DEFAULT_TIMEOUT_HOURS


class QuarantineUpdate(BaseModel):
    quarantined: bool


class FilteringToggle(BaseModel):
    enabled: bool


class BlocklistAdd(BaseModel):
    name: str
    url: str


class BlocklistUrl(BaseModel):
    url: str


class BlocklistToggle(BaseModel):
    url: str
    enabled: bool


class RuleAdd(BaseModel):
    domain: str
    action: str


class RuleRemove(BaseModel):
    rule: str


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def device_label(row):
    """Display name: explicit friendly name, else DHCP hostname, else a
    fallback. Never show a bare row id to the operator."""
    return row["friendly_name"] or row["hostname"] or ("device %d" % row["id"])


def device_identifiers(c, device_id):
    """Every identifier AdGuard could use to recognise this device: every MAC
    it has ever used, plus its current IP. Passed to adguard.py's per-device
    functions so a device's filtering setting survives a DHCP renewal or a
    MAC rotation instead of being silently orphaned on the old address (see
    ENHANCEMENT-PLAN.md finding A3). Also returns the current IP on its own,
    since check_host() and the DPI enrollment set still need a plain
    address rather than a list.
    """
    macs = [r["mac"] for r in c.execute(
        "SELECT mac FROM device_macs WHERE device_id=?", (device_id,))]
    ip_row = c.execute(
        "SELECT ip FROM device_ips WHERE device_id=? ORDER BY last_seen DESC LIMIT 1",
        (device_id,)).fetchone()
    current_ip = ip_row["ip"] if ip_row else None
    identifiers = list(macs)
    if current_ip:
        identifiers.append(current_ip)
    return identifiers, current_ip


def humanize_bytes(n):
    n = n or 0
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f TB" % n


def bucket_series(c, start, end, bucket_s, device_id=None):
    """
    Time-bucketed series for the dashboard charts.

    Buckets are pre-seeded across the entire window before events are added,
    so quiet periods render as real zeros. A gap in a time series reads as
    "data missing"; on a security dashboard that is a materially different
    claim from "nothing happened", and the wrong one to make by accident.

    Pass device_id to scope every series to one device, for its detail page.
    """
    n = max(1, int((end - start) / bucket_s))
    labels, down, up, blocked, allowed, events = [], [0]*n, [0]*n, [0]*n, [0]*n, [0]*n

    fmt = "%H:%M" if (end - start) <= 86400 else "%d %b %H:%M"
    for i in range(n):
        labels.append(time.strftime(fmt, time.localtime(start + i * bucket_s)))

    dev_clause = " AND device_id=?" if device_id is not None else ""
    dev_arg = (device_id,) if device_id is not None else ()

    for r in c.execute(
        "SELECT ts, bytes_toclient, bytes_toserver FROM events"
        " WHERE event_type='flow' AND ts >= ? AND ts < ?" + dev_clause,
        (start, end) + dev_arg):
        i = int((r["ts"] - start) / bucket_s)
        if 0 <= i < n:
            down[i] += r["bytes_toclient"] or 0
            up[i] += r["bytes_toserver"] or 0

    for r in c.execute(
        "SELECT ts, blocked FROM events"
        " WHERE event_type='dns_query' AND ts >= ? AND ts < ?" + dev_clause,
        (start, end) + dev_arg):
        i = int((r["ts"] - start) / bucket_s)
        if 0 <= i < n:
            if r["blocked"]:
                blocked[i] += 1
            else:
                allowed[i] += 1

    for r in c.execute(
        "SELECT ts FROM events WHERE ts >= ? AND ts < ?" + dev_clause,
        (start, end) + dev_arg):
        i = int((r["ts"] - start) / bucket_s)
        if 0 <= i < n:
            events[i] += 1

    return {
        "labels": labels,
        # Kbps rather than raw bytes, so the y-axis means the same thing
        # whichever bucket width the selected range happens to use.
        "down_kbps": [round(b / bucket_s / 1024, 2) for b in down],
        "up_kbps": [round(b / bucket_s / 1024, 2) for b in up],
        "blocked": blocked,
        "allowed": allowed,
        "events": events,
    }


def _tracker_breakdown(c, start, end, device_id=None, limit=10):
    """Group DNS lookups in [start, end) by the tracker company they belong
    to, per tracker_entities.py. Returns a summary plus the top companies by
    how often they were contacted - this is what step 5.3's "N tracking
    companies contacted, M blocked" figure and per-device privacy report
    are built from.

    Runs over raw events rather than a rollup table, since Stage 1's
    device_hourly/filter_hourly rollups don't exist yet (see the plan's
    "out of order" note); grouping by domain first keeps this to one row
    per distinct domain rather than one per event.
    """
    dev_clause = " AND device_id=?" if device_id is not None else ""
    dev_arg = (device_id,) if device_id is not None else ()
    rows = c.execute(
        "SELECT dns_rrname, count(*) n, sum(blocked=1) b FROM events"
        " WHERE event_type='dns_query' AND dns_rrname IS NOT NULL"
        "   AND ts >= ? AND ts < ?" + dev_clause +
        " GROUP BY dns_rrname", (start, end) + dev_arg)

    companies = {}
    for r in rows:
        company = tracker_entities.attribute_domain(r["dns_rrname"])
        if company is None:
            continue
        slot = companies.setdefault(company, {"company": company, "contacted": 0, "blocked": 0})
        slot["contacted"] += r["n"]
        slot["blocked"] += r["b"] or 0

    ranked = sorted(companies.values(), key=lambda x: -x["contacted"])
    return {
        "companies_contacted": len(ranked),
        "companies_blocked": sum(1 for x in ranked if x["blocked"] > 0),
        "top": ranked[:limit],
    }


def _savings_estimate(requests_blocked):
    """See AVG_BLOCKED_REQUEST_BYTES above for why this is an estimate."""
    est_bytes = requests_blocked * AVG_BLOCKED_REQUEST_BYTES
    return {
        "requests_blocked": requests_blocked,
        "estimated_bytes": est_bytes,
        "estimated_bytes_h": humanize_bytes(est_bytes),
        "method": ("estimated as blocked requests x %d KB/request - a typical size for a "
                   "blocked ad/tracker call, not a measurement of this network's traffic. "
                   "Step 7.5 replaces this with a benchmarked figure." % (AVG_BLOCKED_REQUEST_BYTES // 1024)),
    }


def _tier2_breakdown(c, start, end, device_id=None):
    """Counts of what the Tier-2 (selective HTTPS inspection) addon actually
    did in [start, end): decrypt / passthrough / ads_stripped / path_blocked
    / tls_failed decisions, plus the total ad objects removed. tls_failed
    (step 5.6) is what the CA-trust check in api_filtering_dpi_enrolled
    reads to notice a device that likely hasn't installed the CA. Source
    data is written by dpi/securepi_adfilter.py and read by ingest.py's
    read_dpi_events() - see ENHANCEMENT-PLAN.md step 5.1."""
    dev_clause = " AND device_id=?" if device_id is not None else ""
    dev_arg = (device_id,) if device_id is not None else ()
    counts = {"decrypt": 0, "passthrough": 0, "ads_stripped": 0, "path_blocked": 0, "tls_failed": 0}
    for r in c.execute(
        "SELECT dpi_action, count(*) n FROM events"
        " WHERE source='dpi' AND ts >= ? AND ts < ?" + dev_clause +
        " GROUP BY dpi_action", (start, end) + dev_arg):
        if r["dpi_action"] in counts:
            counts[r["dpi_action"]] = r["n"]
    ads_removed = c.execute(
        "SELECT COALESCE(sum(dpi_ads_removed),0) FROM events"
        " WHERE source='dpi' AND dpi_action='ads_stripped'"
        "   AND ts >= ? AND ts < ?" + dev_clause, (start, end) + dev_arg).fetchone()[0]
    counts["ads_removed"] = ads_removed
    counts["active"] = any(v for k, v in counts.items() if k != "ads_removed")
    return counts


def _percentile(sorted_values, pct):
    """Nearest-rank percentile of an already-sorted list. Returns None for
    an empty list rather than raising, since "no data yet" is a normal
    state here (a fresh gateway with little DNS traffic)."""
    if not sorted_values:
        return None
    idx = min(len(sorted_values) - 1, int(round(pct / 100.0 * (len(sorted_values) - 1))))
    return round(sorted_values[idx], 1)


def _dns_latency_percentiles(c, start, end, sample_limit=5000):
    """p50/p95 DNS resolution latency (step 5.5c), from dns_elapsed_ms
    captured on every AdGuard query since step 5.1. Only meaningful for
    NOT-cached answers - a cache hit's latency says more about SQLite than
    about the upstream resolver, so it's excluded here rather than
    diluting the figure."""
    rows = c.execute(
        "SELECT dns_elapsed_ms FROM events"
        " WHERE event_type='dns_query' AND dns_cached=0 AND dns_elapsed_ms IS NOT NULL"
        "   AND ts >= ? AND ts < ? ORDER BY id DESC LIMIT ?",
        (start, end, sample_limit)).fetchall()
    values = sorted(r["dns_elapsed_ms"] for r in rows)
    return {
        "sample_size": len(values),
        "p50_ms": _percentile(values, 50),
        "p95_ms": _percentile(values, 95),
    }


@app.get("/api/overview")
def api_overview(range: str = Query("6h")):
    spec = RANGES.get(range, RANGES["6h"])
    c = db()
    now = time.time()
    start = now - spec["seconds"]

    series = bucket_series(c, start, now, spec["bucket"])

    # --- KPI tiles -------------------------------------------------------
    devices_total = c.execute("SELECT count(*) FROM devices").fetchone()[0]
    devices_active = c.execute(
        "SELECT count(*) FROM devices WHERE last_seen > ?", (now - 600,)).fetchone()[0]
    events_total = c.execute("SELECT count(*) FROM events").fetchone()[0]
    events_window = c.execute(
        "SELECT count(*) FROM events WHERE ts >= ?", (start,)).fetchone()[0]
    events_per_min = round(events_window / max(1, spec["seconds"] / 60.0), 1)

    incidents_open = c.execute(
        "SELECT count(*) FROM incidents WHERE status='new'").fetchone()[0]
    incidents_high = c.execute(
        "SELECT count(*) FROM incidents WHERE status='new' AND severity='high'").fetchone()[0]

    dns_total = c.execute(
        "SELECT count(*) FROM events WHERE event_type='dns_query' AND ts >= ?",
        (start,)).fetchone()[0]
    dns_blocked = c.execute(
        "SELECT count(*) FROM events WHERE event_type='dns_query' AND blocked=1 AND ts >= ?",
        (start,)).fetchone()[0]
    block_rate = round(100.0 * dns_blocked / dns_total, 1) if dns_total else 0.0

    bytes_window = c.execute(
        "SELECT COALESCE(sum(bytes_toclient),0)+COALESCE(sum(bytes_toserver),0)"
        " FROM events WHERE event_type='flow' AND ts >= ?", (start,)).fetchone()[0]

    # --- breakdowns ------------------------------------------------------
    severity = {"high": 0, "medium": 0, "low": 0}
    for r in c.execute(
        "SELECT severity, count(*) n FROM incidents WHERE status='new' GROUP BY severity"):
        if r["severity"] in severity:
            severity[r["severity"]] = r["n"]

    signal_mix = [
        {"signal": r["signal_type"], "count": r["n"]}
        for r in c.execute(
            "SELECT signal_type, count(*) n FROM incidents GROUP BY signal_type ORDER BY n DESC")
    ]

    top_blocked = [
        {"domain": r["dns_rrname"], "count": r["n"]}
        for r in c.execute(
            "SELECT dns_rrname, count(*) n FROM events"
            " WHERE event_type='dns_query' AND blocked=1 AND ts >= ? AND dns_rrname IS NOT NULL"
            " GROUP BY dns_rrname ORDER BY n DESC LIMIT 8", (start,))
    ]

    top_destinations = [
        {"sni": r["tls_sni"], "count": r["n"]}
        for r in c.execute(
            "SELECT tls_sni, count(*) n FROM events"
            " WHERE tls_sni IS NOT NULL AND ts >= ?"
            " GROUP BY tls_sni ORDER BY n DESC LIMIT 8", (start,))
    ]

    top_talkers = []
    for r in c.execute(
        "SELECT d.id, d.hostname, d.friendly_name,"
        "       COALESCE(sum(e.bytes_toclient),0)+COALESCE(sum(e.bytes_toserver),0) total"
        "  FROM devices d JOIN events e ON e.device_id = d.id"
        " WHERE e.event_type='flow' AND e.ts >= ?"
        " GROUP BY d.id ORDER BY total DESC LIMIT 6", (start,)):
        top_talkers.append({
            "id": r["id"], "name": device_label(r),
            "bytes": r["total"], "bytes_h": humanize_bytes(r["total"]),
        })

    protocols = [
        {"name": r["proto"] or "unknown", "count": r["n"]}
        for r in c.execute(
            "SELECT proto, count(*) n FROM events WHERE ts >= ? AND proto IS NOT NULL"
            " GROUP BY proto ORDER BY n DESC LIMIT 6", (start,))
    ]

    event_types = [
        {"name": r["event_type"], "count": r["n"]}
        for r in c.execute(
            "SELECT event_type, count(*) n FROM events WHERE ts >= ?"
            " GROUP BY event_type ORDER BY n DESC LIMIT 8", (start,))
    ]

    # --- live feeds ------------------------------------------------------
    recent_events = []
    for r in c.execute(
        "SELECT e.*, d.hostname, d.friendly_name FROM events e"
        " LEFT JOIN devices d ON d.id = e.device_id"
        " ORDER BY e.id DESC LIMIT 25"):
        recent_events.append(_event_row(r))

    active_incidents = []
    for r in c.execute(
        "SELECT i.*, d.hostname, d.friendly_name FROM incidents i"
        " LEFT JOIN devices d ON d.id = i.device_id"
        " WHERE i.status='new'"
        " ORDER BY CASE i.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,"
        "          i.last_seen DESC LIMIT 8"):
        active_incidents.append({
            "id": r["id"], "title": r["title"], "severity": r["severity"],
            "signal_type": r["signal_type"], "evidence_count": r["evidence_count"],
            "device": device_label(r) if r["device_id"] else None,
            "device_id": r["device_id"],
            "last_seen": time.strftime("%H:%M:%S", time.localtime(r["last_seen"])),
            "age": _age(now - r["last_seen"]),
        })

    return {
        "generated_at": time.strftime("%H:%M:%S", time.localtime(now)),
        "range": range,
        "range_label": spec["label"],
        "kpis": {
            "devices_total": devices_total,
            "devices_active": devices_active,
            "events_total": events_total,
            "events_per_min": events_per_min,
            "incidents_open": incidents_open,
            "incidents_high": incidents_high,
            "blocked": dns_blocked,
            "block_rate": block_rate,
            "traffic": humanize_bytes(bytes_window),
            "dns_total": dns_total,
        },
        "series": series,
        "severity": severity,
        "signal_mix": signal_mix,
        "top_blocked": top_blocked,
        "top_destinations": top_destinations,
        "top_talkers": top_talkers,
        "protocols": protocols,
        "event_types": event_types,
        "recent_events": recent_events,
        "active_incidents": active_incidents,
    }


def _age(seconds):
    """Compact relative age: '4s', '12m', '3h', '2d'."""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "%ds" % seconds
    if seconds < 3600:
        return "%dm" % (seconds // 60)
    if seconds < 86400:
        return "%dh" % (seconds // 3600)
    return "%dd" % (seconds // 86400)


def _event_row(r):
    """One event flattened for display, with a type-appropriate summary."""
    etype = r["event_type"]
    if etype == "flow":
        detail = "%s:%s" % (r["dest_ip"], r["dest_port"])
        extra = "%s down / %s up" % (
            humanize_bytes(r["bytes_toclient"]), humanize_bytes(r["bytes_toserver"]))
    elif etype == "dns_query":
        detail = r["dns_rrname"] or "-"
        extra = "blocked" if r["blocked"] else "allowed"
    elif etype == "dns":
        detail = r["dns_rrname"] or "-"
        extra = r["dns_rrtype"] or ""
    elif etype == "tls":
        detail = r["tls_sni"] or r["dest_ip"] or "-"
        extra = r["tls_version"] or ""
    elif etype == "alert":
        detail = r["alert_signature"] or "-"
        extra = r["alert_category"] or ""
    else:
        detail = "%s -> %s" % (r["src_ip"], r["dest_ip"])
        extra = r["proto"] or ""
    return {
        "time": time.strftime("%H:%M:%S", time.localtime(r["ts"])),
        "type": etype,
        "device": (r["friendly_name"] or r["hostname"]) if "hostname" in r.keys() else None,
        "src": r["src_ip"],
        "detail": detail,
        "extra": extra,
        "blocked": bool(r["blocked"]),
        "severity": r["alert_severity"],
    }


@app.get("/api/devices")
def api_devices():
    c = db()
    now = time.time()
    out = []
    for d in c.execute("SELECT * FROM devices ORDER BY last_seen DESC"):
        ip = c.execute(
            "SELECT ip FROM device_ips WHERE device_id=? ORDER BY last_seen DESC LIMIT 1",
            (d["id"],)).fetchone()
        macs = c.execute(
            "SELECT count(*) n, sum(is_randomized) r FROM device_macs WHERE device_id=?",
            (d["id"],)).fetchone()
        agg = c.execute(
            "SELECT COALESCE(sum(CASE WHEN event_type='flow' THEN bytes_toclient END),0) down,"
            "       COALESCE(sum(CASE WHEN event_type='flow' THEN bytes_toserver END),0) up,"
            "       COALESCE(sum(event_type='dns_query'),0) dns,"
            "       COALESCE(sum(blocked=1),0) blocked,"
            "       COALESCE(sum(event_type='tls'),0) tls,"
            "       COALESCE(sum(alert_signature IS NOT NULL),0) alerts,"
            "       count(*) events"
            "  FROM events WHERE device_id=?", (d["id"],)).fetchone()
        inc = c.execute(
            "SELECT count(*) n, COALESCE(sum(severity='high'),0) high"
            "  FROM incidents WHERE device_id=? AND status='new'", (d["id"],)).fetchone()
        r = risk.device_risk(c, d["id"], now)
        out.append({
            "id": d["id"], "name": device_label(d),
            "hostname": d["hostname"], "ip": ip["ip"] if ip else None,
            "mac_count": macs["n"] or 0, "randomized": bool(macs["r"]),
            "down": agg["down"], "down_h": humanize_bytes(agg["down"]),
            "up": agg["up"], "up_h": humanize_bytes(agg["up"]),
            "dns": agg["dns"], "blocked": agg["blocked"], "tls": agg["tls"],
            "alerts": agg["alerts"], "events": agg["events"],
            "incidents": inc["n"], "incidents_high": inc["high"],
            "risk_score": r["score"], "risk_band": r["band"],
            "last_seen": time.strftime("%H:%M:%S", time.localtime(d["last_seen"])),
            "age": _age(now - d["last_seen"]),
            "online": (now - d["last_seen"]) < 600,
            "is_test": bool(d["friendly_name"] and "TEST HARNESS" in d["friendly_name"]),
        })
    return {"devices": out}


@app.get("/api/incidents")
def api_incidents(severity: str = Query(""), status: str = Query(""),
                  signal: str = Query("")):
    c = db()
    now = time.time()
    sql = ("SELECT i.*, d.hostname, d.friendly_name FROM incidents i"
           " LEFT JOIN devices d ON d.id = i.device_id WHERE 1=1")
    params = []
    if severity:
        sql += " AND i.severity = ?"
        params.append(severity)
    if status:
        sql += " AND i.status = ?"
        params.append(status)
    if signal:
        sql += " AND i.signal_type = ?"
        params.append(signal)
    sql += (" ORDER BY CASE i.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1"
            " ELSE 2 END, i.last_seen DESC")

    out = []
    for r in c.execute(sql, params):
        out.append({
            "id": r["id"], "title": r["title"], "description": r["description"],
            "severity": r["severity"], "status": r["status"],
            "signal_type": r["signal_type"], "evidence_count": r["evidence_count"],
            "device": device_label(r) if r["device_id"] else None,
            "device_id": r["device_id"],
            "first_seen": time.strftime("%H:%M:%S", time.localtime(r["first_seen"])),
            "last_seen": time.strftime("%H:%M:%S", time.localtime(r["last_seen"])),
            "age": _age(now - r["last_seen"]),
        })
    counts = {"high": 0, "medium": 0, "low": 0, "total": 0}
    for r in c.execute("SELECT severity, count(*) n FROM incidents GROUP BY severity"):
        if r["severity"] in counts:
            counts[r["severity"]] = r["n"]
        counts["total"] += r["n"]
    return {"incidents": out, "counts": counts}


@app.get("/api/events")
def api_events(limit: int = Query(60), type: str = Query("")):
    c = db()
    sql = ("SELECT e.*, d.hostname, d.friendly_name FROM events e"
           " LEFT JOIN devices d ON d.id = e.device_id")
    params = []
    if type:
        sql += " WHERE e.event_type = ?"
        params.append(type)
    sql += " ORDER BY e.id DESC LIMIT ?"
    params.append(min(limit, 300))
    return {"events": [_event_row(r) for r in c.execute(sql, params)]}


@app.get("/api/devices/{device_id}/series")
def api_device_series(device_id: int, range: str = Query("24h")):
    spec = RANGES.get(range, RANGES["24h"])
    c = db()
    now = time.time()
    series = bucket_series(c, now - spec["seconds"], now, spec["bucket"], device_id=device_id)
    return {
        "labels": series["labels"],
        "down_kbps": series["down_kbps"],
        "up_kbps": series["up_kbps"],
        "range_label": spec["label"],
    }


@app.get("/api/system")
def api_system():
    """Pipeline health: is ingest keeping up, and is each detection signal
    still running. This is the console's own instrumentation, not network
    data - it answers "can I trust what this dashboard is telling me"."""
    c = db()
    now = time.time()

    stats = c.execute("SELECT * FROM ingest_stats WHERE id=1").fetchone()
    ingest_last_run = stats["last_run"] if stats else None
    ingest = {
        "events_read": stats["events_read"] if stats else 0,
        "events_saved": stats["events_saved"] if stats else 0,
        "parse_errors": stats["parse_errors"] if stats else 0,
        "last_run": time.strftime("%H:%M:%S", time.localtime(ingest_last_run)) if ingest_last_run else None,
        "age": _age(now - ingest_last_run) if ingest_last_run else None,
        "healthy": bool(ingest_last_run and (now - ingest_last_run) < INGEST_STALE_AFTER),
    }

    signals = []
    for sig in SIGNALS:
        row = c.execute(
            "SELECT last_run_ts FROM signal_state WHERE signal_type=?", (sig,)).fetchone()
        last_run = row["last_run_ts"] if row else None
        signals.append({
            "signal": sig,
            "age": _age(now - last_run) if last_run else None,
            "healthy": bool(last_run and (now - last_run) < SIGNAL_STALE_AFTER),
        })

    return {
        "ingest": ingest,
        "signals": signals,
        "healthy": ingest["healthy"] and all(s["healthy"] for s in signals),
    }


@app.get("/api/heatmap")
def api_heatmap():
    """Event volume by day-of-week / hour-of-day over the last 7 days, for
    the weekly activity grid. tm_wday: 0=Monday .. 6=Sunday."""
    c = db()
    now = time.time()
    start = now - 7 * 86400
    grid = [[0] * 24 for _ in range(7)]
    for r in c.execute("SELECT ts FROM events WHERE ts >= ?", (start,)):
        lt = time.localtime(r["ts"])
        grid[lt.tm_wday][lt.tm_hour] += 1
    return {"grid": grid, "days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]}


@app.patch("/api/incidents/{incident_id}")
def api_update_incident(incident_id: int, body: IncidentUpdate):
    if body.status not in INCIDENT_STATUSES:
        raise HTTPException(400, "status must be one of %s" % (INCIDENT_STATUSES,))
    c = db()
    if c.execute("SELECT 1 FROM incidents WHERE id=?", (incident_id,)).fetchone() is None:
        raise HTTPException(404, "incident not found")
    now = time.time()
    c.execute("UPDATE incidents SET status=?, updated_at=? WHERE id=?",
              (body.status, now, incident_id))
    c.commit()
    return {"id": incident_id, "status": body.status}


@app.patch("/api/devices/{device_id}")
def api_rename_device(device_id: int, body: DeviceUpdate):
    name = body.friendly_name.strip()
    if not name:
        raise HTTPException(400, "friendly_name must not be empty")
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    c.execute("UPDATE devices SET friendly_name=? WHERE id=?", (name, device_id))
    c.commit()
    return {"id": device_id, "friendly_name": name}


# ------------------------------------------------------------- filtering --
#
# DNS filtering itself lives entirely in AdGuard Home; this app only gives
# it a console. Every write here calls straight through to AdGuard's own
# control API (see adguard.py) rather than caching or shadowing its state,
# so the console can never drift out of sync with what the resolver is
# actually doing.

@app.get("/api/filtering/status")
def api_filtering_status():
    try:
        status = adguard.filtering_status()
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    filters = [{
        "name": f["name"], "url": f["url"], "enabled": f["enabled"],
        "rules_count": f.get("rules_count", 0),
    } for f in status.get("filters", [])]
    rules = [adguard.describe_rule(r) for r in status.get("user_rules", [])]
    return {"enabled": bool(status.get("enabled")), "filters": filters, "rules": rules}


@app.post("/api/filtering/enabled")
def api_filtering_set_enabled(body: FilteringToggle):
    try:
        adguard.set_filtering_enabled(body.enabled)
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    return {"enabled": body.enabled}


@app.post("/api/filtering/lists")
def api_filtering_add_list(body: BlocklistAdd):
    name, url = body.name.strip(), body.url.strip()
    if not name or not url:
        raise HTTPException(400, "name and url are both required")
    try:
        adguard.add_blocklist(name, url)
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    return {"ok": True}


@app.post("/api/filtering/lists/toggle")
def api_filtering_toggle_list(body: BlocklistToggle):
    try:
        adguard.set_blocklist_enabled(body.url, body.enabled)
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    return {"url": body.url, "enabled": body.enabled}


@app.post("/api/filtering/lists/remove")
def api_filtering_remove_list(body: BlocklistUrl):
    try:
        adguard.remove_blocklist(body.url)
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    return {"ok": True}


@app.post("/api/filtering/rules")
def api_filtering_add_rule(body: RuleAdd):
    domain = body.domain.strip().lower()
    if not domain:
        raise HTTPException(400, "domain is required")
    if body.action not in ("block", "allow"):
        raise HTTPException(400, "action must be 'block' or 'allow'")
    try:
        adguard.add_user_rule(domain, body.action)
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    return {"ok": True}


@app.post("/api/filtering/rules/remove")
def api_filtering_remove_rule(body: RuleRemove):
    try:
        adguard.remove_user_rule(body.rule)
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    return {"ok": True}


@app.get("/api/filtering/querylog")
def api_filtering_querylog(domain: str = Query(""), device_id: str = Query(""),
                            blocked: str = Query(""), limit: int = Query(50)):
    """Query log search, served from our own ingested events rather than
    AdGuard's own log - we already store every DNS lookup with the device
    it resolved for, so this needs no second source of truth."""
    c = db()
    sql = ("SELECT e.*, d.hostname, d.friendly_name FROM events e"
           " LEFT JOIN devices d ON d.id = e.device_id"
           " WHERE e.event_type IN ('dns_query', 'dns')")
    params = []
    if domain:
        sql += " AND e.dns_rrname LIKE ?"
        params.append("%%%s%%" % domain)
    if device_id:
        sql += " AND e.device_id = ?"
        params.append(int(device_id))
    if blocked == "blocked":
        sql += " AND e.blocked = 1"
    elif blocked == "allowed":
        sql += " AND (e.blocked IS NULL OR e.blocked = 0)"
    sql += " ORDER BY e.id DESC LIMIT ?"
    params.append(min(limit, 200))
    return {"results": [_event_row(r) for r in c.execute(sql, params)]}


@app.get("/api/devices/{device_id}/filtering")
def api_device_filtering_status(device_id: int):
    c = db()
    d = c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone()
    if d is None:
        raise HTTPException(404, "device not found")
    identifiers, current_ip = device_identifiers(c, device_id)
    if not identifiers:
        return {"managed": False, "filtering_enabled": True, "ip": None}
    try:
        status = adguard.client_filtering_status(identifiers)
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    status["ip"] = current_ip
    return status


@app.post("/api/devices/{device_id}/filtering")
def api_device_filtering_set(device_id: int, body: DeviceFilterUpdate):
    c = db()
    d = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if d is None:
        raise HTTPException(404, "device not found")
    identifiers, current_ip = device_identifiers(c, device_id)
    if not identifiers:
        raise HTTPException(400, "device has no known address to apply a policy to")
    try:
        adguard.set_client_filtering(identifiers, device_label(d), body.enabled)
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    return {"id": device_id, "filtering_enabled": body.enabled}


@app.get("/api/filtering/check")
def api_filtering_check(domain: str = Query(...), device_id: int = Query(None)):
    """The console's "why is this blocked?" tool: ask AdGuard how it would
    resolve `domain` right now, exactly as if the query came from the given
    device (or network-wide, if no device is given)."""
    domain = domain.strip().lstrip("*.").lower()
    if not domain:
        raise HTTPException(400, "domain is required")
    client_ip = None
    if device_id is not None:
        c = db()
        if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
            raise HTTPException(404, "device not found")
        _, client_ip = device_identifiers(c, device_id)
    try:
        result = adguard.check_host(domain, client_ip)
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    return adguard.describe_check(result, domain)


@app.get("/api/filtering/analytics")
def api_filtering_analytics(range: str = Query("24h")):
    """Network-wide ad-blocking analytics: block rate over time, what's
    being blocked and for whom, which tracker companies are involved, an
    estimated savings figure, and how much Tier 2 (HTTPS inspection) is
    actually doing. See ENHANCEMENT-PLAN.md step 5.3."""
    spec = RANGES.get(range, RANGES["24h"])
    c = db()
    now = time.time()
    start = now - spec["seconds"]

    series = bucket_series(c, start, now, spec["bucket"])
    block_pct = [
        round(100.0 * b / (b + a), 1) if (b + a) else 0.0
        for b, a in zip(series["blocked"], series["allowed"])
    ]

    top_blocked_domains = [
        {"domain": r["dns_rrname"], "count": r["n"]}
        for r in c.execute(
            "SELECT dns_rrname, count(*) n FROM events"
            " WHERE event_type='dns_query' AND blocked=1 AND ts >= ? AND dns_rrname IS NOT NULL"
            " GROUP BY dns_rrname ORDER BY n DESC LIMIT 12", (start,))
    ]

    top_blocked_clients = []
    for r in c.execute(
        "SELECT d.id, d.hostname, d.friendly_name,"
        "       sum(e.event_type='dns_query') dns_total,"
        "       sum(e.blocked=1) blocked"
        "  FROM devices d JOIN events e ON e.device_id = d.id"
        " WHERE e.ts >= ? AND e.event_type='dns_query'"
        " GROUP BY d.id HAVING blocked > 0 ORDER BY blocked DESC LIMIT 8", (start,)):
        dns_total, blocked = r["dns_total"] or 0, r["blocked"] or 0
        top_blocked_clients.append({
            "id": r["id"], "name": device_label(r),
            "dns_total": dns_total, "blocked": blocked,
            "block_pct": round(100.0 * blocked / dns_total, 1) if dns_total else 0.0,
        })

    dns_blocked_window = c.execute(
        "SELECT count(*) FROM events"
        " WHERE event_type='dns_query' AND blocked=1 AND ts >= ?", (start,)).fetchone()[0]

    return {
        "range": range, "range_label": spec["label"],
        "series": {"labels": series["labels"], "block_pct": block_pct,
                   "blocked": series["blocked"], "allowed": series["allowed"]},
        "top_blocked_domains": top_blocked_domains,
        "top_blocked_clients": top_blocked_clients,
        "trackers": _tracker_breakdown(c, start, now),
        "savings": _savings_estimate(dns_blocked_window),
        "tier2": _tier2_breakdown(c, start, now),
    }


@app.get("/api/filtering/lists/health")
def api_filtering_lists_health():
    """Blocklist health and contribution (step 5.4): how stale each list's
    last sync is, and how much of what's actually being blocked can be
    credited to it.

    Contribution is measured from this project's own historical telemetry -
    the dns_filter_list_id captured on every blocked DNS event since step
    5.1 - rather than the offline multi-list replay the plan originally
    proposed. That's a direct measurement of which list's rule actually
    matched each real block, which is both simpler and more honest than a
    synthetic reconstruction would be; it just means blocks recorded before
    5.1 was deployed (dns_filter_list_id IS NULL) aren't attributed to any
    list. What this method genuinely cannot answer - the *overlap* between
    lists, and AdGuard's memory use with lists toggled - is named in
    "deferred_note" below rather than guessed at.
    """
    try:
        filters = adguard.filtering_status().get("filters", [])
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    c = db()
    now = time.time()

    total_attributed = c.execute(
        "SELECT count(*) FROM events WHERE event_type='dns_query' AND blocked=1"
        "   AND dns_filter_list_id IS NOT NULL").fetchone()[0]

    out = []
    for f in filters:
        list_id = f.get("id")
        n = c.execute(
            "SELECT count(*) FROM events WHERE event_type='dns_query' AND blocked=1"
            "   AND dns_filter_list_id=?", (list_id,)).fetchone()[0] if list_id is not None else 0

        age_h, stale = None, False
        last_updated = f.get("last_updated")
        if last_updated:
            try:
                age_h = (now - datetime.datetime.fromisoformat(last_updated).timestamp()) / 3600.0
                stale = age_h > LIST_STALE_AFTER_HOURS
            except ValueError:
                pass  # unexpected timestamp shape - show "unknown" rather than guess

        share = (n / total_attributed) if total_attributed else 0.0
        out.append({
            "id": list_id, "name": f.get("name"), "url": f.get("url"),
            "enabled": bool(f.get("enabled")), "rules_count": f.get("rules_count", 0),
            "last_updated": last_updated,
            "age_h": round(age_h, 1) if age_h is not None else None,
            "stale": stale,
            "contribution": n, "share_pct": round(share * 100, 2),
            "low_contribution": bool(f.get("enabled") and total_attributed and share < LIST_LOW_CONTRIBUTION_SHARE),
        })
    out.sort(key=lambda x: -x["contribution"])

    return {
        "lists": out,
        "total_attributed_blocks": total_attributed,
        "any_stale": any(x["stale"] for x in out),
        "deferred_note": (
            "Contribution is each list's share of blocks we've actually observed and "
            "matched back to it, not a true unique-blocks count. The list-overlap matrix "
            "and AdGuard's memory-vs-rules-toggled measurement from the original plan need "
            "a controlled toggle experiment against a non-production instance - deferred to "
            "Stage 7's evaluation campaign rather than run against the live filter here."),
    }


@app.get("/api/native-profiles")
def api_native_profiles():
    """The vendor telemetry profiles a device can be assigned - see
    app/native_trackers.py. Read-only: this just lists what's available,
    it doesn't touch any device."""
    return {
        "profiles": [
            {"vendor": v, "label": p["label"], "domain_count": len(p["domains"])}
            for v, p in native_trackers.NATIVE_PROFILES.items()
        ],
    }


@app.get("/api/devices/{device_id}/filtering/profiles")
def api_device_profiles(device_id: int):
    """Which native-tracker profiles are currently applied to this device,
    derived from the tag on its own $client-scoped block rules - there is
    no separate table for this, the same way temporary allow rules track
    their own expiry in their comment rather than a database row."""
    c = db()
    d = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if d is None:
        raise HTTPException(404, "device not found")
    try:
        rules = adguard.device_scoped_rules(device_label(d))
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    applied = {}
    for r in rules:
        if r["tag"] and r["tag"] in native_trackers.NATIVE_PROFILES:
            applied.setdefault(r["tag"], 0)
            applied[r["tag"]] += 1
    return {"applied": [
        {"vendor": v, "label": native_trackers.NATIVE_PROFILES[v]["label"], "rule_count": n}
        for v, n in applied.items()
    ]}


@app.post("/api/devices/{device_id}/filtering/profile")
def api_device_apply_profile(device_id: int, body: NativeProfileRequest):
    """Apply a native-tracker profile to one device: a $client-scoped block
    rule per domain in the profile, tagged so it can be found and removed
    as a group later. See ENHANCEMENT-PLAN.md step 5.5 - and its own
    caution about not trusting these domain lists on a real device without
    checking first."""
    prof = native_trackers.profile(body.vendor)
    if prof is None:
        raise HTTPException(400, "unknown vendor profile: %s" % body.vendor)
    c = db()
    d = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if d is None:
        raise HTTPException(404, "device not found")
    name = device_label(d)
    added = 0
    try:
        for domain in prof["domains"]:
            rule = adguard.add_client_rule(name, domain, "block", tag=body.vendor)
            if rule:
                added += 1
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    print("filtering: applied native profile '%s' (%d domains) to device %d (%s)" % (
        body.vendor, len(prof["domains"]), device_id, name), flush=True)
    return {"ok": True, "vendor": body.vendor, "domains": prof["domains"]}


@app.post("/api/devices/{device_id}/filtering/profile/remove")
def api_device_remove_profile(device_id: int, body: NativeProfileRequest):
    c = db()
    d = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if d is None:
        raise HTTPException(404, "device not found")
    name = device_label(d)
    try:
        removed = adguard.remove_client_rule_group(name, body.vendor)
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    print("filtering: removed native profile '%s' (%d rules) from device %d (%s)" % (
        body.vendor, removed, device_id, name), flush=True)
    return {"ok": True, "vendor": body.vendor, "removed": removed}


@app.get("/api/filtering/resolver")
def api_filtering_resolver(range: str = Query("24h")):
    """Resolver quality (step 5.5c): the current AdGuard resolver config,
    and DNS latency actually measured from this network's own traffic -
    not a synthetic benchmark. Read-only; see api_apply_resolver_tuning
    for the one endpoint that can change any of this."""
    spec = RANGES.get(range, RANGES["24h"])
    c = db()
    now = time.time()
    try:
        cfg = adguard.dns_config()
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    latency = _dns_latency_percentiles(c, now - spec["seconds"], now)
    recommended = {
        "cache_optimistic": True,
        "dnssec_enabled": True,
        "upstream_mode": "parallel",
        "upstream_dns_note": "at least two independent DoT/DoH upstreams (e.g. Cloudflare + Quad9)",
    }
    return {
        "current": {
            "upstream_dns": cfg.get("upstream_dns", []),
            "fallback_dns": cfg.get("fallback_dns", []),
            "upstream_mode": cfg.get("upstream_mode") or "(default)",
            "cache_enabled": bool(cfg.get("cache_enabled")),
            "cache_optimistic": bool(cfg.get("cache_optimistic")),
            "cache_size": cfg.get("cache_size"),
            "dnssec_enabled": bool(cfg.get("dnssec_enabled")),
        },
        "recommended": recommended,
        "latency": latency,
        "range": range, "range_label": spec["label"],
    }


@app.post("/api/filtering/resolver/apply")
def api_apply_resolver_tuning(body: ResolverTuningRequest):
    """Apply the recommended resolver tuning: optimistic caching on, DNSSEC
    on, and two independent DoT upstreams (Cloudflare + Quad9) queried in
    parallel with a fallback pair. This changes DNS resolution for every
    device on the network at once, which is exactly the kind of shared,
    hard-to-instantly-undo action this project's own operating rules say
    to get explicit confirmation for - `confirm` has to be sent as true,
    on purpose, from an operator who has seen what it's about to change
    (the console shows GET /api/filtering/resolver's "current" block
    first). There is no scheduler or auto-apply path here."""
    if not body.confirm:
        raise HTTPException(400, "resolver tuning requires confirm=true")
    try:
        new_cfg = adguard.set_dns_tuning(
            upstream_dns=["tls://1.1.1.1", "tls://1.0.0.1", "tls://9.9.9.9"],
            fallback_dns=["tls://9.9.9.9", "tls://1.1.1.1"],
            cache_optimistic=True,
            dnssec_enabled=True,
            upstream_mode="parallel",
        )
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    print("filtering: applied recommended resolver tuning (optimistic cache, "
          "DNSSEC, parallel dual-DoT upstreams)", flush=True)
    return {"ok": True, "applied": new_cfg}


def _ca_info():
    """Tier 2 inspection CA fingerprint and validity window, read straight
    from the certificate file with openssl rather than adding a crypto
    library dependency - the same shell-out approach quarantine.py and
    dpi_enroll.py already use for one-off system facts. See
    ENHANCEMENT-PLAN.md step 5.6d. Automated rotation is NOT implemented
    here - generating a new CA invalidates every enrolled device's stored
    trust at once, which is too consequential to automate without a
    reviewed runbook step; this only ever reads the existing one."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", DPI_CA_PATH, "-noout",
             "-fingerprint", "-sha256", "-enddate", "-startdate"],
            capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"available": False, "error": str(e)}
    if result.returncode != 0:
        return {"available": False, "error": result.stderr.strip() or "CA certificate not found"}
    info = {"available": True}
    for line in result.stdout.splitlines():
        if line.startswith("SHA256 Fingerprint="):
            info["fingerprint_sha256"] = line.split("=", 1)[1]
        elif line.startswith("notBefore="):
            info["not_before"] = line.split("=", 1)[1]
        elif line.startswith("notAfter="):
            info["not_after"] = line.split("=", 1)[1]
    return info


@app.get("/api/filtering/ca")
def api_filtering_ca():
    """CA info for the Tier 2 onboarding card: fingerprint, validity dates,
    and the existing plain-HTTP download URL deploy-dpi.sh already serves
    it from (finding A10 - still plain HTTP, not changed by this step)."""
    info = _ca_info()
    info["download_url"] = DPI_CA_DOWNLOAD_URL
    return info


@app.get("/api/filtering/dpi/enrolled")
def api_filtering_dpi_enrolled():
    """Every currently-enrolled device: its auto-unenroll countdown, and a
    best-effort CA-trust check inferred from its own recent Tier 2
    telemetry (step 5.6b/e). "trusted" means we've seen a successful
    decrypt/ads_stripped more recently than any tls_failed; "check_ca"
    means the opposite; "unverified" means no Tier 2 telemetry at all yet.
    This is inferred from OUR side of the handshake outcome, not confirmed
    from the device itself - the gateway has no way to see whether a
    phone actually trusts the certificate beyond whether the handshake it
    attempted succeeded."""
    try:
        rows = dpi_enroll.enrolled()
    except dpi_enroll.DpiEnrollError as e:
        raise HTTPException(502, str(e))
    c = db()
    out = []
    for row in rows:
        ip = row["ip"]
        name = ip
        dev_row = c.execute(
            "SELECT device_id FROM device_ips WHERE ip=? ORDER BY last_seen DESC LIMIT 1",
            (ip,)).fetchone()
        device_id = dev_row["device_id"] if dev_row else None
        if device_id is not None:
            d = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
            if d:
                name = device_label(d)
        last_ok = c.execute(
            "SELECT max(ts) FROM events WHERE source='dpi' AND src_ip=?"
            "   AND dpi_action IN ('decrypt','ads_stripped')", (ip,)).fetchone()[0]
        last_fail = c.execute(
            "SELECT max(ts) FROM events WHERE source='dpi' AND src_ip=?"
            "   AND dpi_action='tls_failed'", (ip,)).fetchone()[0]
        if last_fail and (not last_ok or last_fail > last_ok):
            trust = "check_ca"
        elif last_ok:
            trust = "trusted"
        else:
            trust = "unverified"
        out.append({
            "ip": ip, "device_id": device_id, "name": name,
            "expires_in_s": row["expires_in_s"], "trust": trust,
        })
    return {"enrolled": out}


@app.get("/api/devices/{device_id}/dpi")
def api_device_dpi_status(device_id: int):
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    ip_row = c.execute(
        "SELECT ip FROM device_ips WHERE device_id=? ORDER BY last_seen DESC LIMIT 1",
        (device_id,)).fetchone()
    if ip_row is None:
        return {"enrolled": False, "ip": None, "expires_in_s": None}
    try:
        rows = {e["ip"]: e for e in dpi_enroll.enrolled()}
    except dpi_enroll.DpiEnrollError as e:
        raise HTTPException(502, str(e))
    row = rows.get(ip_row["ip"])
    return {
        "enrolled": row is not None, "ip": ip_row["ip"],
        "expires_in_s": row["expires_in_s"] if row else None,
    }


@app.post("/api/devices/{device_id}/dpi")
def api_device_dpi_set(device_id: int, body: DpiEnrollRequest):
    """Enroll or unenroll one device for Tier 2 (HTTPS ad removal) - the
    console's replacement for the `sudo securepi enroll/unenroll` CLI. See
    ENHANCEMENT-PLAN.md step 5.6a."""
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    ip_row = c.execute(
        "SELECT ip FROM device_ips WHERE device_id=? ORDER BY last_seen DESC LIMIT 1",
        (device_id,)).fetchone()
    if ip_row is None:
        raise HTTPException(400, "device has no known IP address to enforce against")
    try:
        if body.enrolled:
            dpi_enroll.enroll(ip_row["ip"], hours=body.hours)
        else:
            dpi_enroll.unenroll(ip_row["ip"])
    except dpi_enroll.DpiEnrollError as e:
        raise HTTPException(502, str(e))
    return {"id": device_id, "enrolled": body.enrolled, "ip": ip_row["ip"],
            "expires_in_s": body.hours * 3600 if body.enrolled else None}


@app.get("/api/devices/{device_id}/blocked")
def api_device_blocked(device_id: int, limit: int = Query(25)):
    """Recently blocked domains for one device, folded so a tracker that
    fires dozens of times a minute shows up as one row with a count rather
    than as noise - this is the "recently blocked" panel on the device page."""
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    rows = c.execute(
        "SELECT dns_rrname, block_reason, ts FROM events"
        " WHERE device_id=? AND event_type='dns_query' AND blocked=1"
        " ORDER BY id DESC LIMIT 500", (device_id,)
    ).fetchall()
    folded = {}
    now = time.time()
    for r in rows:
        domain = r["dns_rrname"]
        if domain not in folded:
            folded[domain] = {
                "domain": domain, "reason": r["block_reason"],
                "count": 0, "last_seen": r["ts"], "age": _age(now - r["ts"]),
            }
        folded[domain]["count"] += 1
    results = sorted(folded.values(), key=lambda x: -x["last_seen"])[:min(limit, 100)]
    return {"results": results}


@app.get("/api/devices/{device_id}/filtering/rules")
def api_device_filtering_rules(device_id: int):
    """Allow/block rules scoped to just this device - see adguard.py's
    add_client_rule and device_scoped_rules."""
    c = db()
    d = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if d is None:
        raise HTTPException(404, "device not found")
    try:
        adguard.sweep_expired_client_rules()
        rules = adguard.device_scoped_rules(device_label(d))
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    return {"rules": rules}


@app.post("/api/devices/{device_id}/filtering/allow")
def api_device_allow_domain(device_id: int, body: DeviceRuleRequest):
    """One-click 'unbreak this site for this device' - a per-device allow
    rule, optionally temporary, always with a reason recorded. See
    ENHANCEMENT-PLAN.md step 5.2."""
    c = db()
    d = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if d is None:
        raise HTTPException(404, "device not found")
    domain = body.domain.strip().lstrip("*.").lower()
    if not domain:
        raise HTTPException(400, "domain is required")
    if not body.reason.strip():
        raise HTTPException(400, "a reason is required")
    expires_at = (time.time() + body.hours * 3600) if body.temporary else None
    try:
        adguard.sweep_expired_client_rules()
        rule = adguard.add_client_rule(device_label(d), domain, "allow", expires_at)
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    # A real audit_log table lands in ENHANCEMENT-PLAN.md step 1.5; until
    # then, printing to stdout still puts this in the systemd journal,
    # which is more than the console action would otherwise leave behind.
    print("filtering: allowed %s for device %d (%s) - %s%s" % (
        domain, device_id, device_label(d), body.reason,
        " [temporary, %dh]" % body.hours if body.temporary else ""), flush=True)
    return {"ok": True, "rule": rule, "domain": domain, "expires_at": expires_at}


@app.post("/api/devices/{device_id}/filtering/block")
def api_device_block_domain(device_id: int, body: DeviceBlockRequest):
    """The reverse of allow above: block one domain for one device only,
    without touching the network-wide blocklists."""
    c = db()
    d = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if d is None:
        raise HTTPException(404, "device not found")
    domain = body.domain.strip().lstrip("*.").lower()
    if not domain:
        raise HTTPException(400, "domain is required")
    if not body.reason.strip():
        raise HTTPException(400, "a reason is required")
    try:
        rule = adguard.add_client_rule(device_label(d), domain, "block")
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    print("filtering: blocked %s for device %d (%s) - %s" % (
        domain, device_id, device_label(d), body.reason), flush=True)
    return {"ok": True, "rule": rule, "domain": domain}


@app.get("/api/devices/{device_id}/privacy")
def api_device_privacy(device_id: int):
    """Per-device privacy report: trackers contacted vs blocked, an
    estimated savings figure, and Tier 2 (HTTPS inspection) activity for
    this device specifically. All-time, like the rest of the device
    detail page's aggregates - not windowed, since a "privacy report" is
    meant to describe the device's whole history with us, not a slice of
    it. See ENHANCEMENT-PLAN.md step 5.3."""
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    now = time.time()

    dns_agg = c.execute(
        "SELECT count(*) total, sum(blocked=1) blocked FROM events"
        " WHERE device_id=? AND event_type='dns_query'", (device_id,)).fetchone()
    dns_total, dns_blocked = dns_agg["total"] or 0, dns_agg["blocked"] or 0

    return {
        "dns_total": dns_total, "dns_blocked": dns_blocked,
        "block_pct": round(100.0 * dns_blocked / dns_total, 1) if dns_total else 0.0,
        "trackers": _tracker_breakdown(c, 0, now, device_id=device_id),
        "savings": _savings_estimate(dns_blocked),
        "tier2": _tier2_breakdown(c, 0, now, device_id=device_id),
    }


# --------------------------------------------------------------- quarantine --
#
# Enforcement lives entirely in the `inet filter quarantine` nftables set;
# this app never caches whether a device is quarantined, for the same reason
# filtering doesn't cache AdGuard's state (see above).

@app.get("/api/devices/{device_id}/quarantine")
def api_device_quarantine_status(device_id: int):
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    ip_row = c.execute(
        "SELECT ip FROM device_ips WHERE device_id=? ORDER BY last_seen DESC LIMIT 1",
        (device_id,)).fetchone()
    if ip_row is None:
        return {"quarantined": False, "ip": None}
    try:
        quarantined = quarantine.is_quarantined(ip_row["ip"])
    except quarantine.QuarantineError as e:
        raise HTTPException(502, str(e))
    return {"quarantined": quarantined, "ip": ip_row["ip"]}


@app.post("/api/devices/{device_id}/quarantine")
def api_device_quarantine_set(device_id: int, body: QuarantineUpdate):
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    ip_row = c.execute(
        "SELECT ip FROM device_ips WHERE device_id=? ORDER BY last_seen DESC LIMIT 1",
        (device_id,)).fetchone()
    if ip_row is None:
        raise HTTPException(400, "device has no known IP address to enforce against")
    try:
        if body.quarantined:
            quarantine.quarantine(ip_row["ip"])
        else:
            quarantine.release(ip_row["ip"])
    except quarantine.QuarantineError as e:
        raise HTTPException(502, str(e))
    return {"id": device_id, "quarantined": body.quarantined, "ip": ip_row["ip"]}


# ---------------------------------------------------------------- pages --

@app.get("/", response_class=HTMLResponse)
def page_dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "active": "dashboard", "title": "Dashboard"})


@app.get("/devices", response_class=HTMLResponse)
def page_devices(request: Request):
    return templates.TemplateResponse("devices.html", {
        "request": request, "active": "devices", "title": "Devices"})


@app.get("/incidents", response_class=HTMLResponse)
def page_incidents(request: Request):
    return templates.TemplateResponse("incidents.html", {
        "request": request, "active": "incidents", "title": "Incidents"})


@app.get("/filtering", response_class=HTMLResponse)
def page_filtering(request: Request):
    return templates.TemplateResponse("filtering.html", {
        "request": request, "active": "filtering", "title": "Filtering"})


@app.get("/devices/{device_id}", response_class=HTMLResponse)
def page_device_detail(request: Request, device_id: int):
    c = db()
    d = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if d is None:
        return HTMLResponse("Device not found", status_code=404)
    now = time.time()

    macs = [dict(r) for r in c.execute(
        "SELECT mac, is_randomized, first_seen, last_seen FROM device_macs"
        " WHERE device_id=? ORDER BY last_seen DESC", (device_id,))]
    for m in macs:
        m["first_seen_h"] = time.strftime("%d %b %H:%M", time.localtime(m["first_seen"]))
        m["last_seen_h"] = time.strftime("%d %b %H:%M", time.localtime(m["last_seen"]))

    ips = [dict(r) for r in c.execute(
        "SELECT ip, first_seen, last_seen FROM device_ips"
        " WHERE device_id=? ORDER BY last_seen DESC", (device_id,))]
    for i in ips:
        i["first_seen_h"] = time.strftime("%d %b %H:%M", time.localtime(i["first_seen"]))
        i["last_seen_h"] = time.strftime("%d %b %H:%M", time.localtime(i["last_seen"]))

    agg = c.execute(
        "SELECT COALESCE(sum(CASE WHEN event_type='flow' THEN bytes_toclient END),0) down,"
        "       COALESCE(sum(CASE WHEN event_type='flow' THEN bytes_toserver END),0) up,"
        "       COALESCE(sum(event_type='dns_query'),0) dns,"
        "       COALESCE(sum(blocked=1),0) blocked,"
        "       COALESCE(sum(event_type='tls'),0) tls,"
        "       count(*) events FROM events WHERE device_id=?", (device_id,)).fetchone()

    top_sni = [dict(r) for r in c.execute(
        "SELECT tls_sni, count(*) n FROM events WHERE device_id=? AND tls_sni IS NOT NULL"
        " GROUP BY tls_sni ORDER BY n DESC LIMIT 10", (device_id,))]
    top_blocked = [dict(r) for r in c.execute(
        "SELECT dns_rrname, count(*) n FROM events"
        " WHERE device_id=? AND blocked=1 AND dns_rrname IS NOT NULL"
        " GROUP BY dns_rrname ORDER BY n DESC LIMIT 10", (device_id,))]

    incidents = []
    for r in c.execute(
        "SELECT * FROM incidents WHERE device_id=? ORDER BY last_seen DESC", (device_id,)):
        incidents.append({
            "id": r["id"], "title": r["title"], "severity": r["severity"],
            "status": r["status"], "evidence_count": r["evidence_count"],
            "age": _age(now - r["last_seen"]),
        })

    timeline = [_event_row(r) for r in c.execute(
        "SELECT e.*, d.hostname, d.friendly_name FROM events e"
        " LEFT JOIN devices d ON d.id=e.device_id"
        " WHERE e.device_id=? ORDER BY e.id DESC LIMIT 60", (device_id,))]

    dev_risk = risk.device_risk(c, device_id, now)

    return templates.TemplateResponse("device_detail.html", {
        "request": request, "active": "devices", "title": device_label(d),
        "device": {
            "id": d["id"], "name": device_label(d), "hostname": d["hostname"],
            "first_seen": time.strftime("%d %b %Y %H:%M", time.localtime(d["first_seen"])),
            "last_seen": time.strftime("%d %b %Y %H:%M", time.localtime(d["last_seen"])),
            "online": (now - d["last_seen"]) < 600,
            "age": _age(now - d["last_seen"]),
            "down_h": humanize_bytes(agg["down"]), "up_h": humanize_bytes(agg["up"]),
            "dns": agg["dns"], "blocked": agg["blocked"],
            "tls": agg["tls"], "events": agg["events"],
        },
        "macs": macs, "ips": ips, "top_sni": top_sni, "top_blocked": top_blocked,
        "incidents": incidents, "timeline": timeline, "risk": dev_risk,
    })


@app.get("/incidents/{incident_id}", response_class=HTMLResponse)
def page_incident_detail(request: Request, incident_id: int):
    c = db()
    i = c.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if i is None:
        return HTMLResponse("Incident not found", status_code=404)
    now = time.time()

    dev = None
    if i["device_id"]:
        d = c.execute("SELECT * FROM devices WHERE id=?", (i["device_id"],)).fetchone()
        if d:
            ip_row = c.execute(
                "SELECT ip FROM device_ips WHERE device_id=? ORDER BY last_seen DESC LIMIT 1",
                (d["id"],)).fetchone()
            dev = {"id": d["id"], "name": device_label(d), "has_ip": ip_row is not None}

    evidence = [_event_row(r) for r in c.execute(
        "SELECT e.*, NULL hostname, NULL friendly_name FROM incident_events ie"
        " JOIN events e ON e.id = ie.event_id WHERE ie.incident_id=?"
        " ORDER BY e.ts", (incident_id,))]

    return templates.TemplateResponse("incident_detail.html", {
        "request": request, "active": "incidents", "title": i["title"],
        "incident": {
            "id": i["id"], "title": i["title"], "description": i["description"],
            "severity": i["severity"], "status": i["status"],
            "signal_type": i["signal_type"], "evidence_count": i["evidence_count"],
            "first_seen": time.strftime("%d %b %H:%M:%S", time.localtime(i["first_seen"])),
            "last_seen": time.strftime("%d %b %H:%M:%S", time.localtime(i["last_seen"])),
            "age": _age(now - i["last_seen"]),
        },
        "device": dev, "evidence": evidence,
    })

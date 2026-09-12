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
  /api/devices/{id}/quarantine   quarantine a device via nftables, or undo it
"""

import base64
import secrets
import sqlite3
import time

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.requests import Request

import adguard
import quarantine
import risk

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


class IncidentUpdate(BaseModel):
    status: str


class DeviceUpdate(BaseModel):
    friendly_name: str


class DeviceFilterUpdate(BaseModel):
    enabled: bool


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
    ip_row = c.execute(
        "SELECT ip FROM device_ips WHERE device_id=? ORDER BY last_seen DESC LIMIT 1",
        (device_id,)).fetchone()
    if ip_row is None:
        return {"managed": False, "filtering_enabled": True, "ip": None}
    try:
        status = adguard.client_filtering_status(ip_row["ip"])
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    status["ip"] = ip_row["ip"]
    return status


@app.post("/api/devices/{device_id}/filtering")
def api_device_filtering_set(device_id: int, body: DeviceFilterUpdate):
    c = db()
    d = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if d is None:
        raise HTTPException(404, "device not found")
    ip_row = c.execute(
        "SELECT ip FROM device_ips WHERE device_id=? ORDER BY last_seen DESC LIMIT 1",
        (device_id,)).fetchone()
    if ip_row is None:
        raise HTTPException(400, "device has no known IP address to apply a policy to")
    try:
        adguard.set_client_filtering(ip_row["ip"], device_label(d), body.enabled)
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    return {"id": device_id, "filtering_enabled": body.enabled}


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

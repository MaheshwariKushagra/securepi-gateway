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
  /login             sign in (step 3.1: replaces HTTP Basic Auth)
  /logout            end the current session
  /                  dashboard shell
  /devices           device inventory
  /devices/{id}      per-device detail
  /incidents         incident queue
  /incidents/{id}    incident detail with evidence chain
  /filtering         DNS filtering: blocklists, custom rules, query log
  /settings          thresholds, audit log, password, OSS attributions (step 6.3)
  /hunt              flow/DNS/TLS search with pivots, top talkers, saved searches (step 6.5)
  /reports/weekly    weekly security summary, print-to-PDF (step 6.6)

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
  /api/filtering/dpi/privacy-scope  privacy-scope canary status for the console badge
  /api/filtering/dpi/pinned         devices currently auto-bypassed for a pinned app (step 5.8)
  /api/filtering/dpi/rules          view/edit the Tier 2 rule set, with per-rule hit counts (step 5.9)
  /api/filtering/dpi/effectiveness  ad-removal effectiveness watchdog status (step 5.10)
  /api/devices/{id}/dpi             enroll/unenroll one device for Tier 2 (replaces the CLI)
  /api/devices/{id}/blocked         recently blocked domains for one device
  /api/devices/{id}/filtering/rules allow/block rules scoped to one device
  /api/devices/{id}/filtering/allow one-click unbreak, optionally temporary
  /api/devices/{id}/filtering/block block one domain for one device only
  /api/devices/{id}/privacy         per-device tracker/privacy report
  /api/devices/{id}/quarantine   quarantine a device via nftables, or undo it
  /api/devices/{id}/baseline     behavioural-baseline "learning" status (step 6.1)
  /api/devices/{id}/fingerprint  device type/vendor/OS classification with evidence (step 6.2)
  /api/settings                  view/edit console-tunable detection thresholds (step 6.3)
  /api/settings/retention        honest "not yet implemented" - Stage 1's F3
  /api/settings/channels         honest "not yet implemented" - Stage 4's R3
  /api/settings/password         change the console's shared login password (step 3.1: hashed, not plaintext)
  /api/audit                     recent audit log entries
  /api/attributions              third-party components this project uses, with real versions/licences
  /api/incidents/{id}            PATCH: change status, now audited with a real timeline entry
  /api/incidents/{id}/notes      POST: add an analyst note (step 6.4)
  /hunt                          flow/DNS/TLS search page with pivots (step 6.5)
  /api/hunt                      search + top talkers/destinations/protocol breakdown
  /api/hunt/saved                list/create saved searches
  /api/hunt/saved/{id}/remove    delete a saved search
  /reports/weekly                weekly security summary, print-to-PDF (step 6.6)
  /api/reports/weekly            incidents by tactic, riskiest devices, ad-blocking, platform health
"""

import collections
import datetime
import json
import os
import sqlite3
import subprocess
import tempfile
import time
from typing import Any, Optional
from urllib.parse import parse_qs, quote

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request

import adfilter_rules
import adguard
import audit
import dpi_enroll
import fingerprint
import firewall_sets
import native_trackers
import notify
import orchestrator
import playbooks
import profiles
import risk
import session_auth
import settings
import suppression
import tracker_entities

DB_PATH = "/var/lib/securepi/securepi.db"
CONSOLE_USERNAME = session_auth.CONSOLE_USERNAME
# Moved out of /root (step 3.3): /root is 700 root-only, so once
# securepi-web drops root (finding G9) it can no longer traverse into
# it at all, regardless of this file's own permissions. Lives in
# /etc/securepi instead - root:securepi, 750 - readable/writable by the
# securepi group the unprivileged service user belongs to. This is a
# plain data file (a password hash, since step 3.1), not something
# that grants system control the way nftables access does, so direct
# group access is proportionate; contrast with quarantine/enrollment,
# which still go through the privileged helper because THOSE control
# the firewall.
CONSOLE_PASSWORD_FILE = "/etc/securepi/console-password"

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


# Session-cookie auth as ASGI middleware rather than a FastAPI dependency,
# for the same reason the Basic Auth it replaces (step 3.1) was one: it
# runs ahead of routing, so it also covers the /static mount, and it keeps
# auth as one linear function instead of a dependency wired onto every
# route (see SECUREPI-15-DAY-PLAN.md 4.5 - no dependency-injection
# patterns). Fails closed: a missing/expired/unrecognised session sends an
# API caller a 401 and a browser to /login, never through to a route.
#
# The Origin check runs first and applies to EVERY state-changing request,
# authenticated or not (including /login itself) - ENHANCEMENT-PLAN.md
# step 3.1's "Cross-origin POST rejected" exit criterion. It's on top of,
# not instead of, the session cookie's own SameSite=Strict attribute -
# see session_auth.origin_is_allowed()'s docstring for why both exist.
@app.middleware("http")
async def session_auth_middleware(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if not session_auth.origin_is_allowed(request.headers.get("origin"), request.headers.get("host")):
            return PlainTextResponse("cross-origin request rejected", status_code=403)

    path = request.url.path
    if path == "/login" or path.startswith("/static/"):
        return await call_next(request)

    conn = db()
    token = request.cookies.get(session_auth.SESSION_COOKIE)
    session = session_auth.get_session(conn, token)
    if session is None:
        if path.startswith("/api/"):
            return JSONResponse({"error": "authentication required"}, status_code=401)
        return RedirectResponse(url="/login?next=%s" % quote(path, safe=""), status_code=303)
    session_auth.touch_session(conn, token)
    return await call_next(request)


# Registered after session_auth_middleware, so it wraps OUTSIDE it -
# Starlette runs the last-registered middleware first on the way in and
# last on the way out, which means this touches every response,
# including the 401s/redirects the auth middleware returns directly,
# not just the ones that reach a real route. Step 3.4 security
# self-review: standard, low-risk hardening headers with no functional
# cost here - this console never needs to be framed by another page,
# never serves user-uploaded content a browser might MIME-sniff, and
# never needs to leak its own internal URLs into an outbound Referer.
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = Query("/"), error: Optional[str] = Query(None)):
    return templates.TemplateResponse("login.html", {"request": request, "next": next, "error": error})


@app.post("/login")
async def do_login(request: Request):
    """Check the password, and on success issue a session cookie instead
    of asking the browser to resend the password on every future request
    (what Basic Auth did through Stage 2). Reads a plain HTML form, not
    JSON - this page has to work even if a future change to app.js is
    broken, since it's the one page a locked-out operator most needs to
    load reliably.

    Parses the body with urllib.parse rather than Starlette's own
    request.form(): checked live before settling on this - form()
    needs the separate `python-multipart` package installed even for a
    plain application/x-www-form-urlencoded body (not just real
    multipart/form-data), which this project doesn't otherwise depend
    on anywhere, on the Mac or the gateway. A hand-rolled parse of a
    single flat field avoids that dependency entirely, in keeping with
    this project's own "plain Python" standing constraint."""
    body = await request.body()
    form = parse_qs(body.decode(), keep_blank_values=True)
    password = form.get("password", [""])[0]
    next_path = form.get("next", ["/"])[0] or "/"
    if not next_path.startswith("/") or next_path.startswith("//"):
        next_path = "/"  # never redirect off-site (open-redirect guard)
    ip = request.client.host if request.client else "unknown"

    conn = db()
    session_auth.cleanup_expired(conn)
    if not session_auth.check_rate_limit(conn, ip):
        return templates.TemplateResponse("login.html", {
            "request": request, "next": next_path,
            "error": "Too many attempts from this address. Wait a few minutes and try again.",
        }, status_code=429)

    try:
        stored = _console_password()
    except FileNotFoundError:
        stored = None

    # PBKDF2 deliberately takes a noticeable fraction of a second. This
    # handler is `async` (it has to await the request body), so running
    # the hash directly here would freeze every other console request -
    # including other tabs' live refreshes - for that whole time.
    # run_in_threadpool runs the same plain function on a worker thread
    # and waits for its answer without blocking everything else.
    ok = stored is not None and await run_in_threadpool(session_auth.verify_password, password, stored)
    if ok:
        if session_auth.needs_rehash(stored):
            encoded = await run_in_threadpool(session_auth.hash_password, password)
            session_auth.write_password_file(CONSOLE_PASSWORD_FILE, encoded)
        session_auth.clear_attempts(conn, ip)
        token = session_auth.create_session(conn, CONSOLE_USERNAME)
        audit.log(conn, CONSOLE_USERNAME, "auth.login", detail="ip=%s" % ip)
        response = RedirectResponse(url=next_path, status_code=303)
        response.set_cookie(
            key=session_auth.SESSION_COOKIE, value=token, httponly=True,
            samesite="strict",
            # Step 3.2 made the real gateway HTTPS-only, so this is always
            # True there - a plain HTTP request can no longer even reach
            # this code. Derived from the request rather than hardcoded so
            # docs/demo/serve.py's local, plain-HTTP screenshot tool (never
            # a real security boundary) keeps working without a special case.
            secure=(request.url.scheme == "https"),
            max_age=settings.get(conn, "session_absolute_timeout_seconds"),
        )
        return response

    session_auth.record_failed_attempt(conn, ip)
    print("console: failed login attempt from %s" % ip, flush=True)
    return templates.TemplateResponse("login.html", {
        "request": request, "next": next_path, "error": "Incorrect password.",
    }, status_code=401)


@app.post("/logout")
def do_logout(request: Request):
    token = request.cookies.get(session_auth.SESSION_COOKIE)
    if token:
        conn = db()
        audit.log(conn, CONSOLE_USERNAME, "auth.logout")
        session_auth.delete_session(conn, token)
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(session_auth.SESSION_COOKIE)
    return response

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
SIGNALS = ["port_scan", "network_sweep", "slow_scan", "dns_bypass", "ids_alert", "threat_intel",
           "dns_tunneling", "beacon", "brute_force", "malicious_domain", "new_device",
           "adblock_ineffective", "volume_anomaly", "campaign"]

# Step 6.1's own exit criterion calls this "the learning badge until 7
# days of data exist" - matches BASELINE_MIN_SAMPLES in correlation.py.
BASELINE_LEARNING_DAYS = 7
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

# Step 5.9: the versioned, console-editable Tier 2 rule set, and the
# per-rule hit-count snapshot dpi/securepi_adfilter.py writes. Both plain
# files, like the CA - no database table for either.
DPI_RULES_PATH = "/var/lib/securepi-dpi/adfilter-rules.json"
DPI_RULE_STATS_PATH = "/var/log/securepi/dpi-rule-stats.json"

# dpi/privacy_canary.py (step 5.7) checks every 15 minutes; twice that
# before the console calls the check itself stale, the same slack
# SIGNAL_STALE_AFTER/INGEST_STALE_AFTER give the correlation engine and
# ingest above.
PRIVACY_SCOPE_STALE_AFTER = 30 * 60


class IncidentUpdate(BaseModel):
    status: str


class IncidentNote(BaseModel):
    note: str


class SuppressionCreate(BaseModel):
    # device_id omitted (None) means network-wide for this signal_type -
    # see suppression.py's own module docstring.
    signal_type: str
    device_id: Optional[int] = None
    reason: str
    expires_in_days: Optional[float] = None


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
    # 1-720 (30 days): matches the privileged helper's own hard bound
    # (gateway/securepi-web-helper, step 3.3) - validated here too so a
    # bad value gets a clean 422 instead of a 502 from the helper
    # rejecting it two layers down.
    hours: int = Field(default=dpi_enroll.DEFAULT_TIMEOUT_HOURS, ge=1, le=720)


class DpiRulesUpdate(BaseModel):
    decrypt_suffixes: list[str]
    ad_fields: list[str]
    ad_renderers: list[str]
    blocked_paths: list[str]
    reason: str
    confirm_privacy_scope_change: bool = False
    # Step 5.11, Path 1 (cosmetic CSS injection only - see
    # ENHANCEMENT-PLAN.md's record of Path 2 and why it was deferred).
    # None (not False/[]) means "not sent, leave the current value alone" -
    # api_dpi_rules_set merges these against the rules already on disk,
    # so a request that only means to edit e.g. blocked_paths can't
    # silently wipe an operator's cosmetic settings back to defaults just
    # by omitting these two fields.
    cosmetic_injection_enabled: Optional[bool] = None
    cosmetic_selectors: Optional[list[str]] = None


class SettingUpdate(BaseModel):
    # `value: Any`, not `float` or `int` - a typed field would let
    # FastAPI/Pydantic silently coerce the JSON number before
    # settings.validate() ever sees it (an int setting sent as `3` could
    # arrive already turned into `3.0`), defeating that function's own
    # int-vs-float check. Passed through exactly as the client sent it.
    value: Any
    reason: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class SavedSearchCreate(BaseModel):
    name: str
    device_id: Optional[int] = None
    ip: Optional[str] = None
    domain: Optional[str] = None
    port: Optional[int] = None
    event_type: Optional[str] = None
    range: Optional[str] = None


class QuarantineUpdate(BaseModel):
    quarantined: bool
    # Stage 4 (step 4.2): optional. No minutes means until released; a
    # reason is recorded with the policy either way.
    minutes: Optional[int] = Field(default=None, ge=5, le=43200)
    reason: str = "quarantined from the console"


class PolicyCreate(BaseModel):
    kind: str
    device_id: Optional[int] = None
    target: Optional[str] = None
    minutes: Optional[int] = Field(default=None, ge=1, le=43200)
    reason: str
    incident_id: Optional[int] = None


class PolicyEnd(BaseModel):
    reason: str = ""


class PolicyExtend(BaseModel):
    minutes: int = Field(ge=5, le=43200)
    reason: str = "extended from the console"


class TrustUpdate(BaseModel):
    trust: str
    reason: str = ""


class RestrictUnknownUpdate(BaseModel):
    enabled: bool
    # Lockout-safe switch-on (step 4.4): approve every device already on
    # the network first, so turning this on never cuts off a device that
    # was working a moment ago.
    approve_existing: bool = True


class ProfileAssign(BaseModel):
    profile: str
    reason: str = "profile set from the console"


class PauseRequest(BaseModel):
    minutes: int = Field(ge=1, le=1440)
    reason: str = "paused from the console"


class ProfileEdit(BaseModel):
    safe_search: Optional[bool] = None
    blocked_services: Optional[list] = None
    schedule: Optional[dict] = None
    clear_schedule: bool = False
    reason: str = ""


class ChannelCreate(BaseModel):
    kind: str
    name: str
    config: dict
    min_severity: str = "medium"


class ChannelUpdate(BaseModel):
    enabled: Optional[bool] = None
    min_severity: Optional[str] = None


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
    / tls_failed / pin_bypass decisions, plus the total ad objects removed.
    tls_failed (step 5.6) is what the CA-trust check in
    api_filtering_dpi_enrolled reads to notice a device that likely hasn't
    installed the CA. pin_bypass (step 5.8) is a connection auto-passed-
    through because the same (device, host) pair failed the handshake
    repeatedly - see api_filtering_dpi_pinned for the "currently bypassed"
    view of the same data. Source data is written by
    dpi/securepi_adfilter.py and read by ingest.py's read_dpi_events() -
    see ENHANCEMENT-PLAN.md step 5.1."""
    dev_clause = " AND device_id=?" if device_id is not None else ""
    dev_arg = (device_id,) if device_id is not None else ()
    counts = {"decrypt": 0, "passthrough": 0, "ads_stripped": 0, "path_blocked": 0,
              "tls_failed": 0, "pin_bypass": 0}
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
        # severity is picked with max() only because every incident of a
        # given signal_type is always raised with the SAME literal severity
        # (see correlation.py's raise_incident() calls) - it never actually
        # varies within a group, so which aggregate wins doesn't matter.
        # Added in step 2.1 so the console tints new signals (network_sweep,
        # slow_port_scan, slow_network_sweep) correctly without needing
        # their names hardcoded in app.js the way the old two-signal check
        # did (see that file's git history).
        {"signal": r["signal_type"], "count": r["n"], "severity": r["sev"]}
        for r in c.execute(
            "SELECT signal_type, count(*) n, max(severity) sev FROM incidents"
            " GROUP BY signal_type ORDER BY n DESC")
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


def _top_evidence_domain(signal_type, evidence):
    """A one-click 'block this domain' action (step 6.4) is only offered
    for malicious_domain incidents where the evidence chain actually
    names a domain - the most frequently seen one. Reuses the existing
    per-device block endpoint from step 5.x rather than a new one."""
    if signal_type != "malicious_domain":
        return None
    domains = [e["detail"] for e in evidence if e["type"] == "dns_query" and e["detail"] != "-"]
    if not domains:
        return None
    return collections.Counter(domains).most_common(1)[0][0]


def _incident_notes(conn, incident_id):
    return [{
        "ts": time.strftime("%d %b %H:%M:%S", time.localtime(n["ts"])),
        "author": n["author"], "note": n["note"],
    } for n in conn.execute(
        "SELECT * FROM incident_notes WHERE incident_id=? ORDER BY id DESC", (incident_id,))]


def _incident_timeline(conn, incident_id, created_at):
    """The status-change timeline reads from audit_log rather than a
    dedicated history table - api_update_incident already writes one row
    there per change (action='incident.status_change'). The incident's
    own creation is added as the timeline's oldest entry, since it always
    predates any status change and audit.for_target only has rows from
    that point onward."""
    timeline = [{
        "ts": time.strftime("%d %b %H:%M:%S", time.localtime(a["ts"])),
        "detail": a["detail"],
    } for a in audit.for_target(conn, str(incident_id))
      if a["action"] == "incident.status_change"]
    timeline.append({
        "ts": time.strftime("%d %b %H:%M:%S", time.localtime(created_at)),
        "detail": "raised as new",
    })
    return timeline


def _related_open_incidents(conn, device_id, exclude_incident_id, now):
    """Other still-open incidents on the same device, whatever their signal.
    This is deliberately NOT the campaign view: campaigns (step 2.8,
    correlation.py's campaign_signal) only link incidents spanning distinct
    ATT&CK tactics, and live in their own table. The template's card footer
    says so and points to where an open campaign is shown."""
    return [{
        "id": r["id"], "title": r["title"], "severity": r["severity"],
        "signal_type": r["signal_type"],
        "last_seen": _age(now - r["last_seen"]),
    } for r in conn.execute(
        "SELECT * FROM incidents WHERE device_id=? AND id!=? AND status IN ('new','investigating')"
        " ORDER BY last_seen DESC LIMIT 10", (device_id, exclude_incident_id))]


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
        # Stage 4: what the console is enforcing on this device, from the
        # policies table (the device page reads the live firewall state).
        pol = {row["kind"]: row for row in c.execute(
            "SELECT kind, target, expires_at FROM policies WHERE status='active' AND device_id=?"
            " AND kind IN ('quarantine','profile','pause')", (d["id"],))}
        out.append({
            "id": d["id"], "name": device_label(d),
            "trust": d["trust"],
            "quarantined": "quarantine" in pol,
            "profile": pol["profile"]["target"] if "profile" in pol else profiles.DEFAULT_PROFILE,
            "profile_label": profiles.BUILTIN_PROFILES[pol["profile"]["target"]]["label"]
                             if "profile" in pol else profiles.BUILTIN_PROFILES[profiles.DEFAULT_PROFILE]["label"],
            "paused": "pause" in pol,
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


def _hunt_where(device_id, ip, domain, port, event_type, start):
    """Shared WHERE-clause builder for /api/hunt's display query and its
    aggregate query, so both operate over exactly the same filtered set
    of events - "top talkers for this search" must mean top talkers OF
    the filtered traffic, not of the whole time range. Every filter is
    optional and they combine with AND; ip/domain use the events table's
    existing dest_ip/dns_rrname/tls_sni indexes rather than a full-text
    search engine, which is enough at this project's real data volume."""
    where = ["e.ts >= ?"]
    params = [start]
    if device_id:
        where.append("e.device_id = ?")
        params.append(device_id)
    if ip:
        where.append("(e.src_ip = ? OR e.dest_ip = ?)")
        params.extend([ip, ip])
    if domain:
        where.append("(e.dns_rrname LIKE ? OR e.tls_sni LIKE ?)")
        like = "%%%s%%" % domain
        params.extend([like, like])
    if port:
        where.append("(e.src_port = ? OR e.dest_port = ?)")
        params.extend([port, port])
    if event_type:
        where.append("e.event_type = ?")
        params.append(event_type)
    return " AND ".join(where), params


def _hunt_aggregates(conn, where_sql, params):
    """Top talkers (by bytes, device-attributed traffic only), top
    destinations (domain if known, else the raw IP) and a protocol
    breakdown, all computed over the filtered rows the caller already
    matched - not a second, differently-scoped query."""
    talkers = collections.Counter()
    destinations = collections.Counter()
    protocols = collections.Counter()
    for r in conn.execute("SELECT * FROM events e WHERE %s" % where_sql, params):
        if r["device_id"]:
            talkers[r["device_id"]] += (r["bytes_toclient"] or 0) + (r["bytes_toserver"] or 0)
        dest = r["dns_rrname"] or r["tls_sni"] or r["dest_ip"]
        if dest:
            destinations[dest] += 1
        protocols[r["event_type"]] += 1

    top_talkers = []
    for device_id, total_bytes in talkers.most_common(10):
        if total_bytes <= 0:
            continue
        d = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        top_talkers.append({
            "device_id": device_id,
            "device": device_label(d) if d else "device %d" % device_id,
            "bytes": total_bytes, "bytes_label": humanize_bytes(total_bytes),
        })
    return {
        "top_talkers": top_talkers,
        "top_destinations": [{"name": n, "count": c} for n, c in destinations.most_common(10)],
        "protocol_breakdown": [{"type": t, "count": c} for t, c in protocols.most_common()],
    }


@app.get("/api/hunt")
def api_hunt(device_id: int = Query(0), ip: str = Query(""), domain: str = Query(""),
              port: int = Query(0), event_type: str = Query(""), range: str = Query("1h"),
              limit: int = Query(200)):
    """Flow/DNS/TLS search with pivots, top talkers, top destinations and
    a protocol breakdown (ENHANCEMENT-PLAN.md step 6.5). Not the full
    Hunt catalogue entry's every idea - this is search + aggregates over
    the existing events table, which is what its own exit criterion
    ("everything device X talked to in the last hour, in two clicks")
    actually asks for."""
    spec = RANGES.get(range, RANGES["1h"])
    c = db()
    start = time.time() - spec["seconds"]
    where_sql, params = _hunt_where(device_id, ip, domain, port, event_type, start)

    rows = c.execute(
        ("SELECT e.*, d.hostname, d.friendly_name FROM events e"
         " LEFT JOIN devices d ON d.id = e.device_id WHERE %s"
         " ORDER BY e.id DESC LIMIT ?") % where_sql,
        params + [min(limit, 1000)],
    ).fetchall()

    result = {"events": [_event_row(r) for r in rows], "range_label": spec["label"]}
    result.update(_hunt_aggregates(c, where_sql, params))
    return result


@app.get("/api/hunt/saved")
def api_hunt_saved_list():
    c = db()
    return {"searches": [{
        "id": r["id"], "name": r["name"], "filters": json.loads(r["filters"]),
        "created_at": time.strftime("%d %b %H:%M", time.localtime(r["created_at"])),
    } for r in c.execute("SELECT * FROM saved_searches ORDER BY id DESC")]}


@app.post("/api/hunt/saved")
def api_hunt_saved_create(body: SavedSearchCreate):
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "name is required")
    filters = {
        "device_id": body.device_id, "ip": body.ip, "domain": body.domain,
        "port": body.port, "event_type": body.event_type, "range": body.range,
    }
    c = db()
    c.execute("INSERT INTO saved_searches (name, filters, created_at) VALUES (?, ?, ?)",
              (name, json.dumps(filters), time.time()))
    c.commit()
    audit.log(c, CONSOLE_USERNAME, "hunt.save_search", target=name, detail=json.dumps(filters))
    return {"ok": True}


@app.post("/api/hunt/saved/{search_id}/remove")
def api_hunt_saved_remove(search_id: int):
    c = db()
    row = c.execute("SELECT name FROM saved_searches WHERE id=?", (search_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "saved search not found")
    c.execute("DELETE FROM saved_searches WHERE id=?", (search_id,))
    c.commit()
    audit.log(c, CONSOLE_USERNAME, "hunt.remove_search", target=row["name"])
    return {"ok": True}


@app.get("/hunt", response_class=HTMLResponse)
def page_hunt(request: Request):
    c = db()
    devices = [{"id": d["id"], "name": device_label(d)}
               for d in c.execute("SELECT * FROM devices ORDER BY last_seen DESC")]
    return templates.TemplateResponse("hunt.html", {
        "request": request, "active": "hunt", "title": "Hunt", "devices": devices,
    })


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


@app.get("/api/dns-status")
def api_dns_status():
    """ENHANCEMENT-PLAN.md step 3.6: is DNS currently fail-open (AdGuard
    not answering, plaintext DNS redirected to a public upstream
    resolver). Reads app/health.py's own live status table directly -
    this console runs unprivileged (step 3.3) and cannot ask nftables
    itself, and this row is written only by the (root) ingest process,
    never by this app."""
    row = db().execute("SELECT * FROM dns_failopen_state WHERE id=1").fetchone()
    active = bool(row["active"]) if row else False
    changed_at = row["changed_at"] if row else None
    return {
        "active": active,
        "since": time.strftime("%H:%M:%S", time.localtime(changed_at)) if active and changed_at else None,
        "age": _age(time.time() - changed_at) if active and changed_at else None,
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
    row = c.execute("SELECT status FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "incident not found")
    before = row["status"]
    now = time.time()
    c.execute("UPDATE incidents SET status=?, updated_at=? WHERE id=?",
              (body.status, now, incident_id))
    c.commit()
    audit.log(c, CONSOLE_USERNAME, "incident.status_change", target=str(incident_id),
              detail="%s -> %s" % (before, body.status))
    return {"id": incident_id, "status": body.status}


@app.post("/api/incidents/{incident_id}/notes")
def api_add_incident_note(incident_id: int, body: IncidentNote):
    note = body.note.strip()
    if not note:
        raise HTTPException(400, "note must not be empty")
    c = db()
    if c.execute("SELECT 1 FROM incidents WHERE id=?", (incident_id,)).fetchone() is None:
        raise HTTPException(404, "incident not found")
    now = time.time()
    c.execute("INSERT INTO incident_notes (incident_id, ts, author, note) VALUES (?, ?, ?, ?)",
              (incident_id, now, CONSOLE_USERNAME, note))
    c.commit()
    audit.log(c, CONSOLE_USERNAME, "incident.note_added", target=str(incident_id), detail=note)
    return {"ok": True}


@app.get("/api/campaigns")
def api_list_campaigns(status: str = Query("")):
    """ENHANCEMENT-PLAN.md step 2.8. Each row's `tactics` field is
    already the kill chain itself (see correlation.py's campaign_signal),
    so this needs no extra assembly - unlike incidents, campaigns aren't
    paginated here since there are always far fewer of them."""
    c = db()
    q = "SELECT * FROM campaigns"
    params = ()
    if status:
        q += " WHERE status = ?"
        params = (status,)
    q += " ORDER BY updated_at DESC"
    campaigns = [dict(r) for r in c.execute(q, params)]
    for camp in campaigns:
        camp["incident_ids"] = [r["id"] for r in c.execute(
            "SELECT id FROM incidents WHERE campaign_id = ? ORDER BY first_seen", (camp["id"],))]
    return campaigns


@app.get("/api/suppressions")
def api_list_suppressions():
    return suppression.list_suppressions(db())


@app.post("/api/incidents/{incident_id}/suppress")
def api_suppress_from_incident(incident_id: int, body: SuppressionCreate):
    """ENHANCEMENT-PLAN.md step 2.7: the only way a suppression rule
    comes into being - starting from a real incident this operator has
    already marked false_positive, never pre-emptively. body.signal_type
    is required to match the incident's own signal_type (not taken on
    faith from the request) so a client can't suppress a different
    signal by passing an arbitrary type here."""
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(400, "reason must not be empty")
    c = db()
    row = c.execute("SELECT status, signal_type, device_id FROM incidents WHERE id=?",
                     (incident_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "incident not found")
    if row["status"] != "false_positive":
        raise HTTPException(400, "a suppression can only be created from an incident "
                                  "already marked false_positive")
    if body.signal_type != row["signal_type"]:
        raise HTTPException(400, "signal_type must match the incident's own signal_type")
    device_id = row["device_id"] if body.device_id is None else body.device_id
    expires_at = (time.time() + body.expires_in_days * 86400) if body.expires_in_days else None
    suppression_id = suppression.add_suppression(
        c, body.signal_type, device_id, reason, CONSOLE_USERNAME, expires_at)
    audit.log(c, CONSOLE_USERNAME, "suppression.create", target=str(suppression_id),
              detail="signal=%s device=%s reason=%s%s" % (
                  body.signal_type, device_id, reason,
                  " expires_in_days=%s" % body.expires_in_days if body.expires_in_days else ""))
    return {"id": suppression_id, "signal_type": body.signal_type, "device_id": device_id,
            "expires_at": expires_at}


@app.delete("/api/suppressions/{suppression_id}")
def api_remove_suppression(suppression_id: int):
    c = db()
    if not suppression.remove_suppression(c, suppression_id):
        raise HTTPException(404, "suppression not found")
    audit.log(c, CONSOLE_USERNAME, "suppression.remove", target=str(suppression_id))
    return {"ok": True}


@app.patch("/api/devices/{device_id}")
def api_rename_device(device_id: int, body: DeviceUpdate):
    name = body.friendly_name.strip()
    if not name:
        raise HTTPException(400, "friendly_name must not be empty")
    c = db()
    row = c.execute("SELECT friendly_name, hostname FROM devices WHERE id=?", (device_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "device not found")
    before = row["friendly_name"] or row["hostname"] or ("device %d" % device_id)
    c.execute("UPDATE devices SET friendly_name=? WHERE id=?", (name, device_id))
    c.commit()
    audit.log(c, CONSOLE_USERNAME, "device.rename", target=str(device_id),
              detail="%s -> %s" % (before, name))
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
    audit.log(db(), CONSOLE_USERNAME, "filtering.set_enabled", detail="enabled=%s" % body.enabled)
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
    audit.log(db(), CONSOLE_USERNAME, "filtering.add_list", target=url, detail=name)
    return {"ok": True}


@app.post("/api/filtering/lists/toggle")
def api_filtering_toggle_list(body: BlocklistToggle):
    try:
        adguard.set_blocklist_enabled(body.url, body.enabled)
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    audit.log(db(), CONSOLE_USERNAME, "filtering.toggle_list", target=body.url,
              detail="enabled=%s" % body.enabled)
    return {"url": body.url, "enabled": body.enabled}


@app.post("/api/filtering/lists/remove")
def api_filtering_remove_list(body: BlocklistUrl):
    try:
        adguard.remove_blocklist(body.url)
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    audit.log(db(), CONSOLE_USERNAME, "filtering.remove_list", target=body.url)
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
    audit.log(db(), CONSOLE_USERNAME, "filtering.add_rule", target=domain, detail=body.action)
    return {"ok": True}


@app.post("/api/filtering/rules/remove")
def api_filtering_remove_rule(body: RuleRemove):
    try:
        adguard.remove_user_rule(body.rule)
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    audit.log(db(), CONSOLE_USERNAME, "filtering.remove_rule", target=body.rule)
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
    """The device's filtering profile and pause state (step 4.3), plus
    whether AdGuard currently has filtering on for it - read live, so a
    change made in AdGuard itself shows up here too."""
    c = db()
    d = c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone()
    if d is None:
        raise HTTPException(404, "device not found")
    view = _device_filtering_view(c, device_id, time.time())
    identifiers, current_ip = device_identifiers(c, device_id)
    view["ip"] = current_ip
    if not identifiers:
        view.update(managed=False, filtering_enabled=True)
        return view
    try:
        view.update(adguard.client_filtering_status(identifiers))
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    return view


@app.post("/api/devices/{device_id}/filtering")
def api_device_filtering_set(device_id: int, body: DeviceFilterUpdate):
    """The original on/off switch, kept for compatibility: since step 4.3
    "off" is the Unrestricted profile and "on" is back to Standard, both
    applied through the orchestrator."""
    return api_device_profile_set(device_id, ProfileAssign(
        profile=profiles.DEFAULT_PROFILE if body.enabled else "unrestricted",
        reason="filtering switched %s from the console" % ("on" if body.enabled else "off")))


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
    """Which vendor-telemetry profiles are applied to this device - one
    orchestrator policy each (step 4.1), plus a note if its filtering
    profile is Strict privacy, which applies all of them."""
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    applied = []
    for r in orchestrator.active_policies(c, "native_profile", device_id):
        prof = native_trackers.profile(r["target"])
        if prof:
            applied.append({"vendor": r["target"], "label": prof["label"], "rule_count": len(prof["domains"]),
                            "policy_id": r["id"]})
    strict = any(r["target"] == "strict_privacy" for r in orchestrator.active_policies(c, "profile", device_id))
    return {"applied": applied, "via_strict_privacy": strict}


@app.post("/api/devices/{device_id}/filtering/profile")
def api_device_apply_profile(device_id: int, body: NativeProfileRequest):
    """Apply a vendor-telemetry profile to one device: a $client-scoped
    block rule per domain, as one orchestrator policy (step 4.1). See
    ENHANCEMENT-PLAN.md step 5.5 for why these lists are kept small."""
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    prof = native_trackers.profile(body.vendor)
    if prof is None:
        raise HTTPException(400, "unknown vendor profile: %s" % body.vendor)
    p = _create_policy(c, "native_profile", device_id, body.vendor, None,
                       "vendor telemetry block list applied from the console")
    return {"ok": True, "vendor": body.vendor, "domains": prof["domains"], "policy_id": p["id"]}


@app.post("/api/devices/{device_id}/filtering/profile/remove")
def api_device_remove_profile(device_id: int, body: NativeProfileRequest):
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    removed = 0
    for r in orchestrator.active_policies(c, "native_profile", device_id):
        if r["target"] == body.vendor:
            _end_policy(c, r["id"], "removed from the console")
            removed += 1
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
    audit.log(db(), CONSOLE_USERNAME, "filtering.resolver_tuning_apply",
              detail="optimistic cache, DNSSEC, parallel dual-DoT upstreams")
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
        # Confirmed live against the real gateway: openssl prints this as
        # "sha256 Fingerprint=..." (lowercase "sha256") - assuming the
        # all-caps spelling from openssl's own flag name was wrong and
        # would have left fingerprint_sha256 silently missing forever.
        if line.lower().startswith("sha256 fingerprint="):
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


@app.get("/api/filtering/dpi/privacy-scope")
def api_privacy_scope():
    """Status for the console's "privacy scope verified N min ago" badge
    (step 5.7). Reads what dpi/privacy_canary.py - a separate,
    continuously-running process, not something this endpoint invokes -
    already wrote: when it last ran (signal_state), and whether an open
    failure incident exists right now (incidents). If the canary hasn't
    been deployed at all, this reads as "stale", which is the honest
    state to show rather than a false green."""
    c = db()
    now = time.time()
    row = c.execute(
        "SELECT last_run_ts FROM signal_state WHERE signal_type='privacy_scope'").fetchone()
    last_run = row["last_run_ts"] if row else None
    stale = (last_run is None) or (now - last_run) >= PRIVACY_SCOPE_STALE_AFTER
    failing = c.execute(
        "SELECT id FROM incidents WHERE signal_type='privacy_scope_failure' AND status='new'"
        " ORDER BY last_seen DESC LIMIT 1").fetchone()
    return {
        "last_checked": time.strftime("%H:%M:%S", time.localtime(last_run)) if last_run else None,
        "age": _age(now - last_run) if last_run else None,
        "stale": stale,
        "failing": failing is not None,
        "incident_id": failing["id"] if failing else None,
        "healthy": (not stale) and (failing is None),
    }


@app.get("/api/filtering/dpi/pinned")
def api_filtering_dpi_pinned():
    """Currently-active pinning-aware auto-passthroughs (step 5.8): a
    (device, host) pair the addon has stopped trying to decrypt for a
    while because the app kept failing the handshake - almost always
    certificate pinning, not a missing CA (the console's CA-trust check,
    step 5.6, is a better read on that case). This is the console's "App
    pins its certificate - bypassed" indicator.

    dpi_ads_removed on a pin_bypass row holds the bypass's own expiry
    epoch, not a count - see securepi_adfilter.py's _log_event docstring
    for why that field does double duty rather than adding a new column."""
    c = db()
    now = time.time()
    rows = c.execute(
        "SELECT src_ip, tls_sni, max(ts) last_seen, max(dpi_ads_removed) expires_at"
        " FROM events WHERE source='dpi' AND dpi_action='pin_bypass'"
        " GROUP BY src_ip, tls_sni HAVING expires_at > ?", (now,)).fetchall()
    out = []
    for r in rows:
        ip = r["src_ip"]
        name = ip
        dev_row = c.execute(
            "SELECT device_id FROM device_ips WHERE ip=? ORDER BY last_seen DESC LIMIT 1",
            (ip,)).fetchone()
        device_id = dev_row["device_id"] if dev_row else None
        if device_id is not None:
            d = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
            if d:
                name = device_label(d)
        out.append({
            "ip": ip, "device_id": device_id, "name": name, "sni": r["tls_sni"],
            "last_seen": _age(now - r["last_seen"]),
            "expires_in_s": int(r["expires_at"] - now),
        })
    return {"pinned": out}


def _read_dpi_rules():
    """Current Tier 2 rule set, falling back to the built-in defaults if
    the file is missing or invalid - the same graceful-degradation
    contract the addon's own loader has, using the same shared
    adfilter_rules module. See that module's docstring for why one
    source file in git is deployed to two locations (this console
    process and the DPI venv) rather than imported across a boundary
    that would drag mitmproxy into the console."""
    try:
        return adfilter_rules.load_rules(DPI_RULES_PATH)
    except (OSError, ValueError, json.JSONDecodeError):
        return dict(adfilter_rules.DEFAULT_RULES)


def _read_dpi_rule_stats():
    try:
        with open(DPI_RULE_STATS_PATH) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


@app.get("/api/filtering/dpi/rules")
def api_dpi_rules_get():
    """The Tier 2 rule set plus per-rule hit counts, for the console's
    rule editor and "dead rules" view (step 5.9). Hit counts are since
    the last securepi-dpi restart, not lifetime - the addon keeps them in
    process memory, not the database (see its _write_rule_stats
    docstring), the same trade-off step 5.8's pinning state makes."""
    rules = _read_dpi_rules()
    stats = _read_dpi_rule_stats()
    hits = stats.get("hits") or {"ad_fields": {}, "ad_renderers": {}, "blocked_paths": {}}

    def annotate(category):
        return [
            {"rule": r, "hits": hits.get(category, {}).get(r, 0)}
            for r in rules.get(category, [])
        ]

    return {
        "version": rules.get("version"),
        "updated_at": rules.get("updated_at"),
        "decrypt_suffixes": rules.get("decrypt_suffixes", []),
        "ad_fields": annotate("ad_fields"),
        "ad_renderers": annotate("ad_renderers"),
        "blocked_paths": annotate("blocked_paths"),
        "stats_age": _age(time.time() - stats["written_at"]) if stats.get("written_at") else None,
        # Step 5.11, Path 1 - see adfilter_rules.py's OPTIONAL_RULE_DEFAULTS.
        "cosmetic_injection_enabled": rules.get("cosmetic_injection_enabled", False),
        "cosmetic_selectors": rules.get("cosmetic_selectors", []),
    }


@app.post("/api/filtering/dpi/rules")
def api_dpi_rules_set(body: DpiRulesUpdate):
    """Edit the Tier 2 rule set from the console (step 5.9). Validated
    with the exact same logic the addon's own loader uses (shared via
    adfilter_rules.py) before anything is written to disk. A change to
    decrypt_suffixes - which changes what this gateway is even able to
    decrypt - needs an explicit confirm_privacy_scope_change=true, the
    same pattern step 5.5's resolver tuning uses for an equally
    consequential change. "Audit" is a print() into the journal, same
    stopgap every other filtering endpoint in this file already uses
    until Stage 1's real audit_log table exists (step 1.5) - `reason` is
    required for the same reason it's required on the allow/block
    endpoints."""
    if not body.reason.strip():
        raise HTTPException(400, "a reason is required")
    current = _read_dpi_rules()
    new_rules = {
        "decrypt_suffixes": body.decrypt_suffixes,
        "ad_fields": body.ad_fields,
        "ad_renderers": body.ad_renderers,
        "blocked_paths": body.blocked_paths,
        # None means "this request doesn't mean to touch cosmetic
        # settings" - keep whatever's already on disk, not the Pydantic
        # field default, so an edit to e.g. blocked_paths alone can never
        # silently reset these. See DpiRulesUpdate's own docstring.
        "cosmetic_injection_enabled": (
            body.cosmetic_injection_enabled if body.cosmetic_injection_enabled is not None
            else current.get("cosmetic_injection_enabled", False)),
        "cosmetic_selectors": (
            body.cosmetic_selectors if body.cosmetic_selectors is not None
            else current.get("cosmetic_selectors", [])),
    }
    try:
        adfilter_rules.validate_rules(new_rules)
    except ValueError as e:
        raise HTTPException(400, str(e))

    if set(new_rules["decrypt_suffixes"]) != set(current.get("decrypt_suffixes", [])):
        if not body.confirm_privacy_scope_change:
            raise HTTPException(400,
                "changing decrypt_suffixes changes what this gateway is able to decrypt - "
                "resend with confirm_privacy_scope_change=true to proceed")

    new_rules["version"] = (current.get("version") or 0) + 1
    new_rules["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Write to a uniquely named temporary file, then rename it over the
    # real one - atomic, so the addon never reads a half-written file.
    # The name is unique (mkstemp) rather than a fixed "<path>.tmp" so two
    # saves arriving at once can't write into the same temporary file.
    fd, tmp_path = tempfile.mkstemp(prefix=".adfilter-rules.", dir=os.path.dirname(DPI_RULES_PATH))
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(new_rules, f, indent=2)
        os.chmod(tmp_path, 0o664)  # the root-run addon and the console both read it
        os.replace(tmp_path, DPI_RULES_PATH)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise

    print("filtering: DPI rules updated to version %d - %s" % (new_rules["version"], body.reason), flush=True)
    audit.log(db(), CONSOLE_USERNAME, "filtering.dpi_rules_update",
              target="version %d" % new_rules["version"], detail=body.reason)
    return {"ok": True, "version": new_rules["version"]}


@app.get("/api/filtering/dpi/effectiveness")
def api_dpi_effectiveness():
    """Whether the ad-removal effectiveness watchdog (step 5.10,
    `correlation.adblock_effectiveness_signal`) has an open concern right
    now - read from the incidents table the correlation engine already
    writes to on its own schedule, not a separate status file. See
    REPORT-adblocking.md's SSAI section for what this can and cannot
    distinguish."""
    c = db()
    now = time.time()
    rows = c.execute(
        "SELECT i.id, i.device_id, d.hostname, d.friendly_name, i.last_seen"
        "  FROM incidents i LEFT JOIN devices d ON d.id = i.device_id"
        " WHERE i.signal_type='adblock_ineffective' AND i.status='new'"
        " ORDER BY i.last_seen DESC").fetchall()
    return {
        "healthy": len(rows) == 0,
        "affected": [
            {"incident_id": r["id"], "device_id": r["device_id"],
             "name": device_label(r) if r["device_id"] else "unknown device",
             "age": _age(now - r["last_seen"])}
            for r in rows
        ],
    }


@app.get("/api/devices/{device_id}/dpi")
def api_device_dpi_status(device_id: int):
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    ip = orchestrator.device_ip(c, device_id)
    if ip is None:
        return {"enrolled": False, "ip": None, "expires_in_s": None}
    try:
        rows = {e["ip"]: e for e in dpi_enroll.enrolled()}
    except dpi_enroll.DpiEnrollError as e:
        raise HTTPException(502, str(e))
    row = rows.get(ip)
    pol = orchestrator.active_policies(c, "enroll", device_id)
    return {
        "enrolled": row is not None, "ip": ip,
        "expires_in_s": int(pol[0]["expires_at"] - time.time()) if pol else (row["expires_in_s"] if row else None),
        "policy_id": pol[0]["id"] if pol else None,
    }


@app.post("/api/devices/{device_id}/dpi")
def api_device_dpi_set(device_id: int, body: DpiEnrollRequest):
    """Enroll or unenroll one device for Tier 2 (HTTPS ad removal), now as
    an orchestrator policy (step 4.1): the enrollment follows the device
    to a new IP after a DHCP renewal, and ends on time. It is never
    re-added if something else turns it off - see orchestrator.py."""
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    if body.enrolled:
        p = _create_policy(c, "enroll", device_id, None, time.time() + body.hours * 3600,
                           "HTTPS ad removal enabled from the console for %dh" % body.hours)
        return {"id": device_id, "enrolled": True, "ip": orchestrator.device_ip(c, device_id),
                "expires_in_s": body.hours * 3600, "policy_id": p["id"]}
    for r in orchestrator.active_policies(c, "enroll", device_id):
        _end_policy(c, r["id"], "unenrolled from the console")
    # Also clear an enrollment the orchestrator doesn't know about yet
    # (made with the CLI in the last few seconds), so "unenroll" always
    # means off.
    ip = orchestrator.device_ip(c, device_id)
    if ip:
        try:
            dpi_enroll.unenroll(ip)
        except dpi_enroll.DpiEnrollError as e:
            raise HTTPException(502, str(e))
    audit.log(c, CONSOLE_USERNAME, "device.dpi_set", target=str(device_id), detail="enrolled=False")
    return {"id": device_id, "enrolled": False, "ip": ip, "expires_in_s": None}


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
    """Allow/block rules for this device: the orchestrator's policies
    (step 4.1), plus any older rule still sitting in AdGuard that names
    this device."""
    c = db()
    d = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if d is None:
        raise HTTPException(404, "device not found")
    now = time.time()
    rows = c.execute("SELECT * FROM policies WHERE status='active' AND kind IN ('allow_domain','block_domain')"
                     " AND device_id=? ORDER BY id DESC", (device_id,)).fetchall()
    return {"rules": [
        {"policy_id": r["id"], "domain": r["target"], "action": "allow" if r["kind"] == "allow_domain" else "block",
         "scope": "device", "expires_at": r["expires_at"], "reason": r["reason"],
         "remaining_s": int(r["expires_at"] - now) if r["expires_at"] else None}
        for r in rows
    ]}


@app.post("/api/devices/{device_id}/filtering/allow")
def api_device_allow_domain(device_id: int, body: DeviceRuleRequest):
    """One-click 'unbreak this site for this device' - a per-device allow
    rule, optionally temporary, always with a reason recorded (step 5.2),
    applied through the orchestrator since step 4.1. Before that, a
    temporary allow carried its expiry as a "# ..." comment on the rule
    line, which AdGuard does not ignore: the rule never matched (found
    and fixed in Stage 4 - see adguard.py)."""
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    if not body.hours or not 1 <= body.hours <= 720:
        raise HTTPException(400, "hours must be from 1 to 720")
    expires_at = (time.time() + body.hours * 3600) if body.temporary else None
    p = _create_policy(c, "allow_domain", device_id, body.domain, expires_at,
                       body.reason + (" [temporary, %dh]" % body.hours if body.temporary else ""))
    print("filtering: allowed %s for device %d - %s%s" % (
        p["target"], device_id, body.reason, " [temporary, %dh]" % body.hours if body.temporary else ""), flush=True)
    return {"ok": True, "policy_id": p["id"], "domain": p["target"], "expires_at": expires_at}


@app.post("/api/devices/{device_id}/filtering/block")
def api_device_block_domain(device_id: int, body: DeviceBlockRequest):
    """The reverse of allow above: block one domain for one device only,
    without touching the network-wide blocklists."""
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    p = _create_policy(c, "block_domain", device_id, body.domain, None, body.reason)
    print("filtering: blocked %s for device %d - %s" % (p["target"], device_id, body.reason), flush=True)
    return {"ok": True, "policy_id": p["id"], "domain": p["target"]}


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


# ------------------------------------------------------------ intelligence --
#
# Stage 6 (ENHANCEMENT-PLAN.md): behavioural baselines, device
# fingerprinting, hunt/explorer. Reads correlation.py's own signal
# (behavioral_baseline_signal) and app/rollup.py's device_hourly table -
# this app never recomputes the baseline itself, the same "one source of
# truth" discipline the filtering endpoints already follow for AdGuard.

@app.get("/api/devices/{device_id}/baseline")
def api_device_baseline(device_id: int):
    """Status for the console's "learning" badge (step 6.1). Uses a
    simpler days-since-first-seen approximation of the signal's own,
    more precise per-hour-of-day sample count (correlation.py's
    BASELINE_MIN_SAMPLES) - good enough for a badge that just needs to
    say "give it about a week", not to make the actual detection
    decision, which the signal computes fresh itself every cycle."""
    c = db()
    d = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if d is None:
        raise HTTPException(404, "device not found")
    now = time.time()
    days_seen = (now - d["first_seen"]) / 86400.0
    open_incident = c.execute(
        "SELECT id, last_seen FROM incidents"
        " WHERE device_id=? AND signal_type='volume_anomaly' AND status='new'"
        " ORDER BY last_seen DESC LIMIT 1", (device_id,)).fetchone()
    return {
        "learning": days_seen < BASELINE_LEARNING_DAYS,
        "days_seen": round(days_seen, 1),
        "days_needed": BASELINE_LEARNING_DAYS,
        "flagged": open_incident is not None,
        "incident_id": open_incident["id"] if open_incident else None,
    }


@app.get("/api/devices/{device_id}/fingerprint")
def api_device_fingerprint(device_id: int):
    """Device type/vendor/OS classification with its evidence (step 6.2),
    and - if the result matches a known vendor - the native-tracker
    profile (step 5.5) this device would suggest. This is a second,
    DISPLAY-ONLY identity anchor: it is not consulted anywhere in
    registry.py's own MAC/hostname identity resolution, deliberately -
    see ENHANCEMENT-PLAN.md's note on this step for why. Filtering
    profile auto-suggestion (the plan's other stated goal for this step,
    referencing Stage 4's 4.3) is not included: that profile system
    doesn't exist yet."""
    c = db()
    d = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if d is None:
        raise HTTPException(404, "device not found")
    result = fingerprint.classify(c, device_id, d["hostname"])
    profile_key, profile = native_trackers.suggest_profile(result["vendor"], result["os"])
    result["suggested_profile"] = (
        {"vendor": profile_key, "label": profile["label"]} if profile else None
    )
    return result


# ------------------------------------------------------- settings and audit --
#
# Step 6.3 ("Settings view + attributions"). Four detection thresholds are
# genuinely console-tunable via app/settings.py - see that module's own
# docstring for exactly which ones, and why not every constant this
# project has. Retention and notification channels are surfaced honestly
# as NOT YET IMPLEMENTED below, rather than a settings control that would
# not actually do anything - Stage 1's F3 (retention) and Stage 4's R3
# (notification channels) don't exist yet.

# Third-party components this project actually ships or depends on, with
# real installed versions and licences - checked directly on the gateway
# (`AdGuardHome --version`, `suricata` banner, `mitmdump --version`) and
# read from chart.min.js's own header comment, not guessed. tracker_
# entities.py and native_trackers.py are this project's own original,
# hand-curated files (documented as such in their own docstrings), not
# derived from any licensed dataset, so they carry no third-party licence
# to attribute here.
ATTRIBUTIONS = [
    {"name": "Suricata", "version": "7.0.3", "license": "GPLv2",
     "url": "https://suricata.io/", "role": "network IDS / flow, DNS and TLS metadata sensor"},
    {"name": "AdGuard Home", "version": "v0.107.79", "license": "GPLv3",
     "url": "https://github.com/AdguardTeam/AdGuardHome",
     "role": "DNS filtering, DHCP server, blocklist management"},
    {"name": "mitmproxy", "version": "12.2.3", "license": "MIT",
     "url": "https://mitmproxy.org/", "role": "selective HTTPS inspection (Tier 2 ad removal)"},
    {"name": "Chart.js", "version": "v4.4.4", "license": "MIT",
     "url": "https://www.chartjs.org/", "role": "console dashboard charts"},
    {"name": "nftables", "version": "(system package)", "license": "GPLv2",
     "url": "https://netfilter.org/projects/nftables/", "role": "firewall, NAT, quarantine and DPI redirect"},
]


@app.get("/api/settings")
def api_settings_get():
    return {"settings": settings.all_settings(db())}


@app.post("/api/settings/password")
def api_settings_password(body: PasswordChange, request: Request):
    """Change the console's login password. There is one shared account
    today (finding C7 - no per-user accounts yet), so this changes the
    one password everyone uses. Never logs the actual password value,
    before or after, into the audit trail or the journal - only that a
    change happened. Stored as a PBKDF2-HMAC-SHA256 hash (step 3.1 - see
    session_auth.py's module docstring for why not scrypt as originally
    planned), not plaintext.

    Every OTHER signed-in session is signed out afterwards; the one that
    made the change stays signed in. A password is usually changed
    because someone else might know it, and that person's open session
    should stop working at the same moment their password does.

    The new hash is computed first and then swapped in atomically
    (session_auth.write_password_file) - the file is never empty, not
    even for a moment, so no login can ever see a blank password.

    Declared here, before the /api/settings/{key} route below, on
    purpose: Starlette matches routes in declaration order, and a
    parameterized route with the same method and segment count would
    otherwise swallow every request to this literal path with key=
    "password", routing it through SettingUpdate's (value, reason)
    body instead of PasswordChange's - which is exactly what happened
    until this was caught during 6.3's live verification."""
    try:
        current = _console_password()
    except FileNotFoundError:
        raise HTTPException(500, "console password file is missing")
    if not session_auth.verify_password(body.current_password, current):
        raise HTTPException(400, "current password is incorrect")
    if len(body.new_password) < 12:
        raise HTTPException(400, "new password must be at least 12 characters")
    if body.new_password == body.current_password:
        raise HTTPException(400, "new password must be different from the current one")
    encoded = session_auth.hash_password(body.new_password)
    session_auth.write_password_file(CONSOLE_PASSWORD_FILE, encoded)
    c = db()
    session_auth.delete_other_sessions(c, request.cookies.get(session_auth.SESSION_COOKIE))
    audit.log(c, CONSOLE_USERNAME, "settings.password_change",
              detail="password changed (value not logged); other sessions signed out")
    print("settings: console password changed", flush=True)
    return {"ok": True}


@app.post("/api/settings/{key}")
def api_settings_set(key: str, body: SettingUpdate):
    spec = settings.SETTINGS_SCHEMA.get(key)
    if spec and spec.get("dedicated"):
        raise HTTPException(400, "%s has its own control in the console - change it there" % key)
    if not body.reason.strip():
        raise HTTPException(400, "a reason is required")
    c = db()
    try:
        before = settings.get(c, key)
        settings.set_value(c, key, body.value)
    except settings.SettingsError as e:
        raise HTTPException(400, str(e))
    audit.log(c, CONSOLE_USERNAME, "settings.update", target=key,
              detail="%s -> %s (%s)" % (before, body.value, body.reason))
    print("settings: %s changed from %s to %s - %s" % (key, before, body.value, body.reason), flush=True)
    return {"ok": True, "key": key, "value": body.value}


@app.post("/api/settings/{key}/reset")
def api_settings_reset(key: str):
    c = db()
    try:
        before = settings.get(c, key)
        settings.reset_to_default(c, key)
    except settings.SettingsError as e:
        raise HTTPException(400, str(e))
    after = settings.get(c, key)
    audit.log(c, CONSOLE_USERNAME, "settings.reset", target=key, detail="%s -> default (%s)" % (before, after))
    return {"ok": True, "key": key, "value": after}


@app.get("/api/settings/retention")
def api_settings_retention():
    """What app/retention.py (step 1.3) actually keeps, read from its own
    constants so this can't drift from the code. This used to be a
    "not yet implemented" placeholder written before step 1.3 existed."""
    import retention
    c = db()
    last = c.execute("SELECT last_run_ts FROM signal_state WHERE signal_type='retention'").fetchone()
    rows = [{"what": "%s events" % k.replace("_", " "), "days": v} for k, v in sorted(retention.EVENT_RETENTION_DAYS.items())]
    rows.append({"what": "all other events", "days": retention.DEFAULT_EVENT_RETENTION_DAYS})
    rows.append({"what": "hourly device rollups", "days": retention.DEVICE_HOURLY_RETENTION_DAYS})
    rows.append({"what": "incidents", "days": retention.INCIDENT_RETENTION_DAYS})
    rows.append({"what": "audit log", "days": None})
    return {"implemented": True, "rows": rows,
            "last_run": time.strftime("%Y-%m-%d %H:%M", time.localtime(last[0])) if last else None}


@app.get("/api/settings/channels")
def api_settings_channels():
    """Kept for older front-end code: notification channels are real since
    step 4.5 - see /api/notifications/channels."""
    c = db()
    return {"implemented": True, "channels": notify.list_channels(c)}


@app.get("/api/audit")
def api_audit(limit: int = Query(200)):
    rows = audit.recent(db(), limit=limit)
    return {"entries": [
        {"id": r["id"], "ts": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])),
         "actor": r["actor"], "action": r["action"], "target": r["target"], "detail": r["detail"]}
        for r in rows
    ]}


@app.get("/api/attributions")
def api_attributions():
    return {"attributions": ATTRIBUTIONS}


# --------------------------------------------------------------- quarantine --
#
# Enforcement lives entirely in the `inet filter quarantine` nftables set;
# this app never caches whether a device is quarantined, for the same reason
# filtering doesn't cache AdGuard's state (see above).

@app.get("/api/devices/{device_id}/quarantine")
def api_device_quarantine_status(device_id: int):
    """Quarantine state for one device: what the console wants (its active
    quarantine policies) AND what the firewall actually holds right now,
    read live - the same "never show a cached answer" rule this endpoint
    always followed, now checked against the MAC-keyed set (step 4.2)."""
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    now = time.time()
    policies = [_policy_view(c, r, now) for r in orchestrator.active_policies(c, "quarantine", device_id)]
    macs = orchestrator.device_macs(c, device_id)
    try:
        live = firewall_sets.quarantined_macs()
    except firewall_sets.FirewallSetError as e:
        raise HTTPException(502, str(e))
    enforced = [m for m in macs if m in live]
    return {
        "quarantined": bool(policies), "enforced": bool(enforced) and len(enforced) == len(macs),
        "macs": macs, "ip": orchestrator.device_ip(c, device_id), "policies": policies,
        "trust_based": any(p["source"] == "trust" for p in policies),
        "expires_in_s": min((p["remaining_s"] for p in policies if p["remaining_s"] is not None), default=None)
                        if all(p["remaining_s"] is not None for p in policies) and policies else None,
    }


@app.post("/api/devices/{device_id}/quarantine")
def api_device_quarantine_set(device_id: int, body: QuarantineUpdate):
    """Quarantine (optionally for a fixed time) or release a device, through
    the policy orchestrator (step 4.1/4.2). Releasing ends every quarantine
    policy a person or auto-response created; a trust-based restriction is
    ended by approving the device instead, so it's left in place and the
    response says so."""
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    now = time.time()
    if body.quarantined:
        expires = now + body.minutes * 60 if body.minutes else None
        p = _create_policy(c, "quarantine", device_id, None, expires, body.reason)
        print("quarantine: device %d quarantined%s - %s" % (
            device_id, " for %d min" % body.minutes if body.minutes else "", body.reason), flush=True)
        return {"id": device_id, "quarantined": True, "policy": p}
    ended = 0
    for r in orchestrator.active_policies(c, "quarantine", device_id):
        if r["source"] == "trust":
            continue
        _end_policy(c, r["id"], body.reason if body.reason != "quarantined from the console" else "released")
        ended += 1
    trust_left = any(r["source"] == "trust" for r in orchestrator.active_policies(c, "quarantine", device_id))
    return {"id": device_id, "quarantined": trust_left, "released": ended, "trust_based": trust_left}


# ------------------------------------------------ policies (Stage 4) --

KIND_LABELS = {
    "quarantine": "Quarantine", "block_ip": "Block IP", "block_domain": "Block domain",
    "allow_domain": "Allow domain", "profile": "Filtering profile", "pause": "Pause filtering",
    "enroll": "HTTPS inspection", "native_profile": "Vendor telemetry block",
}


def _source_label(source):
    if source == "console":
        return "Console"
    if source == "trust":
        return "Device trust"
    if source == "adopted":
        return "Found in place"
    if source == "migrated":
        return "Migrated rule"
    if source.startswith("incident:"):
        return "Incident #%s" % source.split(":", 1)[1]
    if source.startswith("auto:campaign:"):
        return "Auto-response (campaign #%s)" % source.rsplit(":", 1)[1]
    return source


def _policy_view(c, row, now):
    p = orchestrator.policy_dict(row, now)
    p["kind_label"] = KIND_LABELS.get(p["kind"], p["kind"])
    p["source_label"] = _source_label(p["source"])
    if p["device_id"] is not None:
        d = c.execute("SELECT * FROM devices WHERE id=?", (p["device_id"],)).fetchone()
        p["device_name"] = device_label(d) if d else "device %d" % p["device_id"]
    else:
        p["device_name"] = None
    if p["kind"] == "profile":
        prof = profiles.BUILTIN_PROFILES.get(p["target"])
        p["target_label"] = prof["label"] if prof else p["target"]
    elif p["kind"] == "native_profile":
        prof = native_trackers.profile(p["target"])
        p["target_label"] = prof["label"] if prof else p["target"]
    else:
        p["target_label"] = p["target"]
    p["verified_age_s"] = int(now - p["last_verified_at"]) if p["last_verified_at"] else None
    p["created"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(p["created_at"]))
    if p["ended_at"]:
        p["ended"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(p["ended_at"]))
    return p


def _create_policy(c, kind, device_id, target, expires_at, reason, source="console"):
    """orchestrator.create_policy with its errors mapped to HTTP ones. The
    orchestrator writes the audit row itself (policy.create, or
    policy.rolled_back if the change didn't take)."""
    try:
        return _policy_view(c, orchestrator._row(c, orchestrator.create_policy(
            c, kind, device_id, target, expires_at, reason, actor=CONSOLE_USERNAME, source=source)["id"]),
            time.time())
    except orchestrator.PolicyError as e:
        raise HTTPException(400, str(e))
    except orchestrator.PolicyApplyError as e:
        raise HTTPException(502, str(e))
    except orchestrator.OrchestratorBusy as e:
        raise HTTPException(503, str(e))


def _end_policy(c, policy_id, reason=""):
    try:
        return orchestrator.end_policy(c, policy_id, actor=CONSOLE_USERNAME, reason=reason)
    except orchestrator.PolicyError as e:
        raise HTTPException(400, str(e))
    except orchestrator.PolicyApplyError as e:
        raise HTTPException(502, str(e))
    except orchestrator.OrchestratorBusy as e:
        raise HTTPException(503, str(e))


@app.get("/api/policies")
def api_policies(status: str = Query("active"), device_id: int = Query(0), limit: int = Query(200)):
    """Active policies, or the most recent ended ones (status=ended)."""
    c = db()
    now = time.time()
    sql = "SELECT * FROM policies"
    where, args = [], []
    if status == "active":
        where.append("status='active'")
    elif status == "ended":
        where.append("status != 'active'")
    if device_id:
        where.append("device_id=?")
        args.append(device_id)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY %s DESC LIMIT ?" % ("id" if status == "active" else "COALESCE(ended_at, created_at)")
    args.append(min(limit, 500))
    return {"policies": [_policy_view(c, r, now) for r in c.execute(sql, args).fetchall()]}


@app.post("/api/policies")
def api_policy_create(body: PolicyCreate):
    """Create any kind of policy - the Response page and the incident
    page's response actions use this directly."""
    c = db()
    source = "console"
    if body.incident_id is not None:
        if c.execute("SELECT 1 FROM incidents WHERE id=?", (body.incident_id,)).fetchone() is None:
            raise HTTPException(404, "incident not found")
        source = "incident:%d" % body.incident_id
    expires = time.time() + body.minutes * 60 if body.minutes else None
    p = _create_policy(c, body.kind, body.device_id, body.target, expires, body.reason, source)
    if body.incident_id is not None:
        # Also on the incident's own timeline, next to its status changes.
        audit.log(c, CONSOLE_USERNAME, "incident.response", target=str(body.incident_id),
                  detail="%s %s (policy #%d)" % (p["kind_label"], p["target_label"] or p["device_name"] or "", p["id"]))
    return {"policy": p}


@app.post("/api/policies/{policy_id}/end")
def api_policy_end(policy_id: int, body: PolicyEnd):
    c = db()
    row = orchestrator._row(c, policy_id)
    if row is None:
        raise HTTPException(404, "policy not found")
    if row["source"] == "trust":
        raise HTTPException(400, "this restriction comes from the device's trust state - approve the device to lift it")
    _end_policy(c, policy_id, body.reason)
    return {"policy": _policy_view(c, orchestrator._row(c, policy_id), time.time())}


@app.post("/api/policies/{policy_id}/extend")
def api_policy_extend(policy_id: int, body: PolicyExtend):
    """Replace a timed policy with the same one lasting `minutes` from now."""
    c = db()
    row = orchestrator._row(c, policy_id)
    if row is None or row["status"] != "active":
        raise HTTPException(404, "no active policy with that id")
    if row["source"] == "trust":
        raise HTTPException(400, "a trust-based restriction has no end time to extend")
    p = _create_policy(c, row["kind"], row["device_id"], row["target"], time.time() + body.minutes * 60,
                       "%s (extended from policy #%d)" % (body.reason, policy_id), row["source"])
    return {"policy": p}


@app.get("/api/orchestrator/status")
def api_orchestrator_status():
    """Orchestrator health, counts, and its recent activity (drift fixes,
    rollbacks, expiries) for the Response page."""
    c = db()
    now = time.time()
    st = orchestrator.status(c, now)
    counts = {r["kind"]: r["n"] for r in c.execute(
        "SELECT kind, count(*) AS n FROM policies WHERE status='active' GROUP BY kind")}
    activity = [
        {"ts": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])), "age": _age(now - r["ts"]),
         "actor": r["actor"], "action": r["action"], "target": r["target"], "detail": r["detail"]}
        for r in c.execute("SELECT * FROM audit_log WHERE action LIKE 'policy.%' ORDER BY id DESC LIMIT 40")
    ]
    drift_24h = c.execute("SELECT count(*) FROM audit_log WHERE action='policy.drift_corrected' AND ts > ?",
                          (now - 86400,)).fetchone()[0]
    rollbacks_24h = c.execute("SELECT count(*) FROM audit_log WHERE action='policy.rolled_back' AND ts > ?",
                              (now - 86400,)).fetchone()[0]
    return {"status": st, "counts": counts, "total_active": sum(counts.values()),
            "drift_24h": drift_24h, "rollbacks_24h": rollbacks_24h, "activity": activity}


@app.post("/api/orchestrator/reconcile")
def api_orchestrator_reconcile():
    """"Verify now": run one orchestrator cycle straight away instead of
    waiting for the engine's next one."""
    c = db()
    try:
        summary = orchestrator.reconcile(c)
    except orchestrator.OrchestratorBusy as e:
        raise HTTPException(503, str(e))
    audit.log(c, CONSOLE_USERNAME, "orchestrator.verify", target="orchestrator",
              detail="drift fixed: %d, errors: %d" % (len(summary["drift"]), len(summary["errors"])))
    return {"summary": summary, "status": orchestrator.status(c)}


# -------------------------------------------------- device trust (4.4) --

TRUST_STATES = ("approved", "unknown", "blocked")


@app.post("/api/devices/{device_id}/trust")
def api_device_trust(device_id: int, body: TrustUpdate):
    c = db()
    d = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if d is None:
        raise HTTPException(404, "device not found")
    if body.trust not in TRUST_STATES:
        raise HTTPException(400, "trust must be one of: %s" % ", ".join(TRUST_STATES))
    if body.trust == "blocked" and not orchestrator.device_macs(c, device_id):
        raise HTTPException(400, "this device has no known MAC address, so it can't be blocked at the firewall")
    before = d["trust"]
    c.execute("UPDATE devices SET trust=? WHERE id=?", (body.trust, device_id))
    c.commit()
    audit.log(c, CONSOLE_USERNAME, "device.trust_set", target=str(device_id),
              detail="%s -> %s%s" % (before, body.trust, (" - " + body.reason) if body.reason else ""))
    try:
        orchestrator.reconcile(c)
    except orchestrator.OrchestratorBusy:
        pass  # the engine's next cycle applies it
    return {"id": device_id, "trust": body.trust, "quarantine": api_device_quarantine_status(device_id)}


@app.get("/api/trust")
def api_trust_summary():
    c = db()
    now = time.time()
    counts = {r["trust"]: r["n"] for r in c.execute("SELECT trust, count(*) AS n FROM devices GROUP BY trust")}
    unknown = [
        {"id": r["id"], "name": device_label(r), "hostname": r["hostname"],
         "first_seen_age": _age(now - r["first_seen"]), "last_seen_age": _age(now - r["last_seen"]),
         "restricted": c.execute("SELECT 1 FROM policies WHERE status='active' AND kind='quarantine'"
                                 " AND source='trust' AND device_id=?", (r["id"],)).fetchone() is not None}
        for r in c.execute("SELECT * FROM devices WHERE trust='unknown' ORDER BY last_seen DESC LIMIT 50")
    ]
    return {"restrict_unknown": settings.get(c, "restrict_unknown_devices"),
            "counts": {t: counts.get(t, 0) for t in TRUST_STATES}, "unknown": unknown}


@app.post("/api/trust/restrict")
def api_trust_restrict(body: RestrictUnknownUpdate):
    """Turn "restrict unknown devices" on or off (step 4.4). The generic
    settings endpoint refuses this key on purpose: switching it on goes
    through here so every device already on the network can be approved
    first, in the same step. A restricted device can always still reach
    the gateway itself (the quarantine rule only matches forwarded traffic),
    so approving it from the device that needs approving works too."""
    c = db()
    approved = 0
    if body.enabled and body.approve_existing:
        approved = c.execute("UPDATE devices SET trust='approved' WHERE trust='unknown'").rowcount
        c.commit()
    settings.set_value(c, "restrict_unknown_devices", body.enabled)
    audit.log(c, CONSOLE_USERNAME, "trust.restrict_unknown", target="restrict_unknown_devices",
              detail="enabled=%s, approved %d existing device(s) first" % (body.enabled, approved))
    try:
        orchestrator.reconcile(c)
    except orchestrator.OrchestratorBusy:
        pass
    return {"enabled": body.enabled, "approved": approved, "trust": api_trust_summary()}


# -------------------------------------------- profiles and pause (4.3) --

def _catalog_or_empty():
    try:
        return adguard.service_catalog()
    except adguard.AdGuardError:
        return {}


@app.get("/api/profiles")
def api_profiles():
    c = db()
    catalog = _catalog_or_empty()
    now_local = time.localtime()
    counts = {r["target"]: r["n"] for r in c.execute(
        "SELECT target, count(*) AS n FROM policies WHERE status='active' AND kind='profile' GROUP BY target")}
    out = []
    for p in profiles.all_profiles(c):
        sched = p.get("schedule")
        out.append({
            "key": p["key"], "label": p["label"], "description": p["description"],
            "filtering": p["filtering"], "safe_search": p["safe_search"],
            "blocked_services": p["blocked_services"], "schedule": sched,
            "schedule_label": profiles.describe_schedule(sched),
            "schedule_active": profiles.in_window(sched, now_local) if sched else False,
            "native_trackers": p["native_trackers"], "customized": p["customized"],
            "editable": p["key"] not in ("standard", "unrestricted"),
            "blocked_count": len(profiles.expand_services(p["blocked_services"], catalog)) if catalog else None,
            "devices": counts.get(p["key"], 0),
        })
    groups = {}
    for sid, gid in sorted(catalog.items()):
        groups.setdefault(gid or "other", []).append(sid)
    return {"profiles": out, "service_groups": [{"id": g, "services": v} for g, v in sorted(groups.items())]}


@app.post("/api/profiles/{key}")
def api_profile_edit(key: str, body: ProfileEdit):
    c = db()
    if key == "standard":
        raise HTTPException(400, "Standard means the network's own defaults, so it isn't editable - "
                                 "use another profile for devices that need more")
    edit = {}
    if body.safe_search is not None:
        edit["safe_search"] = body.safe_search
    if body.blocked_services is not None:
        edit["blocked_services"] = body.blocked_services
    if body.clear_schedule:
        edit["schedule"] = None
    elif body.schedule is not None:
        edit["schedule"] = body.schedule
    try:
        prof = profiles.save_edit(c, key, edit)
    except profiles.ProfileError as e:
        raise HTTPException(400, str(e))
    audit.log(c, CONSOLE_USERNAME, "profile.edit", target=key,
              detail=json.dumps(edit, sort_keys=True) + ((" - " + body.reason) if body.reason else ""))
    try:
        orchestrator.reconcile(c)  # devices on this profile pick the change up now
    except orchestrator.OrchestratorBusy:
        pass
    return {"profile": prof}


@app.post("/api/profiles/{key}/reset")
def api_profile_reset(key: str):
    c = db()
    try:
        profiles.reset_profile(c, key)
    except profiles.ProfileError as e:
        raise HTTPException(400, str(e))
    audit.log(c, CONSOLE_USERNAME, "profile.reset", target=key, detail="back to built-in defaults")
    try:
        orchestrator.reconcile(c)
    except orchestrator.OrchestratorBusy:
        pass
    return {"profile": profiles.get_profile(c, key)}


def _device_filtering_view(c, device_id, now):
    prof_p = orchestrator.active_policies(c, "profile", device_id)
    pause_p = orchestrator.active_policies(c, "pause", device_id)
    key = prof_p[0]["target"] if prof_p else profiles.DEFAULT_PROFILE
    prof = profiles.get_profile(c, key)
    return {
        "profile": key, "profile_label": prof["label"], "profile_policy_id": prof_p[0]["id"] if prof_p else None,
        "schedule_label": profiles.describe_schedule(prof.get("schedule")),
        "schedule_active": profiles.in_window(prof.get("schedule"), time.localtime(now)),
        "paused": bool(pause_p),
        "pause_policy_id": pause_p[0]["id"] if pause_p else None,
        "pause_remaining_s": int(pause_p[0]["expires_at"] - now) if pause_p else None,
    }


@app.post("/api/devices/{device_id}/profile")
def api_device_profile_set(device_id: int, body: ProfileAssign):
    """Give a device a filtering profile. Standard is "no profile policy":
    choosing it ends the device's current profile, which puts its AdGuard
    settings back to the network defaults."""
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    if body.profile not in profiles.BUILTIN_PROFILES:
        raise HTTPException(400, "unknown profile: %s" % body.profile)
    if body.profile == profiles.DEFAULT_PROFILE:
        for r in orchestrator.active_policies(c, "profile", device_id):
            _end_policy(c, r["id"], "set back to Standard")
    else:
        _create_policy(c, "profile", device_id, body.profile, None, body.reason)
    return _device_filtering_view(c, device_id, time.time())


@app.post("/api/devices/{device_id}/pause")
def api_device_pause(device_id: int, body: PauseRequest):
    c = db()
    if c.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is None:
        raise HTTPException(404, "device not found")
    _create_policy(c, "pause", device_id, None, time.time() + body.minutes * 60, body.reason)
    return _device_filtering_view(c, device_id, time.time())


@app.post("/api/devices/{device_id}/resume")
def api_device_resume(device_id: int):
    c = db()
    for r in orchestrator.active_policies(c, "pause", device_id):
        _end_policy(c, r["id"], "resumed early")
    return _device_filtering_view(c, device_id, time.time())


@app.get("/api/filtering/pause")
def api_network_pause_status():
    c = db()
    now = time.time()
    rows = [r for r in orchestrator.active_policies(c, "pause") if r["device_id"] is None]
    try:
        enabled, remaining_ms = adguard.protection_status()
    except adguard.AdGuardError:
        enabled, remaining_ms = None, None
    return {"paused": bool(rows), "policy_id": rows[0]["id"] if rows else None,
            "remaining_s": int(rows[0]["expires_at"] - now) if rows else None,
            "adguard_protection_enabled": enabled}


@app.post("/api/filtering/pause")
def api_network_pause(body: PauseRequest):
    """Pause DNS filtering for every device (step 4.3). AdGuard's own timer
    also ends the pause, so it resumes on time even if the orchestrator
    isn't running."""
    c = db()
    _create_policy(c, "pause", None, None, time.time() + body.minutes * 60, body.reason)
    return api_network_pause_status()


@app.post("/api/filtering/resume")
def api_network_resume():
    c = db()
    for r in orchestrator.active_policies(c, "pause"):
        if r["device_id"] is None:
            _end_policy(c, r["id"], "resumed early")
    return api_network_pause_status()


# ------------------------------------------------ incident response (4.2) --

def _incident_response_options(c, incident_id):
    """What an operator could block, from an incident's own evidence: the
    destination domains and IPs its linked events point at, most frequent
    first, with any policy already covering each one."""
    inc = c.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if inc is None:
        return None
    domains = c.execute(
        "SELECT lower(COALESCE(e.dns_rrname, e.tls_sni)) AS d, count(*) AS n FROM incident_events ie"
        " JOIN events e ON e.id = ie.event_id WHERE ie.incident_id=? AND COALESCE(e.dns_rrname, e.tls_sni)"
        " IS NOT NULL GROUP BY d ORDER BY n DESC LIMIT 5", (incident_id,)).fetchall()
    ips = c.execute(
        "SELECT e.dest_ip AS ip, count(*) AS n FROM incident_events ie JOIN events e ON e.id = ie.event_id"
        " WHERE ie.incident_id=? AND e.dest_ip IS NOT NULL GROUP BY e.dest_ip ORDER BY n DESC LIMIT 8",
        (incident_id,)).fetchall()
    out_domains, out_ips = [], []
    for r in domains:
        try:
            d = orchestrator.normalize_domain(r["d"])
        except orchestrator.PolicyError:
            continue
        covered = c.execute("SELECT id, device_id FROM policies WHERE status='active' AND kind='block_domain'"
                            " AND target=? AND (device_id IS NULL OR device_id IS ?)",
                            (d, inc["device_id"])).fetchone()
        out_domains.append({"value": d, "events": r["n"], "blocked_by": covered["id"] if covered else None,
                            "scope": ("network" if covered and covered["device_id"] is None else "device")
                            if covered else None})
    for r in ips:
        try:
            ip = orchestrator.normalize_block_ip(r["ip"])
        except orchestrator.PolicyError:
            continue  # a LAN address, e.g. the victim of a scan - not something to block
        covered = c.execute("SELECT id FROM policies WHERE status='active' AND kind='block_ip' AND target=?",
                            (ip,)).fetchone()
        out_ips.append({"value": ip, "events": r["n"], "blocked_by": covered["id"] if covered else None})
    return {"device_id": inc["device_id"], "domains": out_domains, "ips": out_ips}


@app.get("/api/incidents/{incident_id}/response")
def api_incident_response(incident_id: int):
    c = db()
    opts = _incident_response_options(c, incident_id)
    if opts is None:
        raise HTTPException(404, "incident not found")
    now = time.time()
    opts["policies"] = [_policy_view(c, r, now) for r in c.execute(
        "SELECT * FROM policies WHERE source=? ORDER BY id DESC", ("incident:%d" % incident_id,))]
    if opts["device_id"] is not None:
        d = c.execute("SELECT * FROM devices WHERE id=?", (opts["device_id"],)).fetchone()
        opts["device_name"] = device_label(d) if d else None
        opts["device_trust"] = d["trust"] if d else None
        opts["device_quarantined"] = bool(orchestrator.active_policies(c, "quarantine", opts["device_id"]))
        opts["device_has_mac"] = bool(orchestrator.device_macs(c, opts["device_id"]))
    return opts


# ----------------------------------------------------- notifications (4.5) --

@app.get("/api/notifications/channels")
def api_notification_channels():
    c = db()
    return {"channels": notify.list_channels(c), "kinds": list(notify.KINDS)}


@app.post("/api/notifications/channels")
def api_notification_channel_add(body: ChannelCreate):
    c = db()
    try:
        cid = notify.add_channel(c, body.kind, body.name, body.config, body.min_severity)
    except notify.NotifyError as e:
        raise HTTPException(400, str(e))
    # The channel's settings are deliberately NOT in the audit detail -
    # they include its secrets.
    audit.log(c, CONSOLE_USERNAME, "notify.channel_add", target="channel:%d" % cid,
              detail="%s '%s', min severity %s" % (body.kind, body.name, body.min_severity))
    return {"id": cid, "channels": notify.list_channels(c)}


@app.post("/api/notifications/channels/{channel_id}")
def api_notification_channel_update(channel_id: int, body: ChannelUpdate):
    c = db()
    try:
        notify.update_channel(c, channel_id, enabled=body.enabled, min_severity=body.min_severity)
    except notify.NotifyError as e:
        raise HTTPException(400, str(e))
    audit.log(c, CONSOLE_USERNAME, "notify.channel_update", target="channel:%d" % channel_id,
              detail="enabled=%s min_severity=%s" % (body.enabled, body.min_severity))
    return {"channels": notify.list_channels(c)}


@app.post("/api/notifications/channels/{channel_id}/remove")
def api_notification_channel_remove(channel_id: int):
    c = db()
    try:
        notify.remove_channel(c, channel_id)
    except notify.NotifyError as e:
        raise HTTPException(404, str(e))
    audit.log(c, CONSOLE_USERNAME, "notify.channel_remove", target="channel:%d" % channel_id)
    return {"channels": notify.list_channels(c)}


@app.post("/api/notifications/channels/{channel_id}/test")
def api_notification_channel_test(channel_id: int):
    c = db()
    try:
        notify.send_test(c, channel_id)
    except notify.NotifyError as e:
        audit.log(c, CONSOLE_USERNAME, "notify.test", target="channel:%d" % channel_id, detail="failed: %s" % e)
        raise HTTPException(502, str(e))
    audit.log(c, CONSOLE_USERNAME, "notify.test", target="channel:%d" % channel_id, detail="sent")
    return {"ok": True, "channels": notify.list_channels(c)}


@app.get("/api/notifications/recent")
def api_notifications_recent(limit: int = Query(40)):
    c = db()
    now = time.time()
    return {"notifications": [
        {"id": r["id"], "channel": r["channel_name"], "kind": r["channel_kind"], "incident_id": r["incident_id"],
         "status": r["status"], "attempts": r["attempts"], "title": r["title"], "detail": r["detail"],
         "age": _age(now - r["ts"]), "ts": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))}
        for r in notify.recent(c, limit)
    ], "quiet_now": notify.in_quiet_hours(c, now)}


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


@app.get("/response", response_class=HTMLResponse)
def page_response(request: Request):
    return templates.TemplateResponse("response.html", {
        "request": request, "active": "response", "title": "Response"})


@app.get("/settings", response_class=HTMLResponse)
def page_settings(request: Request):
    return templates.TemplateResponse("settings.html", {
        "request": request, "active": "settings", "title": "Settings"})


def _week_bounds(week_str):
    """The Monday-to-Sunday week containing `week_str` (an ISO date), or
    the most recently FULLY COMPLETED week if `week_str` is empty or
    unparseable - deliberately never the current, still-in-progress week,
    since a report for a week that hasn't finished yet would silently
    under-count everything in it."""
    today = datetime.date.today()
    monday = today - datetime.timedelta(days=today.weekday() + 7)
    if week_str:
        try:
            d = datetime.date.fromisoformat(week_str)
            monday = d - datetime.timedelta(days=d.weekday())
        except ValueError:
            pass
    start = datetime.datetime.combine(monday, datetime.time.min).timestamp()
    end = start + 7 * 86400
    return start, end, monday


@app.get("/api/reports/weekly")
def api_weekly_report(week: str = Query("")):
    """The weekly security summary (ENHANCEMENT-PLAN.md step 6.6):
    incidents by ATT&CK tactic, riskiest devices, an ad-blocking summary,
    and platform health, all scoped to one Monday-Sunday week. Reuses
    step 5.3/5.6's own analytics helpers (_tracker_breakdown,
    _savings_estimate, _tier2_breakdown) rather than duplicating them -
    they already accept an arbitrary [start, end) window, not just
    "since now"."""
    c = db()
    start, end, monday = _week_bounds(week)

    incidents = c.execute(
        "SELECT * FROM incidents WHERE created_at >= ? AND created_at < ?", (start, end)).fetchall()
    by_tactic = collections.Counter()
    for i in incidents:
        attack = playbooks.get_attack(i["signal_type"])
        by_tactic[attack["tactic"] if attack else "Not ATT&CK-mapped"] += 1
    incidents_by_tactic = [{"tactic": t, "count": n} for t, n in by_tactic.most_common()]

    # Riskiest devices FOR THIS WEEK - deliberately NOT risk.device_risk(),
    # which was tried first and rejected: that function's decay has a
    # 24-hour half-life, built for "how worried should I be right now" on
    # the live dashboard. Evaluated a full 7 days later (this function's
    # own end-of-week timestamp), an incident from early in the week has
    # already decayed through ~7 half-lives and rounds to zero - a report
    # that showed "no risk" for a week that had a real port scan on Monday
    # would be actively misleading. Retrospective scoring instead sums
    # each week's own severity weights with no decay - "what happened this
    # week", not "how urgent does it still look today". Resolved incidents
    # still count (they were real); false positives don't (adjudicated as
    # noise).
    weight_by_device = collections.Counter()
    for i in incidents:
        if i["status"] == "false_positive" or i["device_id"] is None:
            continue
        weight_by_device[i["device_id"]] += risk.SEVERITY_WEIGHT.get(i["severity"], 0)

    riskiest = []
    for device_id, weight in weight_by_device.items():
        d = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if d is None or weight <= 0:
            continue
        score = min(100, round(weight))
        riskiest.append({"id": device_id, "name": device_label(d),
                          "score": score, "band": risk.risk_band(score)})
    riskiest.sort(key=lambda x: -x["score"])

    dns_total = c.execute(
        "SELECT count(*) FROM events WHERE event_type='dns_query' AND ts >= ? AND ts < ?",
        (start, end)).fetchone()[0]
    dns_blocked = c.execute(
        "SELECT count(*) FROM events WHERE event_type='dns_query' AND blocked=1 AND ts >= ? AND ts < ?",
        (start, end)).fetchone()[0]

    # Platform health: only what's genuinely measurable after the fact.
    # Stage 3's V5 ("Platform and WAN health" - Suricata stats, disk
    # headroom, a WAN latency probe) hasn't been built, so this
    # deliberately does not claim any packet-drop or WAN-latency figure.
    events_ingested = c.execute(
        "SELECT count(*) FROM events WHERE ts >= ? AND ts < ?", (start, end)).fetchone()[0]
    platform_signal_types = ("adblock_ineffective", "privacy_scope_failure")
    platform_incidents = sum(1 for i in incidents if i["signal_type"] in platform_signal_types)

    return {
        "week_start": monday.isoformat(),
        "week_end": (monday + datetime.timedelta(days=6)).isoformat(),
        "incident_count": len(incidents),
        "incidents_by_tactic": incidents_by_tactic,
        "riskiest_devices": riskiest[:10],
        "adblock": {
            "dns_total": dns_total, "dns_blocked": dns_blocked,
            "block_pct": round(100.0 * dns_blocked / dns_total, 1) if dns_total else 0.0,
            "trackers": _tracker_breakdown(c, start, end),
            "savings": _savings_estimate(dns_blocked),
            "tier2": _tier2_breakdown(c, start, end),
        },
        "platform": {"events_ingested": events_ingested, "platform_incidents": platform_incidents},
    }


@app.get("/reports/weekly", response_class=HTMLResponse)
def page_weekly_report(request: Request):
    return templates.TemplateResponse("reports_weekly.html", {
        "request": request, "active": "reports", "title": "Weekly Report"})


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
            "trust": d["trust"],
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
            dev = {"id": d["id"], "name": device_label(d), "has_ip": ip_row is not None,
                   "trust": d["trust"], "has_mac": bool(orchestrator.device_macs(c, d["id"]))}

    evidence = [_event_row(r) for r in c.execute(
        "SELECT e.*, NULL hostname, NULL friendly_name FROM incident_events ie"
        " JOIN events e ON e.id = ie.event_id WHERE ie.incident_id=?"
        " ORDER BY e.ts", (incident_id,))]

    top_domain = _top_evidence_domain(i["signal_type"], evidence)
    notes = _incident_notes(c, incident_id)
    timeline = _incident_timeline(c, incident_id, i["created_at"])
    related = _related_open_incidents(c, i["device_id"], incident_id, now) if i["device_id"] else []

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
        "device": dev, "evidence": evidence, "notes": notes, "timeline": timeline,
        "related": related,
        "attack": playbooks.get_attack(i["signal_type"]),
        "playbook": playbooks.get_playbook(i["signal_type"]),
        "top_domain": top_domain,
    })

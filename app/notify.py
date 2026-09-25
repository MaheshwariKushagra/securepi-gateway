#!/usr/bin/env python3
"""
SecurePi Gateway - incident notifications (ENHANCEMENT-PLAN.md step 4.5).

Sends new incidents to the operator's own channels: ntfy, Telegram, email
(SMTP) or a generic webhook. dispatch() runs once per engine cycle.

The rules, in the order they're applied
----------------------------------------
1. One notification per incident per channel. The notifications table's
   UNIQUE (channel_id, incident_id) makes this a database guarantee, not
   just a code path: an incident that a signal keeps extending every
   cycle is still only sent once.
2. Severity threshold per channel: a channel set to 'high' never gets a
   medium incident.
3. Quiet hours (optional): during them only high-severity incidents go
   out straight away; everything else is held.
4. Rate limit per channel per hour: anything over it is held too.
5. Held notifications are never dropped. They're collected into one
   digest message, sent at most every notify_digest_minutes once sending
   is allowed again.

A failed send is retried on later cycles, up to MAX_ATTEMPTS times.

What leaves the gateway
------------------------
Each channel sends to a service the operator chose. By default a message
carries the incident's title, severity, device and a link back to this
console. With a channel's "include details" option on, the description
goes too, and it can contain domains and IP addresses. Channel secrets (a
bot token, an SMTP password, a webhook signing key) are stored in the
database and are never returned by the console's API - see masked_config().
"""

import hashlib
import hmac
import json
import re
import smtplib
import ssl
import time
import urllib.error
import urllib.request
from email.message import EmailMessage

import settings

KINDS = ("ntfy", "telegram", "email", "webhook")
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}
MAX_ATTEMPTS = 3
SEND_TIMEOUT_S = 8
CONSOLE_URL = "https://10.10.0.1:8000"

# Which config fields each kind needs, and which of them are secrets.
FIELDS = {
    "ntfy": {"required": ("server", "topic"), "optional": ("token",), "secret": ("token",)},
    "telegram": {"required": ("bot_token", "chat_id"), "optional": (), "secret": ("bot_token",)},
    "email": {"required": ("host", "port", "security", "sender", "recipient"),
              "optional": ("username", "password"), "secret": ("password",)},
    "webhook": {"required": ("url",), "optional": ("secret",), "secret": ("secret",)},
}

_URL_RE = re.compile(r"^https?://[^\s/$.?#][^\s]*$", re.IGNORECASE)
_TOPIC_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_BOT_TOKEN_RE = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{20,}$")
_CHAT_ID_RE = re.compile(r"^(-?\d{1,20}|@[A-Za-z0-9_]{5,64})$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class NotifyError(Exception):
    """A channel's settings are invalid, or a send failed."""


# ------------------------------------------------------------- channels --

def validate_channel(kind, config):
    """Check a channel's settings. Returns a cleaned copy or raises
    NotifyError with a reason the console can show as-is."""
    if kind not in KINDS:
        raise NotifyError("unknown channel type: %s" % kind)
    spec = FIELDS[kind]
    clean = {}
    for f in spec["required"]:
        v = config.get(f)
        if v is None or (isinstance(v, str) and not v.strip()):
            raise NotifyError("%s is required" % f.replace("_", " "))
        clean[f] = v.strip() if isinstance(v, str) else v
    for f in spec["optional"]:
        v = config.get(f)
        if isinstance(v, str) and v.strip():
            clean[f] = v.strip()
    clean["include_details"] = bool(config.get("include_details"))

    if kind == "ntfy":
        if not _URL_RE.match(clean["server"]):
            raise NotifyError("server must be an http(s):// address, e.g. https://ntfy.sh")
        clean["server"] = clean["server"].rstrip("/")
        if not _TOPIC_RE.match(clean["topic"]):
            raise NotifyError("topic may only use letters, numbers, - and _ (at most 64)")
    elif kind == "telegram":
        if not _BOT_TOKEN_RE.match(clean["bot_token"]):
            raise NotifyError("that doesn't look like a Telegram bot token (123456:ABC...)")
        if not _CHAT_ID_RE.match(str(clean["chat_id"])):
            raise NotifyError("chat id must be a number or an @channel name")
        clean["chat_id"] = str(clean["chat_id"])
    elif kind == "email":
        try:
            clean["port"] = int(clean["port"])
        except (TypeError, ValueError):
            raise NotifyError("port must be a number")
        if not 1 <= clean["port"] <= 65535:
            raise NotifyError("port must be between 1 and 65535")
        if clean["security"] not in ("starttls", "ssl", "none"):
            raise NotifyError("security must be starttls, ssl or none")
        for f in ("sender", "recipient"):
            if not _EMAIL_RE.match(clean[f]):
                raise NotifyError("%s must be an email address" % f)
        if clean.get("password") and not clean.get("username"):
            raise NotifyError("a password needs a username")
    elif kind == "webhook":
        if not _URL_RE.match(clean["url"]):
            raise NotifyError("url must be an http(s):// address")
    return clean


def masked_config(kind, config):
    """The channel's settings with every secret replaced by a short hint -
    the only form that ever leaves the gateway through the API."""
    out = dict(config)
    for f in FIELDS.get(kind, {}).get("secret", ()):
        if out.get(f):
            v = str(out[f])
            out[f] = "••••" + (v[-4:] if len(v) > 8 else "")
    return out


def channel_dict(row):
    config = json.loads(row["config"])
    return {
        "id": row["id"], "kind": row["kind"], "name": row["name"],
        "config": masked_config(row["kind"], config),
        "min_severity": row["min_severity"], "enabled": bool(row["enabled"]),
        "last_sent_at": row["last_sent_at"], "last_error": row["last_error"],
        "last_error_at": row["last_error_at"],
    }


def list_channels(conn):
    return [channel_dict(r) for r in conn.execute("SELECT * FROM notification_channels ORDER BY id")]


def add_channel(conn, kind, name, config, min_severity="medium", now=None):
    now = now if now is not None else time.time()
    name = (name or "").strip()
    if not name or len(name) > 60:
        raise NotifyError("a name of up to 60 characters is required")
    if min_severity not in SEVERITY_RANK:
        raise NotifyError("minimum severity must be low, medium or high")
    clean = validate_channel(kind, config)
    cur = conn.execute(
        "INSERT INTO notification_channels (kind, name, config, min_severity, enabled, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, 1, ?, ?)", (kind, name, json.dumps(clean), min_severity, now, now))
    conn.commit()
    return cur.lastrowid


def update_channel(conn, channel_id, enabled=None, min_severity=None, now=None):
    now = now if now is not None else time.time()
    row = conn.execute("SELECT * FROM notification_channels WHERE id=?", (channel_id,)).fetchone()
    if row is None:
        raise NotifyError("channel not found")
    if min_severity is not None and min_severity not in SEVERITY_RANK:
        raise NotifyError("minimum severity must be low, medium or high")
    conn.execute("UPDATE notification_channels SET enabled=COALESCE(?, enabled),"
                 " min_severity=COALESCE(?, min_severity), updated_at=? WHERE id=?",
                 (None if enabled is None else int(bool(enabled)), min_severity, now, channel_id))
    conn.commit()


def remove_channel(conn, channel_id):
    conn.execute("DELETE FROM notifications WHERE channel_id=?", (channel_id,))
    cur = conn.execute("DELETE FROM notification_channels WHERE id=?", (channel_id,))
    conn.commit()
    if cur.rowcount == 0:
        raise NotifyError("channel not found")


# -------------------------------------------------------------- messages --

def incident_message(inc, device_name, include_details):
    """(title, body) for one incident."""
    title = "[%s] %s" % (inc["severity"].upper(), inc["title"])
    lines = []
    if device_name:
        lines.append("Device: %s" % device_name)
    if include_details and inc["description"]:
        lines.append(inc["description"])
    lines.append("%s/incidents/%d" % (CONSOLE_URL, inc["id"]))
    return title, "\n".join(lines)


def digest_message(rows):
    """(title, body) for a digest of held incidents."""
    by_sev = {}
    for r in rows:
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
    counts = ", ".join("%d %s" % (by_sev[s], s) for s in ("high", "medium", "low") if s in by_sev)
    title = "SecurePi digest: %d incident%s (%s)" % (len(rows), "" if len(rows) == 1 else "s", counts)
    lines = ["- [%s] %s" % (r["severity"], r["title"]) for r in rows[:25]]
    if len(rows) > 25:
        lines.append("- ... and %d more" % (len(rows) - 25))
    lines.append("%s/incidents" % CONSOLE_URL)
    return title, "\n".join(lines)


# --------------------------------------------------------------- senders --

def _post(url, body_bytes, headers):
    req = urllib.request.Request(url, data=body_bytes, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=SEND_TIMEOUT_S, context=ssl.create_default_context()) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:200].strip()
        raise NotifyError("HTTP %d from %s%s" % (e.code, url.split("?")[0], (": " + detail) if detail else ""))
    except (urllib.error.URLError, OSError) as e:
        raise NotifyError("could not reach %s: %s" % (url.split("/")[2] if "//" in url else url, e))


def build_request(kind, config, title, body, severity, event):
    """(url, body bytes, headers) for the HTTP-based kinds. Pure, so the
    exact request each channel sends can be tested without a network."""
    if kind == "ntfy":
        payload = {"topic": config["topic"], "title": title, "message": body,
                   "priority": {"high": 5, "medium": 4, "low": 3}.get(severity, 3),
                   "tags": ["shield"] if severity != "high" else ["rotating_light"]}
        headers = {"Content-Type": "application/json"}
        if config.get("token"):
            headers["Authorization"] = "Bearer %s" % config["token"]
        return config["server"], json.dumps(payload).encode(), headers
    if kind == "telegram":
        payload = {"chat_id": config["chat_id"], "text": "%s\n\n%s" % (title, body),
                   "disable_web_page_preview": True}
        return ("https://api.telegram.org/bot%s/sendMessage" % config["bot_token"],
                json.dumps(payload).encode(), {"Content-Type": "application/json"})
    if kind == "webhook":
        payload = {"source": "securepi-gateway", "title": title, "message": body,
                   "severity": severity, "event": event, "sent_at": int(time.time())}
        raw = json.dumps(payload, sort_keys=True).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "SecurePi-Gateway/1"}
        if config.get("secret"):
            sig = hmac.new(config["secret"].encode(), raw, hashlib.sha256).hexdigest()
            headers["X-SecurePi-Signature"] = "sha256=%s" % sig
        return config["url"], raw, headers
    raise NotifyError("not an HTTP channel: %s" % kind)


def build_email(config, title, body):
    msg = EmailMessage()
    msg["Subject"] = title
    msg["From"] = config["sender"]
    msg["To"] = config["recipient"]
    msg.set_content(body + "\n\n-- SecurePi Gateway")
    return msg


def send(kind, config, title, body, severity="medium", event=None):
    """Send one message on one channel, or raise NotifyError."""
    if kind == "email":
        msg = build_email(config, title, body)
        try:
            if config["security"] == "ssl":
                server = smtplib.SMTP_SSL(config["host"], config["port"], timeout=SEND_TIMEOUT_S,
                                          context=ssl.create_default_context())
            else:
                server = smtplib.SMTP(config["host"], config["port"], timeout=SEND_TIMEOUT_S)
            with server:
                if config["security"] == "starttls":
                    server.starttls(context=ssl.create_default_context())
                if config.get("username"):
                    server.login(config["username"], config.get("password", ""))
                server.send_message(msg)
        except (smtplib.SMTPException, OSError) as e:
            raise NotifyError("email to %s failed: %s" % (config["host"], e))
        return
    url, raw, headers = build_request(kind, config, title, body, severity, event)
    _post(url, raw, headers)


# -------------------------------------------------------------- dispatch --

def in_quiet_hours(conn, now):
    if not settings.get(conn, "notify_quiet_hours_enabled"):
        return False
    start = settings.get(conn, "notify_quiet_start_hour")
    end = settings.get(conn, "notify_quiet_end_hour")
    hour = time.localtime(now).tm_hour
    if start == end:
        return False
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end


def _sent_last_hour(conn, channel_id, now):
    return conn.execute("SELECT count(*) FROM notifications WHERE channel_id=? AND status='sent'"
                        " AND ts > ?", (channel_id, now - 3600)).fetchone()[0]


def _device_name(conn, device_id):
    if device_id is None:
        return None
    d = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if d is None:
        return None
    return d["friendly_name"] or d["hostname"] or ("device %d" % d["id"])


def _record_result(conn, channel_id, ok, error, now):
    if ok:
        conn.execute("UPDATE notification_channels SET last_sent_at=? WHERE id=?", (now, channel_id))
    else:
        conn.execute("UPDATE notification_channels SET last_error=?, last_error_at=? WHERE id=?",
                     (error, now, channel_id))


def dispatch(conn, now=None, sender=None):
    """One notification cycle. `sender` defaults to send() above; tests
    pass a fake. Returns {"sent": n, "held": n, "failed": n, "digests": n}."""
    now = now if now is not None else time.time()
    sender = sender or send
    out = {"sent": 0, "held": 0, "failed": 0, "digests": 0}

    state = conn.execute("SELECT * FROM notify_state WHERE id=1").fetchone()
    max_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM incidents").fetchone()[0]
    channels = conn.execute("SELECT * FROM notification_channels WHERE enabled=1 ORDER BY id").fetchall()
    last_id = state["last_incident_id"] if state else None
    if last_id is None or not channels:
        # First run, or nothing to send to: start from "now" rather than
        # sending every historical incident the moment a channel is added.
        conn.execute("UPDATE notify_state SET last_incident_id=? WHERE id=1", (max_id,))
        conn.commit()
        return out

    new_incidents = conn.execute("SELECT * FROM incidents WHERE id > ? ORDER BY id", (last_id,)).fetchall()
    quiet = in_quiet_hours(conn, now)
    limit = settings.get(conn, "notify_rate_limit_per_hour")

    for inc in new_incidents:
        for ch in channels:
            if SEVERITY_RANK.get(inc["severity"], 0) < SEVERITY_RANK.get(ch["min_severity"], 2):
                continue
            config = json.loads(ch["config"])
            title, body = incident_message(inc, _device_name(conn, inc["device_id"]),
                                           config.get("include_details"))
            if (quiet and inc["severity"] != "high") or _sent_last_hour(conn, ch["id"], now) >= limit:
                conn.execute("INSERT OR IGNORE INTO notifications (channel_id, incident_id, ts, status,"
                             " title) VALUES (?, ?, ?, 'held', ?)", (ch["id"], inc["id"], now, title))
                out["held"] += 1
                continue
            cur = conn.execute("INSERT OR IGNORE INTO notifications (channel_id, incident_id, ts, status,"
                               " title) VALUES (?, ?, ?, 'failed', ?)", (ch["id"], inc["id"], now, title))
            if cur.rowcount == 0:
                continue  # already handled - the one-per-incident guarantee
            nid = cur.lastrowid
            _try_send(conn, sender, ch, config, nid, title, body, inc["severity"],
                      {"type": "incident", "incident_id": inc["id"]}, now, out)
    conn.execute("UPDATE notify_state SET last_incident_id=? WHERE id=1", (max_id,))
    conn.commit()

    _retry_failed(conn, sender, channels, now, out)
    if not quiet:
        _send_digests(conn, sender, channels, now, out)
    conn.commit()
    return out


def _try_send(conn, sender, ch, config, nid, title, body, severity, event, now, out):
    try:
        sender(ch["kind"], config, title, body, severity, event)
        conn.execute("UPDATE notifications SET status='sent', attempts=attempts+1, ts=?, detail=NULL"
                     " WHERE id=?", (now, nid))
        _record_result(conn, ch["id"], True, None, now)
        out["sent"] += 1
    except NotifyError as e:
        conn.execute("UPDATE notifications SET status='failed', attempts=attempts+1, detail=? WHERE id=?",
                     (str(e), nid))
        _record_result(conn, ch["id"], False, str(e), now)
        out["failed"] += 1


def _retry_failed(conn, sender, channels, now, out):
    by_id = {c["id"]: c for c in channels}
    rows = conn.execute("SELECT n.*, i.severity, i.title AS inc_title, i.description, i.device_id,"
                        " i.id AS inc_id FROM notifications n JOIN incidents i ON i.id = n.incident_id"
                        " WHERE n.status='failed' AND n.attempts < ? AND n.ts < ?",
                        (MAX_ATTEMPTS, now - 30)).fetchall()
    for r in rows:
        ch = by_id.get(r["channel_id"])
        if ch is None:
            continue
        config = json.loads(ch["config"])
        inc = {"id": r["inc_id"], "severity": r["severity"], "title": r["inc_title"],
               "description": r["description"]}
        title, body = incident_message(inc, _device_name(conn, r["device_id"]), config.get("include_details"))
        _try_send(conn, sender, ch, config, r["id"], title, body, r["severity"],
                  {"type": "incident", "incident_id": r["inc_id"]}, now, out)


def _send_digests(conn, sender, channels, now, out):
    interval = settings.get(conn, "notify_digest_minutes") * 60
    for ch in channels:
        held = conn.execute("SELECT n.id, i.severity, i.title FROM notifications n JOIN incidents i"
                            " ON i.id = n.incident_id WHERE n.channel_id=? AND n.status='held'"
                            " ORDER BY i.id", (ch["id"],)).fetchall()
        if not held:
            continue
        last = conn.execute("SELECT MAX(ts) FROM notifications WHERE channel_id=? AND incident_id IS NULL"
                            " AND status='sent'", (ch["id"],)).fetchone()[0]
        if last is not None and now - last < interval:
            continue
        title, body = digest_message(held)
        worst = max((r["severity"] for r in held), key=lambda s: SEVERITY_RANK.get(s, 0))
        try:
            sender(ch["kind"], json.loads(ch["config"]), title, body, worst, {"type": "digest", "count": len(held)})
        except NotifyError as e:
            _record_result(conn, ch["id"], False, str(e), now)
            out["failed"] += 1
            continue
        conn.execute("INSERT INTO notifications (channel_id, incident_id, ts, status, attempts, title)"
                     " VALUES (?, NULL, ?, 'sent', 1, ?)", (ch["id"], now, title))
        conn.executemany("UPDATE notifications SET status='digested' WHERE id=?", [(r["id"],) for r in held])
        _record_result(conn, ch["id"], True, None, now)
        out["digests"] += 1


def send_test(conn, channel_id):
    """Send a clearly-labelled test message on one channel, for the
    console's "Send test" button. Raises NotifyError on failure."""
    ch = conn.execute("SELECT * FROM notification_channels WHERE id=?", (channel_id,)).fetchone()
    if ch is None:
        raise NotifyError("channel not found")
    now = time.time()
    try:
        send(ch["kind"], json.loads(ch["config"]), "SecurePi test notification",
             "If you can read this, the '%s' channel works.\n%s" % (ch["name"], CONSOLE_URL),
             "low", {"type": "test"})
    except NotifyError as e:
        _record_result(conn, ch["id"], False, str(e), now)
        conn.commit()
        raise
    _record_result(conn, ch["id"], True, None, now)
    conn.commit()


def recent(conn, limit=50):
    return conn.execute(
        "SELECT n.*, c.name AS channel_name, c.kind AS channel_kind FROM notifications n"
        " JOIN notification_channels c ON c.id = n.channel_id ORDER BY n.id DESC LIMIT ?",
        (min(limit, 200),)).fetchall()

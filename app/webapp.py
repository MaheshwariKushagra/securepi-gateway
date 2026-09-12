#!/usr/bin/env python3
"""
SecurePi Gateway - the web console.

Server-rendered (Jinja2) rather than a JS single-page app, per the project's
timeline constraints: this gets a live, navigable console in a fraction of
the time a React build would take, at the cost of a full-page refresh rather
than push updates. The auto-refresh meta tag in base.html (15s) covers the
"feels live" requirement without needing a WebSocket layer.

Three views, matching what the plan calls for:
  /            overview  - recent activity across the whole network
  /devices     device inventory and per-device drill-down
  /incidents   the correlation engine's output: queue, severity, evidence
"""

import json
import sqlite3
import time

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

DB_PATH = "/opt/securepi/securepi.db"

app = FastAPI(title="SecurePi Gateway")
app.mount("/static", StaticFiles(directory="/opt/securepi/static"), name="static")
templates = Jinja2Templates(directory="/opt/securepi/templates")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def fmt_time(ts):
    if ts is None:
        return "-"
    return time.strftime("%H:%M:%S", time.localtime(ts))


def device_name(row):
    """A device's display name: the friendly name if one has been set,
    otherwise the DHCP hostname, otherwise a plain fallback."""
    return row["friendly_name"] or row["hostname"] or ("device %d" % row["id"])



def time_buckets(c, hours=6, bucket_minutes=15):
    """
    Build the data for the throughput and blocked-query charts: fixed-width
    time buckets covering the trailing window, each with total bytes
    transferred and blocked-query count in that slice.

    Buckets are pre-seeded at zero for the WHOLE window before events are
    added in, so a quiet period shows as a real zero on the chart rather than
    silently vanishing (a gap in the x-axis reads as missing data, not "no
    activity", which is the wrong story to tell about a quiet network).
    """
    now = time.time()
    bucket_s = bucket_minutes * 60
    n_buckets = int((hours * 3600) / bucket_s)
    start = now - n_buckets * bucket_s

    labels = []
    bytes_per_bucket = [0] * n_buckets
    blocked_per_bucket = [0] * n_buckets
    for i in range(n_buckets):
        bucket_t = start + i * bucket_s
        labels.append(time.strftime("%H:%M", time.localtime(bucket_t)))

    for r in c.execute(
        """SELECT ts, bytes_toclient, bytes_toserver FROM events
            WHERE event_type = 'flow' AND ts > ?""",
        (start,),
    ):
        idx = int((r["ts"] - start) / bucket_s)
        if 0 <= idx < n_buckets:
            bytes_per_bucket[idx] += (r["bytes_toclient"] or 0) + (r["bytes_toserver"] or 0)

    for r in c.execute(
        """SELECT ts FROM events
            WHERE event_type = 'dns_query' AND blocked = 1 AND ts > ?""",
        (start,),
    ):
        idx = int((r["ts"] - start) / bucket_s)
        if 0 <= idx < n_buckets:
            blocked_per_bucket[idx] += 1

    # Bytes/sec, not raw bytes, so the chart reads sensibly regardless of the
    # bucket width chosen above.
    throughput_kbps = [round(b / bucket_s / 1024, 2) for b in bytes_per_bucket]

    return {
        "labels": labels,
        "throughput_kbps": throughput_kbps,
        "blocked_per_bucket": blocked_per_bucket,
    }


@app.get("/", response_class=HTMLResponse)
def overview(request: Request):
    c = db()
    device_count = c.execute("SELECT count(*) FROM devices").fetchone()[0]
    event_count = c.execute("SELECT count(*) FROM events").fetchone()[0]
    open_incidents = c.execute(
        "SELECT count(*) FROM incidents WHERE status = 'new'"
    ).fetchone()[0]
    since = time.time() - 86400
    blocked_count = c.execute(
        "SELECT count(*) FROM events WHERE blocked = 1 AND ts > ?", (since,)
    ).fetchone()[0]

    recent_dns = []
    for r in c.execute(
        """SELECT e.ts, e.dns_rrname, e.blocked, e.src_ip, d.hostname, d.friendly_name
             FROM events e LEFT JOIN devices d ON d.id = e.device_id
            WHERE e.event_type = 'dns_query'
            ORDER BY e.id DESC LIMIT 15"""
    ):
        recent_dns.append({
            "time": fmt_time(r["ts"]), "dns_rrname": r["dns_rrname"],
            "blocked": r["blocked"], "src_ip": r["src_ip"],
            "device": r["friendly_name"] or r["hostname"],
        })

    recent_flows = []
    for r in c.execute(
        """SELECT e.ts, e.dest_ip, e.dest_port, e.proto, e.src_ip, d.hostname, d.friendly_name
             FROM events e LEFT JOIN devices d ON d.id = e.device_id
            WHERE e.event_type = 'flow'
            ORDER BY e.id DESC LIMIT 15"""
    ):
        recent_flows.append({
            "time": fmt_time(r["ts"]), "dest_ip": r["dest_ip"], "dest_port": r["dest_port"],
            "proto": r["proto"], "src_ip": r["src_ip"],
            "device": r["friendly_name"] or r["hostname"],
        })

    severity_counts = dict(c.execute(
        "SELECT severity, count(*) FROM incidents GROUP BY severity"
    ).fetchall())
    chart_data = time_buckets(c, hours=6, bucket_minutes=15)

    return templates.TemplateResponse("overview.html", {"request": request,
        "active": "overview", "title": "Overview",
        "device_count": device_count, "event_count": event_count,
        "open_incidents": open_incidents, "blocked_count": blocked_count,
        "recent_dns": recent_dns, "recent_flows": recent_flows,
        "severity_counts": {
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
        },
        "chart_data": chart_data,
    })


@app.get("/devices", response_class=HTMLResponse)
def devices_page(request: Request):
    c = db()
    devices = []
    for d in c.execute("SELECT * FROM devices ORDER BY last_seen DESC"):
        ip = c.execute(
            "SELECT ip FROM device_ips WHERE device_id = ? ORDER BY last_seen DESC LIMIT 1",
            (d["id"],),
        ).fetchone()
        agg = c.execute(
            """SELECT
                   sum(CASE WHEN event_type='flow' THEN bytes_toclient ELSE 0 END) down,
                   sum(CASE WHEN event_type='flow' THEN bytes_toserver ELSE 0 END) up,
                   sum(event_type='dns_query') dns,
                   sum(event_type='tls') tls,
                   sum(alert_signature IS NOT NULL) alerts
               FROM events WHERE device_id = ?""",
            (d["id"],),
        ).fetchone()
        devices.append({
            "id": d["id"], "name": device_name(d),
            "ip": ip["ip"] if ip else None,
            "down_mb": round((agg["down"] or 0) / 1048576, 2),
            "up_kb": round((agg["up"] or 0) / 1024, 1),
            "dns_count": agg["dns"] or 0, "tls_count": agg["tls"] or 0,
            "alert_count": agg["alerts"] or 0,
            "last_seen": fmt_time(d["last_seen"]),
        })
    return templates.TemplateResponse("devices.html", {"request": request,         "active": "devices", "title": "Devices", "devices": devices,})


@app.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(request: Request, device_id: int):
    c = db()
    d = c.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if d is None:
        return HTMLResponse("Device not found", status_code=404)

    macs = ", ".join(
        r["mac"] for r in c.execute(
            "SELECT mac FROM device_macs WHERE device_id = ? ORDER BY last_seen DESC",
            (device_id,),
        )
    ) or "-"
    ips = ", ".join(
        r["ip"] for r in c.execute(
            "SELECT DISTINCT ip FROM device_ips WHERE device_id = ? ORDER BY last_seen DESC",
            (device_id,),
        )
    ) or "-"
    agg = c.execute(
        """SELECT
               sum(CASE WHEN event_type='flow' THEN bytes_toclient ELSE 0 END) down,
               sum(CASE WHEN event_type='flow' THEN bytes_toserver ELSE 0 END) up,
               sum(event_type='dns_query') dns,
               sum(blocked=1) blocked
           FROM events WHERE device_id = ?""",
        (device_id,),
    ).fetchone()

    device = {
        "id": d["id"], "name": device_name(d), "macs": macs, "ips": ips,
        "first_seen": fmt_time(d["first_seen"]), "last_seen": fmt_time(d["last_seen"]),
        "down_mb": round((agg["down"] or 0) / 1048576, 2),
        "up_kb": round((agg["up"] or 0) / 1024, 1),
        "dns_count": agg["dns"] or 0, "blocked_count": agg["blocked"] or 0,
    }

    top_destinations = [
        {"tls_sni": r["tls_sni"], "n": r["n"]}
        for r in c.execute(
            """SELECT tls_sni, count(*) n FROM events
                WHERE device_id = ? AND tls_sni IS NOT NULL
                GROUP BY tls_sni ORDER BY n DESC LIMIT 10""",
            (device_id,),
        )
    ]

    timeline = []
    for r in c.execute(
        "SELECT * FROM events WHERE device_id = ? ORDER BY id DESC LIMIT 40",
        (device_id,),
    ):
        if r["event_type"] == "flow":
            detail = "%s:%s (%s)" % (r["dest_ip"], r["dest_port"], r["proto"])
        elif r["event_type"] == "dns_query":
            detail = "%s%s" % (r["dns_rrname"], " [blocked]" if r["blocked"] else "")
        elif r["event_type"] == "tls":
            detail = r["tls_sni"] or "-"
        elif r["event_type"] == "alert":
            detail = r["alert_signature"] or "-"
        else:
            detail = "%s -> %s" % (r["src_ip"], r["dest_ip"])
        timeline.append({"time": fmt_time(r["ts"]), "event_type": r["event_type"], "detail": detail})

    return templates.TemplateResponse("device_detail.html", {"request": request,         "active": "devices", "title": device["name"],
        "device": device, "top_destinations": top_destinations, "timeline": timeline,})


@app.get("/incidents", response_class=HTMLResponse)
def incidents_page(request: Request):
    c = db()
    incidents = []
    for i in c.execute(
        """SELECT inc.*, d.hostname, d.friendly_name
             FROM incidents inc LEFT JOIN devices d ON d.id = inc.device_id
            ORDER BY
                CASE inc.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                inc.last_seen DESC"""
    ):
        incidents.append({
            "id": i["id"], "severity": i["severity"], "title": i["title"],
            "status": i["status"], "evidence_count": i["evidence_count"],
            "last_seen": fmt_time(i["last_seen"]),
            "device_name": i["friendly_name"] or i["hostname"],
        })
    return templates.TemplateResponse("incidents.html", {"request": request,         "active": "incidents", "title": "Incidents", "incidents": incidents,})


@app.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_detail(request: Request, incident_id: int):
    c = db()
    i = c.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if i is None:
        return HTMLResponse("Incident not found", status_code=404)

    device_name_val = None
    if i["device_id"]:
        d = c.execute("SELECT * FROM devices WHERE id = ?", (i["device_id"],)).fetchone()
        if d:
            device_name_val = device_name(d)

    incident = dict(i)
    incident["first_seen"] = fmt_time(i["first_seen"])
    incident["last_seen"] = fmt_time(i["last_seen"])
    incident["device_name"] = device_name_val

    evidence = []
    for r in c.execute(
        """SELECT e.* FROM incident_events ie JOIN events e ON e.id = ie.event_id
            WHERE ie.incident_id = ? ORDER BY e.ts""",
        (incident_id,),
    ):
        if r["event_type"] == "flow":
            detail = "%s:%s -> %s:%s (%s)" % (r["src_ip"], r["src_port"], r["dest_ip"], r["dest_port"], r["proto"])
        elif r["event_type"] == "dns_query":
            detail = "%s%s" % (r["dns_rrname"], " [blocked: %s]" % r["block_reason"] if r["blocked"] else "")
        else:
            detail = "%s -> %s" % (r["src_ip"], r["dest_ip"])
        evidence.append({"time": fmt_time(r["ts"]), "event_type": r["event_type"], "detail": detail})

    return templates.TemplateResponse("incident_detail.html", {"request": request,         "active": "incidents", "title": incident["title"],
        "incident": incident, "evidence": evidence,})

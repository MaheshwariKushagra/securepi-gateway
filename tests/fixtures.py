#!/usr/bin/env python3
"""
SecurePi Gateway - shared test fixtures (ENHANCEMENT-PLAN.md step 1.1).

Not a test file itself (no test_*.py name, so `unittest discover` skips
it) - a helper module every test_*.py file in this directory imports.

Two kinds of fixture live here, matching what 1.1's own row asks for:

1. A temp-DB helper (`temp_db()`) plus small row-insertion helpers
   (`insert_device`, `insert_flow`, `insert_dns_query`, `insert_dpi_event`,
   `insert_device_hourly`) for tests that exercise `app/correlation.py`'s
   signals directly against a real, schema-correct in-memory SQLite
   database - the same pattern this project's own throwaway session smoke
   tests already used successfully, made permanent here.
2. Synthetic eve.json / AdGuard querylog generators (`make_eve_flow`,
   `make_eve_dns_query`, `make_eve_alert`, `make_agh_entry`) - raw,
   Suricata- and AdGuard-shaped dictionaries for tests that exercise
   `app/ingest.py`'s own parsing (`flatten_suricata`, `flatten_agh`)
   rather than the database layer. No real device data anywhere - every
   IP, MAC and domain below is either a private-range placeholder or an
   obviously-fake example.com-style name.
"""

import os
import sqlite3
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.join(REPO_ROOT, "app")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

SCHEMA_PATH = os.path.join(APP_DIR, "schema.sql")


def temp_db():
    """A fresh in-memory SQLite database with the real schema.sql applied -
    the temp-DB helper step 1.1 asks for. Every test gets its own; nothing
    persists between tests and nothing touches a real database file."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    with open(SCHEMA_PATH) as fh:
        conn.executescript(fh.read())
    return conn


def insert_device(conn, device_id, hostname=None, friendly_name=None,
                   first_seen=None, last_seen=None):
    now = time.time()
    conn.execute(
        "INSERT INTO devices (id, hostname, friendly_name, first_seen, last_seen)"
        " VALUES (?, ?, ?, ?, ?)",
        (device_id, hostname, friendly_name,
         first_seen if first_seen is not None else now,
         last_seen if last_seen is not None else now),
    )
    conn.commit()


def insert_flow(conn, device_id, dest_ip, dest_port, ts,
                 src_ip="10.10.0.50", bytes_toclient=0, bytes_toserver=0, flow_start=None):
    conn.execute(
        "INSERT INTO events (ts, ts_iso, source, event_type, src_ip, dest_ip, dest_port,"
        " device_id, bytes_toclient, bytes_toserver, blocked, flow_start)"
        " VALUES (?, 'test', 'suricata', 'flow', ?, ?, ?, ?, ?, ?, 0, ?)",
        (ts, src_ip, dest_ip, dest_port, device_id, bytes_toclient, bytes_toserver, flow_start),
    )
    conn.commit()


def insert_dns_query(conn, device_id, dns_rrname, ts, blocked=0, src_ip="10.10.0.50"):
    conn.execute(
        "INSERT INTO events (ts, ts_iso, source, event_type, src_ip, device_id,"
        " dns_rrname, blocked)"
        " VALUES (?, 'test', 'adguard', 'dns_query', ?, ?, ?, ?)",
        (ts, src_ip, device_id, dns_rrname, 1 if blocked else 0),
    )
    conn.commit()


def insert_ioc(conn, indicator, ioc_type, source="feodo", description="test IOC", ts=None):
    ts = ts if ts is not None else time.time()
    conn.execute(
        "INSERT INTO ioc (indicator, ioc_type, source, description, first_seen, last_seen)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (indicator, ioc_type, source, description, ts, ts),
    )
    conn.commit()


def insert_alert(conn, device_id, alert_category, ts, alert_signature="ET TEST signature",
                  alert_severity=2, src_ip="10.10.0.50", dest_ip="203.0.113.5"):
    conn.execute(
        "INSERT INTO events (ts, ts_iso, source, event_type, src_ip, dest_ip, device_id,"
        " alert_signature, alert_category, alert_severity)"
        " VALUES (?, 'test', 'suricata', 'alert', ?, ?, ?, ?, ?, ?)",
        (ts, src_ip, dest_ip, device_id, alert_signature, alert_category, alert_severity),
    )
    conn.commit()


def insert_tls(conn, device_id, tls_sni, ts, src_ip="10.10.0.50"):
    conn.execute(
        "INSERT INTO events (ts, ts_iso, source, event_type, src_ip, device_id, tls_sni)"
        " VALUES (?, 'test', 'suricata', 'tls', ?, ?, ?)",
        (ts, src_ip, device_id, tls_sni),
    )
    conn.commit()


def insert_bypass_attempt(conn, device_id, block_reason, ts, src_ip="10.10.0.50",
                           dest_ip="9.9.9.9", dest_port=853, proto="TCP"):
    conn.execute(
        "INSERT INTO events (ts, ts_iso, source, event_type, src_ip, device_id,"
        " dest_ip, dest_port, proto, block_reason)"
        " VALUES (?, 'test', 'nftables', 'bypass_attempt', ?, ?, ?, ?, ?, ?)",
        (ts, src_ip, device_id, dest_ip, dest_port, proto, block_reason),
    )
    conn.commit()


def insert_dpi_event(conn, device_id, dpi_action, ts, dpi_ads_removed=0):
    conn.execute(
        "INSERT INTO events (ts, ts_iso, source, event_type, device_id, dpi_action,"
        " dpi_ads_removed, blocked)"
        " VALUES (?, 'test', 'dpi', 'dpi_decision', ?, ?, ?, 0)",
        (ts, device_id, dpi_action, dpi_ads_removed),
    )
    conn.commit()


def insert_device_hourly(conn, device_id, hour_start, bytes_down, bytes_up):
    conn.execute(
        "INSERT INTO device_hourly (device_id, hour_start, bytes_down, bytes_up)"
        " VALUES (?, ?, ?, ?)",
        (device_id, hour_start, bytes_down, bytes_up),
    )
    conn.commit()


def make_eve_flow(src_ip="10.10.0.50", dest_ip="93.184.216.34", dest_port=443,
                   bytes_toclient=1000, bytes_toserver=200, timestamp=None, start=None):
    """A synthetic Suricata eve.json 'flow' record, shaped like a real one."""
    record = {
        "timestamp": timestamp or "2026-09-14T10:00:00.000000+0000",
        "event_type": "flow",
        "src_ip": src_ip, "src_port": 51000, "dest_ip": dest_ip, "dest_port": dest_port,
        "proto": "TCP", "app_proto": "tls",
        "flow_id": 123456789, "community_id": "1:testCommunityId=",
        "flow": {
            "bytes_toserver": bytes_toserver, "bytes_toclient": bytes_toclient,
            "pkts_toserver": 10, "pkts_toclient": 12, "state": "closed", "age": 3,
        },
    }
    if start:
        record["flow"]["start"] = start
    return record


def make_eve_dns_query(src_ip="10.10.0.50", rrname="example.com", timestamp=None):
    """A synthetic Suricata eve.json 'dns' query record (source='suricata',
    NOT the AdGuard-sourced dns_query type - see flatten_suricata/flatten_agh)."""
    return {
        "timestamp": timestamp or "2026-09-14T10:00:00.000000+0000",
        "event_type": "dns",
        "src_ip": src_ip, "src_port": 53211, "dest_ip": "1.1.1.1", "dest_port": 53,
        "proto": "UDP",
        "dns": {"type": "query", "rrname": rrname, "rrtype": "A"},
    }


def make_eve_alert(src_ip="10.10.0.50", dest_ip="203.0.113.5", signature="ET TEST signature",
                    severity=2, timestamp=None):
    return {
        "timestamp": timestamp or "2026-09-14T10:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": src_ip, "src_port": 51000, "dest_ip": dest_ip, "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature": signature, "category": "Test category",
            "severity": severity, "signature_id": 2000001,
        },
    }


def make_agh_entry(client_ip="10.10.0.50", domain="ads.example.com",
                    blocked=True, timestamp=None, cached=False,
                    upstream="tls://1.1.1.1", elapsed_ns=5_000_000):
    """A synthetic AdGuard Home querylog.json line, shaped like a real one."""
    entry = {
        "T": timestamp or "2026-09-14T10:00:00.5Z",
        "QH": domain, "QT": "A", "QC": "IN",
        "IP": client_ip,
        "Cached": cached,
        "Elapsed": elapsed_ns,
        "Result": {},
    }
    if upstream:
        entry["Upstream"] = upstream
    if blocked:
        entry["Result"] = {
            "IsFiltered": True,
            "Rules": [{"FilterListID": 1, "Text": "||%s^" % domain}],
        }
    return entry


def make_agh_api_entry(client_ip="10.10.0.50", domain="ads.example.com",
                        blocked=True, timestamp=None, cached=False,
                        upstream="tls://1.1.1.1", elapsed_ms="5.123456",
                        reason=None, status="NOERROR", rrtype="A"):
    """A synthetic /control/querylog API entry - a DIFFERENT shape from
    the on-disk file (make_agh_entry above). Fields and their real
    values (including the exact two 'reason' strings used below) were
    confirmed live against the real gateway's real AdGuard API before
    being encoded here, not guessed - see app/ingest.py's
    flatten_agh_api docstring."""
    if reason is None:
        reason = "FilteredBlackList" if blocked else "NotFilteredNotFound"
    entry = {
        "answer": [{"type": "A", "value": "0.0.0.0" if blocked else "93.184.216.34", "ttl": 10}],
        "answer_dnssec": False,
        "cached": cached,
        "client": client_ip,
        "client_info": {"whois": {}, "name": "", "disallowed_rule": "", "disallowed": False},
        "client_proto": "",
        "elapsedMs": elapsed_ms,
        "question": {"class": "IN", "name": domain, "type": rrtype},
        "reason": reason,
        "rules": [],
        "status": status,
        "time": timestamp or "2026-09-14T10:00:00.500000000Z",
        "upstream": upstream or "",
    }
    if blocked:
        entry["filterId"] = 1
        entry["rule"] = "||%s^" % domain
        entry["rules"] = [{"filter_list_id": 1, "text": "||%s^" % domain}]
    return entry

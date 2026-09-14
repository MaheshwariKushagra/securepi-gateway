#!/usr/bin/env python3
"""Build a SYNTHETIC SecurePi database for README screenshots.

Nothing here is real network data: hostnames are invented, addresses are
private-range, MACs are made up, and domains are well-known public
ad/tracker/service names. Incidents are produced by running the project's
real correlation engine over this data, not inserted by hand (except a few
historical, already-adjudicated ones for a realistic incident list).
"""
import os, random, sqlite3, sys, time, json

# The repository root, two folders up from docs/demo/.
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "app"))
import correlation, rollup, audit  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "securepi.db")
random.seed(1411)
if os.path.exists(OUT):
    os.remove(OUT)
for ext in ("-wal", "-shm"):
    if os.path.exists(OUT + ext):
        os.remove(OUT + ext)

conn = sqlite3.connect(OUT)
conn.row_factory = sqlite3.Row
conn.executescript(open(os.path.join(REPO, "app/schema.sql")).read())
NOW = time.time()
H = 3600
DAY = 86400

# id, hostname, friendly, ip, mac, randomized, kind, first_seen_days_ago, bytes/h (MB), dns/h
DEVICES = [
    (1, "reception-pc",   "Reception PC",      "10.10.0.21", "3c:52:82:4a:10:21", 0, "windows", 13, 60, 220),
    (2, "finance-laptop", "Finance Laptop",    "10.10.0.22", "3c:52:82:4a:10:22", 0, "windows", 13, 140, 300),
    (3, "Galaxy-S23",     None,                "10.10.0.31", "ca:25:11:6e:0b:31", 1, "android", 12, 90, 260),
    (4, "iPhone",         "Manager iPhone",    "10.10.0.32", "a2:c8:7d:19:44:32", 1, "ios", 12, 70, 200),
    (5, "lobby-tv",       "Lobby Smart TV",    "10.10.0.41", "f4:7b:09:2c:77:41", 0, "tv", 11, 400, 120),
    (6, "nas-storage",    "NAS",               "10.10.0.20", "00:11:32:aa:20:20", 0, "linux", 13, 30, 40),
]
ATTACKER = (7, "kali", None, "10.10.0.66", "02:42:0a:0a:00:66", 1, "linux", 0, 5, 30)

ALLOWED = ["www.google.com", "outlook.office365.com", "teams.microsoft.com", "github.com",
           "api.github.com", "fonts.gstatic.com", "www.wikipedia.org", "cdn.jsdelivr.net",
           "i.ytimg.com", "www.youtube.com", "clients4.google.com", "login.microsoftonline.com",
           "connectivitycheck.gstatic.com", "captive.apple.com", "time.cloudflare.com",
           "update.googleapis.com", "slack.com", "zoom.us", "dropbox.com", "netflix.com"]
BLOCKED = ["doubleclick.net", "googlesyndication.com", "googleadservices.com",
           "app-measurement.com", "scorecardresearch.com", "adnxs.com", "criteo.com",
           "taboola.com", "outbrain.com", "pubmatic.com", "firebaselogging-pa.googleapis.com",
           "graph.facebook.com", "ads.yahoo.com", "samsungads.com", "track.hubspot.com",
           "bat.bing.com", "analytics.tiktok.com", "ads.linkedin.com", "amazon-adsystem.com",
           "hotjar.com", "mixpanel.com", "segment.io"]
LIST_IDS = [1, 1, 1, 2, 3, 3, 4, 5]
PUBLIC_DST = ["142.250.66.4", "13.107.42.14", "140.82.121.4", "151.101.1.140", "104.16.85.20",
              "52.97.146.2", "23.185.0.4", "185.199.108.153", "31.13.79.35"]

evrows = []


def ev(ts, **kw):
    row = {"ts": ts, "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)),
           "source": "suricata"}
    row.update(kw)
    evrows.append(row)


def diurnal(hour, kind):
    if kind in ("windows",):
        return 1.0 if 9 <= hour <= 18 else 0.12
    if kind == "tv":
        return 1.0 if 17 <= hour <= 23 else 0.05
    if kind == "linux":
        return 0.6
    return 0.9 if 7 <= hour <= 23 else 0.15


def insert_device(d, first_seen):
    did, host, friendly, ip, mac, rnd, kind = d[:7]
    conn.execute("INSERT INTO devices (id, hostname, friendly_name, first_seen, last_seen) VALUES (?,?,?,?,?)",
                 (did, host, friendly, first_seen, NOW - random.randint(5, 90)))
    conn.execute("INSERT INTO device_macs (device_id, mac, is_randomized, first_seen, last_seen) VALUES (?,?,?,?,?)",
                 (did, mac, rnd, first_seen, NOW))
    conn.execute("INSERT INTO device_ips (device_id, ip, first_seen, last_seen) VALUES (?,?,?,?)",
                 (did, ip, first_seen, NOW + 3600))


for d in DEVICES:
    insert_device(d, NOW - d[7] * DAY)
# The Android phone re-randomized its MAC once; the registry kept it as one device.
conn.execute("INSERT INTO device_macs (device_id, mac, is_randomized, first_seen, last_seen) VALUES (3,'de:9a:41:0f:73:e2',1,?,?)",
             (NOW - 12 * DAY, NOW - 5 * DAY))

# ---- 7+ days of hourly history, straight into device_hourly (baseline data)
start_hist = int((NOW - 9 * DAY) // H) * H
raw_from = int((NOW - 36 * H) // H) * H
for d in DEVICES:
    did, kind, mb, dns = d[0], d[6], d[8], d[9]
    for hs in range(start_hist, raw_from, H):
        f = diurnal(time.localtime(hs).tm_hour, kind) * random.uniform(0.75, 1.25)
        down = int(mb * 1e6 * f * 0.85)
        up = int(mb * 1e6 * f * 0.15)
        q = int(dns * f)
        conn.execute("INSERT INTO device_hourly VALUES (?,?,?,?,?,?,?)",
                     (did, hs, down, up, q, int(q * random.uniform(0.08, 0.2)), int(q * 0.6)))

# ---- 36 hours of raw events
for d in DEVICES:
    did, host, friendly, ip, mac, rnd, kind, _, mb, dns = d
    for hs in range(raw_from, int(NOW), H):
        span = min(H, NOW - hs - 1)
        if span <= 0:
            continue
        f = diurnal(time.localtime(hs).tm_hour, kind) * random.uniform(0.75, 1.25)
        nq = max(1, int(dns * f * 0.35 * span / H))
        for _ in range(nq):
            t = hs + random.random() * span
            if random.random() < 0.16:
                dom = random.choice(BLOCKED[:12] if kind != "android" else BLOCKED[:6])
                ev(t, source="adguard", event_type="dns_query", src_ip=ip, device_id=did,
                   dns_rrname=dom, dns_rrtype="A", blocked=1, block_reason="FilteredBlackList",
                   dns_filter_list_id=random.choice(LIST_IDS), dns_cached=0,
                   dns_elapsed_ms=round(random.uniform(0.2, 2.0), 2))
            else:
                dom = random.choice(ALLOWED)
                cached = random.random() < 0.55
                ev(t, source="adguard", event_type="dns_query", src_ip=ip, device_id=did,
                   dns_rrname=dom, dns_rrtype=random.choice(["A", "AAAA", "HTTPS"]), blocked=0,
                   dns_rcode="NOERROR", dns_cached=int(cached),
                   dns_upstream=None if cached else random.choice(["tls://1.1.1.1:853", "tls://9.9.9.9:853"]),
                   dns_elapsed_ms=round(random.uniform(0.1, 1.5) if cached else random.gammavariate(3, 9), 2))
        nflows = max(1, int(f * 30 * span / H))
        per = mb * 1e6 * f * (span / H) / nflows
        for _ in range(nflows):
            t = hs + random.random() * span
            dst = random.choice(PUBLIC_DST)
            b = int(per * random.uniform(0.5, 1.5))
            ev(t, event_type="flow", src_ip=ip, src_port=random.randint(40000, 60000), dest_ip=dst,
               dest_port=443, proto="TCP", app_proto="tls", device_id=did,
               bytes_toclient=int(b * 0.85), bytes_toserver=int(b * 0.15),
               pkts_toserver=random.randint(10, 200), pkts_toclient=random.randint(10, 400),
               flow_state="closed", flow_age=random.randint(1, 120))
            if random.random() < 0.3:
                ev(t, event_type="tls", src_ip=ip, dest_ip=dst, dest_port=443, proto="TCP",
                   device_id=did, tls_sni=random.choice(ALLOWED), tls_version="TLS 1.3",
                   tls_ja3="%032x" % random.getrandbits(128))

# DHCP fingerprint evidence for the phones
ev(NOW - 11 * H, event_type="dhcp", src_ip="10.10.0.31", device_id=3, dhcp_params="1,3,6,15,26,28,51,58,59,43")
ev(NOW - 10 * H, event_type="dhcp", src_ip="10.10.0.32", device_id=4, dhcp_params="1,121,3,6,15,108,114,119,252")

# Tier 2 (selective HTTPS inspection) on the Android phone - ads stripped from YouTube
for i in range(40):
    t = NOW - random.random() * 20 * H
    ev(t, source="dpi", event_type="dpi_decision", src_ip="10.10.0.31", device_id=3,
       tls_sni="www.youtube.com", dpi_action="ads_stripped", dpi_ads_removed=random.randint(1, 3))
for i in range(120):
    t = NOW - random.random() * 20 * H
    ev(t, source="dpi", event_type="dpi_decision", src_ip="10.10.0.31", device_id=3,
       tls_sni=random.choice(["www.youtube.com", "youtubei.googleapis.com"]), dpi_action="decrypt")
for i in range(260):
    t = NOW - random.random() * 20 * H
    ev(t, source="dpi", event_type="dpi_decision", src_ip="10.10.0.31", device_id=3,
       tls_sni=random.choice(["netbanking.example-bank.com", "mail.google.com", "web.whatsapp.com"]),
       dpi_action="passthrough")

# ---- Suricata IDS alerts, low volume, over the day
SIGS = [("ET SCAN Possible Nmap User-Agent Observed", "Web Application Attack", 1, 2024364),
        ("ET POLICY Observed DNS Query to .onion proxy Domain", "Potential Corporate Privacy Violation", 2, 2022048),
        ("ET INFO Session Traversal Utilities for NAT (STUN Binding Request)", "Attempted User Privilege Gain", 3, 2033078),
        ("SURICATA STREAM Packet with invalid ack", "Generic Protocol Command Decode", 3, 2210045)]
for _ in range(60):
    s = random.choices(SIGS, weights=[1, 1, 6, 10])[0]
    d = random.choice(DEVICES)
    ev(NOW - random.random() * 30 * H, event_type="alert", src_ip=d[3], dest_ip=random.choice(PUBLIC_DST),
       dest_port=443, proto="TCP", device_id=d[0], alert_signature=s[0], alert_category=s[1],
       alert_severity=s[2], alert_signature_id=s[3])


def flush():
    cols = sorted({k for r in evrows for k in r})
    conn.executemany("INSERT INTO events (%s) VALUES (%s)" % (",".join(cols), ",".join("?" * len(cols))),
                     [tuple(r.get(c) for c in cols) for r in sorted(evrows, key=lambda r: r["ts"])])
    evrows.clear()
    conn.commit()


flush()
print("rollup rows:", rollup.rollup_closed_hours(conn, NOW))

# ---- Historical, already-adjudicated incidents (the real engine raised these
# kinds of incidents on earlier days; recreated here as plain rows)
HIST = [
    (5, "new_device", "low", "New device joined the network: lobby-tv", "resolved", 11 * DAY, 0, None),
    (3, "new_device", "low", "New device joined the network: Galaxy-S23", "resolved", 12 * DAY, 0, None),
    (4, "new_device", "low", "New device joined the network: iPhone", "resolved", 12 * DAY, 0, None),
    (3, "malicious_domain", "medium", "Blocked lookups against 16 distinct domains (600s window)", "false_positive", 4 * DAY, 58,
     "58 blocked DNS queries across 16 distinct domains. Top domains: app-measurement.com (x11), doubleclick.net (x9), googlesyndication.com (x7), adnxs.com (x5), criteo.com (x4)."),
    (2, "volume_anomaly", "medium", "Unusual data volume for this device at this time of day", "resolved", 2 * DAY, 0,
     "812.4 MB so far this hour, vs. a 9-day average of 131.0 MB at 14:00 (z=6.2) - could be a large upload/exfiltration, or just an unusually heavy session."),
]
for did, sig, sev, title, status, ago, n, desc in HIST:
    t = NOW - ago
    if desc is None:
        desc = "First seen at %s; not previously known to the registry." % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))
    cur = conn.execute("INSERT INTO incidents (device_id, signal_type, severity, title, description, status,"
                       " first_seen, last_seen, created_at, updated_at, evidence_count) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                       (did, sig, sev, title, desc, status,
                        t, t + 400, t + 20, t + 3 * H, n))
    audit.log(conn, "securepi", "incident.status_change", str(cur.lastrowid), "new -> %s" % status)

# ---- The live attack: an unknown device joins, scans the NAS, then brute-forces SSH
atk_first = NOW - 14 * 60
insert_device(ATTACKER, atk_first)
conn.execute("UPDATE devices SET last_seen=? WHERE id=7", (NOW - 20,))
ip = ATTACKER[3]
ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5900, 8080, 8443]
t0 = NOW - 230
for i, p in enumerate(ports):
    ev(t0 + i * 3.2, event_type="flow", src_ip=ip, src_port=51000 + i, dest_ip="10.10.0.20", dest_port=p,
       proto="TCP", device_id=7, bytes_toserver=74, bytes_toclient=60, pkts_toserver=1, pkts_toclient=1,
       flow_state="closed", flow_age=0)
t1 = NOW - 95
for i in range(24):
    ev(t1 + i * 3.6, event_type="flow", src_ip=ip, src_port=52000 + i, dest_ip="10.10.0.20", dest_port=22,
       proto="TCP", app_proto="ssh", device_id=7, bytes_toserver=2100, bytes_toclient=2600,
       pkts_toserver=14, pkts_toclient=12, flow_state="closed", flow_age=2)
ev(t1 + 10, event_type="alert", src_ip=ip, dest_ip="10.10.0.20", dest_port=22, proto="TCP", device_id=7,
   alert_signature="ET SCAN Potential SSH Scan", alert_category="Attempted Information Leak",
   alert_severity=2, alert_signature_id=2001219)
# A phone burst of many distinct blocked domains (an ad-heavy app)
for i, dom in enumerate(BLOCKED):
    for _ in range(random.randint(1, 3)):
        ev(NOW - 500 + i * 18 + random.random() * 5, source="adguard", event_type="dns_query",
           src_ip="10.10.0.32", device_id=4, dns_rrname=dom, dns_rrtype="A", blocked=1,
           block_reason="FilteredBlackList", dns_filter_list_id=random.choice(LIST_IDS))
flush()

conn.execute("UPDATE ingest_stats SET events_read=?, events_saved=?, parse_errors=0, last_run=? WHERE id=1",
             (conn.execute("SELECT count(*) FROM events").fetchone()[0] + 12,
              conn.execute("SELECT count(*) FROM events").fetchone()[0], NOW))

print("engine:", correlation.run_all(conn))

# Operator workflow on the live incidents: triage, notes, audit trail
scan = conn.execute("SELECT id FROM incidents WHERE signal_type='port_scan'").fetchone()
if scan:
    conn.execute("UPDATE incidents SET status='investigating' WHERE id=?", (scan["id"],))
    audit.log(conn, "securepi", "incident.status_change", str(scan["id"]), "new -> investigating")
    conn.execute("INSERT INTO incident_notes (incident_id, ts, author, note) VALUES (?,?,?,?)",
                 (scan["id"], NOW - 40, "securepi",
                  "Unknown host 'kali' joined 14 min ago with a randomized MAC. 16 ports probed on the NAS "
                  "in under a minute - quarantining pending identification."))
audit.log(conn, "securepi", "settings.update", "port_scan_threshold", "8 -> 8 (reviewed, unchanged)")
audit.log(conn, "securepi", "filtering.allow", "clients4.google.com", "unbreak: Android push notifications")
audit.log(conn, "securepi", "dpi.enroll", "10.10.0.31", "Tier 2 inspection enabled for 24h")
conn.execute("INSERT INTO saved_searches (name, filters, created_at) VALUES (?,?,?)",
             ("SSH to the NAS", json.dumps({"ip": "10.10.0.20", "port": "22", "range": "24h"}), NOW - DAY))
conn.execute("INSERT INTO saved_searches (name, filters, created_at) VALUES (?,?,?)",
             ("Blocked ad traffic", json.dumps({"domain": "doubleclick.net", "range": "24h"}), NOW - 2 * DAY))
conn.commit()
for r in conn.execute("SELECT id, signal_type, severity, status, evidence_count, title FROM incidents"):
    print(dict(r))
print("events:", conn.execute("SELECT count(*) FROM events").fetchone()[0])

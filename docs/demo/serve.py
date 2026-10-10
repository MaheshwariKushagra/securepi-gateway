#!/usr/bin/env python3
"""Run the real SecurePi console (app/webapp.py, unmodified on disk) locally on
the Mac against the synthetic demo DB, with gateway-only dependencies (the DNS filter's
API, nftables, the CA file) replaced by in-memory stand-ins."""
import datetime, os, shutil, sys, threading, time, types, json, sqlite3

# The repository root, two folders up from docs/demo/.
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(REPO, "app"))
sys.path.insert(0, os.path.join(REPO, "dpi"))
DB = os.path.join(HERE, "securepi.db")
RULE_STATS = os.path.join(HERE, "dpi-rule-stats.json")
if not os.path.exists(RULE_STATS):
    with open(RULE_STATS, "w") as f:
        f.write("{}")

import adguard, dpi_enroll, quarantine, correlation, rollup  # noqa: E402
import firewall_sets, notify, orchestrator  # noqa: E402

# ---- DNS-filter stand-in
iso = lambda h: (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=h)).isoformat()
FILTERS = [
    {"id": 1, "name": "Default DNS filter list", "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", "enabled": True, "rules_count": 71384, "last_updated": iso(3)},
    {"id": 2, "name": "AdAway Default Blocklist", "url": "https://adaway.org/hosts.txt", "enabled": True, "rules_count": 6540, "last_updated": iso(3)},
    {"id": 3, "name": "HaGeZi Pro", "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt", "enabled": True, "rules_count": 243921, "last_updated": iso(3)},
    {"id": 4, "name": "OISD Big", "url": "https://big.oisd.nl", "enabled": True, "rules_count": 331443, "last_updated": iso(3)},
    {"id": 5, "name": "Peter Lowe's List", "url": "https://pgl.yoyo.org/adservers/serverlist.php", "enabled": True, "rules_count": 3447, "last_updated": iso(3)},
]
USER_RULES = ["@@||clients4.google.com^$client='Galaxy-S23'  # unbreak", "||telemetry.example-vendor.com^"]
CLIENTS = [{"name": "Galaxy-S23", "ids": ["ca:25:11:6e:0b:31", "10.10.0.31"], "filtering_enabled": True}]


PROTECTION = {"enabled": True, "until": None}
CATALOG = [(sid, gid) for gid, ids in {
    "gaming": ["steam", "roblox", "epic_games", "minecraft", "playstation", "xboxlive", "twitch"],
    "social_network": ["tiktok", "instagram", "facebook", "snapchat", "reddit", "twitter", "onlyfans", "4chan"],
    "gambling": ["betway", "betfair"], "dating": ["tinder", "grindr"],
    "messenger": ["whatsapp", "telegram", "discord", "signal"], "shopping": ["amazon", "temu"],
    "ai": ["chatgpt", "claude"], "privacy": ["proton", "icloud_private_relay"],
    "streaming": ["youtube", "netflix", "spotify"]}.items() for sid in ids]


def fake_request(method, path, body=None):
    if path.startswith("/control/filtering/status"):
        return {"enabled": True, "interval": 24, "filters": FILTERS, "user_rules": USER_RULES}
    if path.startswith("/control/filtering/set_rules"):
        USER_RULES[:] = body["rules"]
        return None
    if path == "/control/clients/add":
        CLIENTS.append(dict(body))
        return None
    if path == "/control/clients/update":
        for i, c in enumerate(CLIENTS):
            if c["name"] == body["name"]:
                CLIENTS[i] = dict(body["data"])
        return None
    if path == "/control/clients/delete":
        CLIENTS[:] = [c for c in CLIENTS if c["name"] != body["name"]]
        return None
    if path.startswith("/control/clients"):
        return {"clients": CLIENTS}
    if path.startswith("/control/status"):
        left = max(0, int(((PROTECTION["until"] or 0) - time.time()) * 1000))
        if not PROTECTION["enabled"] and PROTECTION["until"] and left == 0:
            PROTECTION.update(enabled=True, until=None)  # The DNS filter's own auto-resume
        return {"protection_enabled": PROTECTION["enabled"], "protection_disabled_duration": left}
    if path.startswith("/control/protection"):
        PROTECTION["enabled"] = body["enabled"]
        PROTECTION["until"] = time.time() + body.get("duration", 0) / 1000.0 if not body["enabled"] else None
        return None
    if path.startswith("/control/blocked_services/all"):
        return {"blocked_services": [{"id": sid, "group_id": gid} for sid, gid in CATALOG]}
    if path.startswith("/control/dns_info"):
        return {"upstream_dns": ["tls://1.1.1.1", "tls://9.9.9.9"], "fallback_dns": ["https://dns.quad9.net/dns-query"],
                "upstream_mode": "parallel", "cache_enabled": True, "cache_optimistic": True,
                "cache_size": 4194304, "dnssec_enabled": True}
    if path.startswith("/control/filtering/check_host"):
        return demo_check_host(path)
    return {}


def _matches(name, domain):
    return name == domain or name.endswith("." + domain)


def demo_check_host(path):
    """The DNS filter's "would this be blocked for this device?" answer, worked
    out from the demo's own rules - so a usability-study participant who
    allows a domain for one device sees it allowed for that device only
    (step 7.9). Order as in the real filter: allow rules, then block rules,
    then the blocklists (here: every domain the seed recorded as blocked)."""
    from urllib.parse import parse_qs, urlsplit
    query = parse_qs(urlsplit(path).query)
    name = (query.get("name") or [""])[0].lower().rstrip(".")
    client_ip = (query.get("client") or [""])[0]
    client_name = None
    for c in CLIENTS:
        if client_ip and client_ip in c.get("ids", []):
            client_name = c["name"]
    for allow_first in (True, False):
        for rule in USER_RULES:
            text = rule.split("  #", 1)[0].strip()
            is_allow = text.startswith("@@")
            if is_allow != allow_first:
                continue
            body = text[2:] if is_allow else text
            domain, _, modifiers = body.partition("$")
            domain = domain.strip("|^")
            if not domain or not _matches(name, domain):
                continue
            if "client=" in modifiers:
                wanted = modifiers.split("client=", 1)[1].strip("'\"")
                if wanted != client_name:
                    continue
            return {"reason": "NotFilteredWhiteList" if is_allow else "FilteredBlackList",
                    "rules": [{"text": text, "filter_list_id": 0}]}
    with sqlite3.connect(DB) as conn:
        row = conn.execute("SELECT dns_rrname, dns_filter_list_id FROM events WHERE event_type='dns_query'"
                           " AND blocked=1 AND (dns_rrname=? OR ? LIKE '%.' || dns_rrname) LIMIT 1",
                           (name, name)).fetchone()
    if row:
        return {"reason": "FilteredBlackList", "rules": [{"text": "||%s^" % row[0], "filter_list_id": row[1] or 1}]}
    return {"reason": "NotFilteredNotFound", "rules": []}


adguard._request = fake_request
quarantine.quarantined_ips = lambda: []

# ---- nftables stand-ins: each set is {element: absolute expiry or None},
# reported back as seconds left, the way `nft -j list set` does.
SETS = {"mac": {}, "ip": {}, "enrolled": {"10.10.0.31": time.time() + 19 * 3600 + 1240}}


def _left(name):
    now = time.time()
    for k, v in list(SETS[name].items()):
        if v is not None and v <= now:
            del SETS[name][k]  # the kernel's own timeout
    return {k: (None if v is None else int(v - now)) for k, v in SETS[name].items()}


def _adder(name):
    return lambda value, seconds=None: SETS[name].__setitem__(value, None if seconds is None else time.time() + seconds)


firewall_sets.quarantined_macs = lambda: _left("mac")
firewall_sets.quarantine_mac = _adder("mac")
firewall_sets.release_mac = lambda mac: SETS["mac"].pop(mac, None)
firewall_sets.blocked_ips = lambda: _left("ip")
firewall_sets.block_ip = _adder("ip")
firewall_sets.unblock_ip = lambda ip: SETS["ip"].pop(ip, None)
dpi_enroll.enrolled = lambda: [{"ip": k, "expires_in_s": v} for k, v in _left("enrolled").items()]
dpi_enroll.enroll = lambda ip, hours=24: SETS["enrolled"].__setitem__(ip, time.time() + hours * 3600)
dpi_enroll.unenroll = lambda ip: SETS["enrolled"].pop(ip, None)
orchestrator.LOCK_PATH = os.path.join(HERE, "orchestrator.lock")

# ---- The demo edits its OWN copy of the DPI rule set, never the tracked
# dpi/adfilter-rules.json - saving a rule change in the demo console used
# to rewrite the real, deployed rules file in the repository. The copy is
# refreshed from the repository each time the demo starts.
DEMO_RULES = os.path.join(HERE, "adfilter-rules.demo.json")
shutil.copyfile(os.path.join(REPO, "dpi/adfilter-rules.json"), DEMO_RULES)

# ---- The demo password ("demo"), as a real hash file the console reads
# itself. It used to be faked by replacing _console_password() with a
# function returning the plain word - but since Audit10Oct H6 the login
# re-reads the password file before issuing a session, and refuses if it
# no longer holds what was checked, so a faked value refused every login.
# Created when missing (the file is gitignored, so a fresh checkout has none).
import session_auth  # noqa: E402
DEMO_PASSWORD_FILE = os.path.join(HERE, "console-password.demo")
if not os.path.exists(DEMO_PASSWORD_FILE):
    session_auth.write_password_file(DEMO_PASSWORD_FILE, session_auth.hash_password("demo"))

# ---- Load webapp.py with its gateway paths pointed at the repo / demo DB
src = open(os.path.join(REPO, "app/webapp.py")).read()
src = (src.replace('"/opt/securepi/static"', repr(os.path.join(REPO, "app/static")))
          .replace('"/opt/securepi/templates"', repr(os.path.join(REPO, "app/templates")))
          .replace('DB_PATH = "/var/lib/securepi/securepi.db"', "DB_PATH = %r" % DB)
          # step 3.1: a successful login rewrites this file with a fresh
          # hash (see session_auth.needs_rehash) - point that at a local,
          # writable path instead of the real gateway's one (moved out
          # of /root in step 3.3, but still root:securepi-group-owned,
          # which this Mac has no matching group for anyway).
          .replace('CONSOLE_PASSWORD_FILE = "/etc/securepi/console-password"',
                    "CONSOLE_PASSWORD_FILE = %r" % DEMO_PASSWORD_FILE)
          .replace('DPI_RULES_PATH = "/var/lib/securepi-dpi/adfilter-rules.json"',
                   "DPI_RULES_PATH = %r" % DEMO_RULES)
          .replace('"/var/log/securepi/dpi-rule-stats.json"', repr(os.path.join(HERE, "dpi-rule-stats.json"))))
webapp = types.ModuleType("webapp")
webapp.__file__ = os.path.join(REPO, "app/webapp.py")
sys.modules["webapp"] = webapp
exec(compile(src, webapp.__file__, "exec"), webapp.__dict__)
webapp._ca_info = lambda: {"available": True,
                           "fingerprint_sha256": "4F:9C:F9:2B:...:DEMO:ONLY",
                           "not_before": "Sep 12 08:00:00 2026 GMT", "not_after": "Sep 12 08:00:00 2028 GMT"}
correlation.DB_PATH = DB


def engine_loop():
    """The same 15s cycle engine.py runs on the gateway."""
    while True:
        c = sqlite3.connect(DB)
        c.row_factory = sqlite3.Row
        rollup.rollup_closed_hours(c)
        correlation.run_all(c)
        orchestrator.reconcile(c)
        notify.dispatch(c)
        now = time.time()
        c.execute("UPDATE ingest_stats SET last_run=? WHERE id=1", (now,))
        c.execute("INSERT OR REPLACE INTO signal_state VALUES ('privacy_scope', ?)", (now - 240,))
        c.execute("UPDATE devices SET last_seen=? WHERE id IN (1,2,3,4,5,6,7)", (now - 30,))
        c.commit()
        c.close()
        time.sleep(15)


threading.Thread(target=engine_loop, daemon=True).start()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(webapp.app, host="127.0.0.1", port=8765, log_level="warning")

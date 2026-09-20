#!/usr/bin/env python3
"""Run the real SecurePi console (app/webapp.py, unmodified on disk) locally on
the Mac against the synthetic demo DB, with gateway-only dependencies (AdGuard
Home's API, nftables, the CA file) replaced by in-memory stand-ins."""
import datetime, os, sys, threading, time, types, json, sqlite3

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

# ---- AdGuard Home stand-in
iso = lambda h: (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=h)).isoformat()
FILTERS = [
    {"id": 1, "name": "AdGuard DNS filter", "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", "enabled": True, "rules_count": 71384, "last_updated": iso(3)},
    {"id": 2, "name": "AdAway Default Blocklist", "url": "https://adaway.org/hosts.txt", "enabled": True, "rules_count": 6540, "last_updated": iso(3)},
    {"id": 3, "name": "HaGeZi Pro", "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt", "enabled": True, "rules_count": 243921, "last_updated": iso(3)},
    {"id": 4, "name": "OISD Big", "url": "https://big.oisd.nl", "enabled": True, "rules_count": 331443, "last_updated": iso(3)},
    {"id": 5, "name": "Peter Lowe's List", "url": "https://pgl.yoyo.org/adservers/serverlist.php", "enabled": True, "rules_count": 3447, "last_updated": iso(3)},
]
USER_RULES = ["@@||clients4.google.com^$client='Galaxy-S23'  # unbreak", "||telemetry.example-vendor.com^"]
CLIENTS = [{"name": "Galaxy-S23", "ids": ["ca:25:11:6e:0b:31", "10.10.0.31"], "filtering_enabled": True}]


def fake_request(method, path, body=None):
    if path.startswith("/control/filtering/status"):
        return {"enabled": True, "interval": 24, "filters": FILTERS, "user_rules": USER_RULES}
    if path.startswith("/control/clients"):
        return {"clients": CLIENTS}
    if path.startswith("/control/dns_info"):
        return {"upstream_dns": ["tls://1.1.1.1", "tls://9.9.9.9"], "fallback_dns": ["https://dns.quad9.net/dns-query"],
                "upstream_mode": "parallel", "cache_enabled": True, "cache_optimistic": True,
                "cache_size": 4194304, "dnssec_enabled": True}
    if path.startswith("/control/filtering/check_host"):
        return {"reason": "FilteredBlackList", "rules": [{"text": "||doubleclick.net^", "filter_list_id": 1}]}
    return {}


adguard._request = fake_request
dpi_enroll.enrolled = lambda: [{"ip": "10.10.0.31", "expires_in_s": 19 * 3600 + 1240}]
quarantine.quarantined_ips = lambda: ["10.10.0.66"]

# ---- Load webapp.py with its gateway paths pointed at the repo / demo DB
src = open(os.path.join(REPO, "app/webapp.py")).read()
src = (src.replace('"/opt/securepi/static"', repr(os.path.join(REPO, "app/static")))
          .replace('"/opt/securepi/templates"', repr(os.path.join(REPO, "app/templates")))
          .replace('DB_PATH = "/opt/securepi/securepi.db"', "DB_PATH = %r" % DB)
          # step 3.1: a successful login rewrites this file with a fresh
          # hash (see session_auth.needs_rehash) - point that at a local,
          # writable path instead of the real gateway's one (moved out
          # of /root in step 3.3, but still root:securepi-group-owned,
          # which this Mac has no matching group for anyway).
          .replace('CONSOLE_PASSWORD_FILE = "/etc/securepi/console-password"',
                    "CONSOLE_PASSWORD_FILE = %r" % os.path.join(HERE, "console-password.demo"))
          .replace('DPI_RULES_PATH = "/opt/securepi-dpi/adfilter-rules.json"',
                   "DPI_RULES_PATH = %r" % os.path.join(REPO, "dpi/adfilter-rules.json"))
          .replace('"/var/log/securepi/dpi-rule-stats.json"', repr(os.path.join(HERE, "dpi-rule-stats.json"))))
webapp = types.ModuleType("webapp")
webapp.__file__ = os.path.join(REPO, "app/webapp.py")
sys.modules["webapp"] = webapp
exec(compile(src, webapp.__file__, "exec"), webapp.__dict__)
webapp._console_password = lambda: "demo"
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

#!/usr/bin/env python3
"""
SecurePi Gateway - offline threat intelligence (ENHANCEMENT-PLAN.md step
2.4).

Fetches three abuse.ch feeds daily (run by securepi-intel-refresh.timer,
never on a request path - "offline" in this step's own name means "not a
live lookup service", not "no internet access needed" - the fetch itself
obviously needs it):

  - Feodo Tracker: known botnet command-and-control IP addresses.
  - URLhaus: hostnames currently serving malware, as a hosts-file-style
    list (127.0.0.1  <hostname> per line).
  - ThreatFox: mixed-type IOCs. Only the 'ip:port' and 'domain' rows are
    used - hash-type rows (sha256/sha1/md5) aren't network-matchable, and
    'url' rows would need parsing out a hostname this project doesn't
    otherwise need. Real column layout confirmed against a live download
    (14 September 2026), not guessed from documentation.

Every fetch function returns a list of (indicator, ioc_type, description)
tuples and raises on failure - refresh_all() below is what decides a
failure means "leave yesterday's indicators in place", never "empty the
table". See gateway/refresh-doh-set.sh for the same fail-safe philosophy
applied to nftables' doh_resolvers set.

Domain-type indicators are also written to a plain blocklist file, served
over loopback HTTP by securepi-static.service (AdGuard's own add_url
endpoint validates the URL scheme and rejects file:// outright - the
first design here assumed otherwise and was corrected after a live 400
response), and registered with AdGuard as a normal blocklist source -
"the same domains are pushed to AdGuard... so they're both blocked and
turned into incidents", per this step's own wording. IP-type indicators
aren't pushed anywhere: AdGuard blocks DNS names, not arbitrary
destination IPs, so those exist only for app/correlation.py's
threat_intel_signal to match against events.dest_ip.
"""

import os
import re
import sqlite3
import time
import urllib.error
import urllib.request

import adguard

DB_PATH = "/var/lib/securepi/securepi.db"
DOMAIN_BLOCKLIST_DIR = "/opt/securepi/static"
DOMAIN_BLOCKLIST_PATH = DOMAIN_BLOCKLIST_DIR + "/ioc-domains.txt"
BLOCKLIST_MAX_AGE_DAYS = 30  # see _write_domain_blocklist_file
# AdGuard's add_url endpoint validates the URL scheme server-side and
# rejects anything but http/https outright (confirmed live: a file://
# URL fails with "bad enum value: \"file\"; want \"http\" or \"https\"" -
# an assumption this project got wrong on the first attempt and fixed
# rather than worked around). securepi-static.service (a plain
# `python3 -m http.server`, the same pattern dpi/deploy-dpi.sh already
# uses for the CA download server) serves this directory on loopback
# only - nothing here needs to be reachable from the LAN, just from
# AdGuard's own process on this same host.
DOMAIN_BLOCKLIST_URL = "http://127.0.0.1:8082/ioc-domains.txt"
FETCH_TIMEOUT_SECONDS = 30

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"
THREATFOX_URL = "https://threatfox.abuse.ch/export/csv/recent/"

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _fetch_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": "SecurePi-Gateway-Intel/1.0"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_SECONDS) as resp:
        return resp.read().decode("utf-8", errors="replace")


def fetch_feodo():
    """Feodo Tracker's IP blocklist: one bare IP per line, '#'-comments
    and a blank-line-free plain text file - confirmed against a live
    download."""
    text = _fetch_text(FEODO_URL)
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if IP_RE.match(line):
            out.append((line, "ip", "Feodo Tracker botnet C2"))
    return out


def fetch_urlhaus():
    """URLhaus's host file: '127.0.0.1<TAB>hostname' per line, plus
    '#'-comment header lines - confirmed against a live download."""
    text = _fetch_text(URLHAUS_URL)
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) == 2 and parts[0] == "127.0.0.1":
            out.append((parts[1], "domain", "URLhaus malware-hosting host"))
    return out


def _parse_csv_line(line):
    """ThreatFox's export is CSV with every field double-quoted AND a
    space after each separating comma - confirmed against a live
    download: `"field1", "field2", "field3"`, not the more common
    `"field1","field2","field3"`. Python's csv module would also work,
    but this feed's own quoting is simple and consistent enough that a
    plain split on the exact separator is clearer here than pulling in
    csv for one caller."""
    return [f.strip().strip('"') for f in line.split('", "')]


def fetch_threatfox():
    """ThreatFox's recent-IOCs CSV. Columns confirmed live: first_seen_utc,
    id, ioc_value, ioc_type, threat_type, malware, malware_alias,
    malware_printable, ... Only ioc_type in {'ip:port', 'domain'} is used
    - see the module docstring for why the others are skipped."""
    text = _fetch_text(THREATFOX_URL)
    out = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = _parse_csv_line(line)
        if len(fields) < 6:
            continue
        ioc_value, ioc_type, malware = fields[2], fields[3], fields[7] if len(fields) > 7 else ""
        description = "ThreatFox: %s" % (malware or fields[5] or "unspecified malware")
        if ioc_type == "domain":
            out.append((ioc_value, "domain", description))
        elif ioc_type == "ip:port":
            ip = ioc_value.split(":")[0]
            if IP_RE.match(ip):
                out.append((ip, "ip", description))
    return out


FEEDS = {
    "feodo": fetch_feodo,
    "urlhaus": fetch_urlhaus,
    "threatfox": fetch_threatfox,
}


def _upsert_indicators(conn, source, indicators, now):
    """Insert new indicators, extend last_seen for ones still present -
    never touches a row from a DIFFERENT source, and never deletes a row
    just because this particular feed no longer lists it (a conservative
    choice: an indicator ThreatFox drops but Feodo still lists stays
    live, and even a single feed dropping something doesn't retroactively
    un-flag traffic already correlated against it)."""
    for indicator, ioc_type, description in indicators:
        conn.execute(
            """INSERT INTO ioc (indicator, ioc_type, source, description, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(indicator, ioc_type, source)
               DO UPDATE SET last_seen = excluded.last_seen, description = excluded.description""",
            (indicator, ioc_type, source, description, now, now),
        )


def _write_domain_blocklist_file(conn):
    """Every CURRENT domain-type IOC, as a plain AdGuard-syntax blocklist
    file - the mechanism that turns these into a Tier 1 block, not just a
    correlation match. Rewritten in full each refresh; AdGuard re-reads
    it on its own configured interval, same as any other blocklist URL.

    "Current" means its feed listed it within BLOCKLIST_MAX_AGE_DAYS of
    that same feed's most recent refresh. The ioc table deliberately
    keeps every indicator ever seen (see _upsert_indicators) so past
    traffic can still be matched against it - but abuse.ch feeds list a
    lot of hacked, legitimate websites that are later cleaned up, and
    blocking those for ever turns yesterday's warning into today's broken
    website (Audit.md). Measured against each feed's own latest refresh,
    not today's date, so a feed that can't be downloaded for a while
    doesn't empty the blocklist."""
    os.makedirs(DOMAIN_BLOCKLIST_DIR, exist_ok=True)
    rows = conn.execute(
        """SELECT DISTINCT i.indicator FROM ioc i
            WHERE i.ioc_type = 'domain'
              AND i.last_seen >= (SELECT max(j.last_seen) FROM ioc j WHERE j.source = i.source) - ?""",
        (BLOCKLIST_MAX_AGE_DAYS * 86400,),
    ).fetchall()
    with open(DOMAIN_BLOCKLIST_PATH, "w") as f:
        f.write("! Title: SecurePi Gateway - offline threat intel (abuse.ch)\n")
        f.write("! Rewritten by app/intel.py - do not edit by hand\n")
        for r in rows:
            f.write("||%s^\n" % r["indicator"])


def refresh_all(conn):
    """Refresh every feed. Returns {source: (ok, count_or_error)}. A
    failed feed's existing indicators are left untouched (fail-safe) -
    only intel_feed_state records the failure, so 'feed age visible'
    (this step's own exit criterion) can show a real, honest age even
    when today's fetch didn't succeed."""
    now = time.time()
    results = {}
    for source, fetch_fn in FEEDS.items():
        try:
            indicators = fetch_fn()
            if not indicators:
                raise ValueError("feed returned zero indicators - treating as a bad fetch")
            _upsert_indicators(conn, source, indicators, now)
            conn.execute(
                """INSERT INTO intel_feed_state (source, last_fetched, last_error, indicator_count)
                       VALUES (?, ?, NULL, ?)
                   ON CONFLICT(source) DO UPDATE SET
                       last_fetched=excluded.last_fetched, last_error=NULL,
                       indicator_count=excluded.indicator_count""",
                (source, now, len(indicators)),
            )
            results[source] = (True, len(indicators))
        except (urllib.error.URLError, ValueError, OSError) as exc:
            conn.execute(
                """INSERT INTO intel_feed_state (source, last_fetched, last_error, indicator_count)
                       VALUES (?, NULL, ?, NULL)
                   ON CONFLICT(source) DO UPDATE SET last_error=excluded.last_error""",
                (source, str(exc)),
            )
            results[source] = (False, str(exc))
    conn.commit()
    _write_domain_blocklist_file(conn)
    return results


def ensure_adguard_blocklist_registered():
    """Register the domain blocklist file with AdGuard if it isn't
    already - idempotent, safe to call every run (add_blocklist's own
    docstring: AdGuard's add_url endpoint, called here through the same
    thin wrapper every other blocklist registration in this project
    uses)."""
    existing = {f["url"] for f in adguard.filtering_status().get("filters", [])}
    if DOMAIN_BLOCKLIST_URL not in existing:
        adguard.add_blocklist("Offline Threat Intel (abuse.ch, via SecurePi)", DOMAIN_BLOCKLIST_URL)


def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    results = refresh_all(conn)
    for source, result in results.items():
        ok, detail = result
        print("intel: %s -> %s" % (source, ("%d indicators" % detail) if ok else ("FAILED: %s" % detail)),
              flush=True)
    ensure_adguard_blocklist_registered()


if __name__ == "__main__":
    main()

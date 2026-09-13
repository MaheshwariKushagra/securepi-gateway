#!/usr/bin/env python3
"""
SecurePi Gateway - device fingerprinting (ENHANCEMENT-PLAN.md step 6.2).

Combines several weak, independent signals into a best-guess device
type/vendor/OS with a confidence level, plus the actual evidence that
led there - never a bare verdict with nothing behind it. This is
explicitly a SECOND identity anchor for display (the operator can see
"this looks like a Samsung Android phone"), not a replacement for
registry.py's own MAC/hostname-based identity resolution, and it is not
wired into that resolution logic this pass - see the plan's note on
this step for why that's a deliberate scope boundary, not an oversight.

Signals used, and how confidently, stated plainly rather than implied
by the code alone
-------------------------------------------------------------------------
- **Hostname patterns** (HOSTNAME_PATTERNS) - real signal, real data
  (the device's own announced DHCP hostname). Patterns are generic
  vendor/product-name substrings and Samsung's public Galaxy model-code
  convention (S-series, A-series, Note, Z Fold/Flip - product names,
  not anything specific to a device seen on this network), not hardcoded
  to any specific real hostname.
- **Connectivity-check domains** (CONNECTIVITY_CHECK_DOMAINS) - real
  signal, matched against the device's actual DNS query history. These
  are well-documented, widely-used captive-portal-detection endpoints
  each OS vendor ships (Android/iOS/Windows/Firefox/GNOME each probe a
  known domain on every network change) - high confidence in the domain
  names themselves, since they're stable, publicly documented, and
  don't change with a device's specific configuration the way a MAC or
  a TLS fingerprint would.
- **MAC OUI** (OUI_PREFIXES) - deliberately a SHORT list. Getting an
  IEEE OUI prefix wrong is actively misleading, unlike a domain name a
  wrong table entry would just be a silent no-op for; this file avoids
  guessing exact hex values from memory beyond a couple of very
  well-known ones. Only ever consulted for a NON-randomized MAC - see
  is_randomized handling below - which is why this signal likely
  contributes nothing at all for either real phone on this network,
  since both use randomized MACs. That is reported honestly
  ("mac_randomized") rather than silently skipped without explanation.
- **JA3** and **DHCP option 55** (dhcp_params) - shown as raw EVIDENCE
  only, never used to vote on a classification. Neither has a verified
  reference database behind it in this codebase: a real device's JA3
  varies per app/library making the connection, not per OS, so using
  one device's own observed hashes to classify itself (or worse, other
  devices) would be circular; and no real extended-mode DHCP event has
  been observed yet to confirm the option-55 field even parses as
  expected (see ingest.py's flatten_suricata). Showing them as evidence
  without a fabricated lookup table is the honest middle ground.
"""

import re

# (regex, category, vendor, os, weight). Matched against devices.hostname,
# case-insensitively. category is one of "phone", "tablet", "computer",
# "iot"; vendor/os may be None when the pattern doesn't imply one.
HOSTNAME_PATTERNS = [
    (r"iphone", "phone", "Apple", "iOS", 3),
    (r"ipad", "tablet", "Apple", "iPadOS", 3),
    (r"macbook", "computer", "Apple", "macOS", 3),
    (r"\bimac\b", "computer", "Apple", "macOS", 3),
    (r"android", "phone", None, "Android", 2),
    (r"galaxy", "phone", "Samsung", "Android", 3),
    # Samsung's own public Galaxy model-code convention (S/A/Note/Z-series -
    # real product names, not specific to any device on this network).
    (r"-s2[0-9]\b", "phone", "Samsung", "Android", 3),
    (r"-a[0-9]{2}\b", "phone", "Samsung", "Android", 2),
    (r"\bnote[0-9]*\b", "phone", "Samsung", "Android", 2),
    (r"z[- ]?fold|z[- ]?flip", "phone", "Samsung", "Android", 3),
    (r"pixel", "phone", "Google", "Android", 3),
    (r"redmi|poco", "phone", "Xiaomi", "Android", 3),
    (r"\bmi[- ]?[0-9]", "phone", "Xiaomi", "Android", 2),
    (r"xiaomi", "phone", "Xiaomi", "Android", 2),
    (r"oneplus", "phone", "OnePlus", "Android", 3),
    (r"realme", "phone", "Realme", "Android", 2),
    (r"\boppo\b", "phone", "Oppo", "Android", 2),
    (r"\bvivo\b", "phone", "Vivo", "Android", 2),
    (r"desktop-", "computer", "Microsoft", "Windows", 3),
    (r"-pc\b", "computer", None, "Windows", 1),
    (r"laptop", "computer", None, None, 1),
    (r"raspberry[- ]?pi", "iot", "Raspberry Pi Foundation", "Linux", 3),
    (r"echo-|amazon-echo", "iot", "Amazon", None, 3),
    (r"firetv|fire-tv", "iot", "Amazon", "Fire OS", 3),
    (r"chromecast", "iot", "Google", "Chromecast", 3),
    (r"\broku\b", "iot", "Roku", None, 3),
    (r"sonos", "iot", "Sonos", None, 3),
    (r"nest-", "iot", "Google", None, 2),
    (r"smart-tv|smarttv", "iot", None, None, 2),
]

# Well-documented, stable per-OS captive-portal / connectivity-check
# endpoints - see this module's docstring for why these carry more
# confidence than the OUI table below.
CONNECTIVITY_CHECK_DOMAINS = {
    "connectivitycheck.gstatic.com": ("Android", 3),
    "connectivitycheck.android.com": ("Android", 3),
    "clients3.google.com": ("Android", 2),
    "captive.apple.com": ("iOS/macOS", 3),
    "gsp-ssl.ls.apple.com": ("iOS/macOS", 2),
    "www.msftconnecttest.com": ("Windows", 3),
    "www.msftncsi.com": ("Windows", 3),
    "dns.msftncsi.com": ("Windows", 2),
    "detectportal.firefox.com": ("Firefox", 2),
    "nmcheck.gnome.org": ("Linux (GNOME)", 3),
}

# Deliberately short - see this module's docstring for why. Expand this
# from a real IEEE OUI registry export before trusting it beyond these
# couple of entries. Keys are the first 3 octets, colon-separated,
# uppercase, matching how MACs are stored elsewhere in this project.
OUI_PREFIXES = {
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
}


def _hostname_evidence(hostname):
    if not hostname:
        return []
    out = []
    for pattern, category, vendor, os_name, weight in HOSTNAME_PATTERNS:
        if re.search(pattern, hostname, re.IGNORECASE):
            out.append({
                "source": "hostname", "detail": "hostname matches /%s/" % pattern,
                "category": category, "vendor": vendor, "os": os_name, "weight": weight,
            })
    return out


def _connectivity_check_evidence(c, device_id):
    rows = c.execute(
        "SELECT DISTINCT dns_rrname FROM events"
        " WHERE device_id=? AND event_type='dns_query' AND dns_rrname IS NOT NULL",
        (device_id,)).fetchall()
    queried = {r["dns_rrname"].lower().rstrip(".") for r in rows}
    out = []
    for domain, (os_name, weight) in CONNECTIVITY_CHECK_DOMAINS.items():
        if domain in queried:
            out.append({
                "source": "connectivity_check", "detail": "queried %s" % domain,
                "category": None, "vendor": None, "os": os_name, "weight": weight,
            })
    return out


def _oui_evidence(c, device_id):
    macs = c.execute(
        "SELECT mac, is_randomized FROM device_macs WHERE device_id=?", (device_id,)).fetchall()
    if not macs:
        return []
    if all(m["is_randomized"] for m in macs):
        return [{
            "source": "mac_oui", "detail": "every MAC seen for this device is randomized - "
                                            "no manufacturer prefix to read",
            "category": None, "vendor": None, "os": None, "weight": 0,
        }]
    out = []
    for m in macs:
        if m["is_randomized"]:
            continue
        prefix = m["mac"].upper().replace("-", ":")[:8]
        vendor = OUI_PREFIXES.get(prefix)
        if vendor:
            out.append({
                "source": "mac_oui", "detail": "%s prefix matches %s" % (prefix, vendor),
                "category": None, "vendor": vendor, "os": None, "weight": 3,
            })
    return out


def _ja3_evidence(c, device_id):
    """Informational only - see this module's docstring for why JA3
    never contributes a classification vote here."""
    rows = c.execute(
        "SELECT tls_ja3, count(*) n FROM events"
        " WHERE device_id=? AND tls_ja3 IS NOT NULL GROUP BY tls_ja3 ORDER BY n DESC LIMIT 3",
        (device_id,)).fetchall()
    if not rows:
        return []
    summary = ", ".join("%s (x%d)" % (r["tls_ja3"], r["n"]) for r in rows)
    return [{
        "source": "ja3", "detail": "most common TLS client fingerprints: %s" % summary,
        "category": None, "vendor": None, "os": None, "weight": 0,
    }]


def _dhcp_params_evidence(c, device_id):
    """Informational only - no reference database of option-55 sequences
    exists in this codebase yet. See this module's docstring."""
    macs = [r["mac"] for r in c.execute(
        "SELECT mac FROM device_macs WHERE device_id=?", (device_id,))]
    if not macs:
        return []
    placeholders = ",".join("?" for _ in macs)
    row = c.execute(
        "SELECT dhcp_params FROM events"
        " WHERE event_type='dhcp' AND dhcp_params IS NOT NULL"
        "   AND src_ip IN (SELECT ip FROM device_ips WHERE device_id=?)"
        " ORDER BY ts DESC LIMIT 1", (device_id,)).fetchone()
    if not row:
        return []
    return [{
        "source": "dhcp_option_55", "detail": "requested parameters: %s" % row["dhcp_params"],
        "category": None, "vendor": None, "os": None, "weight": 0,
    }]


def classify(c, device_id, hostname):
    """Combine every signal into a best-guess (category, vendor, os) plus
    a confidence tier and the full evidence list behind it. Each of
    category/vendor/os is voted on independently - a piece of evidence
    can inform one, two, or none of them (a connectivity-check domain
    says nothing about vendor; a hostname match for "galaxy" says
    nothing about which specific device category beyond "phone", which
    it does specify).
    """
    evidence = (
        _hostname_evidence(hostname)
        + _connectivity_check_evidence(c, device_id)
        + _oui_evidence(c, device_id)
        + _ja3_evidence(c, device_id)
        + _dhcp_params_evidence(c, device_id)
    )

    def best(field):
        votes = {}
        for e in evidence:
            val = e.get(field)
            if val:
                votes[val] = votes.get(val, 0) + e["weight"]
        if not votes:
            return None, 0
        winner = max(votes, key=votes.get)
        return winner, votes[winner]

    category, cat_weight = best("category")
    vendor, vendor_weight = best("vendor")
    os_name, os_weight = best("os")

    total_weight = cat_weight + vendor_weight + os_weight
    if total_weight >= 6:
        confidence = "high"
    elif total_weight >= 3:
        confidence = "medium"
    elif total_weight > 0:
        confidence = "low"
    else:
        confidence = "unknown"

    return {
        "category": category,
        "vendor": vendor,
        "os": os_name,
        "confidence": confidence,
        "evidence": evidence,
    }

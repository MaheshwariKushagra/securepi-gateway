#!/usr/bin/env python3
"""
SecurePi Gateway - DNS-filter client.

The DNS filter owns DNS filtering: blocklist sources, custom allow/block rules,
and per-client policy. This module is a thin wrapper around its control API
so the console can manage filtering without an operator opening the DNS filter's
own UI - which is deliberately bound to 127.0.0.1 and never exposed on the
network (see REPORT-adblocking.md).

Uses urllib rather than requests: this is the only place in the app that
needs an HTTP client, so a stdlib call beats adding a dependency on a
memory-constrained gateway (see SECUREPI-15-DAY-PLAN.md 2.6).
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode

BASE_URL = "http://127.0.0.1:3000"
USERNAME = "securepi"
# Moved out of /root (step 3.3, finding G9): once securepi-web drops
# root it can no longer traverse into /root at all. /etc/securepi is
# root:securepi, 750 - the unprivileged service user's own group can
# read this file directly, the same proportionate "plain data file,
# not firewall control" reasoning app/webapp.py's CONSOLE_PASSWORD_FILE
# comment gives.
PASSWORD_FILE = "/etc/securepi/dns-password"


class AdGuardError(Exception):
    """The DNS filter could not be reached, or rejected a request."""


def _password():
    try:
        with open(PASSWORD_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        raise AdGuardError("DNS-filter admin password file is missing: %s" % PASSWORD_FILE)


def _request(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE_URL + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    token = b64encode(("%s:%s" % (USERNAME, _password())).encode()).decode()
    req.add_header("Authorization", "Basic %s" % token)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read()
            if not raw:
                return None
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                # Several DNS-filter endpoints (add_url, remove_url, ...) reply
                # with a plain-text "OK ..." body on success, not JSON.
                return raw.decode(errors="replace")
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace").strip()
        reason = (": %s" % detail) if detail else ""
        raise AdGuardError("The DNS filter rejected %s %s (HTTP %d)%s" % (method, path, e.code, reason))
    except (urllib.error.URLError, OSError) as e:
        raise AdGuardError("Could not reach the DNS filter at %s: %s" % (BASE_URL, e))


# --------------------------------------------------------------- blocklists

def filtering_status():
    return _request("GET", "/control/filtering/status") or {}


def set_filtering_enabled(enabled):
    _request("POST", "/control/filtering/config", {"enabled": enabled, "interval": 24})


def add_blocklist(name, url):
    _request("POST", "/control/filtering/add_url", {"name": name, "url": url, "whitelist": False})


def remove_blocklist(url):
    _request("POST", "/control/filtering/remove_url", {"url": url, "whitelist": False})


def set_blocklist_enabled(url, enabled):
    current = next((f for f in filtering_status().get("filters", []) if f["url"] == url), None)
    if current is None:
        raise AdGuardError("no blocklist registered with that URL")
    _request("POST", "/control/filtering/set_url", {
        "url": url, "whitelist": False,
        "data": {"enabled": enabled, "name": current["name"], "url": url},
    })


# -------------------------------------------------------------- user rules

def user_rules():
    return filtering_status().get("user_rules") or []


def add_user_rule(domain, action):
    """action is 'block' or 'allow'. A no-op if the rule already exists."""
    rule = ("||%s^" % domain) if action == "block" else ("@@||%s^" % domain)
    rules = user_rules()
    if rule not in rules:
        rules.append(rule)
        _request("POST", "/control/filtering/set_rules", {"rules": rules})


def remove_user_rule(rule):
    rules = [r for r in user_rules() if r != rule]
    _request("POST", "/control/filtering/set_rules", {"rules": rules})


def add_nxdomain_rule(domain):
    """Force a genuine NXDOMAIN response for this exact domain, regardless
    of the gateway's global blocking_mode (confirmed live: this gateway
    runs 'default' mode, which answers a plain blocked query with
    0.0.0.0/:: - a real, if bogus, answer, not a failed lookup).

    ENHANCEMENT-PLAN.md step 2.2 needs this for two specific domains that
    check for a FAILED resolution, not just "some answer": Firefox's DoH
    canary (use-application-dns.net - Firefox auto-enables DoH unless this
    fails to resolve) and Apple's iCloud Private Relay opt-out domains
    (mask.icloud.com / mask-h2.icloud.com - Apple's own documented network
    signal for disabling Private Relay). A plain add_user_rule('block')
    would answer 0.0.0.0 here, which is a resolvable address as far as
    either check is concerned - it would not actually disable either
    feature. The DNS filter's $dnsrewrite modifier overrides the global mode on a
    per-rule basis; NXDOMAIN is one of its documented shorthand values."""
    rule = "||%s^$dnsrewrite=NXDOMAIN" % domain
    rules = user_rules()
    if rule not in rules:
        rules.append(rule)
        _request("POST", "/control/filtering/set_rules", {"rules": rules})


def describe_rule(rule):
    """Turn a raw DNS-filter rule string into something the console can show
    next to a plain-language action, rather than syntax the operator has to
    parse themselves.

    Handles both network-wide rules (||domain^ / @@||domain^) and the
    per-device rules the orchestrator writes via domain_rule() (the same
    shape, with a trailing $client=name modifier after the ^). A trailing
    "  # ..." comment is stripped first: rules written by an older version
    of this module carried one, and a live DNS filter may still hold them."""
    body = rule.partition("  #")[0]
    scope = "network"
    if "^$client=" in body:
        body, _, client_name = body.partition("^$client=")
        body += "^"
        scope = "device: %s" % unquote_client(client_name)
    if body.startswith("@@||") and body.endswith("^"):
        return {"rule": rule, "domain": body[4:-1], "action": "allow", "scope": scope}
    if body.startswith("||") and body.endswith("^"):
        return {"rule": rule, "domain": body[2:-1], "action": "block", "scope": scope}
    return {"rule": rule, "domain": None, "action": "custom", "scope": scope}


# ----------------------------------------------------------- per-client policy
#
# A device is identified to the DNS filter by a LIST of identifiers - every MAC it
# has ever used, plus its current IP - not by IP alone.
#
# Why this matters: the DNS filter is also our DHCP server, so it supports MAC-based
# client identifiers directly. Keying on IP alone (the original version of
# this module) meant a device's per-device filtering setting was silently
# lost every time its DHCP lease renewed to a new address - the device kept
# its identity in OUR device registry, but the DNS filter had no way to know the
# "new" IP was the same device. See ENHANCEMENT-PLAN.md finding A3.

def _find_client(identifiers):
    """identifiers is a list of MACs and/or IPs that could name this device.
    Returns the first persistent client whose own id list overlaps with any
    of them."""
    wanted = set(identifiers)
    if not wanted:
        return None
    clients = _request("GET", "/control/clients") or {}
    for cl in clients.get("clients") or []:
        if wanted & set(cl.get("ids") or []):
            return cl
    return None


def client_filtering_status(identifiers):
    cl = _find_client(identifiers)
    if cl is None:
        return {"managed": False, "filtering_enabled": True}
    return {"managed": True, "filtering_enabled": bool(cl.get("filtering_enabled", True))}


# --------------------------------------------------------- "why blocked?"

def check_host(name, client_ip=None):
    """Ask the DNS filter how it would resolve `name` right now, exactly as if a
    query for it arrived from `client_ip` - this is the engine behind the
    console's "why is this blocked?" tool. Passing client_ip matters because
    a per-device ($client=) rule or a per-client upstream
    only applies to a query the DNS filter can see as coming from that client."""
    path = "/control/filtering/check_host?name=%s" % urllib.parse.quote(name)
    if client_ip:
        path += "&client=%s" % urllib.parse.quote(client_ip)
    return _request("GET", path) or {}


# Plain-language reasons for the codes the DNS filter's check_host and query log
# both use, so the console never has to show raw DNS-filter internals to the
# operator - the same normalization spirit as describe_rule() below.
_REASON_TEXT = {
    "NotFilteredNotFound": "Not blocked - no rule matches this domain",
    "NotFilteredAllowList": "Allowed by an explicit rule",
    "NotFilteredWhiteList": "Allowed by an explicit rule",
    "FilteredBlackList": "Blocked by a blocklist rule",
    "FilteredSafeBrowsing": "Blocked - flagged as unsafe",
    "FilteredParental": "Blocked by parental controls",
    "FilteredInvalid": "Blocked - invalid response from upstream",
    "FilteredSafeSearch": "Rewritten to enforce safe search",
    "FilteredBlockedService": "Blocked - part of a blocked service",
    "Rewritten": "Answered by a local rewrite",
    "RewrittenAutoHosts": "Answered from the local hosts file",
    "RewrittenRule": "Answered by a rewrite rule",
}


def describe_check(result, domain):
    """Turn a check_host response into what the console shows: a plain
    verdict, whether it's blocked, and which rule/list is responsible.

    `domain` is passed in rather than read from `result` because the DNS filter's
    check_host response never echoes the hostname it was asked about at
    all (confirmed against a live gateway - {"reason":..., "rule":...,
    "rules":[...], ...}, no "host" or "name" key anywhere). Assuming one
    existed was a real bug caught during the first live deploy of this
    feature - the console showed "null" as the domain in every result
    until this was fixed.

    `cname`, if the DNS filter reports one, means the block happened via
    CNAME-cloaking: the queried domain itself doesn't match any rule, but
    the address it's an alias for does (see ENHANCEMENT-PLAN.md step
    5.5). This on-demand check is the only place this project currently
    surfaces that - the DNS filter's stored query log has no equivalent field
    (confirmed by inspecting it directly), only the raw base64 DNS answer
    packet, which would need a hand-written wire-format parser to read;
    tagging historical blocked events as CNAME-cloaked or not is deferred
    rather than guessed at from an unparsed field."""
    reason = result.get("reason", "")
    rule = None
    filter_id = None
    if result.get("rules"):
        rule = result["rules"][0].get("text")
        filter_id = result["rules"][0].get("filter_list_id")
    return {
        "domain": domain,
        "blocked": reason.startswith("Filtered") and reason != "FilteredSafeSearch",
        "reason_code": reason,
        "reason": _REASON_TEXT.get(reason, reason or "Unknown"),
        "rule": rule,
        "filter_list_id": filter_id,
        "cname": result.get("cname") or None,
    }


# ------------------------------------------------------------- resolver --
#
# Resolver quality (step 5.5c): cache behaviour, DNSSEC, and upstream
# redundancy. Read-only by default - applying a change here affects DNS
# resolution for the whole network, which is exactly the kind of
# shared-infrastructure change this project's own operating rules say to
# confirm before doing, not just before deploying the code that could do
# it. set_dns_tuning() exists so the console can offer it as an explicit,
# reviewable action; nothing calls it automatically.

def dns_config():
    """Current resolver configuration, straight from the DNS filter - confirmed
    live against the real endpoint (GET /control/dns_info), not guessed:
    upstream_dns, cache_optimistic, dnssec_enabled and friends."""
    return _request("GET", "/control/dns_info") or {}


def set_dns_tuning(upstream_dns=None, fallback_dns=None, cache_optimistic=None,
                    dnssec_enabled=None, upstream_mode=None):
    """Update resolver settings, changing only the fields actually passed
    in - everything else is read back from the live config first and sent
    through unchanged, since the DNS filter's dns_config endpoint replaces the
    whole object rather than patching it. Every argument left as None
    is a no-op for that field."""
    current = dns_config()
    if upstream_dns is not None:
        current["upstream_dns"] = upstream_dns
    if fallback_dns is not None:
        current["fallback_dns"] = fallback_dns
    if cache_optimistic is not None:
        current["cache_optimistic"] = cache_optimistic
    if dnssec_enabled is not None:
        current["dnssec_enabled"] = dnssec_enabled
    if upstream_mode is not None:
        current["upstream_mode"] = upstream_mode
    _request("POST", "/control/dns_config", current)
    return current


# ------------------------------------------------- orchestrator (Stage 4) --
#
# The functions below are what app/orchestrator.py (ENHANCEMENT-PLAN.md
# step 4.1) uses to read and write the DNS filter's state as a whole, so it can
# compare what's there with what the console wants and put it right.
#
# A real bug found while building this (26 September 2026): the DNS filter does
# NOT ignore text after "#" on a rule line. The old per-device helpers
# (add_client_rule and friends, since removed - nothing called them any
# more) stored an expiry and tag as a trailing "  # securepi-..." comment,
# and a rule written that way never matches anything - checked live with
# check_host() for four rule shapes: with the comment, none of them
# blocked; without it, they did. So the orchestrator writes plain rules
# with no comment at all, and remembers which ones are its own in its own
# state table instead of marking the rule text.

def quote_client(name):
    """A $client= value, quoted and escaped the way the DNS filter's rule syntax
    requires for a name with spaces or punctuation: single quotes around
    it, and a backslash before any quote, comma or pipe inside it. The
    quoted form was checked live to match (see the note above)."""
    escaped = ""
    for ch in name:
        if ch in "'\",|":
            escaped += "\\" + ch
        else:
            escaped += ch
    return "'%s'" % escaped


def unquote_client(value):
    """The reverse of quote_client, for showing a rule's device name."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    out, escape = "", False
    for ch in value:
        if escape:
            out += ch
            escape = False
        elif ch == "\\":
            escape = True
        else:
            out += ch
    return out


def domain_rule(domain, action, client_name=None):
    """One plain rule line: block or allow `domain` and every subdomain,
    for one client or (client_name None) for every device."""
    prefix = "@@" if action == "allow" else ""
    rule = "%s||%s^" % (prefix, domain)
    if client_name:
        rule += "$client=%s" % quote_client(client_name)
    return rule


def set_user_rules(rules):
    """Replace the whole custom-rules list in one request."""
    _request("POST", "/control/filtering/set_rules", {"rules": list(rules)})


def list_clients():
    """Every persistent client, as the DNS filter returns it."""
    return (_request("GET", "/control/clients") or {}).get("clients") or []


def add_client(obj):
    _request("POST", "/control/clients/add", obj)


def update_client(name, obj):
    _request("POST", "/control/clients/update", {"name": name, "data": obj})


def delete_client(name):
    _request("POST", "/control/clients/delete", {"name": name})


def protection_status():
    """(enabled, milliseconds left on a timed pause or 0) from the DNS filter's
    own status endpoint - the network-wide "pause filtering" state."""
    st = _request("GET", "/control/status") or {}
    return bool(st.get("protection_enabled", True)), int(st.get("protection_disabled_duration") or 0)


def set_protection(enabled, duration_ms=None):
    """Turn network-wide filtering on or off. With `duration_ms`, the DNS filter
    pauses it for that long and turns it back on by itself - the
    orchestrator still checks, but the pause ends even if it doesn't."""
    body = {"enabled": bool(enabled)}
    if not enabled and duration_ms:
        body["duration"] = int(duration_ms)
    _request("POST", "/control/protection", body)


_catalog_cache = {"at": 0, "catalog": {}}


def service_catalog(max_age_s=3600):
    """{service_id: group_id} for every service the DNS filter can block, e.g.
    {"steam": "gaming", "tiktok": "social_network"}. Cached for an hour -
    it only changes when the DNS filter itself is upgraded."""
    now = time.time()
    if _catalog_cache["catalog"] and now - _catalog_cache["at"] < max_age_s:
        return _catalog_cache["catalog"]
    data = _request("GET", "/control/blocked_services/all") or {}
    catalog = {sv["id"]: sv.get("group_id") for sv in data.get("blocked_services") or []}
    _catalog_cache.update(at=now, catalog=catalog)
    return catalog


def service_groups():
    """[(group_id, [service ids])] in the DNS filter's own order - for the
    console's profile editor."""
    groups = {}
    for sid, gid in service_catalog().items():
        groups.setdefault(gid or "other", []).append(sid)
    return sorted(groups.items())

#!/usr/bin/env python3
"""
SecurePi Gateway - AdGuard Home client.

AdGuard Home owns DNS filtering: blocklist sources, custom allow/block rules,
and per-client policy. This module is a thin wrapper around its control API
so the console can manage filtering without an operator opening AdGuard's
own UI - which is deliberately bound to 127.0.0.1 and never exposed on the
network (see REPORT-adblocking.md).

Uses urllib rather than requests: this is the only place in the app that
needs an HTTP client, so a stdlib call beats adding a dependency on a
memory-constrained gateway (see SECUREPI-15-DAY-PLAN.md 2.6).
"""

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode

BASE_URL = "http://127.0.0.1:3000"
USERNAME = "securepi"
PASSWORD_FILE = "/root/.securepi-dns-password"


class AdGuardError(Exception):
    """AdGuard Home could not be reached, or rejected a request."""


def _password():
    try:
        with open(PASSWORD_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        raise AdGuardError("AdGuard Home admin password file is missing: %s" % PASSWORD_FILE)


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
                # Several AdGuard endpoints (add_url, remove_url, ...) reply
                # with a plain-text "OK ..." body on success, not JSON.
                return raw.decode(errors="replace")
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace").strip()
        reason = (": %s" % detail) if detail else ""
        raise AdGuardError("AdGuard Home rejected %s %s (HTTP %d)%s" % (method, path, e.code, reason))
    except (urllib.error.URLError, OSError) as e:
        raise AdGuardError("Could not reach AdGuard Home at %s: %s" % (BASE_URL, e))


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


def describe_rule(rule):
    """Turn a raw AdGuard rule string into something the console can show
    next to a plain-language action, rather than syntax the operator has to
    parse themselves.

    Handles both network-wide rules (||domain^ / @@||domain^) and the
    per-device rules add_client_rule() writes (the same shape, with a
    trailing $client=name modifier instead of nothing after the ^, and
    possibly a "  # securepi-expires:..." comment after that - stripped
    here first, since AdGuard's own user_rules() mixes every rule together
    regardless of which function wrote it, so this has to cope with the
    comment even when called from a place that never added one)."""
    body = rule.partition("  #")[0]
    scope = "network"
    if "^$client=" in body:
        body, _, client_name = body.partition("^$client=")
        body += "^"
        scope = "device: %s" % client_name
    if body.startswith("@@||") and body.endswith("^"):
        return {"rule": rule, "domain": body[4:-1], "action": "allow", "scope": scope}
    if body.startswith("||") and body.endswith("^"):
        return {"rule": rule, "domain": body[2:-1], "action": "block", "scope": scope}
    return {"rule": rule, "domain": None, "action": "custom", "scope": scope}


# ----------------------------------------------------------- per-client policy
#
# A device is identified to AdGuard by a LIST of identifiers - every MAC it
# has ever used, plus its current IP - not by IP alone.
#
# Why this matters: AdGuard is also our DHCP server, so it supports MAC-based
# client identifiers directly. Keying on IP alone (the original version of
# this module) meant a device's per-device filtering setting was silently
# lost every time its DHCP lease renewed to a new address - the device kept
# its identity in OUR device registry, but AdGuard had no way to know the
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


def set_client_filtering(identifiers, name, enabled):
    """Create or update the AdGuard client entry for a device, so its DNS
    filtering can be switched independently of the network-wide default.

    `identifiers` should be every MAC the device has used plus its current
    IP (see webapp.py's _device_identifiers helper). When the client already
    exists, its id list is MERGED with the ones passed in rather than
    replaced, so a MAC picked up since the client was first created (a
    randomized address rotating again) is added rather than dropped -
    AdGuard itself never removes an id we don't ask it to.

    Everything else about the client is left on AdGuard's own defaults."""
    existing = _find_client(identifiers)
    if existing:
        merged_ids = sorted(set(existing.get("ids") or []) | set(identifiers))
        existing["ids"] = merged_ids
        existing["filtering_enabled"] = enabled
        existing["use_global_settings"] = False
        _request("POST", "/control/clients/update",
                  {"name": existing["name"], "data": existing})
    else:
        _request("POST", "/control/clients/add", {
            "name": name,
            "ids": sorted(set(identifiers)),
            "use_global_settings": False,
            "filtering_enabled": enabled,
            "safebrowsing_enabled": False,
            "parental_enabled": False,
            "use_global_blocked_services": True,
            "blocked_services": [],
            "tags": [],
        })


# --------------------------------------------------------- "why blocked?"

def check_host(name, client_ip=None):
    """Ask AdGuard how it would resolve `name` right now, exactly as if a
    query for it arrived from `client_ip` - this is the engine behind the
    console's "why is this blocked?" tool. Passing client_ip matters because
    a per-device rule (see add_client_rule below) or a per-client upstream
    only applies to a query AdGuard can see as coming from that client."""
    path = "/control/filtering/check_host?name=%s" % urllib.parse.quote(name)
    if client_ip:
        path += "&client=%s" % urllib.parse.quote(client_ip)
    return _request("GET", path) or {}


# Plain-language reasons for the codes AdGuard's check_host and query log
# both use, so the console never has to show raw AdGuard internals to the
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

    `domain` is passed in rather than read from `result` because AdGuard's
    check_host response never echoes the hostname it was asked about at
    all (confirmed against a live gateway - {"reason":..., "rule":...,
    "rules":[...], ...}, no "host" or "name" key anywhere). Assuming one
    existed was a real bug caught during the first live deploy of this
    feature - the console showed "null" as the domain in every result
    until this was fixed.

    `cname`, if AdGuard reports one, means the block happened via
    CNAME-cloaking: the queried domain itself doesn't match any rule, but
    the address it's an alias for does (see ENHANCEMENT-PLAN.md step
    5.5). This on-demand check is the only place this project currently
    surfaces that - AdGuard's stored query log has no equivalent field
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


# ------------------------------------------------- per-device allow/block

_EXPIRES_RE = re.compile(r"securepi-expires:(\d+)")
_TAG_RE = re.compile(r"securepi-tag:(\S+)")


def add_client_rule(client_name, domain, action, expires_at=None, tag=None):
    """A per-DEVICE allow or block rule, using AdGuard's $client rule
    modifier so it affects only the one persistent client named
    `client_name` (see set_client_filtering above - every device we manage
    already has one) rather than the whole network. This is what "allow
    this domain for this device only" and "block this domain for this
    device only" actually are; the network-wide rules in add_user_rule()
    are a different, coarser tool.

    `expires_at`, if given, is an epoch timestamp stored as a trailing
    comment on the rule line itself (AdGuard ignores text after '#').
    There is no separate table for this - sweep_expired_client_rules()
    below is what finds and removes it later. A real scheduled job belongs
    in ENHANCEMENT-PLAN.md step 1.3/4.1; until that exists, the filtering
    endpoints in webapp.py call the sweep opportunistically on every
    request, which is enough for a "pause this for an hour" feature.

    `tag`, if given, marks the rule as belonging to a named group in that
    same comment (space-separated from the expiry, if both are present) -
    used by native-tracker profiles (step 5.5) so every rule a profile
    added can be found and removed together later by
    remove_client_rule_group(), the same way a single temporary rule finds
    itself again via its expiry."""
    verb = "@@" if action == "allow" else ""
    base = "%s||%s^$client=%s" % (verb, domain, client_name)
    comment_bits = []
    if expires_at:
        comment_bits.append("securepi-expires:%d" % int(expires_at))
    if tag:
        comment_bits.append("securepi-tag:%s" % tag)
    rule = ("%s  # %s" % (base, " ".join(comment_bits))) if comment_bits else base
    rules = user_rules()
    if not any(r.split("  #")[0] == base for r in rules):
        rules.append(rule)
        _request("POST", "/control/filtering/set_rules", {"rules": rules})
    return rule


def remove_client_rule(rule):
    remove_user_rule(rule)


def remove_client_rule_group(client_name, tag):
    """Remove every rule scoped to this device AND carrying this tag in
    one go - what "remove this native-tracker profile" (step 5.5) actually
    does. Returns how many rules were removed."""
    marker = "$client=%s" % client_name
    tag_marker = "securepi-tag:%s" % tag
    rules = user_rules()
    keep = []
    removed = 0
    for r in rules:
        base, _, comment = r.partition("  #")
        if marker in base and tag_marker in comment:
            removed += 1
            continue
        keep.append(r)
    if removed:
        _request("POST", "/control/filtering/set_rules", {"rules": keep})
    return removed


def device_scoped_rules(client_name):
    """Every allow/block rule that was scoped to this one device, newest
    first, for the "recently allowed/blocked for this device" panel."""
    marker = "$client=%s" % client_name
    out = []
    for r in user_rules():
        base, _, comment = r.partition("  #")
        if marker not in base:
            continue
        desc = describe_rule(base)
        desc["rule"] = r
        m = _EXPIRES_RE.search(comment)
        desc["expires_at"] = int(m.group(1)) if m else None
        t = _TAG_RE.search(comment)
        desc["tag"] = t.group(1) if t else None
        out.append(desc)
    return list(reversed(out))


def sweep_expired_client_rules():
    """Remove any $client rule past the expiry recorded in its own comment.
    See add_client_rule's docstring for why this lives here instead of in a
    scheduler. Returns True if anything was actually removed.

    Matches the expiry with a regex rather than a plain substring split,
    so it still works now that a rule's comment can carry a tag alongside
    the expiry (add_client_rule above) instead of only ever one or the
    other."""
    now = time.time()
    rules = user_rules()
    keep = []
    changed = False
    for r in rules:
        base, _, comment = r.partition("  #")
        m = _EXPIRES_RE.search(comment)
        if m and int(m.group(1)) < now:
            changed = True
            continue
        keep.append(r)
    if changed:
        _request("POST", "/control/filtering/set_rules", {"rules": keep})
    return changed


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
    """Current resolver configuration, straight from AdGuard - confirmed
    live against the real endpoint (GET /control/dns_info), not guessed:
    upstream_dns, cache_optimistic, dnssec_enabled and friends."""
    return _request("GET", "/control/dns_info") or {}


def set_dns_tuning(upstream_dns=None, fallback_dns=None, cache_optimistic=None,
                    dnssec_enabled=None, upstream_mode=None):
    """Update resolver settings, changing only the fields actually passed
    in - everything else is read back from the live config first and sent
    through unchanged, since AdGuard's dns_config endpoint replaces the
    whole object rather than patching it (same pattern as
    set_client_filtering's full-object POST). Every argument left as None
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

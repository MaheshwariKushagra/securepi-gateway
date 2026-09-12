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
import urllib.error
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
    parse themselves."""
    if rule.startswith("@@||") and rule.endswith("^"):
        return {"rule": rule, "domain": rule[4:-1], "action": "allow"}
    if rule.startswith("||") and rule.endswith("^"):
        return {"rule": rule, "domain": rule[2:-1], "action": "block"}
    return {"rule": rule, "domain": None, "action": "custom"}


# ----------------------------------------------------------- per-client policy

def _find_client(ip):
    clients = _request("GET", "/control/clients") or {}
    for cl in clients.get("clients") or []:
        if ip in (cl.get("ids") or []):
            return cl
    return None


def client_filtering_status(ip):
    cl = _find_client(ip)
    if cl is None:
        return {"managed": False, "filtering_enabled": True}
    return {"managed": True, "filtering_enabled": bool(cl.get("filtering_enabled", True))}


def set_client_filtering(ip, name, enabled):
    """Create or update the AdGuard client entry for a device's IP, so its
    DNS filtering can be switched independently of the network-wide default.
    Everything else about the client is left on AdGuard's own defaults."""
    existing = _find_client(ip)
    if existing:
        existing["filtering_enabled"] = enabled
        existing["use_global_settings"] = False
        _request("POST", "/control/clients/update",
                  {"name": existing["name"], "data": existing})
    else:
        _request("POST", "/control/clients/add", {
            "name": name,
            "ids": [ip],
            "use_global_settings": False,
            "filtering_enabled": enabled,
            "safebrowsing_enabled": False,
            "parental_enabled": False,
            "use_global_blocked_services": True,
            "blocked_services": [],
            "tags": [],
        })

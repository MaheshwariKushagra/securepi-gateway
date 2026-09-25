#!/usr/bin/env python3
"""
SecurePi Gateway - the two nftables sets added in ENHANCEMENT-PLAN.md
step 4.2, `inet filter quarantine_mac` and `inet filter blocked_ip`.

Same shape as quarantine.py and dpi_enroll.py: every call goes through
gateway/securepi-web-helper (the only privileged program the console may
run, step 3.3), which hardcodes the family/table/set and validates each
argument itself. Nothing here decides WHAT should be in either set - that
is app/orchestrator.py's job. This module only reads and writes them.

Each set is `flags timeout`, so an element can carry a kernel-side
expiry. The orchestrator uses that as a safety net under a timed policy:
if the orchestrator itself stops running, the element still disappears
on its own a minute after the policy was meant to end.
"""

import json
import subprocess

HELPER = "/usr/local/sbin/securepi-web-helper"

# What nft prints when asked to delete an element that isn't in a
# `flags timeout` set - confirmed live on the gateway (step 4.2), the
# same message dpi_enroll.py already matches for its own timeout set.
_NOT_FOUND = "no such file or directory"


class FirewallSetError(Exception):
    """The privileged helper could not be reached, or refused a request."""


def _run(verb, *args):
    try:
        return subprocess.run(["sudo", HELPER, verb] + [str(a) for a in args],
                              capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise FirewallSetError("could not run the privileged helper: %s" % e)


def parse_set_elements(nft_json_text):
    """{value: seconds_left or None} from `nft -j list set` output.

    A plain element comes back as a bare string. One with a timeout comes
    back as {"elem": {"val": ..., "timeout": N, "expires": N}} - both
    shapes confirmed live on the gateway before this was written. Pure (no
    subprocess), so it can be tested without root."""
    data = json.loads(nft_json_text)
    out = {}
    for obj in data.get("nftables", []):
        if "set" not in obj:
            continue
        for e in obj["set"].get("elem") or []:
            if isinstance(e, dict):
                inner = e.get("elem", e)
                out[str(inner.get("val")).lower()] = inner.get("expires")
            else:
                out[str(e).lower()] = None
    return out


def _list(verb):
    result = _run(verb)
    if result.returncode != 0:
        raise FirewallSetError("%s failed: %s" % (verb, result.stderr.strip()))
    return parse_set_elements(result.stdout)


def _add(verb, value, seconds=None):
    args = [value] if seconds is None else [value, int(seconds)]
    result = _run(verb, *args)
    if result.returncode != 0:
        raise FirewallSetError("%s %s failed: %s" % (verb, value, result.stderr.strip()))


def _delete(verb, value):
    """Idempotent: deleting an element that isn't there is not an error."""
    result = _run(verb, value)
    if result.returncode != 0 and _NOT_FOUND not in result.stderr.lower():
        raise FirewallSetError("%s %s failed: %s" % (verb, value, result.stderr.strip()))


# ------------------------------------------------------------ quarantine_mac

def quarantined_macs():
    return _list("quarantine-mac-list")


def quarantine_mac(mac, seconds=None):
    _add("quarantine-mac-add", mac.lower(), seconds)


def release_mac(mac):
    _delete("quarantine-mac-delete", mac.lower())


# ---------------------------------------------------------------- blocked_ip

def blocked_ips():
    return _list("blocked-ip-list")


def block_ip(ip, seconds=None):
    _add("blocked-ip-add", ip, seconds)


def unblock_ip(ip):
    _delete("blocked-ip-delete", ip)

#!/usr/bin/env python3
"""
SecurePi Gateway - Tier 2 (HTTPS ad removal) enrollment.

The `ip nat enrolled` set already exists (see gateway/nftables.conf): its
dpi-redirect rule sends every enrolled device's HTTPS traffic through the
inspection proxy, which then decides per-connection whether to actually
decrypt. This module is the console's control surface for that set,
replacing the `sudo securepi enroll/unenroll` CLI (ENHANCEMENT-PLAN.md
step 5.6a). Deliberately mirrors quarantine.py's shape - same nft-via-
subprocess approach, same idempotency contract - since it is solving the
same kind of problem for a different set.

This process runs as root already (webapp.py's systemd unit has no User=
line), so it can call `nft` directly. No separate privileged helper was
needed for this step, unlike what the plan assumed going in.

Keyed on IP, not MAC - one deliberate scope reduction
-------------------------------------------------------
The plan asked for the enrolled set to be keyed on MAC, so a device stays
enrolled across a MAC rotation. Doing that means changing the
dpi-redirect rule in gateway/nftables.conf to match on `ether saddr`
instead of `ip saddr @enrolled` - a change to the rule that decides which
connections reach the inspection proxy at all. Given how much rides on
that one rule (get it wrong and Tier 2 either inspects nothing or
inspects everything), this was judged too risky to change in the same
pass as the rest of this step. Left keyed on IP, with the same accepted
limitation quarantine.py already documents for the same reason: a DHCP
lease renewal drops enrollment until the console re-applies it.

Auto-unenroll via a native nftables timeout, not a scheduler
---------------------------------------------------------------
Step 5.6c wants an auto-unenroll timer. Rather than build a polling sweep
(the pattern 5.2 uses for temporary allow rules, because AdGuard's rules
have no native expiry), the `enrolled` set now carries `flags timeout`
(see gateway/nftables.conf), so an element can be given a TTL directly
and the kernel expires it with no code involved at all.

That flag was added and reload-tested live before this module was
written, which surfaced a real, non-obvious nftables behaviour: `nft add
element` on an element that already exists is a silent no-op, EVEN WHEN
the new command specifies a different timeout - it does not refresh the
expiry. So enroll() below always deletes the element first, then adds it
fresh; anything else would make "re-enroll to reset the 24h clock" not
actually work.
"""

import json
import subprocess

FAMILY, TABLE, SET_NAME = "ip", "nat", "enrolled"
DEFAULT_TIMEOUT_HOURS = 24


class DpiEnrollError(Exception):
    """nftables could not be reached, or rejected a request."""


def _run(args):
    try:
        return subprocess.run(["nft"] + args, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise DpiEnrollError("could not run nft: %s" % e)


def enrolled():
    """Every currently-enrolled IP, with the seconds left before it
    auto-expires (None if it has no timeout, which shouldn't happen once
    every enrollment goes through enroll() below, but a manually-added
    element wouldn't have one)."""
    result = _run(["-j", "list", "set", FAMILY, TABLE, SET_NAME])
    if result.returncode != 0:
        raise DpiEnrollError("nft list set failed: %s" % result.stderr.strip())
    data = json.loads(result.stdout)
    out = []
    for obj in data.get("nftables", []):
        if "set" not in obj:
            continue
        for e in obj["set"].get("elem") or []:
            # A plain element comes back as a bare string; one with a
            # timeout comes back as {"elem": {"val": ..., "expires": N}}.
            if isinstance(e, dict):
                inner = e.get("elem", e)
                out.append({"ip": inner.get("val"), "expires_in_s": inner.get("expires")})
            else:
                out.append({"ip": e, "expires_in_s": None})
    return out


def enrolled_ips():
    return [e["ip"] for e in enrolled()]


def is_enrolled(ip):
    return ip in enrolled_ips()


def enroll(ip, hours=DEFAULT_TIMEOUT_HOURS):
    """(Re-)enroll an address, always with a fresh timeout - see this
    module's docstring for why a plain `add` on an already-enrolled
    address would not reset its clock."""
    unenroll(ip)
    spec = "{ %s timeout %dh }" % (ip, hours) if hours else "{ %s }" % ip
    result = _run(["add", "element", FAMILY, TABLE, SET_NAME, spec])
    if result.returncode != 0:
        raise DpiEnrollError("could not enroll %s: %s" % (ip, result.stderr.strip()))


def unenroll(ip):
    """Idempotent: unenrolling an address that was never enrolled is a no-op."""
    result = _run(["delete", "element", FAMILY, TABLE, SET_NAME, "{ %s }" % ip])
    if result.returncode != 0 and "does not exist" not in result.stderr:
        raise DpiEnrollError("could not unenroll %s: %s" % (ip, result.stderr.strip()))

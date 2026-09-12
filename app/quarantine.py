#!/usr/bin/env python3
"""
SecurePi Gateway - quarantine enforcement.

The `inet filter quarantine` nftables set already exists (see the plan and
GATEWAY-SETUP-RUNBOOK.md): the forward chain drops every packet whose source
address is in it. This module is the console's control surface for that set
- add an address to quarantine a device, remove it to undo.

Keyed on IP, not MAC or device_id
----------------------------------
The firewall set is `type ipv4_addr`, so enforcement has to key on the
device's current address, resolved the same way per-device DNS filtering
already does (device_ips, most recent interval). The known limitation this
carries is that a DHCP lease renewal moves a quarantined device to a new
address the set does not cover, and the block would need reapplying. Solving
that would mean matching on source MAC in the PREROUTING hook instead of
FORWARD, which is a bigger firewall change than a 15-day project needs -
recorded here as a stated limitation rather than solved.

No caching, same as adguard.py
-------------------------------
Every read asks nftables directly rather than mirroring state in SQLite, so
the console can never show "quarantined" for a device nftables has actually
stopped blocking (or vice versa) because a write happened outside the
console.
"""

import json
import subprocess

FAMILY, TABLE, SET_NAME = "inet", "filter", "quarantine"


class QuarantineError(Exception):
    """nftables could not be reached, or rejected a request."""


def _run(args):
    try:
        return subprocess.run(["nft"] + args, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise QuarantineError("could not run nft: %s" % e)


def quarantined_ips():
    result = _run(["-j", "list", "set", FAMILY, TABLE, SET_NAME])
    if result.returncode != 0:
        raise QuarantineError("nft list set failed: %s" % result.stderr.strip())
    data = json.loads(result.stdout)
    for obj in data.get("nftables", []):
        if "set" in obj:
            return obj["set"].get("elem") or []
    return []


def is_quarantined(ip):
    return ip in quarantined_ips()


def quarantine(ip):
    """Idempotent: quarantining an already-quarantined address is a no-op."""
    result = _run(["add", "element", FAMILY, TABLE, SET_NAME, "{ %s }" % ip])
    if result.returncode != 0:
        raise QuarantineError("could not quarantine %s: %s" % (ip, result.stderr.strip()))


def release(ip):
    """Idempotent: releasing an address that was never quarantined is a no-op."""
    result = _run(["delete", "element", FAMILY, TABLE, SET_NAME, "{ %s }" % ip])
    if result.returncode != 0 and "does not exist" not in result.stderr:
        raise QuarantineError("could not release %s: %s" % (ip, result.stderr.strip()))

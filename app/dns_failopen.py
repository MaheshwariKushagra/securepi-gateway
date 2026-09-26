#!/usr/bin/env python3
"""
SecurePi Gateway - DNS fail-open (ENHANCEMENT-PLAN.md step 3.6, F§8.4).

gateway/nftables.conf's own prerouting chain already forces stray plain
DNS (a device hardcoded to some other resolver) back to the gateway's
own address, 10.10.0.1:53, where AdGuard listens - see that file's own
comments. That rule protects filtering; it does nothing for
availability if AdGuard itself is the one not answering there, because
it only matches traffic addressed anywhere ELSE - a client correctly
pointed at 10.10.0.1 (what DHCP handed it) never touches that rule at
all, and just gets nothing back the moment nothing is listening.

This module adds (and later removes) one more prerouting rule that DOES
match traffic addressed to 10.10.0.1:53 specifically, and DNATs it to a
public upstream resolver instead - so LAN clients keep resolving names
(unfiltered, but working) instead of every device going dark the moment
AdGuard stops answering.

Called from app/health.py's check_dns_failopen(), which runs from
app/ingest.py's own systemd unit - already root (see health.py's own
module docstring for why), so unlike app/quarantine.py/app/dpi_enroll.py
(which run from the unprivileged web console, step 3.3) this module
calls `nft` directly - no privileged helper needed here.

Identified by nft's own `comment` field, not a handle held in Python
memory: a crash-and-restart of the ingest process, or of the whole
gateway, must not orphan a rule this module can no longer find. Every
operation re-derives the current handle(s) fresh from `nft -a list`
rather than remembering one from an earlier call.
"""

import re
import subprocess

GATEWAY_IP = "10.10.0.1"
UPSTREAM_RESOLVER = "1.1.1.1"
RULE_COMMENT = "dns-failopen"
NFT_TIMEOUT_S = 5


class DnsFailopenError(Exception):
    """nft could not be run, or refused a command."""


def _run(args):
    try:
        return subprocess.run(["nft"] + args, capture_output=True, text=True, timeout=NFT_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise DnsFailopenError("could not run nft: %s" % e)


def _add_rule_argv(proto):
    """Pure - no subprocess call - so the exact rule shape is testable
    without root or a real nftables ruleset, the same reason
    securepi-web-helper's build_nft_argv() is split out this way."""
    return ["add", "rule", "ip", "nat", "prerouting",
            "iifname", "ap0", "ip", "daddr", GATEWAY_IP,
            proto, "dport", "53", "counter",
            "dnat", "to", "%s:53" % UPSTREAM_RESOLVER,
            "comment", RULE_COMMENT]


def _delete_rule_argv(handle):
    return ["delete", "rule", "ip", "nat", "prerouting", "handle", handle]


def _extract_handles(nft_list_output):
    """Every handle number of a line carrying this module's own rule
    comment, from `nft -a list chain ...`'s text output - never touches
    a rule (like the ruleset's existing dpi-redirect rule) that this
    module didn't add itself."""
    handles = []
    for line in nft_list_output.splitlines():
        if RULE_COMMENT in line:
            m = re.search(r"# handle (\d+)", line)
            if m:
                handles.append(m.group(1))
    return handles


def _handles():
    result = _run(["-a", "list", "chain", "ip", "nat", "prerouting"])
    if result.returncode != 0:
        raise DnsFailopenError("nft list chain failed: %s" % result.stderr.strip())
    return _extract_handles(result.stdout)


def is_active():
    """True if the fail-open redirect is currently in effect."""
    return len(_handles()) > 0


def activate():
    """Idempotent: a call while already active does nothing. Adds both a
    UDP and a TCP rule - a resolver reply too large for one UDP packet
    falls back to TCP, and that fallback needs to be redirected too.

    "Already active" means BOTH rules are there. If only one is - the
    other add failed last time - it is removed and both are added again.
    Treating one rule as "active" used to leave the other transport
    unredirected for as long as the fail-open lasted (Audit.md)."""
    handles = _handles()
    if len(handles) >= 2:
        return
    if handles:
        deactivate()
    for proto in ("udp", "tcp"):
        result = _run(_add_rule_argv(proto))
        if result.returncode != 0:
            raise DnsFailopenError("could not activate dns fail-open (%s): %s" % (proto, result.stderr.strip()))


def deactivate():
    """Idempotent: removes every rule this module's own comment
    identifies, however many there are (normally two) - never a bare
    'delete two rules' assumption, in case activate() partially failed
    or was somehow called an odd number of times."""
    for handle in _handles():
        result = _run(_delete_rule_argv(handle))
        if result.returncode != 0:
            raise DnsFailopenError(
                "could not remove dns fail-open rule (handle %s): %s" % (handle, result.stderr.strip()))

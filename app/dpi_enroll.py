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

Privilege separation (ENHANCEMENT-PLAN.md step 3.3)
-----------------------------------------------------
`securepi-web` no longer runs as root (finding G9), so this module no
longer calls `nft` directly - every call goes through
`gateway/securepi-web-helper`, run via a narrow sudoers NOPASSWD rule.
The helper hardcodes the family/table/set per verb and validates its
own arguments (including the enroll timeout, so an out-of-range value
here is still caught even before this module's own bounds would
matter). This module's idempotency/error-string handling is unchanged:
the helper passes nft's real stdout/stderr/exit code straight through.

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
(the pattern 5.2 uses for temporary allow rules, because the DNS filter's rules
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
import os
import subprocess

DEFAULT_TIMEOUT_HOURS = 24
HELPER = "/usr/local/sbin/securepi-web-helper"


class DpiEnrollError(Exception):
    """The privileged helper could not be reached, or rejected a request."""


def _helper_argv(verb):
    """The console (unprivileged) reaches the helper through its sudoers
    rule. The engine already runs as root, so it calls the helper directly:
    going through sudo there would only add a PAM session line to the
    journal for every call, every 15-second orchestrator cycle."""
    if os.geteuid() == 0:
        return [HELPER, verb]
    return ["sudo", HELPER, verb]


def _run(verb, *args):
    try:
        return subprocess.run(_helper_argv(verb) + list(args), capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise DpiEnrollError("could not run the privileged helper: %s" % e)


def enrolled():
    """Every currently-enrolled IP, with the seconds left before it
    auto-expires (None if it has no timeout, which shouldn't happen once
    every enrollment goes through enroll() below, but a manually-added
    element wouldn't have one)."""
    result = _run("enrolled-list")
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
    address would not reset its clock. `hours` must be a whole number
    from 1 to 720 (30 days) - the privileged helper enforces this bound
    itself (step 3.3), so an out-of-range value is rejected rather than
    silently creating a never-expiring enrollment; webapp.py's own
    DpiEnrollRequest validates the same bound for a cleaner API error."""
    unenroll(ip)
    result = _run("enrolled-add", ip, str(hours))
    if result.returncode != 0:
        raise DpiEnrollError("could not enroll %s: %s" % (ip, result.stderr.strip()))


_NOT_FOUND_MARKERS = (
    "does not exist",       # what quarantine.py's flags-interval set reports
    "no such file or directory",  # what THIS flags-timeout set reports instead -
    # confirmed live: the two sets give genuinely different error text for
    # the exact same "delete an element that isn't there" case, which is
    # why this can't just copy quarantine.py's single-string check.
)


def flush():
    """Unenroll every device at once. This is the fail-safe path for step
    5.7's privacy-scope canary: if there's any doubt the addon is making
    the right decrypt/passthrough decision, the right response is to stop
    inspecting everyone immediately, not leave any device exposed while
    someone investigates. That includes connections already open through
    the proxy: they are closed too (ADBLOCK-ENHANCEMENT-PLAN.md), instead
    of carrying on until the browser happens to close them."""
    result = _run("enrolled-flush")
    if result.returncode != 0:
        raise DpiEnrollError("could not flush the enrolled set: %s" % result.stderr.strip())
    reset_https()


def reset_https(ip=None):
    """Make a change to one device's enrolment or sites apply at once:
    drop its open HTTPS connections, so its browser reconnects under the
    new decision (the redirect is decided when a connection opens - 7.5
    found pre-rolls kept playing until Chrome reconnected). With no IP,
    close every connection to the proxy. Raises DpiEnrollError on failure;
    callers treat that as a lesser problem than the change itself."""
    result = _run("https-reset", ip) if ip else _run("https-reset-all")
    if result.returncode != 0:
        raise DpiEnrollError("could not reset HTTPS connections%s: %s"
                             % (" of " + ip if ip else "", result.stderr.strip()))


def unenroll(ip):
    """Idempotent: unenrolling an address that was never enrolled is a no-op."""
    result = _run("enrolled-delete", ip)
    if result.returncode != 0:
        stderr_lower = result.stderr.lower()
        if not any(marker in stderr_lower for marker in _NOT_FOUND_MARKERS):
            raise DpiEnrollError("could not unenroll %s: %s" % (ip, result.stderr.strip()))

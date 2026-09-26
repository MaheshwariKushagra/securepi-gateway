#!/usr/bin/env python3
"""
SecurePi Gateway - the HTTPS inspection gate (ENHANCEMENT-PLAN.md step
7.7: "inspection must fail open to plain passthrough, not break
browsing").

gateway/nftables.conf only redirects an enrolled device's HTTPS to the
proxy while "ap0" is in the `ip nat dpi_up` set. The proxy's own systemd
unit opens that gate once it is listening and closes it whenever it
stops or crashes (dpi/dpi-gate.sh). That covers every case systemd can
see. The one it can't is a proxy that is still running but no longer
answering - systemd calls it "active", and every enrolled device's HTTPS
would hang. app/health.py's check_dpi_proxy() uses this module to probe
the proxy and close the gate in that case, and to reopen it once the
proxy answers again.

Why a direct TLS handshake is a good liveness probe: the proxy runs in
transparent mode, which needs the original destination that only a real
redirected connection carries. A direct connection to 10.10.0.1:8080 is
therefore closed by a healthy proxy straight away (measured live: an
EOF after ~20 ms), refused if nothing is listening, and simply never
answered if the proxy is hung - the kernel still accepts the TCP
connection into its backlog, but nobody reads it. Three different
outcomes, no traffic decrypted, and nothing written to the proxy's own
logs (checked live).

Runs from app/ingest.py's unit, which is already root (see
app/dns_failopen.py for the same reasoning), so it calls `nft` directly.
"""

import json
import socket
import ssl
import subprocess

PROXY_ADDR = ("10.10.0.1", 8080)
GATE_IFACE = "ap0"
PROBE_TIMEOUT_S = 3
NFT_TIMEOUT_S = 5

# probe() results
ANSWERING = "answering"   # the proxy reacted (closed, reset, or completed a handshake)
REFUSED = "refused"       # nothing is listening
SILENT = "silent"         # connected, but no reaction before the timeout: hung


class DpiGateError(Exception):
    """nft could not be run, or refused a command."""


def _gate_argv(verb):
    """Pure - no subprocess call - so the exact nft commands are testable
    without root, like dns_failopen's own argv builders."""
    if verb == "open":
        return ["add", "element", "ip", "nat", "dpi_up", '{ "%s" }' % GATE_IFACE]
    if verb == "close":
        return ["delete", "element", "ip", "nat", "dpi_up", '{ "%s" }' % GATE_IFACE]
    if verb == "list":
        return ["-j", "list", "set", "ip", "nat", "dpi_up"]
    raise ValueError("unknown gate verb: %r" % verb)


def _run(args):
    try:
        return subprocess.run(["nft"] + args, capture_output=True, text=True, timeout=NFT_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise DpiGateError("could not run nft: %s" % e)


def _elements_from_json(nft_json_text):
    """The element names in `nft -j list set` output, e.g. ["ap0"]. An
    empty set has no "elem" key at all."""
    for item in json.loads(nft_json_text).get("nftables", []):
        if "set" in item:
            return [e for e in item["set"].get("elem", []) if isinstance(e, str)]
    return []


def is_open():
    result = _run(_gate_argv("list"))
    if result.returncode != 0:
        raise DpiGateError("nft list set failed: %s" % result.stderr.strip())
    return GATE_IFACE in _elements_from_json(result.stdout)


def open_gate():
    result = _run(_gate_argv("open"))
    if result.returncode != 0:
        raise DpiGateError("could not open the inspection gate: %s" % result.stderr.strip())


def close_gate():
    result = _run(_gate_argv("close"))
    # Closing a gate that is already closed is not an error worth raising.
    if result.returncode != 0 and is_open():
        raise DpiGateError("could not close the inspection gate: %s" % result.stderr.strip())


def probe(addr=PROXY_ADDR, timeout=PROBE_TIMEOUT_S):
    """ANSWERING, REFUSED or SILENT - see the module docstring."""
    try:
        sock = socket.create_connection(addr, timeout=timeout)
    except ConnectionRefusedError:
        return REFUSED
    except (socket.timeout, OSError):
        return SILENT
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with ctx.wrap_socket(sock, server_hostname="example.com"):
            return ANSWERING
    except socket.timeout:
        return SILENT
    except (ssl.SSLError, ConnectionError, OSError):
        # Closed or reset straight away: exactly what a healthy
        # transparent-mode proxy does with a direct connection.
        return ANSWERING
    finally:
        sock.close()

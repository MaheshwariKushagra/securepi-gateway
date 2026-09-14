#!/usr/bin/env python3
"""
SecurePi Gateway - live-demo red-team simulator.

WHAT THIS IS
------------
A small, self-contained tool for demonstrating that the SecurePi Gateway IDS
actually detects and stops an attack, live, from a genuinely separate machine.

You run this on a THIRD laptop that is joined to the SecurePi-Test Wi-Fi. On a
single command it performs three classic attacks against the gateway, in order,
and narrates itself so you can talk an audience through each stage:

    1. Port scan        -> the console raises a "port_scan" incident (Discovery)
    2. SSH brute force   -> raises a "brute_force" incident (Credential Access)
    3. C2 beacon         -> raises a "beacon" incident (Command & Control)

After the beacon incident appears, the tool KEEPS beaconing. That is your cue to
open the attacker's device page in the SecurePi console and click "Quarantine".
Within a few seconds the beacon check-ins here flip from "OK" to "BLOCKED",
because the gateway firewall is now dropping this laptop's outbound traffic.
That is the "detected AND stopped" moment.

AUTHORISATION / SAFETY
----------------------
This is an authorised demo tool for the operator's OWN SecurePi network. It only
opens ordinary TCP connections (the same thing any browser does) plus one small,
benign, repeated check-in to an external address. It performs NO exploitation, no
password guessing, and sends no malicious payload - the gateway's detection is
based on *patterns of connections*, not on any real attack succeeding, so plain
connections are all that is needed. All targets are configurable and default to
the operator's own gateway.

REQUIREMENTS
------------
Python 3 only. No pip installs, no administrator/root rights. Works the same on
Windows, macOS and Linux.

USAGE
-----
    python securepi_attack.py                 # run the full demo campaign
    python securepi_attack.py --selftest      # prove the tool works, no gateway
    python securepi_attack.py --help          # see all options

See redteam/README.md for the full pre-demo checklist and talking points.
"""

import argparse
import socket
import sys
import threading
import time


# ---------------------------------------------------------------------------
# Configuration. These are the defaults; every one can be overridden with a
# command-line flag (see build_parser() at the bottom), so you never have to
# edit this file to tune the demo.
# ---------------------------------------------------------------------------

# The gateway is the target for the scan and the brute force. We aim at the
# gateway itself because it is always powered on and always answers on the
# network, so the attack traffic is guaranteed to be seen by the sensor. (A scan
# aimed at an address with no machine behind it produces no traffic at all, and
# so would not be detected.)
GATEWAY_IP = "10.10.0.1"

# The beacon (stage 3) must go to a destination OUT on the internet, reached
# *through* the gateway. That is deliberate: the gateway's quarantine only drops
# traffic that passes *through* it, so an external target is what lets you see
# the block happen. 1.1.1.1:443 is Cloudflare - a real, always-up address that
# connects instantly before quarantine and cleanly times out after it.
C2_IP = "1.1.1.1"
C2_PORT = 443

# Stage 1: the ports we knock on. The IDS raises a port-scan alert once it sees
# connections to 8 or more different ports in a short window; 14 gives us margin.
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080]

# Stage 2: repeated connections to the SSH port. The IDS raises a brute-force
# alert at 6 attempts in 120 seconds; 20 gives us clear margin.
BRUTE_PORT = 22
BRUTE_TRIES = 20

# Stage 3: the beacon. The IDS raises a beacon alert once it sees 8+ connections
# to the same destination that are very regular in timing and size, so we keep
# both fixed. Sending every 15 seconds means the beacon alert appears after
# about 2 minutes; the check-ins then continue until you press Ctrl+C.
BEACON_EVERY = 15      # seconds between check-ins (kept fixed = regular timing)
BEACON_SIZE = 512      # bytes per check-in  (kept fixed = regular size)

# How long to wait after launch before attacking. When this laptop joins the
# Wi-Fi the gateway needs a moment to register it as a new device; giving it a
# short head start makes attribution reliable and lets the "new_device" incident
# appear on the console first.
SETTLE_SECS = 45

# Connection timeouts (seconds). Short, so a closed port or a blocked beacon is
# reported quickly rather than hanging.
CONNECT_TIMEOUT = 1.5
BEACON_TIMEOUT = 4.0


# ---------------------------------------------------------------------------
# Small terminal helpers - colour and timestamps, purely cosmetic so the demo
# reads well on screen. Colour is switched off automatically if the terminal
# does not support it (e.g. redirected to a file).
# ---------------------------------------------------------------------------

class C:
    """ANSI colour codes, blanked out when the output is not a real terminal."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    OFF = "\033[0m"

    @classmethod
    def disable(cls):
        for name in ("RED", "GREEN", "YELLOW", "CYAN", "BOLD", "DIM", "OFF"):
            setattr(cls, name, "")


def stamp():
    """Current wall-clock time as HH:MM:SS, for a running log look."""
    return time.strftime("%H:%M:%S")


def log(msg, colour=""):
    """Print one timestamped line."""
    print("%s[%s]%s %s%s" % (C.DIM, stamp(), C.OFF, colour, msg + C.OFF if colour else msg))


def banner(text):
    """Print a boxed section header."""
    line = "=" * 62
    print()
    print(C.CYAN + line + C.OFF)
    print(C.CYAN + C.BOLD + "  " + text + C.OFF)
    print(C.CYAN + line + C.OFF)


# ---------------------------------------------------------------------------
# Networking primitives. Everything the tool does is built on a single, simple
# operation: try to open a TCP connection to an address and port.
# ---------------------------------------------------------------------------

def tcp_connect(ip, port, timeout=CONNECT_TIMEOUT, payload=None):
    """
    Try to open a TCP connection to ip:port.

    Returns True if the connection is established, False otherwise (port closed,
    host unreachable, or - importantly for the demo - traffic dropped by a
    quarantine block). If `payload` bytes are given, they are sent once the
    connection is up. The socket is always closed before returning.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        if payload:
            sock.sendall(payload)
        return True
    except OSError:
        # Any network-level failure lands here: refused, timed out, unreachable.
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


def own_ip(gateway_ip):
    """
    Work out this laptop's own address on the SecurePi network.

    Opening a UDP socket "towards" the gateway does not send anything, but it
    makes the OS pick the local address it would use to reach the gateway, which
    is exactly the LAN IP the console will show for this device.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((gateway_ip, 53))
        return probe.getsockname()[0]
    except OSError:
        return "unknown"
    finally:
        probe.close()


# ---------------------------------------------------------------------------
# Attack stages.
# ---------------------------------------------------------------------------

def stage_port_scan(gateway_ip, ports):
    """Stage 1: connect to many different ports on the gateway in quick succession."""
    banner("STAGE 1 - PORT SCAN")
    log("Probing %d ports on the gateway %s ..." % (len(ports), gateway_ip), C.YELLOW)
    open_ports = []
    for port in ports:
        is_open = tcp_connect(gateway_ip, port)
        state = (C.GREEN + "open" + C.OFF) if is_open else (C.DIM + "closed" + C.OFF)
        print("    port %-5d  %s" % (port, state))
        if is_open:
            open_ports.append(port)
        time.sleep(0.15)   # small gap so the scan is easy to watch on screen
    log("Port scan complete: %d/%d ports answered." % (len(open_ports), len(ports)), C.YELLOW)
    log("--> Watch the console: a 'port_scan' incident (Discovery / T1046) "
        "should appear in ~15-20s.", C.CYAN)


def stage_brute_force(gateway_ip, port, tries):
    """Stage 2: hammer the SSH port with repeated connection attempts."""
    banner("STAGE 2 - SSH BRUTE FORCE")
    log("Opening %d rapid connections to %s:%d (the SSH port) ..."
        % (tries, gateway_ip, port), C.YELLOW)
    reached = 0
    for i in range(1, tries + 1):
        # We are NOT trying passwords - the gateway detects the *burst of
        # connection attempts* itself, so simply connecting is enough.
        ok = tcp_connect(gateway_ip, port)
        if ok:
            reached += 1
        print("    attempt %2d/%d  ->  %s" % (
            i, tries, ("connected" if ok else "no answer")))
        time.sleep(0.2)
    log("Brute-force burst complete (%d attempts)." % tries, C.YELLOW)
    log("--> Watch the console: a 'brute_force' incident (Credential Access / "
        "T1110) should appear in ~15-20s.", C.CYAN)


def stage_beacon(c2_ip, c2_port, every, size):
    """
    Stage 3: a command-and-control beacon that keeps checking in forever.

    This is the stage that demonstrates the *block*. It runs until you press
    Ctrl+C. After 8 regular check-ins the console raises the beacon incident;
    that is your cue to quarantine this device in the console. When you do, the
    check-ins here flip from OK to BLOCKED.
    """
    banner("STAGE 3 - C2 BEACON  (this stage runs until you press Ctrl+C)")
    log("Beaconing to external C2 %s:%d every %ds, %d bytes each ..."
        % (c2_ip, c2_port, every, size), C.YELLOW)
    payload = b"\x00" * size
    count = 0
    was_blocked = False
    announced_alert = False
    announced_quarantine_hint = False
    try:
        while True:
            count += 1
            ok = tcp_connect(c2_ip, c2_port, timeout=BEACON_TIMEOUT, payload=payload)

            if ok:
                if was_blocked:
                    # We were being blocked and now we are not - the operator
                    # released the quarantine. Useful when resetting the demo.
                    log("check-in #%d ... OK  (block lifted - quarantine released)"
                        % count, C.GREEN)
                    was_blocked = False
                else:
                    log("check-in #%d ... OK" % count, C.GREEN)
            else:
                if not was_blocked:
                    log("check-in #%d ... BLOCKED  <-- traffic dropped by the "
                        "gateway (quarantine active)" % count, C.RED + C.BOLD)
                    print()
                    log("The SecurePi Gateway detected this device and is now "
                        "STOPPING it. Detection + response demonstrated.", C.RED + C.BOLD)
                    print()
                    was_blocked = True
                else:
                    log("check-in #%d ... BLOCKED" % count, C.RED)

            # After enough regular check-ins, prompt the presenter.
            if count == 8 and not announced_alert:
                log("--> Watch the console: a 'beacon' incident (Command & "
                    "Control / T1071) should appear now.", C.CYAN)
                announced_alert = True
            if count == 10 and not announced_quarantine_hint and not was_blocked:
                print()
                log("NOW: open this device's page in the SecurePi console and "
                    "click 'Quarantine'.", C.BOLD)
                log("     Watch these check-ins turn from OK to BLOCKED.", C.BOLD)
                print()
                announced_quarantine_hint = True

            time.sleep(every)
    except KeyboardInterrupt:
        print()
        log("Beacon stopped. Demo over.", C.YELLOW)


# ---------------------------------------------------------------------------
# Preflight and orchestration.
# ---------------------------------------------------------------------------

def preflight(gateway_ip):
    """
    Check we are on the right network before doing anything. Returns True if the
    gateway is reachable, False (with an explanation) if not.
    """
    banner("SecurePi Gateway - RED-TEAM SIMULATOR (authorised demo)")
    me = own_ip(gateway_ip)
    print("  This device (attacker) : %s%s%s" % (C.BOLD, me, C.OFF))
    print("  Gateway target         : %s%s%s" % (C.BOLD, gateway_ip, C.OFF))
    print("  Plan                   : port scan -> SSH brute force -> C2 beacon")
    print()
    log("Checking the gateway is reachable ...")
    # Port 53 (DNS) and 80 are the likeliest to answer on the gateway.
    reachable = tcp_connect(gateway_ip, 53) or tcp_connect(gateway_ip, 80)
    if reachable:
        log("Gateway is reachable. Ready.", C.GREEN)
        return True
    log("Cannot reach the gateway at %s." % gateway_ip, C.RED + C.BOLD)
    log("Is this laptop connected to the 'SecurePi-Test' Wi-Fi? "
        "(Or pass --gateway <ip>.)", C.RED)
    return False


def settle_countdown(seconds):
    """Wait a short while so the gateway registers this device first."""
    banner("SETTLING IN")
    log("Letting the gateway register this laptop as a new device ...", C.YELLOW)
    log("--> Watch the console: a 'new_device' incident should appear.", C.CYAN)
    for remaining in range(seconds, 0, -1):
        # Overwrite one line with a live countdown.
        sys.stdout.write("\r    starting the attack in %2ds ... " % remaining)
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\r" + " " * 40 + "\r")
    sys.stdout.flush()


def run_campaign(args):
    """The full, one-shot demo: preflight, settle, then the three stages."""
    if not preflight(args.gateway):
        return 1
    if args.settle > 0:
        settle_countdown(args.settle)
    stage_port_scan(args.gateway, SCAN_PORTS)
    stage_brute_force(args.gateway, BRUTE_PORT, args.brute_tries)
    stage_beacon(args.c2, args.c2_port, args.beacon_every, BEACON_SIZE)
    return 0


# ---------------------------------------------------------------------------
# Self-test: prove the tool works on this laptop with no gateway present. It
# starts a tiny throwaway server on localhost and scans it, so you can confirm
# Python and the tool run correctly BEFORE you are standing in front of an
# audience. This never touches the SecurePi network.
# ---------------------------------------------------------------------------

def run_selftest():
    banner("SELF-TEST (no gateway needed)")
    log("Own-IP discovery returned: %s" % own_ip("8.8.8.8"))

    # Start a temporary listener on a free localhost port.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    test_port = server.getsockname()[1]

    def accept_loop():
        # Accept and immediately close a few connections, then stop.
        server.settimeout(3)
        for _ in range(3):
            try:
                conn, _addr = server.accept()
                conn.close()
            except OSError:
                break

    threading.Thread(target=accept_loop, daemon=True).start()
    time.sleep(0.2)

    log("Testing connection to an OPEN port (127.0.0.1:%d) ..." % test_port)
    open_ok = tcp_connect("127.0.0.1", test_port)
    log("  result: %s" % ("OK" if open_ok else "FAILED"),
        C.GREEN if open_ok else C.RED)

    # A port nothing is listening on should report closed.
    log("Testing connection to a CLOSED port (127.0.0.1:1) ...")
    closed_ok = not tcp_connect("127.0.0.1", 1, timeout=0.5)
    log("  result: %s" % ("OK (correctly closed)" if closed_ok else "unexpected"),
        C.GREEN if closed_ok else C.RED)

    server.close()
    passed = open_ok and closed_ok
    print()
    if passed:
        log("SELF-TEST PASSED - the tool runs correctly on this laptop.", C.GREEN + C.BOLD)
    else:
        log("SELF-TEST FAILED - check the Python install on this laptop.", C.RED + C.BOLD)
    return 0 if passed else 1


# ---------------------------------------------------------------------------
# Command-line handling.
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description="SecurePi Gateway live-demo red-team simulator "
                    "(authorised demo tool for your own network).")
    p.add_argument("--gateway", default=GATEWAY_IP,
                   help="Gateway IP to scan / brute-force (default: %(default)s)")
    p.add_argument("--c2", default=C2_IP,
                   help="External beacon target IP (default: %(default)s)")
    p.add_argument("--c2-port", type=int, default=C2_PORT,
                   help="External beacon target port (default: %(default)s)")
    p.add_argument("--settle", type=int, default=SETTLE_SECS,
                   help="Seconds to wait before attacking, for device "
                        "registration (default: %(default)s; use 0 to skip)")
    p.add_argument("--brute-tries", type=int, default=BRUTE_TRIES,
                   help="Number of SSH connection attempts (default: %(default)s)")
    p.add_argument("--beacon-every", type=int, default=BEACON_EVERY,
                   help="Seconds between beacon check-ins (default: %(default)s)")
    p.add_argument("--no-color", action="store_true",
                   help="Disable coloured output")
    p.add_argument("--selftest", action="store_true",
                   help="Run a local self-test and exit (no gateway needed)")
    return p


def main():
    args = build_parser().parse_args()

    # Turn colour off if asked, or if output is not an interactive terminal.
    if args.no_color or not sys.stdout.isatty():
        C.disable()

    if args.selftest:
        return run_selftest()
    return run_campaign(args)


if __name__ == "__main__":
    sys.exit(main())

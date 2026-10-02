#!/usr/bin/env python3
"""
Step 7.5's bypass matrix, VPN row (ENHANCEMENT-PLAN.md).

    python3 tools/bypass_vpn.py OUT.json

No VPN app was available on the test devices (the phone has none installed,
and installing one needs an account on the person's phone), so this tests
the gateway's behaviour towards VPN traffic directly, from the Mac on
SecurePi-Test:

  1. Can a VPN app find its servers? The setup/API domains of common VPN
     services are resolved through the gateway's DNS (blocked = 0.0.0.0).
  2. Does the gateway let a VPN handshake out, and does anything notice?
     Five WireGuard handshake-initiation-shaped UDP packets (148 bytes,
     message type 1) go to Cloudflare WARP's public WireGuard endpoint.
     They aren't a valid handshake (the keys are random), so no tunnel
     forms - but on the wire they look like the first packet of one. The
     gateway's IDS flow log and incidents are read afterwards to see
     whether it forwarded them and whether anything flagged them.
"""

import json
import os
import socket
import subprocess
import sys
import time

VPN_DOMAINS = ["api.cloudflareclient.com", "engage.cloudflareclient.com", "api.protonvpn.ch", "account.protonvpn.com",
               "api.nordvpn.com", "www.expressvpn.com", "api.surfshark.com", "www.windscribe.com"]
WARP = ("162.159.192.1", 2408)


def resolve(name):
    out = subprocess.run(["dig", "@10.10.0.1", name, "A", "+short", "+tries=1", "+time=4"],
                         capture_output=True, text=True).stdout.split()
    return out


def main():
    dns = {}
    for name in VPN_DOMAINS:
        answers = resolve(name)
        dns[name] = {"answers": answers[:3],
                     "blocked": any(a in ("0.0.0.0", "127.0.0.1") for a in answers),
                     "resolved": any(a[0].isdigit() and a not in ("0.0.0.0", "127.0.0.1") for a in answers)}
    sent = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    for i in range(5):
        packet = bytes([1, 0, 0, 0]) + os.urandom(144)     # type 1 + reserved + 144 bytes
        s.sendto(packet, WARP)
        t = time.time()
        try:
            reply, _ = s.recvfrom(2048)
            got = len(reply)
        except socket.timeout:
            got = 0
        sent.append({"t": t, "bytes": len(packet), "reply_bytes": got})
        time.sleep(1)
    result = {"dns": dns, "wireguard_probe": {"to": "%s:%d" % WARP, "packets": sent,
                                              "local_port": s.getsockname()[1]}}
    with open(sys.argv[1], "w") as f:
        json.dump(result, f, indent=1)
    print(json.dumps(result, indent=1))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
SecurePi Gateway - the demo's attacks, inside the isolated test harness
(ENHANCEMENT-PLAN.md step 8.3; the script that uses this is docs/DEMO.md).

Run on the gateway as root, from /opt/securepi-eval (gateway/install.sh
puts it there, next to battery.py, which it imports):

    sudo python3 /opt/securepi-eval/demo_attacks.py slow-scan [--run N]
    sudo python3 /opt/securepi-eval/demo_attacks.py campaign  [--run N]
    sudo python3 /opt/securepi-eval/demo_attacks.py cleanup

Every packet stays inside the test harness: from the ns_attacker network
namespace to ns_victim, across the br-test bridge. Nothing is sent to or
from a real device. The IDS captures the harness link (veth-atk) exactly
as it did for the step 7.2 detection battery, and this script calls the
battery's own attack functions (gateway/battery.py) unchanged. So the
demo shows the code path that 7.2 measured, with the same expected times:

  slow-scan  from 10.10.0.247: 9 TCP probes to 10.10.0.221, 50 s apart
             (about 7 minutes of traffic). Too slow for the ordinary
             port-scan signal; caught by the windowed slow_port_scan
             signal. 7.2 median time to detect: 494 s from the start.

  campaign   from 10.10.0.248, all three at once:
               - a 40-port scan of 10.10.0.221            (port_scan,   7.2 median 92 s)
               - 9 SSH logins to 10.10.0.222               (brute_force, 7.2 median 78 s)
               - a check-in to 10.10.0.223 every 10 s, x10 (beacon,      7.2 median 139 s)
             Two different ATT&CK tactics on one device make a campaign
             (campaign_min_distinct_tactics, default 2); with all three
             the kill chain reads Discovery -> Credential Access ->
             Command and Control.

Each run registers a new "[TEST HARNESS] demo ..." device for its address
(as the battery does), so one rehearsal's incidents never merge into the
next one's. --run picks the port numbers; leave it out and it is derived
from the clock, so each rehearsal uses fresh ports.

Each attack prints one line when the engine links its evidence to an
incident ("detected in 81.4s"), or "NOT DETECTED" when the battery's wait
runs out.
"""

import argparse
import os
import subprocess
import sys
import threading
import time

# battery.py sits next to this file, both on the gateway and in the repo.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import battery as b  # noqa: E402

SLOW_HOST = "10.10.0.247"
CAMPAIGN_HOST = "10.10.0.248"
DEMO_HOSTS = [SLOW_HOST, CAMPAIGN_HOST]


def add_address(ip):
    """Give ns_attacker one more source address. Already there (an earlier
    run stopped part-way) is fine."""
    b.sh(["ip", "addr", "add", "%s/24" % ip, "dev", "eth0"], ns=b.NS)


def new_demo_device(name, ip):
    """A fresh harness device that owns `ip` from now on. first_seen is
    30 days back, as in the battery, so it is an established device and
    the new_device signal stays out of the demo."""
    conn = b.db()
    label = "%s %s" % (name, time.strftime("%H:%M"))
    dev = b.make_device(conn, label, ip, first_seen_days=30)
    conn.close()
    print("device %d = \"[TEST HARNESS] %s\" at %s" % (dev, label, ip), flush=True)
    return dev


def start_victim_sshd():
    """The brute-force target: an sshd inside ns_victim that refuses every
    login, so each attempt is a real SSH handshake (the battery's setup)."""
    os.makedirs(b.SSHD_DIR, exist_ok=True)
    if not os.path.exists(b.SSHD_DIR + "/host_key"):
        b.sh(["ssh-keygen", "-q", "-t", "ed25519", "-f", b.SSHD_DIR + "/host_key", "-N", ""])
    with open(b.SSHD_DIR + "/sshd_config", "w") as f:
        f.write("Port 22\nListenAddress 0.0.0.0\nHostKey %s/host_key\nPasswordAuthentication no\n"
                "PubkeyAuthentication no\nUsePAM no\nLogLevel QUIET\n" % b.SSHD_DIR)
    return subprocess.Popen(["ip", "netns", "exec", b.VICTIM_NS, "/usr/sbin/sshd",
                             "-f", b.SSHD_DIR + "/sshd_config", "-D"])


def slow_scan(run):
    add_address(SLOW_HOST)
    dev = new_demo_device("demo slow scanner", SLOW_HOST)
    print("slow scan started at %s: 9 probes, 50 s apart; expect the incident about 8 minutes from now"
          % time.strftime("%H:%M:%S"), flush=True)
    b.slow_port_scan(run, SLOW_HOST, dev)


def campaign(run):
    add_address(CAMPAIGN_HOST)
    dev = new_demo_device("demo attacker", CAMPAIGN_HOST)
    sshd = start_victim_sshd()
    time.sleep(1)
    started = time.time()
    print("campaign started at %s: port scan, SSH brute force and beacon, all from %s"
          % (time.strftime("%H:%M:%S"), CAMPAIGN_HOST), flush=True)
    try:
        # The three attacks run side by side; each prints its own result
        # line as soon as its incident appears.
        threads = [threading.Thread(target=fn, args=(run, CAMPAIGN_HOST, dev))
                   for fn in (b.beacon, b.port_scan, b.brute_force)]
        for t in threads:
            t.start()
        # Watch for the campaign while they run (it needs only two tactics).
        deadline = started + 300
        found = None
        while time.time() < deadline and found is None:
            found = b.db().execute("SELECT id, created_at, tactics FROM campaigns WHERE device_id=?"
                                   " ORDER BY id LIMIT 1", (dev,)).fetchone()
            if found is None:
                time.sleep(1)
        if found:
            print("  campaign #%d (%s) formed %.1fs after the start"
                  % (found["id"], found["tactics"], found["created_at"] - started), flush=True)
        else:
            print("  campaign NOT FORMED within 300 s", flush=True)
        for t in threads:
            t.join()
        if found:
            # The kill chain grows as later tactics are linked; show the final one.
            row = b.db().execute("SELECT tactics FROM campaigns WHERE id=?", (found["id"],)).fetchone()
            print("  campaign #%d final kill chain: %s" % (found["id"], row["tactics"]), flush=True)
    finally:
        sshd.terminate()


def cleanup():
    """Take the demo addresses off ns_attacker. The demo devices and their
    incidents stay, as the battery's do (they are labelled TEST HARNESS)."""
    for ip in DEMO_HOSTS:
        b.sh(["ip", "addr", "del", "%s/24" % ip, "dev", "eth0"], ns=b.NS)
    print("demo addresses removed from ns_attacker", flush=True)


def main():
    ap = argparse.ArgumentParser(description="SecurePi demo attacks inside the test harness")
    ap.add_argument("what", choices=["slow-scan", "campaign", "cleanup"])
    ap.add_argument("--run", type=int, default=None,
                    help="port-numbering run number, 10-99 (default: from the clock)")
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root: sudo python3 %s %s" % (sys.argv[0], args.what))
    run = args.run if args.run is not None else 10 + int(time.time() // 60) % 90
    if args.what == "slow-scan":
        slow_scan(run)
    elif args.what == "campaign":
        campaign(run)
    else:
        cleanup()


if __name__ == "__main__":
    main()

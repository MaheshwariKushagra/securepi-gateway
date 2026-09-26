#!/usr/bin/env python3
"""
SecurePi Gateway - day 14 evaluation script.

Fires each of the four correlation signals three times against the isolated
test harness (ns_attacker / ns_victim, see setup-test-harness.sh) and times
how long the engine takes to raise or extend an incident for it. New-device
detection gets its own throwaway namespaces, since it needs devices the
registry has genuinely never seen before rather than the fixed attacker/
victim pair. Nothing here ever generates traffic from, or targets, the two
real devices on the network (device_id 1 and 2).

Run on the gateway as root:
    sudo python3 evaluate.py

Everything is read from securepi.db and the live nftables/AdGuard state, so
re-running this script is safe and produces fresh, comparable numbers.
"""
import json
import os
import sqlite3
import subprocess
import sys
import time

sys.path.insert(0, "/opt/securepi")
import registry

DB_PATH = "/var/lib/securepi/securepi.db"
ATTACKER_NS = "ns_attacker"
ATTACKER_DEVICE_ID = 4    # [TEST HARNESS] test-attacker
VICTIM_IP = "10.10.0.221"
# Nine more addresses on ns_victim's own interface (ENHANCEMENT-PLAN.md step
# 2.1 / setup-test-harness.sh) - real distinct hosts for a network-sweep
# test to find. A sweep against an address with no host behind it produces
# no IDS flow event at all (the kernel never resolves an ARP entry to
# send the packet on), so this needs actual hosts, not just addresses.
SWEEP_IPS = ["10.10.0.%d" % i for i in range(221, 231)]
RUNS_PER_SIGNAL = 3
POLL_INTERVAL = 1
DETECT_TIMEOUT = 90

# A handful of domains the DNS filter's active blocklists are known to cover (see
# REPORT-adblocking.md) - used both for the malicious-domain signal test and
# the third-party ad-block ratio measurement below.
BLOCKED_DOMAIN = "doubleclick.net"
AD_DOMAINS = [
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "adservice.google.com", "scorecardresearch.com", "adnxs.com",
    "outbrain.com", "taboola.com", "criteo.com", "pubmatic.com",
]


def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def run(args, timeout=30):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def run_in_ns(ns, args, timeout=30):
    return run(["ip", "netns", "exec", ns] + args, timeout=timeout)


def last_touch_now(device_id, signal_type):
    # max(updated_at), not evidence_count: a fresh incident (dedup window
    # expired) can carry a SMALLER evidence_count than an old, unrelated one
    # for the same signal/device, so evidence_count is not a valid "did
    # something just happen" test across separate incidents.
    row = db().execute(
        "SELECT max(updated_at) t FROM incidents WHERE device_id=? AND signal_type=?",
        (device_id, signal_type)).fetchone()
    return row["t"] or 0


def wait_for_touch_after(device_id, signal_type, baseline_touch, timeout=DETECT_TIMEOUT):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if last_touch_now(device_id, signal_type) > baseline_touch:
            return time.time() - t0
        time.sleep(POLL_INTERVAL)
    return None


def test_port_scan(run_no):
    baseline = last_touch_now(ATTACKER_DEVICE_ID, "port_scan")
    t0 = time.time()
    run_in_ns(ATTACKER_NS, ["nmap", "-sT", "-Pn", "--top-ports", "20",
                            "--min-rate", "500", VICTIM_IP], timeout=30)
    latency = wait_for_touch_after(ATTACKER_DEVICE_ID, "port_scan", baseline)
    return latency


SSHD_DIR = "/tmp/eval-sshd"
SSHD_CONFIG = """\
Port 22
ListenAddress 0.0.0.0
HostKey %s/host_key
PasswordAuthentication yes
PermitRootLogin yes
UsePAM no
LogLevel QUIET
""" % SSHD_DIR


def ensure_test_sshd_keys():
    if not os.path.exists(SSHD_DIR + "/host_key"):
        os.makedirs(SSHD_DIR, exist_ok=True)
        with open(SSHD_DIR + "/sshd_config", "w") as f:
            f.write(SSHD_CONFIG)
        run(["ssh-keygen", "-t", "ed25519", "-f", SSHD_DIR + "/host_key", "-N", ""])


def test_brute_force(run_no):
    baseline = last_touch_now(ATTACKER_DEVICE_ID, "brute_force")
    # The signal watches connection attempts at the flow level, not auth
    # success or failure - but hydra needs a real SSH protocol handshake to
    # complete before it will try more than one credential, or it aborts
    # after the first "connection reset". A real (if disposable) sshd inside
    # the isolated victim namespace, guaranteed to reject every credential
    # hydra tries, is what makes this a genuine brute-force run rather than
    # a single failed connection.
    ensure_test_sshd_keys()
    sshd = subprocess.Popen(["ip", "netns", "exec", "ns_victim", "/usr/sbin/sshd",
                             "-f", SSHD_DIR + "/sshd_config", "-D"])
    time.sleep(0.5)
    userlist = "/tmp/eval-users.txt"
    passlist = "/tmp/eval-pass.txt"
    with open(userlist, "w") as f:
        f.write("root\nadmin\n")
    with open(passlist, "w") as f:
        f.write("\n".join("guess%d" % i for i in range(6)) + "\n")
    try:
        run_in_ns(ATTACKER_NS, ["hydra", "-L", userlist, "-P", passlist, "-t", "4",
                                "-w", "2", "ssh://%s" % VICTIM_IP], timeout=45)
        latency = wait_for_touch_after(ATTACKER_DEVICE_ID, "brute_force", baseline)
    finally:
        sshd.terminate()
        sshd.wait(timeout=5)
    return latency


GATEWAY_DNS_IP = "10.10.0.1"  # The DNS filter's own address; see note in test_malicious_domain


def test_malicious_domain(run_no):
    baseline = last_touch_now(ATTACKER_DEVICE_ID, "malicious_domain")
    # ns_attacker cannot reach the DNS filter at all: br-test (the isolated test
    # harness bridge) has no path to ap0 (the production LAN the DNS filter is
    # bound on) - confirmed by testing, not assumed. So this query has to
    # run from the gateway's own network namespace, which means the DNS filter logs
    # its client as 10.10.0.1 (the gateway's own address) rather than the
    # attacker device's IP. A one-off device_ips interval maps that address
    # to the test-attacker device for attribution, exactly as the registry's
    # own historical-interval design intends for a device using a new
    # address - see registry.py's docstring on why attribution is
    # interval-based rather than "whoever holds the address now".
    conn = db()
    registry.touch_interval(conn, "device_ips", ATTACKER_DEVICE_ID, GATEWAY_DNS_IP, "ip", time.time())
    conn.commit()
    for _ in range(MALICIOUS_DOMAIN_QUERIES):
        run(["dig", "+short", "+time=2", "+tries=1", "@%s" % GATEWAY_DNS_IP, BLOCKED_DOMAIN], timeout=5)
    # the DNS filter buffers its query log in memory (querylog.size_memory: 1000 in
    # AdGuardHome.yaml) and was observed, under real continuous traffic, to
    # go over 7 hours without flushing it to the file ingest.py tails - a
    # genuine latency gap between "the DNS filter has seen the query" (immediate,
    # visible over its control API) and "our pipeline has the event" (only
    # after the next flush). Firing enough queries to fill that buffer here
    # forces the flush so this test completes in a reasonable time; in
    # production, malicious-domain detection latency is bounded by whichever
    # is worse: the engine's 15s cycle, or the DNS filter's own flush cadence -
    # worth recording as a limitation, not something this project fixes.
    run(["bash", "-c",
         "seq 1 985 | xargs -P30 -I{} dig +short +time=1 +tries=1 @%s"
         " eval-flush-probe-%d-{}.invalid" % (GATEWAY_DNS_IP, run_no)],
        timeout=60)
    latency = wait_for_touch_after(ATTACKER_DEVICE_ID, "malicious_domain", baseline)
    return latency


MALICIOUS_DOMAIN_QUERIES = 15  # matches MALICIOUS_DOMAIN_THRESHOLD in correlation.py


def test_network_sweep(run_no):
    """ENHANCEMENT-PLAN.md step 2.1's harness scenario for network_sweep_signal
    (the horizontal mirror of test_port_scan): one port, many distinct hosts."""
    baseline = last_touch_now(ATTACKER_DEVICE_ID, "network_sweep")
    run_in_ns(ATTACKER_NS, ["nmap", "-sT", "-Pn", "-p", "443", "--min-rate", "500"]
              + SWEEP_IPS, timeout=30)
    return wait_for_touch_after(ATTACKER_DEVICE_ID, "network_sweep", baseline)


# Slower than SLOW_SCAN_WINDOW_SECONDS/SLOW_SCAN_THRESHOLD (7200/8 = 900s/port)
# would be a genuinely faithful nmap -T0 reproduction, but that's 2 real
# hours per run - impractical to actually execute here. What this DOES need
# to prove is the one thing that matters: paced slower than
# PORT_SCAN_WINDOW_SECONDS/PORT_SCAN_THRESHOLD (300/8 = 37.5s/port), the fast
# signal structurally cannot fire (see correlation.py's slow_scan_signal
# docstring for why), while the slow signal's own window is wide enough to
# still catch it. 45s/port clears that bar with margin either way.
SLOW_SCAN_DELAY_MS = 45000
SLOW_SCAN_PORTS = 8


def test_slow_scan(run_no):
    """ENHANCEMENT-PLAN.md step 2.1's harness scenario for slow_scan_signal.
    Real wall-clock time: ~6 minutes (8 ports x 45s scan-delay, one at a
    time - see SLOW_SCAN_PORTS/SLOW_SCAN_DELAY_MS above). Returns
    (fast_signal_fired, slow_signal_latency_seconds) - the fast
    port_scan_signal firing here would be the actual failure case, since
    it would mean this pacing wasn't slow enough to be a fair test."""
    baseline_fast = last_touch_now(ATTACKER_DEVICE_ID, "port_scan")
    baseline_slow = last_touch_now(ATTACKER_DEVICE_ID, "slow_port_scan")
    ports = ",".join(str(20000 + i) for i in range(SLOW_SCAN_PORTS))
    total_scan_seconds = SLOW_SCAN_PORTS * SLOW_SCAN_DELAY_MS // 1000
    run_in_ns(ATTACKER_NS, ["nmap", "-sT", "-Pn", "-p", ports,
                            "--scan-delay", "%dms" % SLOW_SCAN_DELAY_MS,
                            "--max-parallelism", "1", VICTIM_IP],
              timeout=total_scan_seconds + 60)
    fast_fired = last_touch_now(ATTACKER_DEVICE_ID, "port_scan") > baseline_fast
    slow_latency = wait_for_touch_after(ATTACKER_DEVICE_ID, "slow_port_scan", baseline_slow, timeout=60)
    return fast_fired, slow_latency


def test_new_device(run_no):
    # new_device_signal fires off devices.first_seen, populated by
    # registry.resolve_device() for every real device (DHCP lease or ARP
    # entry). ns_attacker/ns_victim sit on br-test, which - confirmed by a
    # failed ping, not assumed - has no path to the DNS filter's DHCP/ap0 side, so
    # there is no way to make an isolated netns look like a "real" new
    # device through the network. Calling resolve_device() directly with a
    # never-before-seen MAC exercises the exact same code path update_devices
    # would have used had the discovery happened for real, without needing
    # network connectivity this test harness cannot provide.
    conn = db()
    mac = "02:00:00:00:99:%02x" % run_no
    t0 = time.time()
    device_id = registry.resolve_device(conn, mac, "eval-new-device-%d" % run_no, t0)
    conn.commit()

    deadline = time.time() + DETECT_TIMEOUT
    while time.time() < deadline:
        inc = db().execute(
            "SELECT 1 FROM incidents WHERE device_id=? AND signal_type='new_device'",
            (device_id,)).fetchone()
        if inc:
            return time.time() - t0
        time.sleep(POLL_INTERVAL)
    return None


def ad_block_ratio():
    """Compares resolution through the DNS filter (filtering on, as configured
    right now) against a public resolver with no filtering, for a fixed set
    of known third-party ad/tracker domains. See REPORT-adblocking.md 9,
    which left this "to be measured"."""
    blocked = 0
    rows = []
    for domain in AD_DOMAINS:
        # Run directly on the gateway, not inside ns_attacker: the isolated
        # test-harness bridge has no path to the DNS filter (see test_malicious_domain).
        via_adguard = run(["dig", "+short", "+time=2", "@%s" % GATEWAY_DNS_IP, domain])
        via_public = run(["dig", "+short", "+time=2", "@1.1.1.1", domain])
        adguard_result = via_adguard.stdout.strip()
        public_result = via_public.stdout.strip()
        is_blocked = adguard_result in ("", "0.0.0.0") and public_result not in ("", "0.0.0.0")
        blocked += int(is_blocked)
        rows.append((domain, adguard_result or "(blocked)", public_result or "(no answer)"))
    return blocked, len(AD_DOMAINS), rows


def resource_snapshot():
    free = run(["free", "-m"]).stdout
    services = ["securepi-web", "securepi-engine", "securepi-ingest", "suricata", "AdGuardHome"]
    mem = {}
    for svc in services:
        r = run(["systemctl", "show", svc, "-p", "MemoryCurrent"])
        val = r.stdout.strip().split("=")[-1]
        mem[svc] = int(val) // (1024 * 1024) if val.isdigit() else None
    load = run(["cat", "/proc/loadavg"]).stdout.strip()
    return free, mem, load


def throughput_test():
    """iperf3 between ns_attacker and ns_victim (over br-test, captured by
    the IDS on veth-atk exactly like production ap0 traffic) vs. a loopback
    baseline with no bridge/capture path at all - isolates what the
    inspection stack itself costs, separate from the WAN-side ceiling
    already measured in SECUREPI-15-DAY-PLAN.md 2.6. The gateway's own
    br-test has no IP address on it (confirmed: it's a pure L2 bridge), so
    both ends have to be inside the harness namespaces, not the host."""
    server = subprocess.Popen(["ip", "netns", "exec", "ns_victim", "iperf3", "-s", "-1", "-p", "5202"])
    time.sleep(1)
    lan = run_in_ns("ns_attacker", ["iperf3", "-c", VICTIM_IP, "-p", "5202", "-t", "5", "-J"], timeout=15)
    server.wait(timeout=10)

    server2 = subprocess.Popen(["iperf3", "-s", "-1", "-p", "5203"])
    time.sleep(1)
    loop = run(["iperf3", "-c", "127.0.0.1", "-p", "5203", "-t", "5", "-J"], timeout=15)
    server2.wait(timeout=10)

    def mbps(result):
        try:
            data = json.loads(result.stdout)
            return data["end"]["sum_received"]["bits_per_second"] / 1e6
        except Exception:
            return None

    return mbps(lan), mbps(loop)


def main():
    print("=" * 70)
    print("SecurePi Gateway - day 14 evaluation")
    print("=" * 70)

    print("\n--- Detection rate + time-to-detect, %d runs each ---" % RUNS_PER_SIGNAL)
    results = {}
    for name, fn in [("port_scan", test_port_scan),
                      ("brute_force", test_brute_force),
                      ("malicious_domain", test_malicious_domain),
                      ("new_device", test_new_device)]:
        print("\n%s:" % name)
        latencies = []
        for i in range(1, RUNS_PER_SIGNAL + 1):
            lat = fn(i)
            latencies.append(lat)
            print("  run %d: %s" % (i, ("detected in %.1fs" % lat) if lat is not None else "NOT DETECTED"))
        results[name] = latencies

    print("\n--- Ad-block ratio, third-party (%d fixed domains) ---" % len(AD_DOMAINS))
    blocked, total, rows = ad_block_ratio()
    for domain, adguard_result, public_result in rows:
        print("  %-28s adguard=%-12s public=%s" % (domain, adguard_result, public_result))
    print("  blocked %d / %d (%.0f%%)" % (blocked, total, 100 * blocked / total))

    print("\n--- Resource usage ---")
    free, mem, load = resource_snapshot()
    print(free)
    for svc, mb in mem.items():
        print("  %-20s %s MB" % (svc, mb))
    print("  load average:", load)

    print("\n--- Throughput ---")
    lan_mbps, loop_mbps = throughput_test()
    print("  br-test path (through bridge + IDS capture): %s Mbps" %
          ("%.1f" % lan_mbps if lan_mbps else "failed"))
    print("  loopback baseline (no bridge/capture):             %s Mbps" %
          ("%.1f" % loop_mbps if loop_mbps else "failed"))

    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)
    for name, latencies in results.items():
        detected = [l for l in latencies if l is not None]
        if detected:
            avg = sum(detected) / len(detected)
            print("%-20s %d/%d detected, avg %.1fs" % (name, len(detected), len(latencies), avg))
        else:
            print("%-20s 0/%d detected" % (name, len(latencies)))


if __name__ == "__main__":
    main()

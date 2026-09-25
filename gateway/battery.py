#!/usr/bin/env python3
"""
SecurePi Gateway - detection battery (ENHANCEMENT-PLAN.md step 7.2).

Runs every detection signal that real traffic can drive, five times each,
against the isolated test harness, and measures whether it was detected
and how long that took (median and 95th percentile).

Run on the gateway as root, with the normal services running:
    sudo python3 battery.py [--runs 5] [--out /var/tmp/securepi-battery]

What makes this different from evaluate.py (the day-14 script)
---------------------------------------------------------------
1. A run only counts as detected when an incident links an event FROM THAT
   RUN. evaluate.py counted "the incident's updated_at moved", but every
   signal re-examines its whole trailing window each 15-second engine
   cycle and refreshes updated_at while the earlier run's traffic is still
   inside it - so run 2 of a back-to-back pair was "detected" by run 1's
   leftovers within one cycle, whatever run 2 did.
2. Runs are independent. Each run uses its own source host (a separate
   address inside ns_attacker, registered as its own device), so one run's
   traffic can never count toward another run's threshold.
3. The whole harness link (veth-atk) is captured to a pcap with a
   labels.json beside it - the labelled ground truth step 7.1's replay
   tool (tools/replay.py) runs against.

Where the traffic comes from
-----------------------------
Suricata captures on veth-atk, ns_attacker's link to the test bridge. Every
extra host is a secondary address on ns_attacker's own interface, and each
tool is told to send from it (nmap -S, ssh -b, curl --interface, iperf3 -B),
so every packet still crosses the captured link. DNS-based signals can't
use the bridge (it has no path to AdGuard), so their queries are sent from
the gateway itself to AdGuard at 10.10.0.1, and that address is mapped to a
fresh battery device for the length of each run - the same approach
evaluate.py's malicious-domain test uses.

Nothing here sends traffic from, or to, a real device on the network.

What it can't drive, and why (also written to the results file)
----------------------------------------------------------------
- adblock_ineffective needs an enrolled device watching YouTube (step 5.10).
- The platform signals (service down, stale, disk, WAN, fail-open) are
  step 7.7's chaos tests, not detections of an attack.
- volume_anomaly needs seven days of history. The battery writes a
  synthetic ten-day baseline for its own test devices and then makes a
  real, measured transfer - the trigger is real, the history isn't.
- new_device can't be driven through the network from the harness (no
  DHCP path), so it calls registry.resolve_device() with a never-seen MAC,
  the same code the DHCP-lease path runs.
"""

import argparse
import json
import os
import random
import sqlite3
import statistics
import string
import subprocess
import sys
import threading
import time

sys.path.insert(0, "/opt/securepi")
import registry  # noqa: E402

DB_PATH = "/opt/securepi/securepi.db"
NS = "ns_attacker"
VICTIM_NS = "ns_victim"
VICTIM_IP = "10.10.0.221"
VICTIM_IPS = ["10.10.0.%d" % i for i in range(221, 231)]
GATEWAY_DNS = "10.10.0.1"
CAPTURE_IF = "veth-atk"
SSHD_DIR = "/tmp/battery-sshd"

# Secondary addresses inside ns_attacker, one per test host. .231-.235 run
# the fast signals (and so also form a campaign each), .236-.240 the slow
# port scans, .241-.245 the slow sweeps, .246 plays an ordinary user.
FAST_HOSTS = ["10.10.0.%d" % i for i in range(231, 236)]
SLOW_SCAN_HOSTS = ["10.10.0.%d" % i for i in range(236, 241)]
SLOW_SWEEP_HOSTS = ["10.10.0.%d" % i for i in range(241, 246)]
BENIGN_HOST = "10.10.0.246"

# Domains the live blocklists block (checked at start-up, and any that
# resolve are dropped). malicious_domain needs 15 distinct blocked ones.
BLOCKED_CANDIDATES = [
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.com",
    "scorecardresearch.com", "adnxs.com", "outbrain.com", "taboola.com", "criteo.com",
    "pubmatic.com", "app-measurement.com", "ads.yahoo.com", "amazon-adsystem.com",
    "hotjar.com", "mixpanel.com", "bat.bing.com", "ads.linkedin.com", "adsrvr.org",
    "rubiconproject.com", "openx.net", "moatads.com", "quantserve.com", "zedo.com",
]
CANARY = "mask.icloud.com"
IOC_SOURCE = "battery-test"

# How long to keep looking for a detection after a run's traffic ends.
WAIT_AFTER = {"slow_port_scan": 240, "slow_network_sweep": 240, "volume_anomaly": 240}
DEFAULT_WAIT = 150
SLOW_DELAY_S = 50          # > 300 s window / 8 probes, so the fast signals can't fire
SLOW_PROBES = 9


def db():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def sh(args, timeout=120, ns=None):
    if ns:
        args = ["ip", "netns", "exec", ns] + args
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def rand_label(n):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


# ------------------------------------------------------------ test devices

def make_device(conn, name, ip=None, first_seen_days=0):
    """A battery test device, optionally owning an address from now on."""
    now = time.time()
    cur = conn.execute(
        "INSERT INTO devices (hostname, friendly_name, first_seen, last_seen, trust) VALUES (?, ?, ?, ?, 'approved')",
        (name.lower().replace(" ", "-"), "[TEST HARNESS] %s" % name, now - first_seen_days * 86400, now))
    dev = cur.lastrowid
    if ip:
        own_address(conn, dev, ip)
    conn.commit()
    return dev


def own_address(conn, dev, ip):
    """Give `dev` the address from now until the battery is over. A new
    interval that started most recently wins attribution (registry.py)."""
    now = time.time()
    conn.execute("INSERT INTO device_ips (device_id, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                 (dev, ip, now, now + 6 * 3600))
    conn.commit()


# ---------------------------------------------------------------- detection

def detected_at(conn, signal, device, since, event_filter="", params=()):
    """True once an incident of this signal type, for this device, links at
    least one event from this run (ts >= since, plus any run-specific
    filter). This is the run's own evidence, not a refreshed timestamp."""
    row = conn.execute(
        "SELECT 1 FROM incidents i JOIN incident_events ie ON ie.incident_id = i.id"
        " JOIN events e ON e.id = ie.event_id"
        " WHERE i.signal_type = ? AND i.device_id = ? AND e.ts >= ? %s LIMIT 1" % event_filter,
        (signal, device, since) + tuple(params)).fetchone()
    return row is not None


class Run:
    """One run of one signal: when it started and ended, and when (if) the
    engine linked its evidence to an incident."""

    def __init__(self, signal, n, host, device, **label):
        self.signal, self.n, self.host, self.device = signal, n, host, device
        self.label = label
        self.t_start = time.time()
        self.t_end = None
        self.t_detect = None
        self.note = None

    def ended(self):
        self.t_end = time.time()

    def wait(self, check):
        """Poll `check()` every second until it's true or the time is up."""
        deadline = (self.t_end or time.time()) + WAIT_AFTER.get(self.signal, DEFAULT_WAIT)
        while time.time() < deadline:
            if check():
                self.t_detect = time.time()
                return
            time.sleep(1)

    def result(self):
        r = {"signal": self.signal, "run": self.n, "host": self.host, "device_id": self.device,
             "t_start": round(self.t_start, 3), "t_end": round(self.t_end or self.t_start, 3),
             "detected": self.t_detect is not None,
             "ttd_from_start_s": round(self.t_detect - self.t_start, 1) if self.t_detect else None,
             "ttd_from_end_s": round(self.t_detect - self.t_end, 1) if self.t_detect and self.t_end else None}
        if self.note:
            r["note"] = self.note
        r.update(self.label)
        return r


RESULTS = []
RESULTS_LOCK = threading.Lock()


def record(run):
    with RESULTS_LOCK:
        RESULTS.append(run.result())
    status = "detected in %.1fs" % (run.t_detect - run.t_start) if run.t_detect else "NOT DETECTED"
    print("  %-19s run %d (%s): %s" % (run.signal, run.n, run.host, status), flush=True)


# ---------------------------------------------------------- network signals

def port_scan(n, host, dev):
    run = Run("port_scan", n, host, dev, target=VICTIM_IP, expect=True)
    sh(["nmap", "-sT", "-Pn", "-S", host, "-e", "eth0", "--top-ports", "40", "--min-rate", "500", VICTIM_IP], ns=NS)
    run.ended()
    run.wait(lambda: detected_at(db(), "port_scan", dev, run.t_start, "AND e.dest_ip = ?", (VICTIM_IP,)))
    record(run)


def network_sweep(n, host, dev):
    port = str(8000 + n)
    run = Run("network_sweep", n, host, dev, target="port %s x %d hosts" % (port, len(VICTIM_IPS)), expect=True)
    sh(["nmap", "-sT", "-Pn", "-S", host, "-e", "eth0", "-p", port, "--min-rate", "500"] + VICTIM_IPS, ns=NS)
    run.ended()
    run.wait(lambda: detected_at(db(), "network_sweep", dev, run.t_start, "AND e.dest_port = ?", (int(port),)))
    record(run)


def brute_force(n, host, dev):
    target = VICTIM_IPS[1]  # a different victim address from the port scan's
    run = Run("brute_force", n, host, dev, target="%s:22" % target, expect=True)
    for _ in range(9):
        sh(["ssh", "-b", host, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=3", "root@%s" % target, "true"],
           ns=NS, timeout=15)
    run.ended()
    run.wait(lambda: detected_at(db(), "brute_force", dev, run.t_start, "AND e.dest_ip = ? AND e.dest_port = 22", (target,)))
    record(run)


BEACON_SCRIPT = """
import random, socket, sys, time
src, dst, port, count, interval = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5])
random.seed(int(port))
for i in range(count):
    s = socket.socket()
    s.bind((src, 0))
    s.settimeout(2)
    try:
        s.connect((dst, port))
        s.sendall(b"GET /check-in HTTP/1.0\\r\\n\\r\\n")
        s.recv(256)
    except OSError:
        pass
    s.close()
    if i < count - 1:
        time.sleep(interval * random.uniform(0.9, 1.1))   # 10 per cent jitter
"""


def beacon(n, host, dev):
    target, port = VICTIM_IPS[2], 9000 + n
    run = Run("beacon", n, host, dev, target="%s:%d every 10 s +-10%%" % (target, port), expect=True)
    sh(["python3", "-c", BEACON_SCRIPT, host, target, str(port), "10", "10"], ns=NS, timeout=200)
    run.ended()
    run.wait(lambda: detected_at(db(), "beacon", dev, run.t_start, "AND e.dest_ip = ? AND e.dest_port = ?", (target, port)))
    record(run)


def ids_alert(n, host, dev):
    """The classic testmynids.org check, entirely inside the harness: a
    server on the test host answers with a Unix `id` output for root, which
    Suricata's rule 2100498 ("GPL ATTACK_RESPONSE id check returned root")
    matches. The server is the host that 'returned root', so the alert and
    the incident belong to the test host. Three fetches meet the default
    ids_alert_threshold of 3."""
    port = 8080 + n
    body = "/tmp/battery-id-%d" % n
    os.makedirs(body, exist_ok=True)
    with open(body + "/index.html", "w") as f:
        f.write("uid=0(root) gid=0(root) groups=0(root)\n")
    server = subprocess.Popen(["ip", "netns", "exec", NS, "python3", "-m", "http.server", str(port),
                               "--bind", host, "--directory", body],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    run = Run("ids_alert", n, host, dev, target="rule 2100498 via %s:%d" % (host, port), expect=True)
    try:
        for _ in range(4):
            sh(["curl", "-s", "-m", "3", "http://%s:%d/" % (host, port)], ns=VICTIM_NS, timeout=10)
            time.sleep(1)
    finally:
        server.terminate()
    run.ended()
    # The alert is classified by app/signature_taxonomy.py, so its incident
    # type depends on the category - accept any ids_* type for this device.
    run.wait(lambda: db().execute(
        "SELECT 1 FROM incidents i JOIN incident_events ie ON ie.incident_id = i.id JOIN events e ON e.id = ie.event_id"
        " WHERE i.signal_type LIKE 'ids_%' AND i.device_id = ? AND e.ts >= ? AND e.event_type = 'alert' LIMIT 1",
        (dev, run.t_start)).fetchone() is not None)
    record(run)


def slow_port_scan(n, host, dev):
    ports = ",".join(str(20000 + n * 100 + i) for i in range(SLOW_PROBES))
    run = Run("slow_port_scan", n, host, dev, target="%s, %d ports, %d s apart" % (VICTIM_IP, SLOW_PROBES, SLOW_DELAY_S), expect=True)
    sh(["nmap", "-sT", "-Pn", "-S", host, "-e", "eth0", "-p", ports, "--scan-delay", "%ds" % SLOW_DELAY_S,
        "--max-parallelism", "1", VICTIM_IP], ns=NS, timeout=SLOW_PROBES * SLOW_DELAY_S + 120)
    run.ended()
    run.wait(lambda: detected_at(db(), "slow_port_scan", dev, run.t_start, "AND e.dest_ip = ?", (VICTIM_IP,)))
    run.label["fast_signal_also_fired"] = detected_at(db(), "port_scan", dev, run.t_start)
    record(run)


def slow_network_sweep(n, host, dev):
    port = str(7000 + n)
    run = Run("slow_network_sweep", n, host, dev, target="port %s x %d hosts, %d s apart" % (port, len(VICTIM_IPS), SLOW_DELAY_S), expect=True)
    # nmap's --scan-delay paces probes within a host, not across hosts, so
    # a sweep is paced by hand: one host at a time.
    for ip in VICTIM_IPS:
        sh(["nmap", "-sT", "-Pn", "-S", host, "-e", "eth0", "-p", port, ip], ns=NS, timeout=30)
        if ip != VICTIM_IPS[-1]:
            time.sleep(SLOW_DELAY_S)
    run.ended()
    run.wait(lambda: detected_at(db(), "slow_network_sweep", dev, run.t_start, "AND e.dest_port = ?", (int(port),)))
    run.label["fast_signal_also_fired"] = detected_at(db(), "network_sweep", dev, run.t_start)
    record(run)


def volume_anomaly(n, host, dev):
    """A synthetic ten-day baseline of ~10 MB in this hour of the day, then a
    real ~150 MB transfer to the victim - flows Suricata really sees."""
    conn = db()
    hour = int(time.time() // 3600) * 3600
    for d in range(1, 11):
        total = int(10 * 1024 * 1024 * (1.1 if d % 2 else 0.9))
        conn.execute("INSERT OR REPLACE INTO device_hourly (device_id, hour_start, bytes_down, bytes_up) VALUES (?, ?, ?, ?)",
                     (dev, hour - d * 86400, int(total * 0.6), int(total * 0.4)))
    conn.commit()
    port = 5301 + n
    server = subprocess.Popen(["ip", "netns", "exec", VICTIM_NS, "iperf3", "-s", "-1", "-p", str(port)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    run = Run("volume_anomaly", n, host, dev, target="150 MB to %s, baseline synthetic" % VICTIM_IP, expect=True)
    sh(["iperf3", "-c", VICTIM_IP, "-p", str(port), "-B", host, "-n", "150M"], ns=NS, timeout=120)
    server.wait(timeout=20)
    run.ended()
    run.wait(lambda: db().execute(
        "SELECT 1 FROM incidents WHERE signal_type='volume_anomaly' AND device_id=? AND created_at >= ?",
        (dev, run.t_start)).fetchone() is not None)
    record(run)


def benign(host, dev, minutes=4):
    """An ordinary user: irregular web fetches (exponential gaps, varying
    sizes) to a server in the victim namespace. Nothing should fire."""
    root = "/tmp/battery-benign"
    os.makedirs(root, exist_ok=True)
    for i, size in enumerate((900, 4000, 20000, 150000)):
        with open("%s/p%d.html" % (root, i), "w") as f:
            f.write("x" * size)
    server = subprocess.Popen(["ip", "netns", "exec", VICTIM_NS, "python3", "-m", "http.server", "8000",
                               "--bind", VICTIM_IPS[3], "--directory", root],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    run = Run("benign", 1, host, dev, target="irregular web fetches to %s:8000" % VICTIM_IPS[3], expect=False)
    rng = random.Random(7)
    end = time.time() + minutes * 60
    while time.time() < end:
        sh(["curl", "-s", "-m", "3", "--interface", host, "-o", "/dev/null",
            "http://%s:8000/p%d.html" % (VICTIM_IPS[3], rng.randrange(4))], ns=NS, timeout=10)
        time.sleep(min(40, rng.expovariate(1 / 12.0)))
    server.terminate()
    run.ended()
    time.sleep(45)
    fired = [r[0] for r in db().execute(
        "SELECT DISTINCT signal_type FROM incidents WHERE device_id=? AND created_at >= ?", (dev, run.t_start))]
    run.label["incidents_raised"] = fired
    run.t_detect = time.time() if fired else None
    record(run)


# -------------------------------------------------------------- DNS signals

def dns(name, qtype="A"):
    return sh(["dig", "+short", "+time=2", "+tries=1", "@%s" % GATEWAY_DNS, name, qtype], timeout=10)


def dns_track(runs, blocked):
    """All DNS-driven signals, run k on its own device: 10.10.0.1 (where
    the gateway's own queries to AdGuard come from) is mapped to that
    device for run k only, so the runs can't share a threshold."""
    conn = db()
    for n in range(1, runs + 1):
        # first_seen a month back, so the device itself doesn't set off
        # new_device (which has its own track below).
        dev = make_device(conn, "battery dns run %d" % n, first_seen_days=30)
        own_address(conn, dev, GATEWAY_DNS)
        time.sleep(3)
        started = {}

        started["malicious_domain"] = Run("malicious_domain", n, GATEWAY_DNS, dev, target="%d distinct blocked domains" % len(blocked), expect=True)
        for d in blocked:
            dns(d)
        started["malicious_domain"].ended()

        # mask.icloud.com, not the Firefox canary: AdGuard doesn't log
        # use-application-dns.net at all (a finding of this step), and the
        # Suricata path that now covers it only sees queries that cross
        # ap0 - these come from the gateway itself. See correlation.py.
        started["dns_bypass"] = Run("dns_bypass", n, GATEWAY_DNS, dev, target="%s x4 (iCloud Private Relay canary)" % CANARY, expect=True)
        for _ in range(4):
            dns(CANARY)
        started["dns_bypass"].ended()

        ioc = "sp-battery-ioc-%d-%s.invalid" % (n, rand_label(6))
        conn.execute("INSERT INTO ioc (indicator, ioc_type, source, description, first_seen, last_seen)"
                     " VALUES (?, 'domain', ?, 'step 7.2 test indicator', ?, ?)", (ioc, IOC_SOURCE, time.time(), time.time()))
        conn.commit()
        started["threat_intel"] = Run("threat_intel", n, GATEWAY_DNS, dev, target=ioc, expect=True)
        dns(ioc)
        started["threat_intel"].ended()

        tun_base = "sp-tun%d.invalid" % n
        started["dns_tunneling"] = Run("dns_tunneling", n, GATEWAY_DNS, dev, target="25 TXT lookups under %s" % tun_base, expect=True)
        for _ in range(25):
            dns("%s.%s" % (rand_label(22), tun_base), "TXT")
        started["dns_tunneling"].ended()

        dga_base = "sp-dga%d.invalid" % n
        started["dga"] = Run("dga", n, GATEWAY_DNS, dev, target="12 NXDOMAIN lookups under %s" % dga_base, expect=True)
        for _ in range(12):
            dns("%s.%s" % (rand_label(14), dga_base))
        started["dga"].ended()

        checks = {
            "malicious_domain": lambda r: detected_at(db(), "malicious_domain", dev, r.t_start),
            "dns_bypass": lambda r: detected_at(db(), "dns_bypass", dev, r.t_start),
            "threat_intel": lambda r: detected_at(db(), "threat_intel", dev, r.t_start),
            "dns_tunneling": lambda r: detected_at(db(), "dns_tunneling", dev, r.t_start, "AND e.dns_rrname LIKE ?", ("%." + tun_base,)),
            "dga": lambda r: detected_at(db(), "dga", dev, r.t_start, "AND e.dns_rrname LIKE ?", ("%." + dga_base,)),
        }
        threads = []
        for sig, run in started.items():
            t = threading.Thread(target=lambda s=sig, r=run: (r.wait(lambda: checks[s](r)), record(r)))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()


def new_device_track(runs):
    for n in range(1, runs + 1):
        conn = db()
        mac = "02:00:00:7e:%02x:%02x" % (n, random.randrange(256))
        run = Run("new_device", n, mac, None, target="registry.resolve_device() with a never-seen MAC", expect=True)
        dev = registry.resolve_device(conn, mac, "battery-new-device-%d" % n, run.t_start)
        conn.execute("UPDATE devices SET friendly_name=? WHERE id=?", ("[TEST HARNESS] battery new device %d" % n, dev))
        conn.commit()
        run.device = dev
        run.ended()
        run.wait(lambda: db().execute("SELECT 1 FROM incidents WHERE signal_type='new_device' AND device_id=?",
                                      (dev,)).fetchone() is not None)
        record(run)


# ------------------------------------------------------------------ tracks

def fast_track(hosts, devs):
    """Hosts one at a time; on each, the beacon runs in the background while
    the scan, brute force, sweep and IDS runs happen. Each host therefore
    also builds a scan -> brute force -> beacon kill chain - a campaign."""
    for n, (host, dev) in enumerate(zip(hosts, devs), start=1):
        camp_start = time.time()
        b = threading.Thread(target=beacon, args=(n, host, dev))
        b.start()
        port_scan(n, host, dev)
        brute_force(n, host, dev)
        network_sweep(n, host, dev)
        ids_alert(n, host, dev)
        b.join()
        run = Run("campaign", n, host, dev, target="scan -> brute force -> beacon on one host", expect=True)
        run.t_start = camp_start
        run.ended()
        run.wait(lambda: db().execute("SELECT 1 FROM campaigns WHERE device_id=?", (dev,)).fetchone() is not None)
        tactics = db().execute("SELECT tactics FROM campaigns WHERE device_id=?", (dev,)).fetchone()
        run.label["tactics"] = tactics[0] if tactics else None
        record(run)
        volume_anomaly(n, host, dev)


def in_parallel(fn, hosts, devs):
    """Run fn(run_number, host, device) for every host at once. The slow
    scans take ~8 minutes each, and on separate hosts they can't affect
    each other, so there's no reason to wait for one before the next."""
    threads = [threading.Thread(target=fn, args=(n, h, devs[h])) for n, h in enumerate(hosts, start=1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def summarise(results):
    by = {}
    for r in results:
        by.setdefault(r["signal"], []).append(r)
    rows = []
    for sig, rs in sorted(by.items()):
        expect = rs[0].get("expect", True)
        det = [r for r in rs if r["detected"]]
        ttd = sorted(r["ttd_from_start_s"] for r in det)
        p95 = ttd[min(len(ttd) - 1, int(round(0.95 * (len(ttd) - 1))))] if ttd else None
        rows.append({"signal": sig, "runs": len(rs), "detected": len(det), "expected_detection": expect,
                     "ttd_median_s": round(statistics.median(ttd), 1) if ttd else None,
                     "ttd_p95_s": p95, "ttd_min_s": ttd[0] if ttd else None, "ttd_max_s": ttd[-1] if ttd else None})
    return rows


NOT_DRIVEN = {
    "adblock_ineffective": "needs an enrolled device actually watching YouTube (step 5.10)",
    "platform_*": "platform-health signals are step 7.7's chaos tests, not attack detections",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--out", default="/var/tmp/securepi-battery")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    random.seed()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    hosts_all = FAST_HOSTS[:args.runs] + SLOW_SCAN_HOSTS[:args.runs] + SLOW_SWEEP_HOSTS[:args.runs] + [BENIGN_HOST]

    print("== step 7.2 detection battery, %d runs per signal, %s" % (args.runs, stamp), flush=True)
    conn = db()
    blocked = [d for d in BLOCKED_CANDIDATES if dns(d).stdout.strip() in ("", "0.0.0.0")]
    print("   %d blocked domains confirmed for malicious_domain" % len(blocked), flush=True)
    if len(blocked) < 15:
        sys.exit("need 15 blocked domains, only %d are blocked right now" % len(blocked))

    for ip in hosts_all:
        sh(["ip", "addr", "add", "%s/24" % ip, "dev", "eth0"], ns=NS)
    devs = {ip: make_device(conn, "battery host %s" % ip.split(".")[-1], ip, first_seen_days=30) for ip in hosts_all}

    # An sshd in the victim namespace that rejects everything, so each
    # brute-force attempt is a real SSH handshake (as in evaluate.py).
    os.makedirs(SSHD_DIR, exist_ok=True)
    if not os.path.exists(SSHD_DIR + "/host_key"):
        sh(["ssh-keygen", "-q", "-t", "ed25519", "-f", SSHD_DIR + "/host_key", "-N", ""])
    with open(SSHD_DIR + "/sshd_config", "w") as f:
        f.write("Port 22\nListenAddress 0.0.0.0\nHostKey %s/host_key\nPasswordAuthentication no\n"
                "PubkeyAuthentication no\nUsePAM no\nLogLevel QUIET\n" % SSHD_DIR)
    sshd = subprocess.Popen(["ip", "netns", "exec", VICTIM_NS, "/usr/sbin/sshd", "-f", SSHD_DIR + "/sshd_config", "-D"])

    pcap = os.path.join(args.out, "battery-%s.pcap" % stamp)
    # The bulk iperf3 data (volume_anomaly) is left out of the capture to
    # keep it small - volume_anomaly isn't part of the replay's ground truth.
    tcpdump = subprocess.Popen(["tcpdump", "-ni", CAPTURE_IF, "-s", "1024", "-w", pcap,
                                "not (tcp portrange 5301-5310)"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    t0 = time.time()

    tracks = [
        threading.Thread(target=fast_track, args=(FAST_HOSTS[:args.runs], [devs[h] for h in FAST_HOSTS[:args.runs]])),
        threading.Thread(target=in_parallel, args=(slow_port_scan, SLOW_SCAN_HOSTS[:args.runs], devs)),
        threading.Thread(target=in_parallel, args=(slow_network_sweep, SLOW_SWEEP_HOSTS[:args.runs], devs)),
        threading.Thread(target=dns_track, args=(args.runs, blocked)),
        threading.Thread(target=new_device_track, args=(args.runs,)),
        threading.Thread(target=benign, args=(BENIGN_HOST, devs[BENIGN_HOST])),
    ]
    for t in tracks:
        t.start()
    for t in tracks:
        t.join()

    time.sleep(3)
    tcpdump.terminate()
    tcpdump.wait(timeout=10)
    sshd.terminate()
    for ip in hosts_all:
        sh(["ip", "addr", "del", "%s/24" % ip, "dev", "eth0"], ns=NS)
    conn = db()
    conn.execute("DELETE FROM ioc WHERE source=?", (IOC_SOURCE,))
    # 10.10.0.1 back to the test-attacker device, as it was before.
    own_address(conn, 4, GATEWAY_DNS)

    results = sorted(RESULTS, key=lambda r: (r["signal"], r["run"]))
    summary = summarise(results)
    out = {
        "step": "7.2", "started": t0, "finished": time.time(), "runs_per_signal": args.runs,
        "engine_interval_s": 15, "ingest_poll_s": 2,
        "summary": summary, "runs": results, "not_driven": NOT_DRIVEN,
        "pcap": os.path.basename(pcap),
        "hosts": {ip: devs[ip] for ip in hosts_all},
    }
    path = os.path.join(args.out, "battery-%s.json" % stamp)
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
    # labels.json: the replay tool's ground truth for the captured runs.
    labels = {"pcap": os.path.basename(pcap), "source": "step 7.2 battery on the live gateway harness",
              "hosts": {ip: "battery host %s" % ip.split(".")[-1] for ip in hosts_all},
              "runs": [{"signal": r["signal"], "run": r["run"], "host": r["host"], "t_start": r["t_start"],
                        "t_end": r["t_end"], "expect": r.get("expect", True)}
                       for r in results if r["host"] in devs]}
    with open(os.path.join(args.out, "battery-%s.labels.json" % stamp), "w") as f:
        json.dump(labels, f, indent=1)

    print("\n%-20s %5s %9s %10s %8s" % ("signal", "runs", "detected", "median s", "p95 s"))
    for s in summary:
        print("%-20s %5d %9s %10s %8s" % (s["signal"], s["runs"],
              "%d/%d" % (s["detected"], s["runs"]) if s["expected_detection"] else "%d fired" % s["detected"],
              s["ttd_median_s"], s["ttd_p95_s"]))
    print("\nresults: %s\npcap:    %s" % (path, pcap))


if __name__ == "__main__":
    main()

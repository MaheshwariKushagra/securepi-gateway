#!/usr/bin/env python3
"""
SecurePi Gateway - throughput and drops sweep (ENHANCEMENT-PLAN.md step 7.8).

    sudo python3 throughput_sweep.py [--seconds 20] > sweep.json

Sends iperf3 traffic between the test harness's two namespaces (the link the
IDS watches as veth-atk, one capture thread) at rising rates, and for each
rate records:

  sent            what iperf3 says it delivered
  kernel drops    packets the kernel dropped before the IDS saw them (the
                  IDS's own capture counters, from the stats it writes
                  every 8 s - read from its eve.json directly)
  logged          how many bytes the IDS's flow record for that transfer
                  accounts for: the share of the traffic the detection
                  pipeline actually saw
  IDS CPU         CPU seconds the IDS used during the step, as a share of
                  one core

The harness's offloads are off (as the battery needs), so the link carries
ordinary-sized packets like a real Wi-Fi client. Nothing here touches ap0.
"""

import argparse
import json
import subprocess
import time

ATTACKER_NS, VICTIM_NS = "ns_attacker", "ns_victim"
ATTACKER_IP, VICTIM_IP = "10.10.0.220", "10.10.0.221"
EVE = "/var/log/suricata/eve.json"
DB = "file:/var/lib/securepi/securepi.db?mode=ro"
RATES = ["10M", "25M", "50M", "100M", "200M", "400M", "0"]   # 0 = as fast as it goes


def sh(cmd, timeout=None):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def latest_capture_stats():
    """The IDS's newest 'stats' record: capture.kernel_packets / kernel_drops."""
    out = sh(["bash", "-c", "tail -n 4000 %s | grep '\"event_type\":\"stats\"' | tail -1" % EVE]).stdout.strip()
    if not out:
        return None
    s = json.loads(out)["stats"]["capture"]
    return {"t": time.time(), "packets": s.get("kernel_packets", 0), "drops": s.get("kernel_drops", 0)}


def suricata_cpu_seconds():
    pid = sh(["pidof", "suricata"]).stdout.split()[0]
    with open("/proc/%s/stat" % pid) as f:
        fields = f.read().split(")")[1].split()
    ticks = int(fields[11]) + int(fields[12])   # utime + stime
    return ticks / float(sh(["getconf", "CLK_TCK"]).stdout.strip())


def flow_bytes_logged(port, since):
    """Bytes the IDS's flow event(s) for this transfer account for. Flows are
    logged a while after they end, so this waits up to 150 s for them."""
    import sqlite3
    deadline = time.time() + 150
    while time.time() < deadline:
        conn = sqlite3.connect(DB, uri=True, timeout=30)
        row = conn.execute(
            "SELECT count(*), sum(coalesce(bytes_toserver,0) + coalesce(bytes_toclient,0)) FROM events"
            " WHERE event_type='flow' AND src_ip=? AND dest_ip=? AND dest_port=? AND ts >= ?",
            (ATTACKER_IP, VICTIM_IP, port, since)).fetchone()
        conn.close()
        if row[0]:
            return row[1] or 0
        time.sleep(5)
    return None


def step(rate, seconds, port):
    server = subprocess.Popen(["ip", "netns", "exec", VICTIM_NS, "iperf3", "-s", "-1", "-p", str(port)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    before = latest_capture_stats()
    cpu0 = suricata_cpu_seconds()
    t0 = time.time()
    r = sh(["ip", "netns", "exec", ATTACKER_NS, "iperf3", "-c", VICTIM_IP, "-B", ATTACKER_IP, "-p", str(port),
            "-t", str(seconds), "-b", rate, "-J"], timeout=seconds + 60)
    t1 = time.time()
    cpu1 = suricata_cpu_seconds()
    server.wait(timeout=30)
    time.sleep(10)                     # let the next 8-second stats record land
    after = latest_capture_stats()
    result = json.loads(r.stdout)
    sent = result["end"]["sum_sent"]["bytes"]
    logged = flow_bytes_logged(port, t0 - 5)
    out = {"rate": rate, "seconds": round(t1 - t0, 1), "sent_bytes": sent,
           "sent_mbit_s": round(result["end"]["sum_sent"]["bits_per_second"] / 1e6, 1),
           "logged_bytes": logged, "logged_share": round(logged / sent, 3) if logged else None,
           "ids_cpu_core_share": round((cpu1 - cpu0) / (t1 - t0), 2)}
    if before and after:
        packets = after["packets"] - before["packets"]
        drops = after["drops"] - before["drops"]
        out.update({"kernel_packets": packets, "kernel_drops": drops,
                    "drop_pct": round(100.0 * drops / packets, 2) if packets else None})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=20)
    args = ap.parse_args()
    results = []
    for i, rate in enumerate(RATES):
        results.append(step(rate, args.seconds, 5311 + i))
        print(json.dumps(results[-1]), flush=True)
        time.sleep(20)
    print(json.dumps({"steps": results}))


if __name__ == "__main__":
    main()

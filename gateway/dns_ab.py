#!/usr/bin/env python3
"""
SecurePi Gateway - DNS latency, the gateway's resolver vs the ISP's, before
and after step 5.5's resolver tuning (ENHANCEMENT-PLAN.md step 7.5).

    sudo -u securepi-web python3 dns_ab.py DOMAINS.txt OUT.json

On the gateway. The same domains are timed with dig against:

  gateway-current   the DNS filter as it is (Cloudflare DoT, load-balanced,
                    no optimistic cache)
  gateway-tuned     the same after 5.5's recommended tuning (optimistic
                    caching, DNSSEC, Cloudflare + Quad9 DoT in parallel,
                    with a fallback) - applied through app/adguard.py and
                    PUT BACK EXACTLY AS IT WAS afterwards, whatever happens
  isp               the uplink's own resolver (the home router, 192.168.29.1)

For each, a cold pass (the DNS filter's cache cleared first, so every answer
comes from upstream) and a warm pass straight after (cache hits). The ISP's
cache can't be cleared, so its "cold" pass is cold only for names it
hasn't seen - the comparison that is fair in both directions is warm vs
warm, and gateway-current vs gateway-tuned cold vs cold.
"""

import json
import re
import subprocess
import sys
import time

sys.path.insert(0, "/opt/securepi")
import adguard  # noqa: E402

GATEWAY = "10.10.0.1"
ISP = "192.168.29.1"
TUNED = {"upstream_dns": ["tls://1.1.1.1", "tls://9.9.9.9"], "fallback_dns": ["tls://1.0.0.1", "tls://149.112.112.112"],
         "cache_optimistic": True, "dnssec_enabled": True, "upstream_mode": "parallel"}


def dig_ms(server, name):
    r = subprocess.run(["dig", "@" + server, name, "A", "+tries=1", "+time=5"], capture_output=True, text=True)
    m = re.search(r"Query time: (\d+) msec", r.stdout)
    status = re.search(r"status: (\w+)", r.stdout)
    return (int(m.group(1)) if m else None), (status.group(1) if status else "TIMEOUT")


def one_pass(server, names):
    out = []
    for n in names:
        ms, status = dig_ms(server, n)
        out.append({"name": n, "ms": ms, "status": status})
    return out


def pct(values, p):
    values = sorted(v for v in values if v is not None)
    if not values:
        return None
    return values[min(len(values) - 1, int(round(p / 100 * (len(values) - 1))))]


def summary(rows):
    ms = [r["ms"] for r in rows if r["status"] == "NOERROR"]
    return {"n": len(rows), "answered": len(ms), "timeouts": sum(1 for r in rows if r["status"] == "TIMEOUT"),
            "p50_ms": pct(ms, 50), "p95_ms": pct(ms, 95), "max_ms": max(ms) if ms else None}


def measure(label, server, names, clear_cache):
    if clear_cache:
        adguard._request("POST", "/control/cache_clear")
        time.sleep(2)
    cold = one_pass(server, names)
    warm = one_pass(server, names)
    return {"cold": summary(cold), "warm": summary(warm), "raw_cold": cold, "raw_warm": warm}


def main():
    names = [line.strip() for line in open(sys.argv[1]) if line.strip()]
    original = adguard.dns_config()
    keep = {k: original.get(k) for k in ("upstream_dns", "fallback_dns", "cache_optimistic", "dnssec_enabled",
                                         "upstream_mode")}
    result = {"domains": len(names), "original_config": keep, "tuned_config": TUNED, "t": time.time()}
    try:
        result["gateway-current"] = measure("gateway-current", GATEWAY, names, True)
        result["isp"] = measure("isp", ISP, names, False)
        adguard.set_dns_tuning(**TUNED)
        time.sleep(5)
        result["applied_tuned"] = {k: adguard.dns_config().get(k) for k in TUNED}
        result["gateway-tuned"] = measure("gateway-tuned", GATEWAY, names, True)
    finally:
        adguard.set_dns_tuning(**keep)
        time.sleep(3)
        restored = {k: adguard.dns_config().get(k) for k in keep}
        result["restored_config"] = restored
        result["restored_ok"] = restored == keep
    with open(sys.argv[2], "w") as f:
        json.dump(result, f, indent=1)
    for k in ("gateway-current", "gateway-tuned", "isp"):
        if k in result:
            print(k, "cold", result[k]["cold"], "warm", result[k]["warm"])
    print("restored to the original configuration:", result["restored_ok"])


if __name__ == "__main__":
    main()

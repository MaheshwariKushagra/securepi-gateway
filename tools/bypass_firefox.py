#!/usr/bin/env python3
"""
Step 7.5's bypass matrix, Firefox DNS-over-HTTPS rows (ENHANCEMENT-PLAN.md).

    .venv-bench/bin/python tools/bypass_firefox.py OUT.json

Runs on the Mac while it is on SecurePi-Test, with Playwright's Firefox. For
each case Firefox is started with its DoH ("TRR") settings forced, then
asked to load a page on a domain the gateway blocks (doubleclick.net):

  blocked   the page could not be reached - the gateway's DNS answer
            (0.0.0.0) was used, or DoH itself was cut off and nothing
            resolved
  leaked    the page loaded - DNS went around the gateway

and whether anything could resolve at all (example.com), to tell "blocked"
apart from "DoH broke everything". Whether the gateway *noticed* is read
from its own records afterwards (tools/bench_profile.sh's device, the
firewall's bypass log lines and dns_bypass incidents) - see the 7.5 write-up.

Cases:
  default       Firefox's own default with DoH enabled the way it rolls it
                out: TRR mode 2 (DoH first, fall back), which first checks
                the canary domain use-application-dns.net - the gateway
                answers it NXDOMAIN, which should make Firefox stay off DoH
  <provider>    TRR mode 3 (DoH only, no fallback) to one provider, with its
                bootstrap address set so Firefox needn't resolve the DoH
                host first - the strongest form of bypass a user can set
"""

import json
import sys
import time

from playwright.sync_api import sync_playwright

PROVIDERS = {
    "cloudflare": ("https://mozilla.cloudflare-dns.com/dns-query", "1.1.1.1"),
    "google": ("https://dns.google/dns-query", "8.8.8.8"),
    "quad9": ("https://dns.quad9.net/dns-query", "9.9.9.9"),
    "dns.sb": ("https://doh.dns.sb/dns-query", "185.222.222.222"),
    "mullvad": ("https://dns.mullvad.net/dns-query", "194.242.2.2"),
    "alidns": ("https://dns.alidns.com/dns-query", "223.5.5.5"),
}


def try_load(page, url):
    try:
        r = page.goto(url, timeout=20000, wait_until="domcontentloaded")
        return {"loaded": True, "status": r.status if r else None}
    except Exception as e:
        return {"loaded": False, "error": str(e).splitlines()[0][:120]}


def run_case(p, name, prefs):
    browser = p.firefox.launch(headless=True, firefox_user_prefs=prefs)
    page = browser.new_page()
    started = time.time()
    control = try_load(page, "http://example.com/")
    blocked_domain = try_load(page, "http://doubleclick.net/")
    browser.close()
    verdict = "leaked" if blocked_domain["loaded"] else ("blocked" if control["loaded"] else "blocked (no DNS at all)")
    return {"case": name, "started": started, "prefs": prefs, "control_example_com": control,
            "doubleclick_net": blocked_domain, "verdict": verdict}


def main():
    results = []
    with sync_playwright() as p:
        base = {"network.dns.disablePrefetch": True, "network.http.speculative-parallel-limit": 0}
        results.append(run_case(p, "default (TRR mode 2, canary)", dict(base, **{
            "network.trr.mode": 2, "network.trr.uri": PROVIDERS["cloudflare"][0]})))
        time.sleep(5)
        for name, (uri, bootstrap) in PROVIDERS.items():
            results.append(run_case(p, "forced DoH: " + name, dict(base, **{
                "network.trr.mode": 3, "network.trr.uri": uri, "network.trr.bootstrapAddr": bootstrap,
                "network.trr.custom_uri": uri})))
            print(json.dumps({k: results[-1][k] for k in ("case", "verdict")}), flush=True)
            time.sleep(5)
    with open(sys.argv[1], "w") as f:
        json.dump(results, f, indent=1)


if __name__ == "__main__":
    main()

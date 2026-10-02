#!/usr/bin/env python3
"""
SecurePi Gateway - ad-blocking benchmark and breakage check (ENHANCEMENT-PLAN.md step 7.5).

Runs on the Mac, with the Mac joined to SecurePi-Test, in the benchmark
virtualenv (Playwright needs it):

    .venv-bench/bin/python tools/adblock_bench.py load --sites eval/bench-sites.json \\
        --condition tier1 --runs 3 --out eval/results/bench/tier1.jsonl [--extension DIR]
    .venv-bench/bin/python tools/adblock_bench.py pick-top --tranco top-1m.csv --count 50 \\
        --out eval/bench-top50.json
    .venv-bench/bin/python tools/adblock_bench.py summarize FILE.jsonl ... \\
        --disconnect services.json --out summary.json
    .venv-bench/bin/python tools/adblock_bench.py breakage --baseline none.jsonl --test tier1.jsonl

The gateway side of each condition (which filtering profile the Mac's
device has) is set separately, through the orchestrator - this tool only
loads pages and measures.

One load
--------
A fresh browser profile every time (nothing cached, no cookies), headless
Chromium in its new headless mode with an ordinary Chrome user agent, a
1366x768 window. The page is loaded until its `load` event (45 s limit),
then watched for 5 more seconds, since many ad slots fill after load.
Recorded per load:

  requests        every request the page made, with its type and whether it
                  completed (got a response) or failed - a DNS-blocked
                  request fails, because the gateway answers 0.0.0.0
  bytes           response body + headers of each completed request
  third party     a request whose registrable domain (tldextract) differs
                  from the page's
  onLoad, LCP     from the page's own Performance API (LCP: the last
                  largest-contentful-paint entry)
  text length     document.body.innerText length, and the title - used by
                  the breakage check

Tracker companies (summarize) come from Disconnect's tracking-protection
list (CC BY-NC-SA 4.0, (c) Disconnect, Inc., downloaded at run time and
not committed): a company counts as contacted if any request to one of its
domains in the Advertising, Analytics, Social, Fingerprinting or
Cryptomining categories completed.
"""

import argparse
import json
import os
import shutil
import statistics
import sys
import tempfile
import time

import tldextract
from playwright.sync_api import sync_playwright

USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
VIEWPORT = {"width": 1366, "height": 768}
LOAD_TIMEOUT_MS = 45000
SETTLE_MS = 5000
TRACKER_CATEGORIES = ("Advertising", "Analytics", "Social", "FingerprintingInvasive",
                      "FingerprintingGeneral", "Cryptomining")

# Records the page's largest-contentful-paint as it happens.
LCP_SCRIPT = """
window.__lcp = null;
try {
  new PerformanceObserver((list) => {
    const entries = list.getEntries();
    if (entries.length) window.__lcp = entries[entries.length - 1].startTime;
  }).observe({type: 'largest-contentful-paint', buffered: true});
} catch (e) {}
"""

EXTRACT = tldextract.TLDExtract()


def registrable(host):
    """example.co.uk for a.b.example.co.uk; the host itself if that fails."""
    e = EXTRACT(host)
    domain = e.top_domain_under_public_suffix if hasattr(e, "top_domain_under_public_suffix") else e.registered_domain
    return domain or host


def host_of(url):
    try:
        return url.split("/")[2].split(":")[0].lower()
    except IndexError:
        return ""


# ------------------------------------------------------------------ loading --

def load_once(p, url, extension=None, profile=None):
    """Load one page in a fresh profile and return what it did."""
    profile = os.path.join(profile, "chrome") if profile else tempfile.mkdtemp(prefix="bench-profile-")
    # --disable-quic: the gateway rejects QUIC; don't time the fallback.
    # AsyncDns: Chromium's own DNS client, so each fresh browser asks the
    # gateway itself instead of macOS's DNS cache - otherwise an answer
    # cached under one condition would leak into the next.
    args = ["--disable-quic", "--enable-features=AsyncDns"]
    if extension:
        args += ["--disable-extensions-except=" + extension, "--load-extension=" + extension]
    ctx = p.chromium.launch_persistent_context(profile, headless=True, channel="chromium", args=args,
                                               user_agent=USER_AGENT, viewport=VIEWPORT,
                                               ignore_https_errors=False)
    ctx_version = ctx.browser.version if ctx.browser else None
    if extension:
        time.sleep(3)   # let the extension's service worker install its rule sets
    page = ctx.new_page()
    page.add_init_script(LCP_SCRIPT)
    requests = []
    failed = {}
    finished = {}
    page.on("request", lambda r: requests.append(r))
    page.on("requestfailed", lambda r: failed.__setitem__(id(r), r.failure or "failed"))
    page.on("requestfinished", lambda r: finished.__setitem__(id(r), True))
    main_status = {}

    def on_response(resp):
        # The main document's own status, even if the load event never comes.
        try:
            if resp.request.is_navigation_request() and resp.frame == page.main_frame:
                main_status["status"] = resp.status
        except Exception:
            pass
    page.on("response", on_response)
    started = time.time()
    status = None
    error = None
    try:
        resp = page.goto(url, wait_until="load", timeout=LOAD_TIMEOUT_MS)
        status = resp.status if resp else None
    except Exception as e:   # a timeout still leaves a partly loaded page worth measuring
        error = str(e).splitlines()[0][:200]
    try:
        page.wait_for_timeout(SETTLE_MS)
    except Exception:
        pass
    perf = {}
    try:
        perf = page.evaluate("""() => {
            const nav = performance.getEntriesByType('navigation')[0];
            return {onload_ms: nav ? nav.loadEventEnd : null, lcp_ms: window.__lcp,
                    title: document.title, text_len: (document.body && document.body.innerText || '').length,
                    final_url: location.href};
        }""")
    except Exception as e:
        error = error or str(e).splitlines()[0][:200]
    if status is None:
        status = main_status.get("status")
    load_timed_out = bool(error and "Timeout" in error)
    if load_timed_out:
        error = None   # the page is there; it just never stopped loading (reported separately)
    page_domain = registrable(host_of(perf.get("final_url") or url))
    out_requests = []
    for r in requests:
        host = host_of(r.url)
        if not host or r.url.startswith(("data:", "blob:", "chrome-extension:")):
            continue
        item = {"host": host, "type": r.resource_type, "third_party": registrable(host) != page_domain}
        if id(r) in failed:
            item["failed"] = failed[id(r)]
            item["bytes"] = 0
        elif id(r) in finished:
            # sizes() waits for the response to finish, so it's only asked
            # of requests that already have - a streaming ad request still
            # open when the page is closed would otherwise wait forever.
            try:
                sizes = r.sizes()
                item["bytes"] = max(0, sizes.get("responseBodySize", 0)) + max(0, sizes.get("responseHeadersSize", 0))
            except Exception:
                item["bytes"] = 0
        else:
            # Still open when the page was measured: it reached the network
            # (so it counts as completed), but its size isn't known yet.
            item["bytes"] = 0
            item["pending"] = True
        out_requests.append(item)
    ctx.close()
    shutil.rmtree(profile, ignore_errors=True)
    return {"url": url, "status": status, "error": error, "load_timed_out": load_timed_out,
            "chromium": ctx_version,
            "seconds": round(time.time() - started, 1),
            "page_domain": page_domain, "onload_ms": perf.get("onload_ms"), "lcp_ms": perf.get("lcp_ms"),
            "title": perf.get("title"), "text_len": perf.get("text_len"), "final_url": perf.get("final_url"),
            "requests": out_requests}


HARD_LIMIT_S = 150   # one load, browser start to close, whatever happens inside


def load_isolated(url, extension):
    """load_once() in its own process with a hard time limit. A page can
    wedge a Playwright call that has no timeout of its own (seen with
    ndtv.com: one load sat for 8 minutes). Two details matter, both found
    the hard way: Chromium puts itself in its own process group, so
    killing the child's group misses it; and a browser left running holds
    any pipe it inherited, so the result comes back through a file, and
    every process using this load's profile folder is killed at the end."""
    import subprocess
    profile = tempfile.mkdtemp(prefix="bench-profile-")
    result_path = os.path.join(profile, "result.json")
    cmd = [sys.executable, os.path.abspath(__file__), "one", "--url", url, "--profile", profile,
           "--result", result_path]
    if extension:
        cmd += ["--extension", extension]
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    error = None
    try:
        proc.wait(timeout=HARD_LIMIT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        error = "harness: load exceeded %d s and was killed" % HARD_LIMIT_S
    # Anything still running from this load - the browser and its helpers
    # all carry the profile path on their command line.
    subprocess.run(["pkill", "-9", "-f", profile], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rec = None
    if error is None:
        try:
            with open(result_path) as f:
                rec = json.load(f)
        except (OSError, ValueError) as e:
            error = "harness: no result (%s)" % type(e).__name__
    shutil.rmtree(profile, ignore_errors=True)
    if rec is None:
        rec = {"url": url, "status": None, "error": error, "load_timed_out": False,
               "seconds": HARD_LIMIT_S, "page_domain": None, "onload_ms": None, "lcp_ms": None, "title": None,
               "text_len": None, "final_url": None, "requests": []}
    return rec


def cmd_one(args):
    with sync_playwright() as p:
        rec = load_once(p, args.url, args.extension, args.profile)
    with open(args.result, "w") as f:
        json.dump(rec, f)


def cmd_load(args):
    with open(args.sites) as f:
        sites = json.load(f)["sites"]
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    # No Playwright in this (parent) process at all: with a session opened
    # and closed here first, the child loads of heavy pages stalled every
    # time (measured: killed at the limit, vs ~52 s without it). Each child
    # records the browser version instead.
    with open(args.out, "a") as out:
        for run in range(args.first_run, args.first_run + args.runs):
            for url in sites:
                rec = load_isolated(url, args.extension)
                rec.update({"condition": args.condition, "run": run, "t": time.time(),
                            "extension": os.path.basename(args.extension.rstrip("/")) if args.extension else None})
                out.write(json.dumps(rec) + "\n")
                out.flush()
                done = [x for x in rec["requests"] if "failed" not in x]
                print("%-10s run %d  %-45s %3s  %4d req (%4d ok)  %6.0f kB  %5.1fs %s" % (
                    args.condition, run, url[:45], rec["status"], len(rec["requests"]), len(done),
                    sum(x["bytes"] for x in done) / 1000, rec["seconds"], rec["error"] or ""), flush=True)


def cmd_pick_top(args):
    """The first COUNT Tranco domains whose homepage really is a website:
    it loads (HTTP < 400), has a title and some text. Infrastructure
    domains (CDNs, APIs, DNS) fail this and are skipped, with the reason."""
    picked, skipped = [], []
    with open(args.tranco) as f:
        domains = [line.strip().split(",")[1] for line in f if "," in line]
    if True:
        for d in domains:
            if len(picked) >= args.count:
                break
            rec = load_isolated("https://%s/" % d, None)
            ok = rec["status"] is not None and rec["status"] < 400 and (rec["title"] or "").strip() \
                and (rec["text_len"] or 0) >= 100
            if ok:
                picked.append("https://%s/" % d)
            else:
                skipped.append({"domain": d, "status": rec["status"], "error": rec["error"],
                                "title": rec["title"], "text_len": rec["text_len"]})
            print("%-3s %-30s %s" % ("ok" if ok else "--", d, rec["status"] or rec["error"]), flush=True)
    with open(args.out, "w") as f:
        json.dump({"about": "First %d loadable homepages from Tranco list %s (picked with filtering off)."
                   % (args.count, args.tranco_id), "sites": picked, "skipped": skipped}, f, indent=1)


# ---------------------------------------------------------------- summary --

def load_disconnect(path):
    with open(path) as f:
        data = json.load(f)
    domain_to_company = {}
    for category, entries in data["categories"].items():
        if category not in TRACKER_CATEGORIES:
            continue
        for entry in entries:
            for company, props in entry.items():
                for key, domains in props.items():
                    if not isinstance(domains, list):
                        continue
                    for d in domains:
                        domain_to_company.setdefault(d.lower(), company)
    return domain_to_company


def company_for(host, mapping):
    parts = host.split(".")
    for i in range(len(parts) - 1):
        name = ".".join(parts[i:])
        if name in mapping:
            return mapping[name]
    return None


def per_load_metrics(rec, mapping):
    done = [r for r in rec["requests"] if "failed" not in r]
    third = [r for r in done if r["third_party"]]
    companies = {company_for(r["host"], mapping) for r in done} - {None}
    return {"requests_attempted": len(rec["requests"]), "requests_completed": len(done),
            "third_party_completed": len(third), "bytes": sum(r["bytes"] for r in done),
            "third_party_bytes": sum(r["bytes"] for r in third), "tracker_companies": len(companies),
            "onload_ms": None if rec.get("load_timed_out") else rec["onload_ms"], "lcp_ms": rec["lcp_ms"],
            "load_timed_out": 1 if rec.get("load_timed_out") else 0,
            "blocked_or_failed": len(rec["requests"]) - len(done)}


def median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def cmd_summarize(args):
    mapping = load_disconnect(args.disconnect)
    by_condition = {}
    per_site = {}
    for path in args.files:
        with open(path) as f:
            for line in f:
                rec = json.loads(line)
                m = per_load_metrics(rec, mapping)
                by_condition.setdefault(rec["condition"], []).append(m)
                per_site.setdefault(rec["condition"], {}).setdefault(rec["url"], []).append(m)
    keys = ["requests_attempted", "requests_completed", "third_party_completed", "bytes", "third_party_bytes",
            "tracker_companies", "onload_ms", "lcp_ms"]
    summary = {}
    for cond, loads in by_condition.items():
        # Median per site over its runs, then the median and the total across sites.
        sites = per_site[cond]
        site_medians = {url: {k: median([m[k] for m in ms]) for k in keys} for url, ms in sites.items()}
        summary[cond] = {
            "loads": len(loads), "sites": len(sites),
            "loads_where_onload_never_fired": sum(m["load_timed_out"] for m in loads),
            "median_over_sites": {k: median([s[k] for s in site_medians.values()]) for k in keys},
            "sum_over_sites": {k: sum((s[k] or 0) for s in site_medians.values())
                               for k in ("requests_completed", "third_party_completed", "bytes",
                                         "third_party_bytes", "tracker_companies")},
            "per_site": site_medians,
        }
    text = json.dumps(summary, indent=1, sort_keys=True)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")
    for cond, s in summary.items():
        print(cond, json.dumps(s["sum_over_sites"]), "median onload", s["median_over_sites"]["onload_ms"],
              "LCP", s["median_over_sites"]["lcp_ms"])


# --------------------------------------------------------------- breakage --

def cmd_breakage(args):
    """Automatic checklist, test condition against the unfiltered baseline,
    per site (first run of each): the page loaded (status < 400, no
    navigation error), has a title, kept at least half its visible text,
    and no FIRST-party request failed. A site failing any check is listed
    for a person to look at - it is a candidate, not a verdict."""
    def first_runs(path):
        out = {}
        with open(path) as f:
            for line in f:
                rec = json.loads(line)
                out.setdefault(rec["url"], rec)
        return out
    base, test = first_runs(args.baseline), first_runs(args.test)
    flagged = []
    for url, t in test.items():
        b = base.get(url)
        reasons = []
        if t["status"] is None or t["status"] >= 400 or t["error"]:
            reasons.append("did not load (%s)" % (t["status"] or t["error"]))
        if not (t["title"] or "").strip():
            reasons.append("no title")
        if b and (b["text_len"] or 0) > 0 and (t["text_len"] or 0) < 0.5 * b["text_len"]:
            reasons.append("visible text %d vs %d unfiltered" % (t["text_len"] or 0, b["text_len"]))
        first_party_failed = sorted({r["host"] for r in t["requests"] if "failed" in r and not r["third_party"]})
        base_failed = sorted({r["host"] for r in (b or {}).get("requests", []) if "failed" in r and not r["third_party"]})
        newly = [h for h in first_party_failed if h not in base_failed]
        if newly:
            reasons.append("first-party requests failed: %s" % ", ".join(newly[:5]))
        if reasons:
            flagged.append({"url": url, "reasons": reasons})
    result = {"sites": len(test), "flagged": flagged, "flag_rate": len(flagged) / len(test) if test else None}
    print(json.dumps(result, indent=1))
    if args.out:
        with open(args.out, "w") as f:
            json.dump(result, f, indent=1)


def main():
    ap = argparse.ArgumentParser(description="Step 7.5 ad-blocking benchmark.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("load")
    a.add_argument("--sites", required=True)
    a.add_argument("--condition", required=True)
    a.add_argument("--runs", type=int, default=3)
    a.add_argument("--first-run", type=int, default=1, help="number of the first run (when runs of different conditions are interleaved)")
    a.add_argument("--extension")
    a.add_argument("--out", required=True)
    a = sub.add_parser("one")
    a.add_argument("--url", required=True)
    a.add_argument("--extension")
    a.add_argument("--profile", required=True)
    a.add_argument("--result", required=True)
    a = sub.add_parser("pick-top")
    a.add_argument("--tranco", required=True)
    a.add_argument("--tranco-id", default="?")
    a.add_argument("--count", type=int, default=50)
    a.add_argument("--out", required=True)
    a = sub.add_parser("summarize")
    a.add_argument("files", nargs="+")
    a.add_argument("--disconnect", required=True)
    a.add_argument("--out")
    a = sub.add_parser("breakage")
    a.add_argument("--baseline", required=True)
    a.add_argument("--test", required=True)
    a.add_argument("--out")
    args = ap.parse_args()
    {"load": cmd_load, "one": cmd_one, "pick-top": cmd_pick_top, "summarize": cmd_summarize, "breakage": cmd_breakage}[args.cmd](args)


if __name__ == "__main__":
    main()

"""ADBLOCK-ENHANCEMENT-PLAN.md phase C: does a site module remove the
site's feed ads, and does the site still work?

    .venv-bench/bin/python tools/site_ads_measure.py SITE OUT.jsonl --runs N

Runs on the Mac against the logged-in test browser on the Dell (DevTools
on local port 9231 through an SSH tunnel), which browses through a
localhost-only TEST proxy on the Dell running the production addon with
copies of the live rules (see ADBLOCK-ENHANCEMENT-PLAN.md, phase C
notes). Conditions alternate run by run: the site switched OFF for the
test device (connections pass through the proxy undecrypted) and ON
(decrypted, ads removed by the module). The switch is the test proxy's
own site map, set over SSH.

Per run, from what the BROWSER received (after any rewriting):
  ads_received   feed items marked as ads (Instagram: edges whose node.ad
                 is set; Facebook: streamed chunks carrying th_dat_spo)
  items_received feed items / chunks in the feed responses
  labels         most "Sponsored" labels visible at once (Instagram only;
                 Facebook scrambles that text)
  posts          feed posts rendered on the page (breakage check)
  page_errors    uncaught JavaScript errors
Once per condition: does the inbox page still render its list (count of
list rows only - no content)?
"""
import argparse
import json
import re
import subprocess
import sys
import time

from playwright.sync_api import sync_playwright

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from feasibility_capture import json_docs  # noqa: E402

CDP = "http://127.0.0.1:9231"
GATEWAY = "maheshwari@192.168.2.5"
SITES_FILE = "/home/maheshwari/securepi-browser/test-sites.json"
SHOT_DIR = None   # set by --shots

SITES = {
    "instagram": {"feed": "https://www.instagram.com/", "inbox": "https://www.instagram.com/direct/inbox/",
                  "query": "PolarisFeed", "posts_js": "document.querySelectorAll('article').length",
                  "inbox_js": "document.querySelectorAll('[role=listitem], [role=button][tabindex]').length"},
    "facebook": {"feed": "https://www.facebook.com/", "inbox": "https://www.facebook.com/messages/",
                 "query": "CometNewsFeedPaginationQuery",
                 "posts_js": "document.querySelectorAll('[aria-posinset]').length",
                 # The chat list's grid and tabs (a test account with no chats
                 # has no rows; it also shows an end-to-end-encryption prompt).
                 "inbox_js": "document.querySelectorAll('[role=grid], [role=tablist]').length"},
}

LABELS_JS = r"""() => {
  let n = 0;
  for (const el of document.querySelectorAll('span, a')) {
    if (el.childElementCount === 0 && ['Sponsored', 'Ad'].includes((el.textContent || '').trim())) {
      const r = el.getBoundingClientRect();
      if (r.width > 0 && r.height > 0) n++;
    }
  }
  return n;
}"""


def set_condition(site, on):
    """Switch the site for the test device, then restart the test proxy:
    the decision is made per connection, and Chrome would otherwise keep
    using a connection opened under the other condition (the same effect
    7.5 found on phones)."""
    sites = ["youtube", site] if on else ["youtube"]
    subprocess.run(["ssh", "-o", "BatchMode=yes", GATEWAY,
                    "echo '%s' > %s && sudo systemctl restart securepi-testproxy"
                    % (json.dumps({"127.0.0.1": sites}), SITES_FILE)], check=True)
    time.sleep(4)


def count_ads(site, doc):
    ads = items = 0

    def walk(node):
        nonlocal ads, items
        if isinstance(node, dict):
            if site == "instagram" and isinstance(node.get("edges"), list):
                for e in node["edges"]:
                    items += 1
                    if isinstance(e, dict) and isinstance(e.get("node"), dict) and e["node"].get("ad"):
                        ads += 1
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    if site == "facebook":
        items = 1

        def has(node):
            if isinstance(node, dict):
                return node.get("th_dat_spo") is not None or any(has(v) for v in node.values())
            if isinstance(node, list):
                return any(has(v) for v in node)
            return False
        ads = 1 if has(doc) else 0
        return ads, items
    walk(doc)
    return ads, items


SCRIPT_RE = re.compile(r'<script type="application/json"[^>]*>(.*?)</script>', re.S)


def fb_ad_ids(node, feed, side):
    """Distinct Facebook ad ids: feed stories (th_dat_spo.ad_id) and
    right-column units (sponsored_data.ad_id), wherever they appear."""
    if isinstance(node, dict):
        for key, bucket in (("th_dat_spo", feed), ("sponsored_data", side)):
            v = node.get(key)
            if isinstance(v, dict) and v.get("ad_id"):
                bucket.add(str(v["ad_id"]))
        for v in node.values():
            fb_ad_ids(v, feed, side)
    elif isinstance(node, list):
        for v in node:
            fb_ad_ids(v, feed, side)


def run_once(ctx, site, cfg, scrolls):
    page = ctx.new_page()
    rec = {"ads_received": 0, "items_received": 0, "labels": 0, "posts": 0, "page_errors": 0,
           "feed_responses": 0}
    feed_ads, side_ads = set(), set()

    def on_response(resp):
        try:
            if site == "facebook" and resp.request.resource_type == "document" \
                    and resp.url.rstrip("/") == "https://www.facebook.com":
                for block in SCRIPT_RE.findall(resp.text()):
                    if "ad_id" in block:
                        fb_ad_ids(json.loads(block), feed_ads, side_ads)
                return
            if not resp.request.headers.get("x-fb-friendly-name", "").startswith(cfg["query"]):
                return
            rec["feed_responses"] += 1
            for d in json_docs(resp.text()):
                a, i = count_ads(site, d)
                rec["ads_received"] += a
                rec["items_received"] += i
                if site == "facebook":
                    fb_ad_ids(d, feed_ads, side_ads)
        except Exception:
            pass

    page.on("response", on_response)
    page.on("pageerror", lambda e: rec.__setitem__("page_errors", rec["page_errors"] + 1))
    try:
        page.goto(cfg["feed"], wait_until="domcontentloaded", timeout=60000)
        time.sleep(8)
        for _ in range(scrolls):
            page.mouse.wheel(0, 1600)
            time.sleep(2.5)
            if site == "instagram":
                rec["labels"] = max(rec["labels"], page.evaluate(LABELS_JS))
        time.sleep(2)
        rec["posts"] = page.evaluate(cfg["posts_js"])
        if site == "facebook":
            # What the page itself shows: a right-column "Sponsored" unit,
            # and Facebook's own "No more posts" end-of-feed message.
            shown = page.evaluate("""() => ({
                side: [...document.querySelectorAll('[role=complementary]')].some(e => /\\bSponsored\\b/.test(e.innerText)),
                no_more: /No more posts/.test(document.body.innerText)})""")
            rec["right_column_sponsored"] = shown["side"]
            rec["no_more_posts"] = shown["no_more"]
        if rec["posts"] < 3 and SHOT_DIR:
            # Keep a screenshot of a near-empty feed for a person to judge
            # (a slow load and a broken page look alike in the counts).
            rec["screenshot"] = "%s/%s-%d.png" % (SHOT_DIR, site, int(time.time()))
            page.screenshot(path=rec["screenshot"])
    except Exception as e:
        rec["error"] = str(e)[:120]
    page.close()
    if site == "facebook":
        rec["feed_ad_ids"] = len(feed_ads)
        rec["right_column_ad_ids"] = len(side_ads)
    return rec


def inbox_check(ctx, cfg):
    page = ctx.new_page()
    try:
        page.goto(cfg["inbox"], wait_until="domcontentloaded", timeout=60000)
        time.sleep(10)
        return {"inbox_rows": page.evaluate(cfg["inbox_js"]), "inbox_url_ok": "/login" not in page.url}
    except Exception as e:
        return {"inbox_error": str(e)[:120]}
    finally:
        page.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("site", choices=sorted(SITES))
    ap.add_argument("out")
    ap.add_argument("--runs", type=int, default=8)
    ap.add_argument("--scrolls", type=int, default=8)
    ap.add_argument("--shots", help="directory for screenshots of near-empty feeds")
    args = ap.parse_args()
    global SHOT_DIR
    SHOT_DIR = args.shots
    cfg = SITES[args.site]
    with sync_playwright() as p, open(args.out, "a") as out:
        ctx = p.chromium.connect_over_cdp(CDP).contexts[0]
        for i in range(args.runs):
            for on in (False, True):
                set_condition(args.site, on)
                rec = run_once(ctx, args.site, cfg, args.scrolls)
                rec.update(site=args.site, condition="on" if on else "off", run=i, t=time.time())
                out.write(json.dumps(rec) + "\n")
                out.flush()
                print(json.dumps(rec), flush=True)
        for on in (False, True):
            set_condition(args.site, on)
            rec = inbox_check(ctx, cfg)
            rec.update(site=args.site, condition="on" if on else "off", phase="inbox", t=time.time())
            out.write(json.dumps(rec) + "\n")
            print(json.dumps(rec), flush=True)
        set_condition(args.site, False)


if __name__ == "__main__":
    main()

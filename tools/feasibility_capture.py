"""ADBLOCK-ENHANCEMENT-PLAN.md B0: where does each site put its ads, and
which hosts carry its messages?

    .venv-bench/bin/python tools/feasibility_capture.py SITE OUT.json [--scrolls 8]
    SITE: x | instagram | facebook | spotify

Drives the logged-in test browser on the Dell (Chromium with its DevTools
on 127.0.0.1:9230 there, reached through an SSH tunnel on local port
9231) with Playwright's connect_over_cdp. For the site's feed page it
scrolls a few times; then it opens the site's messages page.

Records STRUCTURE ONLY - no response bodies, no message text, no
names. Per response: host, a redacted path (no query string, runs of 5+
digits replaced by {n}), content type and size; for JSON bodies, the
JSON paths (keys only, list positions as []) at which an ad-looking key
or an ad-looking short string value appears, and how many times. Per
page: WebSocket hosts and paths, and how many elements the page itself
labels Sponsored / Promoted / Ad. That is enough to tell where ads are
marked, whether rewriting them is possible, and whether messages share a
host with the feed - without keeping anyone's content.
"""
import argparse
import json
import re
import time
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

CDP = "http://127.0.0.1:9231"

SITES = {
    "x": {"feed": "https://x.com/home", "messages": "https://x.com/messages"},
    "instagram": {"feed": "https://www.instagram.com/", "messages": "https://www.instagram.com/direct/inbox/"},
    "facebook": {"feed": "https://www.facebook.com/", "messages": "https://www.facebook.com/messages/"},
    "spotify": {"feed": "https://open.spotify.com/", "messages": None},
}

AD_KEY = re.compile(r"(^|_|[a-z])(promoted|sponsor|sponsored|advert|advertiser|adplacement|adslot|"
                    r"ad_id|adid|is_ad|isad|ads?_?(info|data|metadata|break|pod|request|slot))", re.I)
AD_VALUE = re.compile(r"^(sponsored|promoted|ad|ads|advertisement|promoted[-_ ].*|sponsored[-_ ].*|"
                      r".*(promoted|sponsored)[-_]?(tweet|post|item|story|content|entry).*)$", re.I)

LABEL_JS = r"""() => {
  const labels = ['Sponsored', 'Promoted', 'Ad', 'Advertisement', 'Paid partnership'];
  let n = 0; const seen = {};
  for (const el of document.querySelectorAll('span, a, div[aria-label], [aria-label]')) {
    const t = (el.getAttribute('aria-label') || (el.childElementCount === 0 ? el.textContent : '') || '').trim();
    if (labels.includes(t)) {
      const r = el.getBoundingClientRect();
      if (r.width > 0 && r.height > 0) { n++; seen[t] = (seen[t] || 0) + 1; }
    }
  }
  return {visible_labels: n, by_label: seen};
}"""


def redact_path(url):
    parts = urlsplit(url)
    segs = [re.sub(r"\d{5,}", "{n}", s) for s in parts.path.split("/")][:6]
    return parts.hostname or "", "/".join(segs)


def walk(node, path, out):
    if isinstance(node, dict):
        for k, v in node.items():
            p = path + "." + k
            if AD_KEY.search(k):
                out[p] = out.get(p, 0) + 1
            walk(v, p, out)
    elif isinstance(node, list):
        for item in node:
            walk(item, path + "[]", out)
    elif isinstance(node, str) and len(node) <= 40 and AD_VALUE.match(node.strip()):
        p = path + "=" + node.strip().lower()[:30]
        out[p] = out.get(p, 0) + 1


def json_docs(text):
    """Bodies may be one JSON value, several on separate lines (streamed
    GraphQL), or carry an anti-hijacking prefix."""
    text = text.lstrip()
    for prefix in ("for (;;);", ")]}'"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    try:
        return [json.loads(text)]
    except Exception:
        docs = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{") or line.startswith("["):
                try:
                    docs.append(json.loads(line))
                except Exception:
                    pass
        return docs


def capture(page, url, scrolls):
    responses, sockets = [], []

    def on_response(resp):
        try:
            host, path = redact_path(resp.url)
            ctype = (resp.headers.get("content-type") or "").split(";")[0]
            rec = {"host": host, "path": path, "type": ctype, "status": resp.status,
                   "method": resp.request.method}
            # GraphQL query names (Facebook/Instagram send them as request
            # headers) - what a rewrite rule can be limited by.
            hdrs = resp.request.headers
            for h in ("x-fb-friendly-name", "x-root-field-name"):
                if hdrs.get(h):
                    rec[h] = hdrs[h][:80]
            if "json" in ctype or "javascript" in ctype or ctype.startswith("text/plain") or "graphql" in path:
                body = resp.text()
                rec["size"] = len(body)
                docs = json_docs(body)
                rec["json_docs"] = len(docs)
                markers = {}
                ad_docs = []
                for d in docs:
                    m = {}
                    walk(d, "$", m)
                    for k, v in m.items():
                        markers[k] = markers.get(k, 0) + v
                    if any("sponsored_data" in k or ".ad." in k or k.endswith(".ad") for k in m):
                        # Outline of a document carrying an ad: its top-level
                        # keys and, for a streamed chunk, its label (no values).
                        ad_docs.append({"keys": sorted(d)[:10] if isinstance(d, dict) else "list",
                                        "label": d.get("label") if isinstance(d, dict) else None})
                if markers:
                    rec["ad_markers"] = markers
                if ad_docs:
                    rec["ad_docs"] = ad_docs
            responses.append(rec)
        except Exception:
            pass

    def on_ws(ws):
        host, path = redact_path(ws.url)
        sockets.append({"host": host, "path": path})

    page.on("response", on_response)
    page.on("websocket", on_ws)
    page.goto(url, wait_until="domcontentloaded", timeout=60000)
    time.sleep(8)
    labels = []
    for _ in range(scrolls):
        page.mouse.wheel(0, 1600)
        time.sleep(2.5)
        labels.append(page.evaluate(LABEL_JS))
    time.sleep(3)
    page.remove_listener("response", on_response)
    page.remove_listener("websocket", on_ws)
    final_host, final_path = redact_path(page.url)
    return {"url": url, "landed_on": final_host + final_path, "responses": responses,
            "websockets": sockets, "label_samples": labels}


def summarise(cap):
    hosts, marked, names = {}, {}, {}
    for r in cap["responses"]:
        hosts[r["host"]] = hosts.get(r["host"], 0) + 1
        name = r.get("x-fb-friendly-name") or r.get("x-root-field-name")
        if name:
            entry = names.setdefault(name, {"requests": 0, "with_ads": 0, "ad_doc_outlines": []})
            entry["requests"] += 1
            if r.get("ad_docs"):
                entry["with_ads"] += 1
                for o in r["ad_docs"]:
                    if o not in entry["ad_doc_outlines"]:
                        entry["ad_doc_outlines"].append(o)
        for p, n in (r.get("ad_markers") or {}).items():
            key = "%s %s %s" % (r["host"], r["path"], p)
            marked[key] = marked.get(key, 0) + n
    return {"hosts": dict(sorted(hosts.items(), key=lambda x: -x[1])),
            "ad_markers": dict(sorted(marked.items(), key=lambda x: -x[1])),
            "websocket_hosts": sorted({w["host"] + w["path"] for w in cap["websockets"]}),
            "query_names": names,
            "max_visible_ad_labels": max([s["visible_labels"] for s in cap["label_samples"]] or [0])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("site", choices=sorted(SITES))
    ap.add_argument("out")
    ap.add_argument("--scrolls", type=int, default=8)
    args = ap.parse_args()
    urls = SITES[args.site]
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(CDP)
        ctx = browser.contexts[0]
        page = ctx.new_page()
        result = {"site": args.site, "t": time.time()}
        try:
            result["feed"] = capture(page, urls["feed"], args.scrolls)
            result["feed_summary"] = summarise(result["feed"])
            if urls["messages"]:
                result["messages"] = capture(page, urls["messages"], 2)
                result["messages_summary"] = summarise(result["messages"])
        finally:
            page.close()
    with open(args.out, "w") as f:
        json.dump(result, f, indent=1)
    s = result["feed_summary"]
    print("landed on:", result["feed"]["landed_on"])
    print("visible ad labels (max per scroll):", s["max_visible_ad_labels"])
    print("top hosts:", list(s["hosts"].items())[:8])
    print("ad markers:", json.dumps(dict(list(s["ad_markers"].items())[:15]), indent=1))
    if "messages_summary" in result:
        m = result["messages_summary"]
        print("messages landed on:", result["messages"]["landed_on"])
        print("messages hosts:", list(m["hosts"].items())[:8])
        print("messages websockets:", m["websocket_hosts"])


if __name__ == "__main__":
    main()

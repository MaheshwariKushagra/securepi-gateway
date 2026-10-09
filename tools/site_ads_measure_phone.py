"""ADBLOCK-ENHANCEMENT-PLAN.md phase C on a real phone: Instagram ads
reaching the phone's Chrome with the site switched off vs on, through the
gateway's real redirect.

    .venv-bench/bin/python tools/site_ads_measure_phone.py OUT.jsonl --runs N [--device-id 2]

The phone is enrolled through the orchestrator for each condition - sites
"youtube" (Instagram off: passed through) or "instagram,youtube" (on) -
and Chrome is force-stopped before every run, so no connection opened
under the other condition carries over. Chrome is driven over raw DevTools
(USB, adb forward to local port 9222); pages are opened by Android intent,
as tools/youtube_tier2.py does.

Per run, from what the phone's Chrome RECEIVED from www.instagram.com
(the home page and its JSON responses, after any rewriting): feed items
whose node.ad is set (ads) and feed items in all (items); plus the most
"Sponsored" labels visible at once while scrolling, and posts rendered.
Bodies are parsed in memory and only these counts are kept.

At the end the phone is left enrolled with Instagram and YouTube on, as
it was.
"""
import argparse
import json
import re
import subprocess
import time
import urllib.request

import websocket

DEV = "http://127.0.0.1:9222"
GATEWAY = "maheshwari@192.168.2.5"
FEED = "https://www.instagram.com/"

LABELS_JS = r"""(() => {
  let n = 0;
  for (const el of document.querySelectorAll('span, a')) {
    if (el.childElementCount === 0 && ['Sponsored', 'Ad'].includes((el.textContent || '').trim())) {
      const r = el.getBoundingClientRect();
      if (r.width > 0 && r.height > 0) n++;
    }
  }
  return n;
})()"""


def ssh(cmd):
    return subprocess.run(["ssh", "-o", "BatchMode=yes", GATEWAY, cmd], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=60)


def set_sites(device_id, sites, hours=24):
    r = ssh("cd /opt/securepi && sudo -u securepi-web python3 -c \"\n"
            "import time, correlation, orchestrator\n"
            "c = correlation.connect()\n"
            "p = orchestrator.create_policy(c, 'enroll', %d, %r, time.time() + %d * 3600,"
            " 'phase C phone measurement: sites %s', actor='site-measure')\n"
            "print(p['target'])\"" % (device_id, sites, hours, ",".join(sites)))
    if r.returncode != 0:
        raise SystemExit("enroll failed: " + r.stderr[-300:])


def adb(serial, *args):
    subprocess.run(["adb", "-s", serial, "shell"] + list(args), stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def find_tab(match, timeout_s=30):
    end = time.time() + timeout_s
    while time.time() < end:
        try:
            for t in json.load(urllib.request.urlopen(DEV + "/json/list", timeout=3)):
                if t.get("type") == "page" and match in t.get("url", ""):
                    return t
        except Exception:
            pass
        time.sleep(1)
    return None


def json_docs(text):
    text = text.lstrip()
    for prefix in ("for (;;);", ")]}'"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    try:
        return [json.loads(text)]
    except Exception:
        out = []
        for line in text.splitlines():
            try:
                out.append(json.loads(line))
            except Exception:
                pass
        return out


SCRIPT_RE = re.compile(r'<script type="application/json"[^>]*>(.*?)</script>', re.S)


def count_feed(doc):
    ads = items = 0

    def walk(node):
        nonlocal ads, items
        if isinstance(node, dict):
            if isinstance(node.get("edges"), list):
                for e in node["edges"]:
                    if isinstance(e, dict) and isinstance(e.get("node"), dict) and \
                            ("media" in e["node"] or "ad" in e["node"]):
                        items += 1
                        if e["node"].get("ad"):
                            ads += 1
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(doc)
    return ads, items


class Cdp:
    def __init__(self, tab):
        self.ws = websocket.create_connection(tab["webSocketDebuggerUrl"], timeout=30, suppress_origin=True)
        self.n = 0
        self.events = []

    def call(self, method, **params):
        self.n += 1
        my = self.n
        self.ws.send(json.dumps({"id": my, "method": method, "params": params}))
        while True:
            m = json.loads(self.ws.recv())
            if m.get("id") == my:
                return m.get("result", {})
            if "method" in m:
                self.events.append(m)

    def pump(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            self.ws.settimeout(max(0.1, end - time.time()))
            try:
                m = json.loads(self.ws.recv())
                if "method" in m:
                    self.events.append(m)
            except websocket.WebSocketTimeoutException:
                break
        self.ws.settimeout(30)


def run_once(serial, scrolls):
    adb(serial, "am", "force-stop", "com.android.chrome")
    time.sleep(2)
    adb(serial, "am", "start", "-a", "android.intent.action.VIEW", "-d", "https://example.com/",
        "com.android.chrome")
    t = find_tab("example.com")
    if t is None:
        return {"error": "tab not found"}
    time.sleep(2)
    cdp = Cdp(t)
    cdp.call("Network.enable", maxResourceBufferSize=20_000_000, maxTotalBufferSize=100_000_000)
    cdp.call("Network.setCacheDisabled", cacheDisabled=True)
    cdp.call("Page.navigate", url=FEED)
    cdp.pump(10)
    labels = 0
    for _ in range(scrolls):
        cdp.call("Runtime.evaluate", expression="window.scrollBy(0, 1400)")
        cdp.pump(2.5)
        labels = max(labels, cdp.call("Runtime.evaluate", expression=LABELS_JS,
                                      returnByValue=True).get("result", {}).get("value") or 0)
    posts = cdp.call("Runtime.evaluate", expression="document.querySelectorAll('article').length",
                     returnByValue=True).get("result", {}).get("value") or 0
    cdp.pump(2)
    # Bodies of www.instagram.com documents and JSON responses that finished.
    wanted, done = {}, set()
    for e in cdp.events:
        p = e.get("params", {})
        if e["method"] == "Network.responseReceived":
            r = p["response"]
            if r["url"].startswith("https://www.instagram.com/") and p.get("type") in ("Document", "XHR", "Fetch"):
                wanted[p["requestId"]] = p.get("type")
        elif e["method"] == "Network.loadingFinished":
            done.add(p["requestId"])
    ads = items = 0
    for rid, kind in wanted.items():
        if rid not in done:
            continue
        try:
            body = cdp.call("Network.getResponseBody", requestId=rid).get("body", "")
        except Exception:
            continue
        docs = []
        if kind == "Document":
            for block in SCRIPT_RE.findall(body):
                if '"edges"' in block:
                    try:
                        docs.append(json.loads(block))
                    except Exception:
                        pass
        else:
            docs = json_docs(body)
        for d in docs:
            a, i = count_feed(d)
            ads += a
            items += i
    cdp.ws.close()
    return {"ads_received": ads, "items_received": items, "labels": labels, "posts": posts,
            "responses_checked": len(wanted)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--runs", type=int, default=8)
    ap.add_argument("--scrolls", type=int, default=8)
    ap.add_argument("--device-id", type=int, default=2)
    ap.add_argument("--serial", default="RZCT30NYTSB")
    args = ap.parse_args()
    try:
        with open(args.out, "a") as out:
            for i in range(args.runs):
                for on in (False, True):
                    set_sites(args.device_id, ["instagram", "youtube"] if on else ["youtube"])
                    rec = run_once(args.serial, args.scrolls)
                    rec.update(site="instagram", condition="on" if on else "off", run=i, t=time.time(),
                               device="A33 Chrome")
                    out.write(json.dumps(rec) + "\n")
                    out.flush()
                    print(json.dumps(rec), flush=True)
    finally:
        set_sites(args.device_id, ["instagram", "youtube"])


if __name__ == "__main__":
    main()

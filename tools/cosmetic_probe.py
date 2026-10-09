"""ADBLOCK-ENHANCEMENT-PLAN.md A3: which ad-shaped elements does real
YouTube render in this browser, and do the rules' cosmetic selectors
match any of them?

    .venv-bench/bin/python tools/cosmetic_probe.py CONDITION OUT.jsonl [VIDEO_ID ...]

Opens m.youtube.com's home page and each watch page in the tablet's
Chrome (by Android intent, as tools/youtube_tier2.py does), scrolls a
little, and records:
  - every element tag whose name looks ad-related (ad, ads, promo,
    promoted, sponsor, companion, banner as a dash-separated word), with
    how many are on the page and how many take up space on screen;
  - how many elements each configured cosmetic selector matches.
A selector that matches nothing on any page is dead in this browser.
The condition (tablet enrolled or not) is set beforehand.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

import websocket

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "dpi"))
import adfilter_rules  # noqa: E402

DEV = "http://127.0.0.1:9223"
SERIAL = "HA13T683"

PROBE_JS = r"""(selectors) => {
  const re = /(^|-)(ad|ads|promo|promoted|sponsor|sponsored|companion|banner)(-|$)/;
  const tags = {};
  for (const el of document.querySelectorAll('*')) {
    const t = el.tagName.toLowerCase();
    if (!t.includes('-') || !re.test(t)) continue;
    const r = el.getBoundingClientRect();
    tags[t] = tags[t] || {count: 0, visible: 0};
    tags[t].count++;
    if (r.width > 0 && r.height > 0) tags[t].visible++;
  }
  const sel = {};
  for (const s of selectors) {
    try { sel[s] = document.querySelectorAll(s).length; } catch (e) { sel[s] = 'invalid'; }
  }
  return {url: location.href, tags: tags, selectors: sel, title: document.title};
}"""


def adb(*args):
    subprocess.run(["adb", "-s", SERIAL, "shell"] + list(args), stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def find_tab(match, timeout_s=25):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            for t in json.load(urllib.request.urlopen(DEV + "/json/list", timeout=3)):
                if t.get("type") == "page" and match in t.get("url", ""):
                    return t
        except Exception:
            pass
        time.sleep(1)
    return None


def evaluate(tab, expression):
    ws = websocket.create_connection(tab["webSocketDebuggerUrl"], timeout=30, suppress_origin=True)
    try:
        ws.send(json.dumps({"id": 1, "method": "Runtime.evaluate",
                            "params": {"expression": expression, "returnByValue": True, "awaitPromise": True}}))
        while True:
            m = json.loads(ws.recv())
            if m.get("id") == 1:
                return (m.get("result") or {}).get("result", {}).get("value")
    finally:
        ws.close()


def close_tabs():
    """Close every open tab, so the one the next intent opens is the only
    match: Chrome freezes scripts in background tabs, and an older tab
    with the same URL would hang the probe."""
    try:
        for t in json.load(urllib.request.urlopen(DEV + "/json/list", timeout=5)):
            if t.get("type") == "page":
                urllib.request.urlopen(DEV + "/json/close/" + t["id"], timeout=5).read()
    except Exception:
        pass
    time.sleep(1)


def probe(url, match, selectors, settle_s=10):
    close_tabs()
    adb("am", "start", "-a", "android.intent.action.VIEW", "-d", url, "com.android.chrome")
    tab = find_tab(match)
    if tab is None:
        return {"url": url, "error": "tab not found"}
    time.sleep(settle_s)
    # Scroll down and back so feed items below the fold get rendered.
    evaluate(tab, "window.scrollTo(0, document.body.scrollHeight / 2)")
    time.sleep(3)
    evaluate(tab, "window.scrollTo(0, 0)")
    time.sleep(1)
    return evaluate(tab, "(%s)(%s)" % (PROBE_JS, json.dumps(selectors)))


def main():
    condition, out = sys.argv[1], sys.argv[2]
    videos = sys.argv[3:] or ["dQw4w9WgXcQ", "kJQP7kiw5Fk", "JGwWNGJdvx8"]
    rules = adfilter_rules.default_rules()
    selectors = rules["modules"]["youtube"]["cosmetic_selectors"]
    adb("am", "force-stop", "com.android.chrome")
    time.sleep(1.5)
    pages = [("https://m.youtube.com/", "m.youtube.com")] + \
            [("https://m.youtube.com/watch?v=" + v, v) for v in videos]
    with open(out, "a") as f:
        for url, match in pages:
            rec = probe(url, match, selectors)
            rec = rec or {"url": url, "error": "no result"}
            rec["condition"] = condition
            rec["t"] = time.time()
            f.write(json.dumps(rec) + "\n")
            f.flush()
            print(condition, url, json.dumps(rec.get("tags")), "selector hits:",
                  sum(v for v in (rec.get("selectors") or {}).values() if isinstance(v, int)),
                  rec.get("error", ""), flush=True)


if __name__ == "__main__":
    main()

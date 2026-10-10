"""ADBLOCK-ENHANCEMENT-PLAN.md A3, desktop half: which ad-shaped elements
does desktop youtube.com render, do they take up space once the addon has
stripped the ads, and do the rules' ytd-* cosmetic selectors match them?

    .venv-bench/bin/python tools/cosmetic_probe_desktop.py CONDITION OUT.jsonl [VIDEO_ID ...]

Uses the Dell test browser (desktop Chromium, DevTools on local port 9231)
through the localhost test proxy; the condition (YouTube switched on or
off for the test device, cosmetic injection on or off in the test rules)
is set beforehand. For the home page and each watch page it records every
element whose tag looks ad-related, with how many take space on screen
(width and height above 1 px) and their total area, plus how many
elements each configured cosmetic selector matches, and whether the
player's video element exists (a breakage check).
"""
import json
import os
import sys
import time

from playwright.sync_api import sync_playwright

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "dpi"))
import adfilter_rules  # noqa: E402

CDP = "http://127.0.0.1:9231"

PROBE_JS = r"""(selectors) => {
  const re = /(^|-)(ad|ads|promo|promoted|sponsor|sponsored|companion|banner|masthead)(-|$)/;
  const tags = {};
  for (const el of document.querySelectorAll('*')) {
    const t = el.tagName.toLowerCase();
    if (!t.includes('-') || !re.test(t)) continue;
    const r = el.getBoundingClientRect();
    const e = tags[t] = tags[t] || {count: 0, visible: 0, area: 0};
    e.count++;
    if (r.width > 1 && r.height > 1) { e.visible++; e.area += Math.round(r.width * r.height); }
  }
  const sel = {};
  for (const s of selectors) {
    try { sel[s] = document.querySelectorAll(s).length; } catch (e) { sel[s] = 'invalid'; }
  }
  const v = document.querySelector('video');
  return {url: location.pathname + location.search, tags, selectors: sel,
          video: v ? {present: true, duration: v.duration || null} : {present: false}};
}"""


def main():
    condition, out = sys.argv[1], sys.argv[2]
    videos = sys.argv[3:] or ["dQw4w9WgXcQ", "kJQP7kiw5Fk", "JGwWNGJdvx8", "OPf0YbXqDm0"]
    selectors = adfilter_rules.default_rules()["modules"]["youtube"]["cosmetic_selectors"]
    pages = ["https://www.youtube.com/"] + ["https://www.youtube.com/watch?v=" + v for v in videos]
    with sync_playwright() as p, open(out, "a") as f:
        ctx = p.chromium.connect_over_cdp(CDP).contexts[0]
        for url in pages:
            page = ctx.new_page()
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=60000)
                time.sleep(10)
                page.mouse.wheel(0, 1200)
                time.sleep(3)
                page.mouse.wheel(0, -1200)
                time.sleep(2)
                rec = page.evaluate(PROBE_JS, selectors)
            except Exception as e:
                rec = {"url": url, "error": str(e)[:120]}
            page.close()
            rec.update(condition=condition, t=time.time())
            f.write(json.dumps(rec) + "\n")
            f.flush()
            vis = {k: v for k, v in (rec.get("tags") or {}).items() if v["visible"]}
            hits = {k: v for k, v in (rec.get("selectors") or {}).items() if v}
            print(condition, rec.get("url"), "visible ad-shaped:", json.dumps(vis), "selector hits:", json.dumps(hits),
                  "video:", (rec.get("video") or {}).get("present"), rec.get("error", ""), flush=True)


if __name__ == "__main__":
    main()

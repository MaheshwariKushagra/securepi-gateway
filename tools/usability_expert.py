#!/usr/bin/env python3
"""
SecurePi Gateway - expert usability measurements for step 7.9 (3 October 2026).

The planned 7.9 study needs 5-8 outside participants; inside one session it
was replaced by an expert review (docs/usability-study/heuristic-evaluation.md
and cognitive-walkthrough.md). This script produces that review's numbers,
against the demo console (docs/demo: the real app on a synthetic database):

    python3 tools/usability_expert.py paths OUT_DIR
    python3 tools/usability_expert.py axe OUT_DIR --axe /path/to/axe.min.js

paths - performs the shortest path for each of the study's six tasks
        (docs/usability-study/tasks.md) with real clicks and typing, counts
        clicks, keystrokes and page loads, estimates an expert's time with
        the Keystroke-Level Model, and checks the task's end state through
        the console's own API. Re-seed the demo first (seed.py, then restart
        serve.py): tasks 2, 3 and 5 change state.
axe   - runs the axe-core accessibility engine (WCAG 2.1 A/AA rules) on every
        console page in both themes at desktop and phone width, and a few
        keyboard-only checks on the task paths.

What this does NOT measure: whether real people succeed, how long they
take, or what they think (SUS) - see the 7.9 write-up.

Keystroke-Level Model (Card, Moran & Newell, 1980), the standard operator
times: K = 0.28 s per keystroke (average skilled typist), P = 1.1 s to point
with the mouse, B = 0.1 s per button press or release, H = 0.4 s to move a
hand between mouse and keyboard, M = 1.35 s of mental preparation before
each action that needs a decision. Waiting for the page (R) is measured,
not modelled, and reported separately.
"""
import argparse
import json
import os
import sys
import time

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8765"
PASSWORD = "demo"   # the demo console's documented password (docs/demo/README.md)

K, P, B, H, M = 0.28, 1.1, 0.1, 0.4, 1.35


class Recorder:
    """Does the actions for one task and keeps count of them."""

    def __init__(self, page):
        self.page = page
        self.clicks = 0
        self.keystrokes = 0
        self.page_loads = 0
        self.klm_s = 0.0
        self.steps = []
        page.on("framenavigated", self._navigated)

    def _navigated(self, frame):
        if frame == self.page.main_frame:
            self.page_loads += 1

    def click(self, locator, what):
        # Think, point, press and release.
        locator.click()
        self.clicks += 1
        self.klm_s += M + P + 2 * B
        self.steps.append("click " + what)

    def type(self, locator, text, what, enter=False):
        # Hand to keyboard, think, type, (Enter), hand back to the mouse.
        locator.fill("")
        locator.type(text)
        n = len(text) + (1 if enter else 0)
        if enter:
            locator.press("Enter")
        self.keystrokes += n
        self.klm_s += H + M + n * K + H
        self.steps.append("type %r into %s%s" % (text, what, " + Enter" if enter else ""))

    def select(self, locator, value, what):
        # A native select: point and click to open, point and click the option.
        locator.select_option(value)
        self.clicks += 2
        self.klm_s += M + 2 * (P + 2 * B)
        self.steps.append("choose %s in %s" % (value, what))

    def read(self, what):
        # Reading a value off the screen to answer: one mental operator.
        self.klm_s += M
        self.steps.append("read " + what)


def login(page):
    page.goto(BASE + "/login")
    page.fill("input[name=password]", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle")


def api(page, path):
    return page.evaluate("p => fetch(p).then(r => r.json())", path)


def settle(page, ms=600):
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(ms)


def device_id(page, name):
    for d in api(page, "/api/devices")["devices"]:
        if d.get("name") == name:
            return d["id"]
    raise RuntimeError("no device called %s in the demo" % name)


def open_device(rec, page, name):
    """Devices page, then the device's row (rows open on click)."""
    rec.click(page.locator("nav a[href='/devices'], .sidebar a[href='/devices']").first, "Devices in the sidebar")
    settle(page)
    rec.click(page.locator("tr.clickable", has_text=name).first, "the %s row" % name)
    settle(page, 1200)


# ------------------------------------------------------------------ tasks --

def task1(page, rec):
    """Which device is the riskiest right now, and why?"""
    open_device(rec, page, "kali")
    risk = page.locator("#riskScore, .card:has-text('Risk score')").first.inner_text()
    rec.read("the risk score card")
    ok = "100" in risk and ("Port scan" in risk or "brute-force" in risk)
    return ok, "kali's page shows risk 100/100 with its port-scan and brute-force incidents" if ok else risk[:200]


def task2(page, rec):
    """Make HubSpot forms work again on the Finance Laptop only."""
    open_device(rec, page, "Finance Laptop")
    row = page.locator("#deviceBlocked .list-row", has_text="hubspot").first
    domain = row.locator(".mono").inner_text().strip()
    rec.read("the Recently Blocked list")
    reason = "hubspot forms for finance"
    page.once("dialog", lambda d: d.accept(reason))   # this button asks with the browser's own prompt()
    rec.click(row.locator("[data-allow]"), "Allow next to " + domain)
    rec.keystrokes += len(reason) + 1
    rec.klm_s += H + M + (len(reason) + 1) * K + H
    rec.steps.append("type the reason into the browser prompt + Enter")
    settle(page, 1500)
    laptop, others = device_id(page, "Finance Laptop"), device_id(page, "Reception PC")
    here = api(page, "/api/filtering/check?domain=%s&device_id=%d" % (domain, laptop))
    there = api(page, "/api/filtering/check?domain=%s&device_id=%d" % (domain, others))
    ok = (not here["blocked"]) and there["blocked"]
    return ok, "%s: allowed on Finance Laptop=%s, still blocked on Reception PC=%s" % (
        domain, not here["blocked"], there["blocked"])


def task3(page, rec):
    """Cut the Task 1 device off the internet for an hour."""
    open_device(rec, page, "kali")
    rec.click(page.locator("#deviceQuarantineActions [data-toggle-menu]"), "Quarantine")
    rec.click(page.locator("#deviceQuarantineActions [data-quarantine-for='60']"), "1 hour")
    rec.type(page.locator(".sp-dialog input[name=reason]"), "suspicious scanning", "the Reason field")
    rec.click(page.locator(".sp-dialog [type=submit]"), "Quarantine (confirm)")
    settle(page, 1500)
    q = api(page, "/api/devices/%d/quarantine" % device_id(page, "kali"))
    left = q.get("expires_in_s") or 0
    ok = q.get("quarantined") and 3300 < left <= 3600
    return ok, "quarantined=%s, %d s left" % (q.get("quarantined"), left)


def task4(page, rec):
    """Why is doubleclick.net blocked on the Manager iPhone?"""
    open_device(rec, page, "Manager iPhone")
    box = page.locator("#deviceCheckDomain")
    rec.click(box, "the domain test box")
    rec.type(box, "doubleclick.net", "the domain test box", enter=True)
    toast = page.locator(".toast").last
    toast.wait_for(timeout=5000)
    text = toast.inner_text()
    rec.read("the result toast")
    ok = "Blocked" in text and ("list" in text.lower() or "filter" in text.lower() or "rule" in text.lower())
    return ok, text.replace("\n", " ")[:200]


def task5(page, rec):
    """Give the Reception PC the Strict privacy profile."""
    open_device(rec, page, "Reception PC")
    rec.select(page.locator("#deviceProfilePick"), "strict_privacy", "DNS filtering profile")
    settle(page, 1500)
    f = api(page, "/api/devices/%d/filtering" % device_id(page, "Reception PC"))
    return f.get("profile") == "strict_privacy", "profile is now %s" % f.get("profile")


def task6(page, rec):
    """Which device used the most data?"""
    rec.click(page.locator("nav a[href='/devices'], .sidebar a[href='/devices']").first, "Devices in the sidebar")
    settle(page)
    top = page.locator("tr.clickable").first.inner_text().split("\n")[0]
    rec.read("the first row (sorted by Down)")
    devices = api(page, "/api/devices")["devices"]
    most = max(devices, key=lambda d: (d.get("down") or 0) + (d.get("up") or 0))
    ok = most["name"] in top
    return ok, "top row %r; most total bytes per the API: %s" % (top, most["name"])


TASKS = [task1, task2, task3, task4, task5, task6]


def cmd_paths(out):
    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()
        login(page)
        for number, fn in enumerate(TASKS, 1):
            page.goto(BASE + "/")
            settle(page)
            rec = Recorder(page)
            started = time.time()
            try:
                ok, detail = fn(page, rec)
            except Exception as exc:
                ok, detail = False, "path failed: %s" % exc
            wall = time.time() - started
            results.append({"task": number, "question": fn.__doc__, "end_state_ok": bool(ok), "detail": detail,
                            "clicks": rec.clicks, "keystrokes": rec.keystrokes, "page_loads": rec.page_loads,
                            "klm_expert_seconds": round(rec.klm_s, 1), "scripted_wall_seconds": round(wall, 1),
                            "steps": rec.steps})
            print("task %d  ok=%-5s clicks %d keys %2d loads %d  KLM %5.1f s  | %s"
                  % (number, ok, rec.clicks, rec.keystrokes, rec.page_loads, rec.klm_s, detail))
            page.screenshot(path=os.path.join(out, "task%d-end.png" % number))
        browser.close()
    write(out, "paths.json", {"base": BASE, "klm_operators_s": {"K": K, "P": P, "B": B, "H": H, "M": M},
                              "tasks": results})


# -------------------------------------------------------------- accessibility --

PAGES = ["/", "/devices", "/devices/{kali}", "/incidents", "/incidents/{incident}", "/filtering",
         "/response", "/hunt", "/settings", "/reports/weekly"]


def keyboard_checks(page):
    """A few keyboard-only facts about the task paths."""
    out = {}
    page.goto(BASE + "/devices")
    settle(page)
    out["device_rows_reachable_by_tab"] = page.evaluate(
        "() => [...document.querySelectorAll('tr.clickable')].some(r => r.tabIndex >= 0 || r.querySelector('a[href]'))")
    # The command palette is the keyboard route to a device.
    page.keyboard.press("Meta+k")
    page.wait_for_timeout(400)
    page.keyboard.type("Finance")
    page.wait_for_timeout(600)
    page.keyboard.press("Enter")
    settle(page)
    out["command_palette_opens_device"] = page.url.rstrip("/").split("/")[-1].isdigit()
    # From the top of a device page: Tab presses to reach the Quarantine button.
    presses = 0
    page.locator("body").focus()
    reached = False
    while presses < 120:
        page.keyboard.press("Tab")
        presses += 1
        if page.evaluate("() => !!document.activeElement.closest('#deviceQuarantineActions')"):
            reached = True
            break
    out["tab_presses_to_quarantine"] = presses if reached else None
    if reached:
        page.keyboard.press("Enter")
        page.wait_for_timeout(300)
        out["quarantine_menu_opens_with_enter"] = page.evaluate(
            "() => [...document.querySelectorAll('#deviceQuarantineActions .row-menu-list button')].some(b => b.offsetParent)")
    return out


def cmd_axe(out, axe_path):
    with open(axe_path) as fh:
        axe_source = fh.read()
    results = {"axe_version": None, "pages": [], "summary": {}}
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for theme in ("dark", "light"):
            for width, height in ((1440, 900), (390, 844)):
                context = browser.new_context(viewport={"width": width, "height": height})
                context.add_init_script("try { localStorage.setItem('sp.theme', '%s') } catch (e) {}" % theme)
                page = context.new_page()
                login(page)
                kali = device_id(page, "kali")
                incident = api(page, "/api/incidents")["incidents"][0]["id"]
                for template in PAGES:
                    path = template.format(kali=kali, incident=incident)
                    page.goto(BASE + path)
                    settle(page, 1200)
                    page.add_script_tag(content=axe_source)
                    r = page.evaluate("""() => axe.run(document, {runOnly: {type: 'tag',
                        values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']}})
                        .then(r => ({version: r.testEngine.version,
                                     violations: r.violations.map(v => ({id: v.id, impact: v.impact,
                                        help: v.help, nodes: v.nodes.length,
                                        sample: v.nodes.slice(0, 3).map(n => n.target.join(' '))}))}))""")
                    results["axe_version"] = r["version"]
                    results["pages"].append({"theme": theme, "width": width, "path": path, "violations": r["violations"]})
                    for v in r["violations"]:
                        key = v["id"]
                        s = results["summary"].setdefault(key, {"impact": v["impact"], "help": v["help"],
                                                                "page_views": 0, "nodes": 0})
                        s["page_views"] += 1
                        s["nodes"] += v["nodes"]
                    print("%-5s %4d  %-22s %d violations" % (theme, width, path, len(r["violations"])))
                if theme == "dark" and width == 1440:
                    results["keyboard"] = keyboard_checks(page)
                context.close()
        browser.close()
    write(out, "axe.json", results)
    print("rules violated:", {k: (v["impact"], v["page_views"]) for k, v in results["summary"].items()})
    print("keyboard:", results.get("keyboard"))


def write(out, name, data):
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, name), "w") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
    print("written to", os.path.join(out, name))


def main():
    ap = argparse.ArgumentParser(description="Expert usability measurements (step 7.9 replacement).")
    ap.add_argument("mode", choices=["paths", "axe"])
    ap.add_argument("out")
    ap.add_argument("--axe", help="path to axe.min.js (npm install axe-core)")
    args = ap.parse_args()
    if args.mode == "paths":
        cmd_paths(args.out)
    else:
        if not args.axe:
            sys.exit("--axe /path/to/axe.min.js is required")
        cmd_axe(args.out, args.axe)


if __name__ == "__main__":
    main()

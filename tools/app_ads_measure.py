"""ADBLOCK-ENHANCEMENT-PLAN.md follow-up 3: how many in-app ads does Tier 1
(DNS filtering) already stop? Apps pin their certificates, so Tier 2 can't
touch them - but ads from ad networks inside apps (AdMob, AppLovin, Unity
and the like) come from the networks' own domains, which DNS can block.

    .venv-bench/bin/python tools/app_ads_measure.py PACKAGE OUT.jsonl --device-id 98 --serial HA13T683 --runs N

Conditions alternate run by run: the device's filtering profile
Unrestricted (DNS filtering off) and Standard (the network blocklists),
set through the orchestrator. Before every run the device's Wi-Fi is
switched off and on, which empties Android's DNS cache, so no answer from
the other condition is reused; the run is dropped if the device doesn't
come back on SecurePi-Test.

Per run (the app force-stopped, then launched and left for --seconds):
  ad_lookups      DNS lookups the device made for known ad-network domains
                  (AD_NETWORK_SUFFIXES), and how many the gateway blocked
  blocked_total   all lookups the gateway blocked in the window
  ad_views        views in the app's UI that look like an ad (an AdMob /
                  ad-network view class or resource id, or an "Ad" label).
                  Unreliable: an empty ad container counts too - judge
                  the screenshots (first use, 10 Oct 2026)
  screenshot      kept, for a person to check whether an ad was on screen
The device's profile is put back to what it was at the end.
"""
import argparse
import json
import os
import re
import subprocess
import time

GATEWAY = "maheshwari@192.168.2.5"

# Ad-network domains (serving, bidding and SDK config). Analytics-only
# domains (app-measurement.com, firebaselogging) are counted separately:
# blocking them doesn't remove an ad.
AD_NETWORK_SUFFIXES = (
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "admob.com",
    "adservice.google.com", "applovin.com", "applvn.com", "unityads.unity3d.com", "unity3d.com",
    "vungle.com", "adcolony.com", "inmobi.com", "chartboost.com", "ironsrc.mobi", "supersonicads.com",
    "mopub.com", "startappservice.com", "appodeal.com", "pangle.io", "pangleglobal.com",
    "bytedance.com", "mintegral.com", "rayjump.com", "fyber.com", "inner-active.mobi", "smaato.net",
    "adsrvr.org", "criteo.com", "taboola.com", "outbrain.com", "amazon-adsystem.com",
)
ANALYTICS_SUFFIXES = ("app-measurement.com", "firebaselogging-pa.googleapis.com", "crashlytics.com")


def ssh(cmd, timeout=60):
    return subprocess.run(["ssh", "-o", "BatchMode=yes", GATEWAY, cmd], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=timeout)


def adb(serial, *args, capture=False):
    r = subprocess.run(["adb", "-s", serial] + list(args), stdin=subprocess.DEVNULL,
                       capture_output=True, text=not capture, timeout=60)
    return r.stdout


def set_profile(device_id, profile):
    r = ssh("cd /opt/securepi && sudo -u securepi-web python3 -c \"\n"
            "import time, correlation, orchestrator\n"
            "c = correlation.connect()\n"
            "orchestrator.create_policy(c, 'profile', %d, %r, time.time() + 2 * 3600,"
            " 'in-app ads measurement: %s', actor='app-measure')\"" % (device_id, profile, profile))
    if r.returncode != 0:
        raise SystemExit("profile change failed: " + r.stderr[-300:])


def end_profile_policies(device_id):
    ssh("cd /opt/securepi && sudo -u securepi-web python3 -c \"\n"
        "import correlation, orchestrator\n"
        "c = correlation.connect()\n"
        "for p in orchestrator.active_policies(c, kind='profile', device_id=%d):\n"
        "    if p['source'] == 'console' and p['created_by'] == 'app-measure':\n"
        "        orchestrator.end_policy(c, p['id'], actor='app-measure', reason='measurement done')\"" % device_id)


def wifi_cycle(serial, want_ip):
    adb(serial, "shell", "svc", "wifi", "disable")
    time.sleep(3)
    adb(serial, "shell", "svc", "wifi", "enable")
    for _ in range(40):
        time.sleep(1)
        out = adb(serial, "shell", "ip", "-4", "addr", "show", "wlan0")
        if want_ip in out:
            time.sleep(3)
            return True
    return False


def dns_since(device_id, t0):
    r = ssh("sudo python3 -c \"\n"
            "import sqlite3, json\n"
            "c = sqlite3.connect('file:/var/lib/securepi/securepi.db?mode=ro', uri=True)\n"
            "rows = c.execute(\\\"SELECT dns_rrname, blocked FROM events WHERE device_id=? AND ts>=?"
            " AND event_type='dns_query'\\\", (%d, %f)).fetchall()\n"
            "print(json.dumps(rows))\"" % (device_id, t0))
    return json.loads(r.stdout or "[]")


def matches(name, suffixes):
    name = (name or "").lower().rstrip(".")
    return any(name == s or name.endswith("." + s) for s in suffixes)


AD_VIEW_RE = re.compile(r'class="[^"]*(gms\.ads|AdView|applovin|unity3d\.ads|NativeAd|BannerView)[^"]*"'
                        r'|resource-id="[^"]*(ad_view|adView|banner_ad|ad_container|native_ad|adContainer)[^"]*"'
                        r'|(text|content-desc)="(Ad|Advertisement|Sponsored)"', re.I)


def run_once(package, serial, seconds, shots, tag):
    adb(serial, "shell", "am", "force-stop", package)
    time.sleep(1)
    adb(serial, "shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1")
    time.sleep(seconds)
    adb(serial, "shell", "uiautomator", "dump", "/sdcard/app.xml")
    xml = adb(serial, "shell", "cat", "/sdcard/app.xml") or ""
    shot = os.path.join(shots, "%s.png" % tag)
    with open(shot, "wb") as f:
        f.write(subprocess.run(["adb", "-s", serial, "exec-out", "screencap", "-p"],
                               capture_output=True, timeout=60).stdout)
    return {"ad_views": len(AD_VIEW_RE.findall(xml)), "screenshot": shot}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("package")
    ap.add_argument("out")
    ap.add_argument("--device-id", type=int, required=True)
    ap.add_argument("--serial", required=True)
    ap.add_argument("--ip", required=True)
    ap.add_argument("--runs", type=int, default=4)
    ap.add_argument("--seconds", type=int, default=40)
    ap.add_argument("--shots", required=True)
    args = ap.parse_args()
    os.makedirs(args.shots, exist_ok=True)
    try:
        with open(args.out, "a") as out:
            for i in range(args.runs):
                for filtering in (False, True):
                    set_profile(args.device_id, "standard" if filtering else "unrestricted")
                    if not wifi_cycle(args.serial, args.ip):
                        print("device did not come back on %s - run skipped" % args.ip, flush=True)
                        continue
                    t0 = float(ssh("date +%s.%N").stdout.strip())
                    tag = "%s-%s-%d" % (args.package.rsplit(".", 1)[-1], "on" if filtering else "off", i)
                    rec = run_once(args.package, args.serial, args.seconds, args.shots, tag)
                    time.sleep(6)   # let ingest catch up with the DNS filter's log
                    rows = dns_since(args.device_id, t0)
                    ads = [(n, b) for n, b in rows if matches(n, AD_NETWORK_SUFFIXES)]
                    rec.update({
                        "package": args.package, "run": i, "filtering": "on" if filtering else "off",
                        "lookups": len(rows), "blocked_total": sum(1 for _, b in rows if b),
                        "ad_lookups": len(ads), "ad_lookups_blocked": sum(1 for _, b in ads if b),
                        "ad_domains": sorted({n for n, _ in ads}),
                        "analytics_lookups": sum(1 for n, _ in rows if matches(n, ANALYTICS_SUFFIXES)),
                        "t": time.time()})
                    out.write(json.dumps(rec) + "\n")
                    out.flush()
                    print(json.dumps(rec), flush=True)
    finally:
        end_profile_policies(args.device_id)


if __name__ == "__main__":
    main()

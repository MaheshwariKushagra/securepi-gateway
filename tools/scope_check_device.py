"""ADBLOCK-ENHANCEMENT-PLAN.md A5: check the privacy scope on a real,
deliberately enrolled device, through the real redirect.

The privacy canary (dpi/privacy_canary.py) calls the addon's decision
method directly; it can't see the nftables redirect or what mitmproxy
actually presents. This does, from the device's own browser: for each
host it records which certificate issuer the browser was shown. The
SecurePi CA means the connection was decrypted; anything else means it
was passed through. What each host SHOULD get comes from the gateway's
live rules file (a host some module covers is decrypted).

Phase 2 checks connection reuse: after loading m.youtube.com, it fetches
other Google hosts from that page. mitmproxy copies the real
certificate's names into its own, so a browser might send a google.com
request down a decrypted YouTube connection. Such a request would show
the SecurePi issuer here.

Run it after every Tier 2 deploy, by hand, on a device its owner chose to
enroll for the test - never on a timer:

    python3 tools/scope_check_device.py OUT.jsonl [--device-id 98] [--enroll-minutes 30]

Needs (as for tools/tls_latency_tablet.py): adb reaching the tablet
(ANDROID_ADB_SERVER_PORT=5038 through the Dell tunnel), Chrome's DevTools
forwarded to 127.0.0.1:9223, and the .venv-bench python (websocket).
With --enroll-minutes the device is enrolled through the orchestrator
first and unenrolled at the end; without it, it must already be enrolled.

Exit status: 0 if no host was decrypted that shouldn't be, 1 otherwise,
2 if the check couldn't run.
"""
import argparse
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

GATEWAY = "maheshwari@192.168.2.5"
DEV = "http://127.0.0.1:9223"   # --devtools-port changes it
NEUTRAL = "https://example.com/"
SECUREPI_ISSUER = "SecurePi"

# Decrypt hosts (from the YouTube module) and hosts that must pass through:
# ordinary sites, Google hosts that share YouTube's certificate, and a
# real look-alike name the suffix match must not catch.
DEFAULT_HOSTS = [
    "m.youtube.com", "www.youtube.com", "i.ytimg.com", "youtubei.googleapis.com",
    "example.com", "www.wikipedia.org", "www.google.com", "accounts.google.com",
    "www.gstatic.com", "fonts.googleapis.com", "www.youtubekids.com",
    # Site modules beyond YouTube (ADBLOCK-ENHANCEMENT-PLAN.md B2): their
    # own host is decrypted only if the device has the site switched on;
    # the live-message hosts, API hosts and CDNs never are.
    "www.instagram.com", "edge-chat.instagram.com", "gateway.instagram.com", "i.instagram.com",
    "static.cdninstagram.com", "www.facebook.com", "gateway.facebook.com", "edge-chat.facebook.com",
]
REUSE_PAGE = "https://m.youtube.com/"
REUSE_HOSTS = ["www.google.com", "accounts.google.com", "www.gstatic.com",
               "fonts.googleapis.com", "play.google.com", "i.ytimg.com"]


def ssh(cmd):
    return subprocess.run(["ssh", "-o", "BatchMode=yes", GATEWAY, cmd], stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=60)


def adb(serial, *args):
    subprocess.run(["adb", "-s", serial, "shell"] + list(args), stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def live_rules():
    r = ssh("sudo cat /var/lib/securepi-dpi/adfilter-rules.json")
    if r.returncode != 0:
        raise SystemExit("could not read the live rules: %s" % r.stderr.strip())
    return adfilter_rules.apply_defaults(adfilter_rules.validate_rules(json.loads(r.stdout)))


ORCH = ("cd /opt/securepi && sudo -u securepi-web python3 -c \"\n"
        "import time, correlation, orchestrator\n"
        "c = correlation.connect()\n%s\"")


def enroll(device_id, minutes):
    r = ssh(ORCH % ("p = orchestrator.create_policy(c, 'enroll', %d, None, time.time() + %d,"
                    " 'A5 scope check (tools/scope_check_device.py)', actor='scope-check')\n"
                    "print(p['id'])" % (device_id, minutes * 60)))
    if r.returncode != 0:
        raise SystemExit("enroll failed: %s" % r.stderr.strip()[-300:])
    return r.stdout.strip()


def unenroll(device_id):
    ssh(ORCH % ("for p in orchestrator.active_policies(c, kind='enroll', device_id=%d):\n"
                "    orchestrator.end_policy(c, p['id'], actor='scope-check', reason='A5 scope check done')\n"
                % device_id))


def device_ip_enrolled(device_id):
    r = ssh(ORCH % ("import orchestrator as o\nprint(o.device_ip(c, %d))" % device_id))
    ip = r.stdout.strip()
    enrolled = ip in ssh("sudo nft list set ip nat enrolled").stdout
    return ip, enrolled


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


class Tab:
    def __init__(self, tab):
        self.ws = websocket.create_connection(tab["webSocketDebuggerUrl"], timeout=20, suppress_origin=True)
        self.n = 0
        self.send("Network.enable")
        self.send("Network.setCacheDisabled", cacheDisabled=True)

    def send(self, method, **params):
        self.n += 1
        self.ws.send(json.dumps({"id": self.n, "method": method, "params": params}))
        return self.n

    def navigate(self, url, settle_s):
        self.send("Page.navigate", url=url)
        end = time.time() + settle_s
        conns = set()
        while time.time() < end:
            self.ws.settimeout(max(0.1, end - time.time()))
            try:
                m = json.loads(self.ws.recv())
            except websocket.WebSocketTimeoutException:
                break
            if m.get("method") == "Network.responseReceived":
                r = m["params"]["response"]
                conns.add((r.get("connectionId"), (r.get("securityDetails") or {}).get("issuer")))
        self.ws.settimeout(20)
        return conns

    def fetch(self, url, wait_s=20):
        """Fetch url from the current page; return Chrome's view of the response."""
        self.send("Runtime.evaluate",
                  expression="fetch(%s, {mode: 'no-cors', cache: 'no-store'}).then(() => 'ok', e => String(e))"
                             % json.dumps(url), awaitPromise=False, returnByValue=True)
        req_id = None
        end = time.time() + wait_s
        while time.time() < end:
            self.ws.settimeout(max(0.1, end - time.time()))
            try:
                m = json.loads(self.ws.recv())
            except websocket.WebSocketTimeoutException:
                break
            method, p = m.get("method"), m.get("params", {})
            if method == "Network.requestWillBeSent" and p.get("request", {}).get("url") == url:
                req_id = p["requestId"]
            elif method == "Network.responseReceived" and p.get("requestId") == req_id:
                r = p["response"]
                return {"status": r.get("status"), "protocol": r.get("protocol"),
                        "issuer": (r.get("securityDetails") or {}).get("issuer"),
                        "connection_id": r.get("connectionId"),
                        "connection_reused": r.get("connectionReused"),
                        "remote_ip": r.get("remoteIPAddress")}
            elif method == "Network.loadingFailed" and p.get("requestId") == req_id:
                return {"error": p.get("errorText")}
        return {"error": "no response within %ds" % wait_s}


def device_sites(ip):
    """The device's switched-on sites from the live site map (B2)."""
    r = ssh("sudo cat /var/lib/securepi-dpi/device-sites.json")
    try:
        return json.loads(r.stdout).get(ip) or ["youtube"]
    except ValueError:
        return ["youtube"]


def verdict(rules, host, res, sites=("youtube",)):
    module = adfilter_rules.module_for_host(rules, host)[0]
    expected = "decrypt" if module in sites else "passthrough"
    if res.get("issuer") is None:
        actual = "unknown"
    else:
        actual = "decrypt" if SECUREPI_ISSUER in res["issuer"] else "passthrough"
    # Privacy fails only when a host is decrypted that shouldn't be. A
    # decrypt host passed through (pin bypass, not enrolled) loses ad
    # removal, not privacy - recorded, not failed.
    return expected, actual, not (actual == "decrypt" and expected == "passthrough")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--device-id", type=int, default=98)
    ap.add_argument("--serial", default="HA13T683")
    ap.add_argument("--enroll-minutes", type=int, default=0)
    ap.add_argument("--host", action="append", help="check these hosts instead of the default list")
    ap.add_argument("--devtools-port", type=int, default=9223)
    args = ap.parse_args()
    global DEV
    DEV = "http://127.0.0.1:%d" % args.devtools_port

    rules = live_rules()
    if args.enroll_minutes:
        print("enrolled, policy", enroll(args.device_id, args.enroll_minutes), flush=True)
        time.sleep(3)
    ip, enrolled = device_ip_enrolled(args.device_id)
    sites = device_sites(ip)
    print("device %d at %s, enrolled: %s, sites: %s" % (args.device_id, ip, enrolled, ",".join(sites)), flush=True)
    if not enrolled:
        print("not enrolled - nothing would be decrypted, so the check means nothing")
        return 2

    failures = 0
    try:
        # A fresh Chrome: no connection opened before enrolment survives.
        adb(args.serial, "am", "force-stop", "com.android.chrome")
        time.sleep(1.5)
        adb(args.serial, "am", "start", "-a", "android.intent.action.VIEW", "-d", NEUTRAL, "com.android.chrome")
        t = find_tab("example.com")
        if t is None:
            print("Chrome tab not found over DevTools")
            return 2
        time.sleep(3)
        tab = Tab(t)
        with open(args.out, "a") as f:
            stamp = int(time.time())
            for host in args.host or DEFAULT_HOSTS:
                url = "https://%s/favicon.ico?scope=%d" % (host, stamp)
                res = tab.fetch(url)
                exp, act, ok = verdict(rules, host, res, sites)
                failures += not ok
                rec = dict(phase="hosts", host=host, expected=exp, actual=act, privacy_ok=ok, **res)
                f.write(json.dumps(rec) + "\n")
                print("%-6s %-26s expected %-11s got %-11s %s" % ("ok" if ok else "FAIL", host, exp, act,
                      res.get("issuer") or res.get("error")), flush=True)

            # Phase 2 starts from a fresh Chrome again, opened straight on
            # YouTube, so no Google connection from phase 1 is there for
            # Chrome to reuse - only YouTube's.
            tab.ws.close()
            adb(args.serial, "am", "force-stop", "com.android.chrome")
            time.sleep(1.5)
            adb(args.serial, "am", "start", "-a", "android.intent.action.VIEW", "-d", NEUTRAL,
                "com.android.chrome")
            t = find_tab("example.com")
            if t is None:
                print("Chrome tab not found over DevTools (phase 2)")
                return 2
            time.sleep(2)
            tab = Tab(t)
            yt = tab.navigate(REUSE_PAGE, settle_s=12)
            yt_conns = {c for c, issuer in yt if issuer and SECUREPI_ISSUER in issuer}
            print("loaded %s: %d decrypted connections" % (REUSE_PAGE, len(yt_conns)), flush=True)
            for host in REUSE_HOSTS:
                url = "https://%s/favicon.ico?reuse=%d" % (host, stamp)
                res = tab.fetch(url)
                exp, act, ok = verdict(rules, host, res, sites)
                failures += not ok
                on_yt = res.get("connection_id") in yt_conns
                rec = dict(phase="reuse", host=host, expected=exp, actual=act, privacy_ok=ok,
                           on_youtube_connection=on_yt, **res)
                f.write(json.dumps(rec) + "\n")
                print("%-6s %-26s expected %-11s got %-11s reused=%s on_youtube_conn=%s" % (
                      "ok" if ok else "FAIL", host, exp, act, res.get("connection_reused"), on_yt), flush=True)
    finally:
        if args.enroll_minutes:
            unenroll(args.device_id)
            print("unenrolled", flush=True)
    print("PRIVACY SCOPE %s (%d unexpected decryptions)" % ("OK" if not failures else "FAILED", failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

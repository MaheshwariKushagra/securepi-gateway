"""ADBLOCK-ENHANCEMENT-PLAN.md follow-up 1: does switching a site on or off
for a device take effect without restarting its browser?

    .venv-bench/bin/python tools/switch_latency.py OUT.jsonl [--device-id 2] [--rounds 3]

With Chrome on the phone left running on www.instagram.com (raw DevTools
over USB, local port 9222), each round switches Instagram off for the
device, reloads the page, and reads the gateway's own decisions for
www.instagram.com from that device since the switch; then switches it
back on and does the same. A decision after the switch means the browser
opened a new connection and the new setting applied - before the reset,
Chrome kept reusing the connection opened under the old setting.
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.request

import websocket

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from site_ads_measure_phone import ssh, set_sites, find_tab, adb  # noqa: E402

DEV = "http://127.0.0.1:9222"
IP = "10.10.0.50"


def set_sites_no_reset(device_id, sites):
    """Control condition: the same switch through the orchestrator, but
    with the connection reset disabled - how it behaved before."""
    r = ssh("cd /opt/securepi && sudo -u securepi-web python3 -c \"\n"
            "import time, correlation, orchestrator\n"
            "class B(orchestrator.Backends):\n"
            "    def reset_https(self, ip): pass\n"
            "c = correlation.connect()\n"
            "orchestrator.create_policy(c, 'enroll', %d, %r, time.time() + 86400,"
            " 'switch-latency control (no reset)', actor='site-measure', backends=B())\"" % (device_id, sites))
    if r.returncode != 0:
        raise SystemExit("enroll failed: " + r.stderr[-300:])


def gateway_now():
    return float(ssh("date +%s.%N").stdout.strip())


def decisions_since(t0):
    r = ssh("sudo python3 -c \"\n"
            "import json\n"
            "out = []\n"
            "for l in open('/var/log/securepi/dpi-events.jsonl'):\n"
            "    e = json.loads(l)\n"
            "    if e['ts'] >= %f and e.get('src_ip') == '%s' and (e.get('sni') == 'www.instagram.com'"
            " or (e.get('module') == 'instagram' and e['decision'] == 'ads_stripped')):\n"
            "        out.append([round(e['ts'] - %f, 2), e['decision'], e.get('ads_removed')])\n"
            "print(json.dumps(out))\"" % (t0, IP, t0))
    return json.loads(r.stdout or "[]")


def reload(tab_ws):
    ws = websocket.create_connection(tab_ws, timeout=30, suppress_origin=True)
    ws.send(json.dumps({"id": 1, "method": "Page.reload", "params": {"ignoreCache": True}}))
    ws.recv()
    ws.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--device-id", type=int, default=2)
    ap.add_argument("--serial", default="RZCT30NYTSB")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--ip", default="10.10.0.50")
    ap.add_argument("--no-reset", action="store_true", help="control: switch without resetting connections")
    ap.add_argument("--devtools-port", type=int, default=9222)
    args = ap.parse_args()
    global DEV, IP
    DEV, IP = "http://127.0.0.1:%d" % args.devtools_port, args.ip
    import site_ads_measure_phone
    site_ads_measure_phone.DEV = DEV
    set_sites(args.device_id, ["instagram", "youtube"])
    # One tab only: Chrome freezes background tabs, so a reload sent to an
    # older Instagram tab would never happen.
    for t in json.load(urllib.request.urlopen(DEV + "/json/list", timeout=5)):
        if t.get("type") == "page":
            urllib.request.urlopen(DEV + "/json/close/" + t["id"], timeout=5).read()
    time.sleep(1)
    adb(args.serial, "am", "start", "-a", "android.intent.action.VIEW", "-d", "https://www.instagram.com/",
        "com.android.chrome")
    tab = find_tab("instagram.com")
    time.sleep(12)
    with open(args.out, "a") as out:
        for i in range(args.rounds):
            for on in (False, True):
                t0 = gateway_now()
                (set_sites_no_reset if args.no_reset else set_sites)(
                    args.device_id, ["instagram", "youtube"] if on else ["youtube"])
                t_set = gateway_now() - t0
                reload(tab["webSocketDebuggerUrl"])
                time.sleep(12)
                d = decisions_since(t0)
                first = next((x for x in d if x[1] in ("decrypt", "passthrough", "pin_bypass")), None)
                rec = {"round": i, "reset": not args.no_reset, "switched_to": "on" if on else "off", "switch_s": round(t_set, 2),
                       "first_decision": first, "decisions": len(d),
                       "ads_stripped": sum(x[2] or 0 for x in d if x[1] == "ads_stripped"),
                       "applied": bool(first) and first[1] == ("decrypt" if on else "passthrough"),
                       "t": time.time()}
                out.write(json.dumps(rec) + "\n")
                out.flush()
                print(json.dumps(rec), flush=True)
    set_sites(args.device_id, ["instagram", "youtube"])


if __name__ == "__main__":
    main()

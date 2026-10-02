"""Step 7.5: TLS setup latency added by HTTPS inspection, measured on the
Lenovo tablet's Chrome (77) over DevTools on tcp:9223.

    python3 tls_latency_tablet.py CELL URL N OUT.jsonl

Each load: force-stop Chrome (no pooled connection survives), open a
neutral page (example.com - it never leads to the test host, so Chrome's
predictor has nothing to pre-connect), then fetch URL from that page while
DevTools watches the network. Chrome's own timing for that request gives
  connect_ms = connectEnd - connectStart   (TCP + TLS)
  tls_ms     = sslEnd - sslStart           (the TLS handshake)
A request that reused a connection has no connect/ssl timing and is
recorded as such, not timed. (Navigating straight to URL didn't work:
after a restart Chrome's predictor had already pre-connected to it, so the
page's own timing showed no handshake.)
"""
import json, subprocess, sys, time, urllib.request
import websocket

cell, url, n, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
DEV = "http://127.0.0.1:9223"
NEUTRAL = "https://example.com/"


def adb(*args):
    subprocess.run(["adb", "-s", "HA13T683", "shell"] + list(args), stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def find_tab(host, timeout_s=25):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            for t in json.load(urllib.request.urlopen(DEV + "/json/list", timeout=3)):
                if t.get("type") == "page" and host in t.get("url", ""):
                    return t
        except Exception:
            pass
        time.sleep(1)
    return None


with open(out, "a") as f:
    for i in range(n):
        adb("am", "force-stop", "com.android.chrome")
        time.sleep(1.5)
        adb("am", "start", "-a", "android.intent.action.VIEW", "-d", NEUTRAL, "com.android.chrome")
        rec = {"cell": cell, "url": url, "i": i, "t": time.time()}
        tab = find_tab("example.com")
        if tab is None:
            rec["error"] = "tab not found"
        else:
            try:
                time.sleep(3)
                ws = websocket.create_connection(tab["webSocketDebuggerUrl"], timeout=20, suppress_origin=True)
                ws.send(json.dumps({"id": 1, "method": "Network.enable", "params": {}}))
                ws.send(json.dumps({"id": 2, "method": "Network.setCacheDisabled", "params": {"cacheDisabled": True}}))
                ws.send(json.dumps({"id": 3, "method": "Runtime.evaluate", "params": {
                    "expression": "fetch(%s, {mode: 'no-cors', cache: 'no-store'}).then(() => 'ok', e => String(e))"
                                  % json.dumps(url + ("&" if "?" in url else "?") + "r=%d%d" % (i, int(time.time()))),
                    "awaitPromise": True, "returnByValue": True}}))
                deadline = time.time() + 20
                timing = None
                while time.time() < deadline and timing is None:
                    m = json.loads(ws.recv())
                    if m.get("method") == "Network.responseReceived" and url.split("?")[0] in m["params"]["response"]["url"]:
                        r = m["params"]["response"]
                        timing = r.get("timing") or {}
                        rec["status"] = r.get("status")
                        rec["protocol"] = r.get("protocol")
                        rec["issuer"] = (r.get("securityDetails") or {}).get("issuer")
                ws.close()
                if timing and timing.get("sslStart", -1) >= 0 and timing.get("connectStart", -1) >= 0:
                    rec["connect_ms"] = round(timing["connectEnd"] - timing["connectStart"], 1)
                    rec["tls_ms"] = round(timing["sslEnd"] - timing["sslStart"], 1)
                    # Request sent -> response headers: with inspection, this is
                    # where the proxy's own upstream connection and handshake land.
                    if timing.get("sendStart", -1) >= 0 and timing.get("receiveHeadersEnd", -1) >= 0:
                        rec["ttfb_ms"] = round(timing["receiveHeadersEnd"] - timing["sendStart"], 1)
                        rec["total_ms"] = round(timing["receiveHeadersEnd"] - timing["connectStart"], 1)
                elif timing is not None:
                    rec["error"] = "connection reused (no connect/ssl timing)"
                else:
                    rec["error"] = "no response event"
            except Exception as ex:
                rec["error"] = str(ex)[:120]
        f.write(json.dumps(rec) + "\n")
        f.flush()
        print(cell, i, rec.get("tls_ms"), rec.get("connect_ms"), rec.get("issuer"), rec.get("error", ""), flush=True)

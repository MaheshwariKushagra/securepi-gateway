# Step 7.8: console API latency, measured on the gateway against the real
# HTTPS server, with a short-lived session made by the app's own code.
import json, ssl, statistics, sys, time, urllib.request, urllib.error
sys.path.insert(0, "/opt/securepi")
import correlation, session_auth
c = correlation.connect()
token = session_auth.create_session(c, "securepi")
inc = c.execute("SELECT max(id) FROM incidents").fetchone()[0]
paths = ["/api/overview?range=1h", "/api/overview?range=24h", "/api/overview?range=7d", "/api/devices",
         "/api/incidents", "/api/incidents?status=new", "/api/heatmap", "/api/dns-status",
         "/api/filtering/analytics?range=24h", "/api/filtering/analytics?range=7d", "/api/filtering/resolver?range=24h",
         "/api/filtering/lists/health", "/api/devices/2/series?range=24h", "/api/devices/2/baseline",
         "/api/incidents/%d" % inc, "/api/hunt?q=dns", "/api/policies?status=active", "/api/reports/weekly",
         "/api/audit?limit=100"]
ctx = ssl._create_unverified_context()   # loopback timing only
out = {}
try:
    for p in paths:
        times, size, status = [], 0, None
        for _ in range(15):
            req = urllib.request.Request("https://10.10.0.1:8000" + p, headers={"Cookie": "sp_session=" + token})
            t = time.perf_counter()
            try:
                with urllib.request.urlopen(req, context=ctx, timeout=60) as r:
                    body = r.read(); status = r.status
            except urllib.error.HTTPError as e:
                body = b""; status = e.code
            times.append((time.perf_counter() - t) * 1000)
            size = len(body)
        times.sort()
        out[p] = {"status": status, "p50_ms": round(statistics.median(times), 1),
                  "p95_ms": round(times[min(len(times) - 1, int(0.95 * len(times)))], 1),
                  "max_ms": round(times[-1], 1), "bytes": size}
        print("%-36s %s  p50 %7.1f ms  p95 %7.1f ms  %7d bytes" % (p, status, out[p]["p50_ms"], out[p]["p95_ms"], size), flush=True)
finally:
    session_auth.delete_session(c, token)
    print("session deleted")
json.dump(out, open(sys.argv[1], "w"), indent=1)

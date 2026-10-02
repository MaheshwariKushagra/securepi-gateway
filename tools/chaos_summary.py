#!/usr/bin/env python3
"""
Step 7.7: summarise chaos runs (gateway/chaos.py timelines + the phone probe).

    python3 tools/chaos_summary.py eval/results/chaos [--out FILE]

Per scenario:
  service down        seconds from the fault until the unit was active again
                      (first sample with ActiveState active after one that wasn't)
  data gap per source seconds from the fault until the first event newer than
                      the fault arrived in the database (IDS, DNS filter, proxy)
  incidents           platform/policy incidents raised, seconds after the fault
  fail-open / gate    when the DNS fail-open rules and the inspection gate
                      changed state
  device experience   from the phone: seconds with DNS failing, seconds with
                      HTTPS failing, and when each recovered
"""

import glob
import json
import os
import sys


def changes(timeline, key, t0):
    out, prev = [], object()
    for o in timeline:
        v = o.get(key)
        if v != prev:
            out.append((round(o["t"] - t0, 1), v))
            prev = v
    return out


def first_newer(timeline, key, t0):
    for o in timeline:
        if o.get(key) and o[key] > t0:
            return round(o["t"] - t0, 1)
    return None


def probe(path, t0):
    if not os.path.exists(path):
        return None
    rows = []
    for line in open(path):
        parts = line.split()
        if len(parts) == 3 and parts[0].isdigit():
            rows.append((int(parts[0]) - t0, parts[1] == "dns=ok", parts[2] == "https=ok"))
    after = [r for r in rows if r[0] >= 0]
    def failing(idx):
        bad = [r[0] for r in after if not r[idx]]
        return {"failed_samples": len(bad), "of": len(after),
                "first_fail_s": round(bad[0], 1) if bad else None,
                "last_fail_s": round(bad[-1], 1) if bad else None}
    return {"samples": len(rows), "before_fault_ok": all(r[1] and r[2] for r in rows if r[0] < 0),
            "dns": failing(1), "https": failing(2)}


def summarise(path):
    d = json.load(open(path))
    t0, tl = d["t_action"], d["timeline"]
    s = {"scenario": d["scenario"]}
    states = changes(tl, "service", t0)
    if states and states[0][1] is not None:
        s["service_states"] = states
        down = [t for t, v in states if v != "active"]
        back = [t for t, v in states if v == "active" and down and t > down[0]]
        s["service_down_s"] = back[0] if back else (0.0 if not down else None)
    s["first_new_event_s"] = {src: first_newer(tl, key, t0) for src, key in
                              (("ids", "ids_newest"), ("dns_filter", "dns_newest"), ("proxy", "dpi_newest"))}
    s["incidents"] = [(i["signal_type"], round(i["created_at"] - t0, 1), i["title"]) for i in d["incidents"]]
    s["failopen"] = changes(tl, "failopen", t0)
    s["gate_open"] = changes(tl, "gate_open", t0)
    if d["scenario"] == "drop-wan":
        s["wan"] = changes(tl, "wan", t0)
    if d["scenario"] == "fill-disk":
        s["disk_free_pct"] = changes(tl, "disk_free_pct", t0)[:4]
    s["device"] = probe(os.path.join(os.path.dirname(path), "a33-%s.txt" % d["scenario"]), t0)
    return s


def main():
    folder = sys.argv[1]
    out = [summarise(p) for p in sorted(glob.glob(os.path.join(folder, "*.json"))) if not p.endswith("summary.json")]
    text = json.dumps(out, indent=1)
    if "--out" in sys.argv:
        open(sys.argv[sys.argv.index("--out") + 1], "w").write(text + "\n")
    print(text)


if __name__ == "__main__":
    main()

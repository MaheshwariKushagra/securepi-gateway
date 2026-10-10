#!/usr/bin/env python3
"""
SecurePi Gateway - held-out false-positive replay (Stage 7.0's one-session
replacement for the seven-day run; EVALUATION-RESULTS-2.md, Stage 7).

    python3 tools/heldout_replay.py LIVE.db --device 99 \\
        --start 2026-10-02T18:20:00 --end 2026-10-02T21:35:00 \\
        [--variant NAME:key=value,key=value ...] [--reference-events-per-day N] \\
        [--live-incidents] [--out FILE]

Replays only the chosen devices' events in [start, end] through the real
correlation signals (tools/sweep.py's own replay: same simulated clock, same
fresh database), once per settings variant, and counts the incidents raised
on those devices. Every incident on held-out benign traffic is a false
positive, except a new_device incident for a device that really did join
then (sweep.is_genuine_join).

Why this window is held-out: the four step 7.3 detection fixes were found
and scored on a copy of the live database taken before the 7.5 benchmark
ran (the Mac, device 99, 2 October 18:25-21:29). The 3 October changes
(malicious_domain retired, TLD-lookup IDS rules not raised) were motivated
by that same benchmark, so for those two the window is NOT held out - the
variants below make that visible rather than hiding it.

Exposure is reported three ways, because one heavy test session is not a
household day: per active device-hour, per 10,000 events, and (with
--reference-events-per-day) an estimate per household day at a stated
event volume. Each count gets an exact two-sided 95% Poisson interval.

Run it from a checkout whose app/ holds the engine to test: a git worktree
at an older commit replays the older engine (copy this file and
tools/sweep.py into it first).
"""
import argparse
import json
import math
import os
import shutil
import sqlite3
import sys
import tempfile
import time as real_time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sweep  # noqa: E402  (also puts app/ on the path and imports correlation/settings)


# ------------------------------------------------------------- statistics --

def poisson_cdf(k, lam):
    """P(X <= k) for X ~ Poisson(lam), summed term by term (k is small here)."""
    if lam <= 0:
        return 1.0
    term = math.exp(-lam)
    total = term
    for i in range(1, k + 1):
        term = term * lam / i
        total += term
    return min(total, 1.0)


def poisson_interval(k, confidence=0.95):
    """Exact (Garwood) two-sided interval for a Poisson count k, by bisection
    on the CDF - no scipy needed. Returns (lower, upper) for the mean count."""
    alpha = 1 - confidence

    def bisect(f, lo, hi):
        for _ in range(200):
            mid = (lo + hi) / 2
            if f(mid):
                hi = mid
            else:
                lo = mid
        return (lo + hi) / 2

    upper = bisect(lambda lam: poisson_cdf(k, lam) <= alpha / 2, 0.0, 10.0 * k + 20.0)
    if k == 0:
        lower = 0.0
    else:
        # P(X >= k) = 1 - P(X <= k-1) reaches alpha/2 at the lower bound.
        lower = bisect(lambda lam: 1 - poisson_cdf(k - 1, lam) >= alpha / 2, 0.0, float(k))
    return lower, upper


def rate(count, exposure, scale=1.0):
    """count/exposure with its 95% interval, all multiplied by scale."""
    if not exposure:
        # No exposure at all - e.g. every device had a single event, so
        # no time between its first and last (Audit10Oct E2). A rate has no
        # meaning here; say so instead of dividing by zero.
        return {"count": count, "exposure": exposure, "rate": None, "ci95": None}
    lo, hi = poisson_interval(count)
    return {"count": count, "exposure": exposure,
            "rate": round(count / exposure * scale, 4),
            "ci95": [round(lo / exposure * scale, 4), round(hi / exposure * scale, 4)]}


# ----------------------------------------------------------------- replay --

def parse_variant(text):
    """NAME:key=value,key=value -> (NAME, {key: value}) with JSON values."""
    name, _, rest = text.partition(":")
    overrides = {}
    for pair in filter(None, rest.split(",")):
        key, _, value = pair.partition("=")
        overrides[key] = json.loads(value)
    return name, overrides


def exposure_of(cols, rows, devices):
    """Events and active hours (clock hours with at least one event) per device."""
    ts_i, dev_i = cols.index("ts"), cols.index("device_id")
    out = {}
    for d in devices:
        stamps = [r[ts_i] for r in rows if r[dev_i] == d]
        hours = {int(t // 3600) for t in stamps}
        span = (max(stamps) - min(stamps)) / 3600 if stamps else 0
        out[str(d)] = {"events": len(stamps), "active_clock_hours": len(hours), "span_hours": round(span, 2)}
    return out


def live_incidents(live_db, devices, start, end):
    """What the live engine actually raised on these devices in the window."""
    live = sqlite3.connect("file:%s?mode=ro" % live_db, uri=True)
    live.row_factory = sqlite3.Row
    marks = ",".join("?" * len(devices))
    rows = live.execute("SELECT device_id, signal_type, first_seen, title FROM incidents"
                        " WHERE device_id IN (%s) AND first_seen BETWEEN ? AND ? ORDER BY first_seen" % marks,
                        list(devices) + [start, end]).fetchall()
    live.close()
    return [dict(r) for r in rows]


def main():
    import os as _os
    _os.environ["TZ"] = "Asia/Kolkata"   # the gateway's zone, as sweep.py does
    real_time.tzset()
    ap = argparse.ArgumentParser(description="Held-out false-positive replay.")
    ap.add_argument("live_db")
    ap.add_argument("--device", action="append", type=int, required=True)
    ap.add_argument("--start", required=True, help="local time YYYY-MM-DDTHH:MM:SS")
    ap.add_argument("--end", required=True)
    ap.add_argument("--variant", action="append", default=[], help="NAME:key=value,... (JSON values)")
    ap.add_argument("--reference-events-per-day", type=float, default=None)
    ap.add_argument("--live-incidents", action="store_true", help="also list what the live engine raised")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    start, end = sweep.parse_local(args.start), sweep.parse_local(args.end)
    cols, rows = sweep.load_events(args.live_db, start, end)
    dev_i = cols.index("device_id")
    rows = [r for r in rows if r[dev_i] in args.device]
    if not rows:
        sys.exit("no events for those devices in that window")
    exposure = exposure_of(cols, rows, args.device)
    total_events = sum(e["events"] for e in exposure.values())
    device_hours = sum(e["span_hours"] for e in exposure.values())
    print("%d events from devices %s, %.2f device-hours" % (total_events, args.device, device_hours))

    workdir = tempfile.mkdtemp(prefix="heldout-")
    base = os.path.join(workdir, "base.db")
    sweep.build_base(args.live_db, base, [])
    variants = [("defaults", {})] + [parse_variant(v) for v in args.variant]
    result = {"live_db": os.path.basename(args.live_db), "devices": args.device,
              "start": args.start, "end": args.end, "step_s": sweep.STEP_S,
              "engine_commit_note": "the engine is whatever app/ this was run from",
              "exposure": exposure, "total_events": total_events, "device_hours": round(device_hours, 2),
              "reference_events_per_day": args.reference_events_per_day, "variants": {}}
    for name, overrides in variants:
        path = os.path.join(workdir, "run.db")
        shutil.copyfile(base, path)
        conn, steps, failures = sweep.simulate(path, cols, rows, overrides, None)
        conn.row_factory = sqlite3.Row
        fps = []
        for inc in conn.execute("SELECT * FROM incidents WHERE device_id IN (%s) ORDER BY first_seen"
                                % ",".join("?" * len(args.device)), args.device):
            if sweep.is_genuine_join(conn, inc):
                continue
            fps.append({"device_id": inc["device_id"], "signal_type": inc["signal_type"],
                        "first_seen": inc["first_seen"], "title": inc["title"]})
        conn.close()
        by_signal = {}
        for f in fps:
            by_signal[f["signal_type"]] = by_signal.get(f["signal_type"], 0) + 1
        entry = {"overrides": overrides, "steps": steps, "failures": failures,
                 "false_positives": fps, "by_signal": by_signal,
                 "per_device_hour": rate(len(fps), device_hours),
                 "per_10k_events": rate(len(fps), total_events, 10000)}
        if args.reference_events_per_day:
            entry["per_household_day"] = rate(len(fps), total_events, args.reference_events_per_day)
        result["variants"][name] = entry
        print("%-28s %3d false positives  %s  per 10k events %s (95%% CI %s)"
              % (name, len(fps), by_signal, entry["per_10k_events"]["rate"], entry["per_10k_events"]["ci95"]))
    if args.live_incidents:
        result["live_incidents"] = live_incidents(args.live_db, args.device, start, end)
    shutil.rmtree(workdir, ignore_errors=True)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as fh:
            json.dump(result, fh, indent=1, sort_keys=True, default=str)
        print("written to %s" % args.out)


if __name__ == "__main__":
    main()

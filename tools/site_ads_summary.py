"""Summarise tools/site_ads_measure.py output (ADBLOCK-ENHANCEMENT-PLAN.md
phase C): per condition, runs in which any ad reached the browser (with a
95% Wilson interval), total ads received, feed items, posts rendered,
page errors, and the inbox check.

    python3 tools/site_ads_summary.py eval/results/sites/instagram-20261010.jsonl
"""
import json
import math
import sys


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def main(path):
    rows = [json.loads(l) for l in open(path) if l.strip()]
    out = {}
    for cond in ("off", "on"):
        runs = [r for r in rows if r.get("condition") == cond and "run" in r and "error" not in r]
        k = sum(1 for r in runs if r["ads_received"] > 0)
        lo, hi = wilson(k, len(runs))
        inbox = [r for r in rows if r.get("condition") == cond and r.get("phase") == "inbox"]
        out[cond] = {
            "runs": len(runs),
            "runs_with_ads": k,
            "rate": round(k / len(runs), 3) if runs else None,
            "wilson95": [round(lo, 3), round(hi, 3)],
            "ads_received_total": sum(r["ads_received"] for r in runs),
            "items_received_mean": round(sum(r["items_received"] for r in runs) / len(runs), 1) if runs else None,
            "max_visible_labels": max([r["labels"] for r in runs] or [0]),
            "posts_min": min([r["posts"] for r in runs] or [0]),
            "page_errors_total": sum(r["page_errors"] for r in runs),
            "errors": sum(1 for r in rows if r.get("condition") == cond and "run" in r and "error" in r),
            "inbox": inbox[-1] if inbox else None,
        }
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main(sys.argv[1])

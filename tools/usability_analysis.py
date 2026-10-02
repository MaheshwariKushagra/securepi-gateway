#!/usr/bin/env python3
"""
SecurePi Gateway - usability study analysis (ENHANCEMENT-PLAN.md step 7.9).

    python3 tools/usability_analysis.py docs/usability-study/observations.csv docs/usability-study/sus.csv

observations.csv: participant,tech_level,age_band,task,success,seconds,errors,assists,notes
sus.csv:          participant,q1..q10 (1-5)

Prints, per task: success rate (partial = 0.5) with a 95% Wilson interval,
median and range of time on task, errors and assists. Then each
participant's SUS score and the mean with a 95% t-interval, placed on
Bangor, Kortum & Miller's (2009) adjective scale.

SUS scoring (Brooke 1996): odd items contribute (answer - 1), even items
(5 - answer); the sum times 2.5 gives 0-100.
"""

import csv
import math
import statistics
import sys

# Two-sided 95% t critical values by degrees of freedom (n - 1), for small n.
T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262,
       10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131}

# Bangor, Kortum & Miller (2009), mean SUS by adjective, used as lower bounds.
ADJECTIVES = [(85.5, "Excellent"), (72.6, "Good"), (52.0, "OK"), (39.2, "Poor"), (25.0, "Awful"),
              (0.0, "Worst imaginable")]


def wilson(successes, n, z=1.96):
    """95% Wilson score interval for a proportion."""
    if n == 0:
        return None, None
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def sus_score(answers):
    total = 0
    for i, a in enumerate(answers, start=1):
        total += (a - 1) if i % 2 == 1 else (5 - a)
    return total * 2.5


def adjective(score):
    for bound, name in ADJECTIVES:
        if score >= bound:
            return name
    return ADJECTIVES[-1][1]


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[1]) as f:
        obs = list(csv.DictReader(f))
    with open(sys.argv[2]) as f:
        sus_rows = list(csv.DictReader(f))
    if not obs and not sus_rows:
        sys.exit("no data yet - the sheets are empty")

    print("TASKS")
    tasks = sorted({r["task"] for r in obs}, key=lambda t: (len(t), t))
    for task in tasks:
        rows = [r for r in obs if r["task"] == task]
        n = len(rows)
        score = sum(float(r["success"]) for r in rows)
        low, high = wilson(score, n)
        times = [float(r["seconds"]) for r in rows]
        print("  task %-3s n=%d  success %.0f%% (95%% CI %.0f-%.0f%%)  time median %.0f s (%.0f-%.0f)"
              "  errors %d  assists %d" % (task, n, 100 * score / n, 100 * low, 100 * high,
                                           statistics.median(times), min(times), max(times),
                                           sum(int(r["errors"] or 0) for r in rows),
                                           sum(int(r["assists"] or 0) for r in rows)))

    print("SUS")
    scores = []
    for r in sus_rows:
        answers = [int(r["q%d" % i]) for i in range(1, 11)]
        if any(a < 1 or a > 5 for a in answers):
            sys.exit("participant %s: SUS answers must be 1-5" % r["participant"])
        s = sus_score(answers)
        scores.append(s)
        print("  %-4s %.1f" % (r["participant"], s))
    if scores:
        mean = statistics.mean(scores)
        line = "  mean %.1f (%s)" % (mean, adjective(mean))
        if len(scores) > 1:
            half = T95.get(len(scores) - 1, 1.96) * statistics.stdev(scores) / math.sqrt(len(scores))
            # SUS can't leave 0-100, so the interval is clipped to it.
            line += ", 95%% CI %.1f-%.1f, n=%d" % (max(0.0, mean - half), min(100.0, mean + half), len(scores))
        print(line)


if __name__ == "__main__":
    main()

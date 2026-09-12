#!/usr/bin/env python3
"""
SecurePi Gateway - device risk scoring.

The score answers one question: how worried should an operator be about this
device right now? It is built from incidents, not raw events - incidents
already carry severity and an evidence chain from the correlation engine, so
re-deriving risk from raw traffic would duplicate that engine's job rather
than build on it.

Weighted and decaying, not a running total
--------------------------------------------
A device that triggered a high-severity incident a week ago and has been
quiet since is less risky today than one that triggered the same incident an
hour ago. Each contributing incident's weight decays on a 24-hour half-life
measured from when it was last active, so the score tracks current risk
rather than a lifetime tally that only ever grows. Resolved and
false-positive incidents contribute nothing - they were adjudicated, and a
score that still penalized a device for a false alarm would be indefensible.

Explainable by construction
------------------------------
The score is a sum of named, weighted terms, never an opaque model, so the
console can show exactly which incidents produced it and by how much. That
traceability is the entire point of a score an operator - or an examiner -
has to be able to justify on demand.
"""

import time

SEVERITY_WEIGHT = {"high": 40, "medium": 20, "low": 8}
HALF_LIFE_SECONDS = 24 * 3600
LIVE_STATUSES = ("new", "investigating")


def _decay(age_seconds):
    return 0.5 ** (age_seconds / HALF_LIFE_SECONDS)


def device_risk(conn, device_id, now=None):
    """Returns {"score": 0-100, "band": ..., "breakdown": [...]}."""
    now = now if now is not None else time.time()
    placeholders = ",".join("?" * len(LIVE_STATUSES))
    rows = conn.execute(
        "SELECT id, title, severity, last_seen FROM incidents"
        " WHERE device_id=? AND status IN (%s)" % placeholders,
        (device_id, *LIVE_STATUSES)).fetchall()

    breakdown = []
    total = 0.0
    for r in rows:
        weight = SEVERITY_WEIGHT.get(r["severity"], 0)
        decay = _decay(max(0.0, now - r["last_seen"]))
        contribution = weight * decay
        total += contribution
        breakdown.append({
            "incident_id": r["id"], "title": r["title"], "severity": r["severity"],
            "weight": weight, "decay": round(decay, 2), "contribution": round(contribution, 1),
        })
    breakdown.sort(key=lambda b: -b["contribution"])
    score = min(100, round(total))
    return {"score": score, "band": risk_band(score), "breakdown": breakdown}


def risk_band(score):
    if score >= 60:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "none"

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

# ENHANCEMENT-PLAN.md step 2.8: "weighted into risk" - an open campaign
# (several incidents recognized as one multi-stage attack, app/
# correlation.py's campaign_signal) adds ONE additional named term, on
# top of whatever its own linked incidents already contribute. Comparable
# to, but deliberately smaller than, a single high-severity incident's
# peak contribution (40): the correlation itself is real extra evidence
# of intent - a scan followed by a beacon is more concerning than either
# alone - but the underlying incidents are already counted; this isn't
# meant to dominate the score.
CAMPAIGN_BONUS = 25

# Incidents that record something the gateway DID, not something the
# device did (step 4.2's automatic quarantine). Counting one would score
# the same campaign twice - once as evidence and again as the response to it.
# vpn_tunnel (ADBLOCK-ENHANCEMENT-PLAN.md A6) is a note that filtering is
# being bypassed, not evidence of anything malicious.
NOT_RISK_EVIDENCE = ("auto_quarantine", "vpn_tunnel")


def _decay(age_seconds):
    return 0.5 ** (age_seconds / HALF_LIFE_SECONDS)


def device_risk(conn, device_id, now=None):
    """Returns {"score": 0-100, "band": ..., "breakdown": [...]}."""
    now = now if now is not None else time.time()
    placeholders = ",".join("?" * len(LIVE_STATUSES))
    excluded = ",".join("?" * len(NOT_RISK_EVIDENCE))
    rows = conn.execute(
        "SELECT id, title, severity, last_seen FROM incidents"
        " WHERE device_id=? AND status IN (%s) AND signal_type NOT IN (%s)" % (placeholders, excluded),
        (device_id, *LIVE_STATUSES, *NOT_RISK_EVIDENCE)).fetchall()

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

    campaign = conn.execute(
        "SELECT id, title, tactics, last_seen FROM campaigns"
        " WHERE device_id=? AND status IN (%s) ORDER BY last_seen DESC LIMIT 1" % placeholders,
        (device_id, *LIVE_STATUSES)).fetchone()
    if campaign is not None:
        decay = _decay(max(0.0, now - campaign["last_seen"]))
        contribution = CAMPAIGN_BONUS * decay
        total += contribution
        breakdown.append({
            "campaign_id": campaign["id"], "title": "%s (%s)" % (campaign["title"], campaign["tactics"]),
            "severity": "campaign", "weight": CAMPAIGN_BONUS, "decay": round(decay, 2),
            "contribution": round(contribution, 1),
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

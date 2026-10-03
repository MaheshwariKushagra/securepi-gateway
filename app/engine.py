#!/usr/bin/env python3
"""SecurePi Gateway - runs the correlation engine on a fixed interval."""
import time
import correlation
import dbconn
import health
import notify
import orchestrator
import rollup
import retention

INTERVAL_SECONDS = 15  # frequent enough to feel live in a demo; cheap at this event volume

if __name__ == "__main__":
    conn = correlation.connect()
    print("correlation engine started, running every %ds" % INTERVAL_SECONDS, flush=True)
    # The engine's heartbeat (health.check_staleness reads it): stamped
    # once now, so an engine that hangs in its very first cycle is still
    # noticed, and again after every completed cycle below. This first
    # write is retried while the database is locked: on 3 October 2026 it
    # crashed the engine at boot (see app/dbconn.py).
    dbconn.retry_while_locked(lambda: health.record_engine_heartbeat(conn),
                              what="engine start-up")
    while True:
        # step 6.1's device_hourly rollup rides this same loop rather than
        # getting its own systemd service - it is a no-op cheap enough to
        # call unconditionally on cycles where nothing new needs rolling
        # up (see rollup.py's own docstring), and it has to run BEFORE the
        # correlation signals so a freshly-closed hour is visible to
        # behavioral_baseline_signal on the very cycle it closes.
        rollup.rollup_closed_hours(conn)
        # step 1.3's retention rides this same loop too - a cheap no-op on
        # every cycle except the ~1-in-5760 that's actually due each day.
        retention.run_retention_if_due(conn)
        results = correlation.run_all(conn)
        fired = sum(v for v in results.values() if v)
        if fired:
            print("incidents raised/updated this cycle: %s" % results, flush=True)
        # Stage 4: the policy orchestrator runs after the signals, so an
        # auto-response to a campaign raised this cycle happens this cycle
        # too, and notifications run last, so they include any incident the
        # orchestrator itself just raised (drift, auto-quarantine). Each is
        # wrapped on its own: a failure in one must never stop detection.
        try:
            summary = orchestrator.reconcile(conn)
            if summary["expired"] or summary["trust"] or summary["auto"] or summary["drift"] \
                    or summary["errors"] or summary["restored"]:
                print("orchestrator: %s" % summary, flush=True)
        except Exception as exc:
            print("orchestrator error: %s" % exc, flush=True)
        try:
            sent = notify.dispatch(conn)
            if any(sent.values()):
                print("notifications: %s" % sent, flush=True)
        except Exception as exc:
            print("notification error: %s" % exc, flush=True)
        health.record_engine_heartbeat(conn)
        time.sleep(INTERVAL_SECONDS)

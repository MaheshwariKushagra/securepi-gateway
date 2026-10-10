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


def run_step(name, fn, *args):
    """Run one step of the cycle; if it fails, log it and carry on, so a
    failure in one step never stops detection (or the heartbeat). Returns
    the step's result, or None if it failed.

    Until 3 October 2026 only the orchestrator and notifications were
    wrapped like this. On 26 September the engine crashed outright when
    the rollup hit "database is locked" (found in the Stage 7 journal
    review), so every step now gets the same treatment."""
    try:
        return fn(*args)
    except Exception as exc:
        print("%s error: %s" % (name, exc), flush=True)
        # Undo whatever the failed step had written but not committed.
        # Every step shares one connection, so those rows used to be saved
        # by the next step's commit - half of a failed step's work, kept
        # as if it had finished (Audit10Oct M3). Ingest and correlation
        # already roll a failed step back the same way.
        conn = args[0] if args else None
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
        return None


def run_cycle(conn):
    """One pass of the engine: rollup, retention, signals, orchestrator,
    notifications, heartbeat - in that order, each guarded by run_step."""
    # step 6.1's device_hourly rollup rides this same loop rather than
    # getting its own systemd service - it is a no-op cheap enough to
    # call unconditionally on cycles where nothing new needs rolling
    # up (see rollup.py's own docstring), and it has to run BEFORE the
    # correlation signals so a freshly-closed hour is visible to
    # behavioral_baseline_signal on the very cycle it closes.
    run_step("rollup", rollup.rollup_closed_hours, conn)
    # step 1.3's retention rides this same loop too - a cheap no-op on
    # every cycle except the ~1-in-5760 that's actually due each day.
    run_step("retention", retention.run_retention_if_due, conn)
    results = run_step("correlation", correlation.run_all, conn) or {}
    fired = sum(v for v in results.values() if v)
    if fired:
        print("incidents raised/updated this cycle: %s" % results, flush=True)
    # Stage 4: the policy orchestrator runs after the signals, so an
    # auto-response to a campaign raised this cycle happens this cycle
    # too, and notifications run last, so they include any incident the
    # orchestrator itself just raised (drift, auto-quarantine).
    summary = run_step("orchestrator", orchestrator.reconcile, conn)
    if summary and (summary["expired"] or summary["trust"] or summary["auto"] or summary["drift"]
                    or summary["errors"] or summary["restored"]):
        print("orchestrator: %s" % summary, flush=True)
    sent = run_step("notification", notify.dispatch, conn)
    if sent and any(sent.values()):
        print("notifications: %s" % sent, flush=True)
    # The heartbeat health.check_staleness reads. If writing it fails, the
    # engine keeps running and the supervisor sees a stale heartbeat -
    # which is the right signal - instead of the engine dying.
    run_step("heartbeat", health.record_engine_heartbeat, conn)


if __name__ == "__main__":
    conn = correlation.connect()
    print("correlation engine started, running every %ds" % INTERVAL_SECONDS, flush=True)
    # The engine's heartbeat (health.check_staleness reads it): stamped
    # once now, so an engine that hangs in its very first cycle is still
    # noticed, and again after every completed cycle. This first write is
    # retried while the database is locked: on 3 October 2026 it crashed
    # the engine at boot (see app/dbconn.py).
    dbconn.retry_while_locked(lambda: health.record_engine_heartbeat(conn),
                              what="engine start-up")
    while True:
        run_cycle(conn)
        time.sleep(INTERVAL_SECONDS)

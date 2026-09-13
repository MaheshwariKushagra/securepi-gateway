#!/usr/bin/env python3
"""SecurePi Gateway - runs the correlation engine on a fixed interval."""
import time
import correlation
import rollup

INTERVAL_SECONDS = 15  # frequent enough to feel live in a demo; cheap at this event volume

if __name__ == "__main__":
    conn = correlation.connect()
    print("correlation engine started, running every %ds" % INTERVAL_SECONDS, flush=True)
    while True:
        # step 6.1's device_hourly rollup rides this same loop rather than
        # getting its own systemd service - it is a no-op cheap enough to
        # call unconditionally on cycles where nothing new needs rolling
        # up (see rollup.py's own docstring), and it has to run BEFORE the
        # correlation signals so a freshly-closed hour is visible to
        # behavioral_baseline_signal on the very cycle it closes.
        rollup.rollup_closed_hours(conn)
        results = correlation.run_all(conn)
        fired = sum(v for v in results.values() if v)
        if fired:
            print("incidents raised/updated this cycle: %s" % results, flush=True)
        time.sleep(INTERVAL_SECONDS)

#!/usr/bin/env python3
"""SecurePi Gateway - runs the correlation engine on a fixed interval."""
import time
import correlation

INTERVAL_SECONDS = 15  # frequent enough to feel live in a demo; cheap at this event volume

if __name__ == "__main__":
    conn = correlation.connect()
    print("correlation engine started, running every %ds" % INTERVAL_SECONDS, flush=True)
    while True:
        results = correlation.run_all(conn)
        fired = sum(v for v in results.values() if v)
        if fired:
            print("incidents raised/updated this cycle: %s" % results, flush=True)
        time.sleep(INTERVAL_SECONDS)

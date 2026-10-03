#!/usr/bin/env python3
"""
SecurePi Gateway - the one place every service opens the database.

Why this exists (found 3 October 2026, see EVALUATION-RESULTS-2.md,
"Boot faults"): at the 07:30 boot, securepi-engine and securepi-ingest
both crashed with "sqlite3.OperationalError: database is locked" and only
came back because systemd restarted them five seconds later. Three things
lined up:

  1. Every service called sqlite3.connect() with Python's default busy
     timeout of 5 seconds - after that, a connection that finds the
     database locked gives up with an error instead of waiting.
  2. The database's write-ahead log (the "-wal" file next to it) had grown
     to 137 MB during 2 October's tests and SQLite never shrinks that file
     on its own. The first process to open the database after a reboot has
     to read the whole log back in, and holds a lock while it does.
  3. At the same moment logrotate was compressing a 306 MB IDS log on the
     same disk, so that recovery took far longer than 5 seconds.

So this module gives every connection:

  - a 30-second busy timeout (BUSY_TIMEOUT_S), so a slow moment waits
    instead of crashing;
  - journal_size_limit = 32 MiB (WAL_SIZE_LIMIT_BYTES), which tells SQLite
    to cut the -wal file back down to that size whenever it resets it,
    so one burst of writes can no longer leave a huge file behind for the
    next boot to recover;
  - rows that can be read by column name (sqlite3.Row), as every caller
    already expected.

and retry_while_locked() for the few start-up steps that must not kill a
service just because the disk is busy for a while at boot.
"""
import sqlite3
import time

# How long a connection waits for a lock before raising "database is
# locked". 30 s comfortably covers a WAL recovery on a busy disk; anything
# longer than that is a real problem that should surface as an error.
BUSY_TIMEOUT_S = 30

# The largest size the -wal file is left at after SQLite resets it.
WAL_SIZE_LIMIT_BYTES = 32 * 1024 * 1024


def connect(path):
    """Open the SQLite database at `path` with the settings above."""
    conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_S)
    conn.row_factory = sqlite3.Row
    # journal_size_limit is a per-connection setting, so it has to be set
    # on every connection, not just once on the file.
    conn.execute("PRAGMA journal_size_limit = %d" % WAL_SIZE_LIMIT_BYTES)
    return conn


def retry_while_locked(step, attempts=6, wait_s=5, what="database step"):
    """Run step() and return its result. If it fails with "database is
    locked", wait `wait_s` seconds and try again, up to `attempts` tries in
    total; the last failure is raised. Any other error is raised at once -
    only a lock is worth waiting out.

    With the defaults (6 tries, 5 s apart, each already waiting up to
    BUSY_TIMEOUT_S on the lock itself) a service rides out several
    minutes of boot-time contention before giving up."""
    for attempt in range(1, attempts + 1):
        try:
            return step()
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc) or attempt == attempts:
                raise
            print("%s: database is locked (attempt %d of %d), retrying in %ds"
                  % (what, attempt, attempts, wait_s), flush=True)
            time.sleep(wait_s)

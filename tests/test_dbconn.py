"""Tests for app/dbconn.py - the one place every service opens the database.

Background (EVALUATION-RESULTS-2.md, "Boot faults", 3 October 2026): at the
07:30 boot both securepi-engine and securepi-ingest crashed with
"sqlite3.OperationalError: database is locked". Every connection used
Python's default 5-second busy timeout, and at boot the first process to
open the database had to recover a 137 MB write-ahead log while logrotate
was compressing a 306 MB IDS log on the same disk. These tests pin down the
fix: a long busy timeout, a cap on how big the WAL file may stay, and a
retry for the start-up steps.
"""
import glob
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import dbconn  # noqa: E402

REPO = os.path.join(os.path.dirname(__file__), "..")


class ConnectSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "t.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_busy_timeout_is_long(self):
        conn = dbconn.connect(self.path)
        busy_ms = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        self.assertEqual(busy_ms, dbconn.BUSY_TIMEOUT_S * 1000)
        self.assertGreaterEqual(dbconn.BUSY_TIMEOUT_S, 30)

    def test_wal_size_is_capped(self):
        conn = dbconn.connect(self.path)
        limit = conn.execute("PRAGMA journal_size_limit").fetchone()[0]
        self.assertEqual(limit, 32 * 1024 * 1024)

    def test_rows_are_addressable_by_name(self):
        conn = dbconn.connect(self.path)
        row = conn.execute("SELECT 1 AS one").fetchone()
        self.assertEqual(row["one"], 1)


class WaitsForALockTests(unittest.TestCase):
    """A real second connection holds a write lock; a dbconn connection
    must wait it out instead of failing."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "t.db")
        setup = sqlite3.connect(self.path)
        setup.execute("PRAGMA journal_mode=WAL")
        setup.execute("CREATE TABLE t (x INTEGER)")
        setup.commit()
        setup.close()

    def tearDown(self):
        self.tmp.cleanup()

    def _hold_write_lock(self, seconds, ready):
        holder = sqlite3.connect(self.path, timeout=0)
        holder.execute("BEGIN IMMEDIATE")
        holder.execute("INSERT INTO t VALUES (1)")
        ready.set()
        time.sleep(seconds)
        holder.commit()
        holder.close()

    def test_write_waits_for_a_held_lock(self):
        ready = threading.Event()
        holder = threading.Thread(target=self._hold_write_lock, args=(2.0, ready))
        holder.start()
        ready.wait(5)
        # A connection with a short timeout gives up while the lock is held...
        impatient = sqlite3.connect(self.path, timeout=0.2)
        with self.assertRaises(sqlite3.OperationalError):
            impatient.execute("INSERT INTO t VALUES (2)")
        impatient.close()
        # ...but a dbconn connection waits and then succeeds.
        conn = dbconn.connect(self.path)
        conn.execute("INSERT INTO t VALUES (3)")
        conn.commit()
        holder.join()
        self.assertEqual(conn.execute("SELECT count(*) FROM t").fetchone()[0], 2)


class RetryWhileLockedTests(unittest.TestCase):
    def test_retries_then_succeeds(self):
        calls = []

        def flaky():
            calls.append(1)
            if len(calls) < 3:
                raise sqlite3.OperationalError("database is locked")
            return "ok"

        result = dbconn.retry_while_locked(flaky, attempts=5, wait_s=0, what="test step")
        self.assertEqual(result, "ok")
        self.assertEqual(len(calls), 3)

    def test_gives_up_after_the_last_attempt(self):
        def always_locked():
            raise sqlite3.OperationalError("database is locked")

        with self.assertRaises(sqlite3.OperationalError):
            dbconn.retry_while_locked(always_locked, attempts=3, wait_s=0, what="test step")

    def test_other_errors_are_not_retried(self):
        calls = []

        def broken():
            calls.append(1)
            raise sqlite3.OperationalError("no such table: nope")

        with self.assertRaises(sqlite3.OperationalError):
            dbconn.retry_while_locked(broken, attempts=5, wait_s=0, what="test step")
        self.assertEqual(len(calls), 1)


class EveryServiceUsesItTests(unittest.TestCase):
    """Structural guard: a new sqlite3.connect() elsewhere in app/ would
    quietly bring the 5-second default timeout back."""

    def test_no_direct_connects_in_app(self):
        offenders = []
        for path in sorted(glob.glob(os.path.join(REPO, "app", "*.py"))):
            if os.path.basename(path) == "dbconn.py":
                continue
            with open(path) as fh:
                for number, line in enumerate(fh, 1):
                    if "sqlite3.connect(" in line:
                        offenders.append("%s:%d" % (os.path.basename(path), number))
        self.assertEqual(offenders, [])

    def test_privacy_canary_uses_it(self):
        with open(os.path.join(REPO, "dpi", "privacy_canary.py")) as fh:
            text = fh.read()
        self.assertNotIn("sqlite3.connect(", text)


if __name__ == "__main__":
    unittest.main()

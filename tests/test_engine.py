"""app/engine.py's cycle must survive a failing step (3 October 2026).

Found in the Stage 7 retrospective of the gateway's journal: on 26 September
the engine crashed when rollup.rollup_closed_hours hit "database is locked"
during the battery's start - rollup, retention and the heartbeat ran
unguarded in the engine loop, while the orchestrator and notifications
next to them were already wrapped "so a failure in one never stops
detection". Every step is now wrapped the same way.
"""
import os
import sqlite3
import sys
import unittest
import unittest.mock as mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

import engine  # noqa: E402


class RunCycleTests(unittest.TestCase):
    def _patched(self, **failing):
        """Patch every step engine.run_cycle calls; the ones named in
        `failing` raise "database is locked"."""
        calls = []

        def make(name, result):
            def step(*args, **kwargs):
                calls.append(name)
                if name in failing:
                    raise sqlite3.OperationalError("database is locked")
                return result
            return step

        patches = [
            mock.patch.object(engine.rollup, "rollup_closed_hours", make("rollup", 0)),
            mock.patch.object(engine.retention, "run_retention_if_due", make("retention", None)),
            mock.patch.object(engine.correlation, "run_all", make("signals", {})),
            mock.patch.object(engine.orchestrator, "reconcile", make("orchestrator", {
                "expired": 0, "trust": 0, "auto": 0, "drift": [], "errors": {}, "restored": []})),
            mock.patch.object(engine.notify, "dispatch", make("notify", {})),
            mock.patch.object(engine.health, "record_engine_heartbeat", make("heartbeat", None)),
        ]
        return patches, calls

    def _run(self, **failing):
        patches, calls = self._patched(**failing)
        for p in patches:
            p.start()
        try:
            engine.run_cycle(conn=None)
        finally:
            for p in patches:
                p.stop()
        return calls

    def test_a_locked_rollup_does_not_stop_detection(self):
        calls = self._run(rollup=True)
        self.assertEqual(calls, ["rollup", "retention", "signals", "orchestrator", "notify", "heartbeat"])

    def test_a_failing_retention_does_not_stop_detection(self):
        calls = self._run(retention=True)
        self.assertIn("signals", calls)
        self.assertIn("heartbeat", calls)

    def test_a_failing_heartbeat_does_not_kill_the_engine(self):
        self._run(heartbeat=True)   # must not raise

    def test_a_failing_signal_pass_still_reaches_the_heartbeat(self):
        calls = self._run(signals=True)
        self.assertEqual(calls[-1], "heartbeat")


class RollbackTests(unittest.TestCase):
    """Audit10Oct M3: a failed step's half-written rows stayed pending on
    the shared connection, and the next step's commit saved them. The
    engine now rolls a failed step back, as ingest and correlation do."""

    def test_a_failed_steps_writes_are_not_committed_by_the_next_step(self):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import fixtures
        conn = fixtures.temp_db()

        def half_writes_then_fails(c):
            c.execute("INSERT INTO signal_state (signal_type, last_run_ts) VALUES ('half-written', 1)")
            raise sqlite3.OperationalError("database is locked")

        def commits(c):
            c.execute("INSERT INTO signal_state (signal_type, last_run_ts) VALUES ('next-step', 2)")
            c.commit()
        engine.run_step("first", half_writes_then_fails, conn)
        engine.run_step("second", commits, conn)
        names = {r[0] for r in conn.execute("SELECT signal_type FROM signal_state")}
        self.assertIn("next-step", names)
        self.assertNotIn("half-written", names)

    def test_a_step_without_a_connection_still_just_logs(self):
        self.assertIsNone(engine.run_step("x", lambda: 1 / 0))


if __name__ == "__main__":
    unittest.main()

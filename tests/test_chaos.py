#!/usr/bin/env python3
"""
SecurePi Gateway - gateway/chaos.py's safety net (Audit10Oct M20).

Every fault the chaos tool injects is meant to be undone by a systemd
timer armed first, "whatever happens to this script". Two gaps: the
timer's systemd-run return code was ignored, so a fault could be injected
with no undo armed at all; and the end of a run cancelled the timer before
checking that the restore had worked. `sh` is replaced by a fake here, so
nothing runs for real.

Run via `make test`, or directly: python3 -m unittest tests.test_chaos -v
"""

import importlib.util
import os
import unittest

_spec = importlib.util.spec_from_file_location(
    "chaos", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gateway", "chaos.py"))
chaos = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chaos)


class _Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class UndoSafetyTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.orig = chaos.sh
        self.addCleanup(setattr, chaos, "sh", self.orig)

    def fake(self, failing=(), state="active"):
        def sh(cmd):
            self.calls.append(cmd)
            if cmd[0] in failing:
                return _Result(returncode=1, stderr="Failed to start transient timer unit")
            if cmd[:2] == ["systemctl", "show"]:
                return _Result(stdout=state + "\n")
            return _Result()
        chaos.sh = sh

    def test_no_fault_without_an_armed_undo(self):
        self.fake(failing=("systemd-run",))
        with self.assertRaises(SystemExit):
            chaos.schedule_undo("securepi-chaos-undo", 60, ["/usr/bin/systemctl", "start", "AdGuardHome"])

    def test_an_armed_undo_returns_normally(self):
        self.fake()
        chaos.schedule_undo("securepi-chaos-undo", 60, ["/usr/bin/systemctl", "start", "AdGuardHome"])
        self.assertTrue(any(c[0] == "systemd-run" for c in self.calls))

    def test_the_undo_is_kept_when_the_restore_did_not_work(self):
        self.fake(state="failed")              # the service won't come back
        self.assertFalse(chaos.restore_and_disarm("kill-dns"))
        self.assertFalse(any(c[:2] == ["systemctl", "stop"] and c[2].endswith(".timer") for c in self.calls))

    def test_the_undo_is_cancelled_only_after_a_confirmed_restore(self):
        self.fake(state="active")
        self.assertTrue(chaos.restore_and_disarm("kill-dns"))
        self.assertIn(["systemctl", "stop", "securepi-chaos-undo.timer"], self.calls)


if __name__ == "__main__":
    unittest.main()

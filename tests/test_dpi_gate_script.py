"""Tests for dpi/dpi-gate.sh, the script securepi-dpi.service runs to open
the HTTPS-inspection gate once the proxy is listening.

3 October 2026: at the 07:30 boot the proxy took longer than the script's
30-second wait to start listening (the disk was busy), the script exited 1,
and systemd marked the whole unit failed and restarted it. Waiting is right;
failing the unit is not - with the gate closed, enrolled devices simply
browse undecrypted (fail-open), and app/health.py's check_dpi_proxy opens
the gate as soon as the proxy answers. So on a timeout the script now logs
and exits 0, and it waits longer (75 s, inside the unit's 90 s start limit).

The script is run for real here, with fake `ss` and `nft` commands first on
PATH, so nothing touches the real firewall.
"""
import os
import stat
import subprocess
import tempfile
import unittest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SCRIPT = os.path.join(REPO, "dpi", "dpi-gate.sh")


class DpiGateScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bin = self.tmp.name
        self.nft_log = os.path.join(self.tmp.name, "nft-calls.txt")

    def _fake(self, name, body):
        path = os.path.join(self.bin, name)
        with open(path, "w") as fh:
            fh.write("#!/bin/bash\n" + body + "\n")
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        return path

    def _run(self, listening, wait_s="2"):
        # Fake `ss`: prints the proxy's listening socket only when asked to.
        self._fake("ss", 'echo "LISTEN 0 4096 10.10.0.1:8080 0.0.0.0:*"' if listening else "true")
        nft = self._fake("nft", 'echo "$@" >> "%s"' % self.nft_log)
        env = dict(os.environ, PATH=self.bin + ":" + os.environ["PATH"],
                   NFT=nft, DPI_GATE_WAIT_S=wait_s)
        return subprocess.run(["bash", SCRIPT, "open"], env=env, capture_output=True, text=True, timeout=30)

    def _nft_calls(self):
        if not os.path.exists(self.nft_log):
            return ""
        with open(self.nft_log) as fh:
            return fh.read()

    def test_opens_the_gate_once_the_proxy_listens(self):
        result = self._run(listening=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("add element ip nat dpi_up", self._nft_calls())

    def test_timeout_leaves_the_gate_closed_without_failing_the_unit(self):
        result = self._run(listening=False, wait_s="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._nft_calls(), "")
        self.assertIn("leaving the inspection gate closed", result.stderr)

    def test_default_wait_fits_inside_the_units_start_limit(self):
        with open(SCRIPT) as fh:
            text = fh.read()
        self.assertIn("DPI_GATE_WAIT_S:-75", text)


if __name__ == "__main__":
    unittest.main()

"""The IDS log rotation the gateway runs since 3 October 2026
(gateway/logrotate-suricata.conf, securepi-ids-logrotate.service/.timer).

Found in step 7.7 and again at the 3 October boot: Ubuntu's own rotation
of the IDS log is weekly with no size cap, uses copytruncate, and only runs
on AC power (logrotate.timer has ConditionACPower=true). The gateway often
ran on battery, so eve.json reached 306 MB without rotating once in 18
days, and the catch-up rotation then landed in the middle of a boot. These
tests pin the replacement down: daily or at 100 MB, rotated by renaming
(which ingest now follows - see app/ingest.py read_eve), checked every 15
minutes regardless of power, and never in the first minutes after a boot.
"""
import os
import re
import unittest

GATEWAY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gateway")


def _read(name):
    with open(os.path.join(GATEWAY, name)) as fh:
        return fh.read()


def _directives(text):
    """Config lines without comments, stripped."""
    lines = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            lines.append(line)
    return lines


class LogrotateConfigTests(unittest.TestCase):
    def setUp(self):
        self.lines = _directives(_read("logrotate-suricata.conf"))

    def test_daily_with_a_size_cap(self):
        self.assertIn("daily", self.lines)
        self.assertIn("maxsize 100M", self.lines)

    def test_rotates_by_renaming_not_copying(self):
        # copytruncate loses lines written between the copy and the
        # truncate; renaming plus the HUP below doesn't, and ingest drains
        # the renamed file.
        self.assertNotIn("copytruncate", self.lines)
        self.assertTrue(any(line.startswith("create ") for line in self.lines))

    def test_newest_rotated_file_stays_uncompressed(self):
        # ingest drains eve.json.1 after a rotation, so it must still be a
        # plain file, and named .1 (no date suffix).
        self.assertIn("delaycompress", self.lines)
        self.assertIn("compress", self.lines)
        self.assertNotIn("dateext", self.lines)

    def test_tells_the_ids_to_reopen_its_logs(self):
        text = "\n".join(self.lines)
        self.assertRegex(text, r"postrotate\s+.*kill -HUP .*suricata\.pid.*\s+endscript")


class TimerAndServiceTests(unittest.TestCase):
    def test_timer_runs_every_15_minutes_and_not_right_after_boot(self):
        timer = _read("securepi-ids-logrotate.timer")
        self.assertIn("OnUnitActiveSec=15min", timer)
        boot = re.search(r"OnBootSec=(\d+)min", timer)
        self.assertIsNotNone(boot)
        self.assertGreaterEqual(int(boot.group(1)), 10)

    def test_runs_on_battery_too(self):
        for name in ("securepi-ids-logrotate.timer", "securepi-ids-logrotate.service"):
            # Only real directives count, not the comments explaining the omission.
            self.assertFalse(any(line.startswith("ConditionACPower") for line in _directives(_read(name))), name)

    def test_service_is_gentle_and_uses_its_own_state(self):
        service = _read("securepi-ids-logrotate.service")
        self.assertIn("Nice=19", service)
        self.assertIn("IOSchedulingClass=idle", service)
        self.assertIn("--state /var/lib/logrotate/securepi-ids.status", service)
        self.assertIn("/etc/securepi/logrotate-suricata.conf", service)

    def test_installer_takes_the_packaged_rotation_out_of_logrotate_d(self):
        installer = _read("install-ids-logrotate.sh")
        self.assertIn("dpkg-divert", installer)
        self.assertIn("/etc/logrotate.d/suricata", installer)

    def test_timer_is_watched_by_the_health_check(self):
        services = os.path.join(os.path.dirname(GATEWAY), "app", "services.list")
        with open(services) as fh:
            self.assertIn("securepi-ids-logrotate.timer", fh.read().split())


if __name__ == "__main__":
    unittest.main()

"""The DoH resolver set refresh (gateway/systemd/securepi-doh-refresh.timer
and .service), STAGE8-RECORD.md M-15.

Found by the installer's check run on 10 October 2026: loading
/etc/nftables.conf at boot leaves the `doh_resolvers` set with only its 14
seed addresses, and the timer was daily only. `Persistent=true` catches up
a run missed while the machine was off, not one that already happened
before the reboot, so after a daytime reboot the IP-level DoH block was
down to 14 addresses for up to a day. These tests pin the fix: a run
shortly after every boot, after the firewall has loaded, on top of the
daily one.
"""
import os
import re
import unittest

SYSTEMD = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gateway", "systemd")


def _directives(name):
    """The unit file's directive lines, without comments."""
    with open(os.path.join(SYSTEMD, name)) as fh:
        lines = [line.split("#", 1)[0].strip() for line in fh]
    return [line for line in lines if line]


class DohRefreshTimerTests(unittest.TestCase):
    def test_runs_soon_after_every_boot(self):
        boot = [line for line in _directives("securepi-doh-refresh.timer") if line.startswith("OnBootSec=")]
        self.assertEqual(len(boot), 1, "no OnBootSec=: the set keeps its 14 seeds after a reboot")
        minutes = re.fullmatch(r"OnBootSec=(\d+)min", boot[0])
        self.assertIsNotNone(minutes, boot[0])
        self.assertLessEqual(int(minutes.group(1)), 10)

    def test_still_runs_daily_and_catches_up_a_missed_day(self):
        timer = _directives("securepi-doh-refresh.timer")
        self.assertIn("OnCalendar=daily", timer)
        self.assertIn("Persistent=true", timer)

    def test_the_refresh_waits_for_the_firewall(self):
        # A boot-time run before nftables.service would fill a set that
        # loading /etc/nftables.conf then resets to the 14 seeds.
        after = " ".join(line for line in _directives("securepi-doh-refresh.service")
                         if line.startswith("After="))
        self.assertIn("nftables.service", after)


if __name__ == "__main__":
    unittest.main()

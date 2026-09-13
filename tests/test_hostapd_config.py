#!/usr/bin/env python3
"""
SecurePi Gateway - hostapd config test (ENHANCEMENT-PLAN.md step 1.7).

Not a functional test - hostapd.conf's real effect (client isolation on
the actual WiFi radio) can't be exercised by a unit test, and the test
harness's own network namespaces are deliberately separate from ap0/
hostapd (see gateway/setup-test-harness.sh's own header), so they can't
exercise it either. This is a structural regression guard: it confirms
ap_isolate=1 is present in the repo's own hostapd.conf, so a future
edit to this file can't silently drop client isolation without at least
failing `make test`.

Run via `make test`, or directly: python3 -m unittest tests.test_hostapd_config -v
"""

import os
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOSTAPD_CONF_PATH = os.path.join(REPO_ROOT, "gateway", "hostapd.conf")


class HostapdConfigTests(unittest.TestCase):
    def test_client_isolation_is_enabled(self):
        with open(HOSTAPD_CONF_PATH) as fh:
            lines = [l.strip() for l in fh if l.strip() and not l.strip().startswith("#")]
        self.assertIn("ap_isolate=1", lines,
                       "gateway/hostapd.conf must set ap_isolate=1 (ENHANCEMENT-PLAN.md step 1.7, finding G8)")


if __name__ == "__main__":
    unittest.main()

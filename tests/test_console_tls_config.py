#!/usr/bin/env python3
"""
SecurePi Gateway - console TLS config tests (ENHANCEMENT-PLAN.md step 3.2).

Not a functional test of TLS itself - gateway/generate-console-tls.sh
writes to root-owned paths under /opt, which only exist on the gateway,
the same reason dpi/deploy-dpi.sh, gateway/refresh-doh-set.sh and
gateway/setup-test-harness.sh have no Mac-side unit tests either (see
EVALUATION-RESULTS-2.md 3.2 for how the actual certificate generation
and TLS handshake were verified live, on the Mac, against a temporary
uvicorn instance, before ever touching the gateway).

These ARE structural regression guards, the same shape
test_hostapd_config.py already uses for gateway/hostapd.conf: they
confirm the two files that must agree with each other about where the
console's certificate and key live - the generation script that writes
them and the systemd unit that reads them - actually do, and that the
certificate's required SANs are still present. A future edit to either
file that silently breaks that agreement fails `make test` immediately
instead of only being discovered live on the gateway.

Run via `make test`, or directly: python3 -m unittest tests.test_console_tls_config -v
"""

import os
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN_SCRIPT_PATH = os.path.join(REPO_ROOT, "gateway", "generate-console-tls.sh")
SERVICE_PATH = os.path.join(REPO_ROOT, "gateway", "securepi-web.service")


class ConsoleTlsConfigTests(unittest.TestCase):
    def setUp(self):
        with open(GEN_SCRIPT_PATH) as fh:
            self.script = fh.read()
        with open(SERVICE_PATH) as fh:
            self.service = fh.read()

    def test_required_sans_are_present(self):
        # localhost/127.0.0.1 for the Mac's SSH tunnel (mac-tunnel.sh),
        # 10.10.0.1 for a device browsing directly on SecurePi-Test.
        # Losing any one of these silently breaks one real access path.
        self.assertIn("DNS:localhost", self.script)
        self.assertIn("IP:10.10.0.1", self.script)
        self.assertIn("IP:127.0.0.1", self.script)

    def test_the_leaf_is_marked_not_a_ca(self):
        # A leaf certificate usable as an intermediate CA would let
        # whatever holds its private key sign other certificates the
        # console's own trusted CA would then also vouch for.
        self.assertIn("basicConstraints = CA:FALSE", self.script)

    def test_the_service_points_at_the_files_the_script_actually_writes(self):
        # The script's own TLS_DIR variable, not a hardcoded guess -
        # if that variable is ever renamed, this test's own extraction
        # breaks loudly instead of quietly checking the wrong path.
        for line in self.script.splitlines():
            if line.startswith("TLS_DIR="):
                tls_dir = line.split("=", 1)[1].strip()
                break
        else:
            self.fail("generate-console-tls.sh has no TLS_DIR= assignment")
        self.assertIn("%s/console.key" % tls_dir, self.service)
        self.assertIn("%s/console.crt" % tls_dir, self.service)

    def test_the_leaf_validity_is_within_apples_ats_limit(self):
        # 825 days is the longest-lived TLS leaf certificate Apple's App
        # Transport Security will trust even once its issuing CA is
        # trusted - the Mac is this console's primary browser. A future
        # edit that quietly lengthens this would re-introduce a
        # certificate warning on macOS that trusting the CA can't fix.
        self.assertIn("-days 825", self.script)

    def test_the_web_service_refuses_plain_http(self):
        # "HTTPS only" (the step's own exit criterion) means the
        # ExecStart line must actually pass both TLS flags to uvicorn -
        # without both, uvicorn serves plain HTTP regardless of what
        # certificate exists on disk.
        self.assertIn("--ssl-keyfile", self.service)
        self.assertIn("--ssl-certfile", self.service)


if __name__ == "__main__":
    unittest.main()

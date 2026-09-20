#!/usr/bin/env python3
"""
SecurePi Gateway - security headers test (ENHANCEMENT-PLAN.md step 3.4,
security self-review).

Structural, not functional: exercising the real middleware needs
FastAPI's TestClient, which needs the `httpx` package this project's
Mac environment doesn't have installed (see session_auth.py's own
module docstring for the same constraint). This confirms the three
header assignments are actually present in security_headers_middleware,
so a future edit can't silently drop one without at least failing
`make test`.

Run via `make test`, or directly: python3 -m unittest tests.test_security_headers -v
"""

import os
import re
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEBAPP_PATH = os.path.join(REPO_ROOT, "app", "webapp.py")


class SecurityHeadersTests(unittest.TestCase):
    def setUp(self):
        with open(WEBAPP_PATH) as fh:
            src = fh.read()
        m = re.search(
            r"async def security_headers_middleware\(request.*?\n(.*?)\n\n\n",
            src, re.DOTALL,
        )
        self.assertIsNotNone(m, "security_headers_middleware not found")
        self.body = m.group(1)

    def test_nosniff_is_set(self):
        self.assertIn('response.headers["X-Content-Type-Options"] = "nosniff"', self.body)

    def test_frame_options_denies_framing(self):
        self.assertIn('response.headers["X-Frame-Options"] = "DENY"', self.body)

    def test_referrer_policy_is_set(self):
        self.assertIn('response.headers["Referrer-Policy"] = "no-referrer"', self.body)


if __name__ == "__main__":
    unittest.main()

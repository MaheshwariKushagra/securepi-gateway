"""Step 5.5's resolver tuning: what the console applies must be exactly the
configuration that was measured (3 October 2026).

The A/B measurement in step 7.5 (gateway/dns_ab.py, cold p50 68 -> 47 ms,
p95 411 -> 281 ms) used upstreams [Cloudflare, Quad9] with fallbacks
[Cloudflare secondary, Quad9 secondary]. The console's apply endpoint
applied something slightly different (three upstreams, and fallbacks that
repeated two of them, so the fallback added nothing). Both now read one
constant, adguard.RECOMMENDED_RESOLVER_TUNING.

FastAPI isn't installed where the tests run, so the endpoint is checked by
reading its source, the same way tests/test_audit_coverage.py does.
"""
import os
import re
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "app"))

import adguard  # noqa: E402


def _function_source(path, name):
    with open(path) as fh:
        text = fh.read()
    match = re.search(r"\ndef %s\(.*?(?=\n(?:@|def |class )|\Z)" % name, text, re.S)
    return match.group(0) if match else ""


class RecommendedResolverTuningTests(unittest.TestCase):
    def test_is_the_configuration_that_was_measured(self):
        self.assertEqual(adguard.RECOMMENDED_RESOLVER_TUNING, {
            "upstream_dns": ["tls://1.1.1.1", "tls://9.9.9.9"],
            "fallback_dns": ["tls://1.0.0.1", "tls://149.112.112.112"],
            "cache_optimistic": True,
            "dnssec_enabled": True,
            "upstream_mode": "parallel",
        })

    def test_no_fallback_repeats_an_upstream(self):
        cfg = adguard.RECOMMENDED_RESOLVER_TUNING
        self.assertEqual(set(cfg["upstream_dns"]) & set(cfg["fallback_dns"]), set())

    def test_every_server_is_encrypted(self):
        cfg = adguard.RECOMMENDED_RESOLVER_TUNING
        for server in cfg["upstream_dns"] + cfg["fallback_dns"]:
            self.assertTrue(server.startswith("tls://"), server)

    def test_the_console_endpoint_applies_it(self):
        body = _function_source(os.path.join(REPO, "app", "webapp.py"), "api_apply_resolver_tuning")
        self.assertIn("adguard.set_dns_tuning(**adguard.RECOMMENDED_RESOLVER_TUNING)", body)
        self.assertNotIn("tls://", body, "the endpoint must not carry its own server list")

    def test_the_ab_measurement_uses_it(self):
        with open(os.path.join(REPO, "gateway", "dns_ab.py")) as fh:
            text = fh.read()
        self.assertIn("TUNED = adguard.RECOMMENDED_RESOLVER_TUNING", text)


if __name__ == "__main__":
    unittest.main()

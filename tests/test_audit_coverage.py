#!/usr/bin/env python3
"""
SecurePi Gateway - audit coverage test (ENHANCEMENT-PLAN.md step 1.5).

Step 6.3 built the audit_log table and the audit.log()/audit.recent()
helpers, and wired them into every write endpoint that existed at the
time. Step 1.5's own remaining job, once that infrastructure already
existed, was finishing the job: ten more write endpoints (device
rename, network-wide filtering enable/blocklist add-toggle-remove/
custom rule add-remove, per-device filtering/DPI-enrollment/quarantine
toggles) were still using the print()-only stopgap 6.3 itself will have
inherited from before either table existed.

This test is a permanent regression guard, not just a one-time check:
it statically scans app/webapp.py's real source for every @app.post/
patch/put-decorated endpoint function and asserts audit.log(...)
appears somewhere in its body. A future endpoint added without an
audit call fails this test immediately, rather than silently
regressing the "every console action -> one audit row" guarantee step
1.5's own exit criterion describes.

Run via `make test`, or directly: python3 -m unittest tests.test_audit_coverage -v
"""

import os
import re
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEBAPP_PATH = os.path.join(REPO_ROOT, "app", "webapp.py")

# Endpoints that are genuinely write-shaped (POST/PATCH/PUT) but don't
# change any state an audit trail would need to explain - read-only
# actions or pure validation that happen to use a non-GET verb. Empty
# today (every real write endpoint is audited); kept as the explicit,
# documented place a future genuinely-stateless POST would be listed,
# rather than silently excluded from this test's scan.
EXPLICITLY_UNAUDITED_OK = set()

# Calls that write their own audit row, so an endpoint that makes one is
# audited even without a direct audit.log() in its own body. Stage 4:
# app/orchestrator.py's create_policy()/end_policy() write policy.create /
# policy.remove / policy.rolled_back themselves, with the actor webapp.py
# passes in, and _create_policy()/_end_policy() are webapp.py's own thin
# wrappers around exactly those two (they only map errors to HTTP codes).
# api_device_filtering_set calls api_device_profile_set, which calls them.
AUDITING_CALLS = ("audit.log(", "_create_policy(", "_end_policy(", "api_device_profile_set(")

ENDPOINT_PATTERN = re.compile(
    # (?:async )? - step 3.1 added this project's first `async def` write
    # endpoint (POST /login). Without this, the scanner below silently
    # skips any async endpoint rather than checking it, which would have
    # let a genuinely unaudited async endpoint pass this test - the
    # opposite of what a "future endpoint added without an audit call
    # fails this test immediately" regression guard is for. Caught by
    # running this exact scanner against the real new endpoint and
    # noticing it wasn't in the results, not assumed.
    r'@app\.(post|patch|put)\("([^"]+)"\)\n(?:async )?def (\w+)\(', re.MULTILINE
)


def _find_endpoints(source):
    matches = list(ENDPOINT_PATTERN.finditer(source))
    endpoints = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(source)
        body = source[start:end]
        endpoints.append({
            "method": m.group(1), "path": m.group(2), "name": m.group(3),
            "audited": any(call in body for call in AUDITING_CALLS),
        })
    return endpoints


class AuditCoverageTests(unittest.TestCase):
    def test_every_write_endpoint_is_audited(self):
        with open(WEBAPP_PATH) as fh:
            source = fh.read()
        endpoints = _find_endpoints(source)
        self.assertGreater(len(endpoints), 20, "the endpoint scanner itself found suspiciously few write routes")

        unaudited = [e for e in endpoints if not e["audited"] and e["name"] not in EXPLICITLY_UNAUDITED_OK]
        self.assertEqual(unaudited, [], "unaudited write endpoint(s): %s" %
                          [(e["method"], e["path"], e["name"]) for e in unaudited])

    def test_the_allowlist_does_not_contain_a_stale_entry(self):
        # If a name is ever added to EXPLICITLY_UNAUDITED_OK, it must
        # still refer to a real endpoint in webapp.py - catches a typo
        # or a since-removed/since-audited endpoint left on the list.
        with open(WEBAPP_PATH) as fh:
            source = fh.read()
        real_names = {e["name"] for e in _find_endpoints(source)}
        stale = EXPLICITLY_UNAUDITED_OK - real_names
        self.assertEqual(stale, set(), "stale allowlist entries: %s" % stale)


if __name__ == "__main__":
    unittest.main()

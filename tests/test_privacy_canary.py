"""dpi/privacy_canary.py's checks (ENHANCEMENT-PLAN.md step 5.7, widened to
every site module by ADBLOCK-ENHANCEMENT-PLAN.md B4), run against the
repository's addon with mitmproxy stubbed out, as tests/test_adfilter.py
does."""
import copy
import os
import sys
import tempfile
import types
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "app"))
sys.path.insert(0, os.path.join(REPO, "dpi"))

if "mitmproxy" not in sys.modules:
    _fake = types.ModuleType("mitmproxy")
    _fake.http = types.ModuleType("mitmproxy.http")
    sys.modules["mitmproxy"] = _fake
    sys.modules["mitmproxy.http"] = _fake.http

import adfilter_rules  # noqa: E402
import privacy_canary  # noqa: E402

ADDON = os.path.join(REPO, "dpi", "securepi_adfilter.py")


class CanaryTests(unittest.TestCase):
    def setUp(self):
        self._orig = privacy_canary.ADDON_PATH
        privacy_canary.ADDON_PATH = ADDON

    def tearDown(self):
        privacy_canary.ADDON_PATH = self._orig

    def _addon(self, rules=None):
        a = privacy_canary._load_addon_fresh().SecurePiAdFilter()
        if rules is not None:
            a._rules = rules
        return a

    def test_every_expected_decision_holds_for_the_real_addon(self):
        addon = self._addon()
        checks = privacy_canary.expected_decisions(addon._rules)
        self.assertIn(("example.com", False), checks)
        self.assertIn(("notyoutube.com", False), checks)
        self.assertIn(("canary.youtube.com", True), checks)
        for host, must in checks:
            self.assertEqual(privacy_canary.will_decrypt(host, addon), must, host)

    def test_every_module_is_covered(self):
        rules = adfilter_rules.default_rules()
        other = copy.deepcopy(rules["modules"]["youtube"])
        other["decrypt_suffixes"] = ["example.org"]
        other["passthrough_suffixes"] = ["chat.example.org"]
        rules["modules"]["other"] = other
        checks = dict(privacy_canary.expected_decisions(rules))
        self.assertTrue(checks["example.org"])
        self.assertFalse(checks["notexample.org"])
        self.assertFalse(checks["chat.example.org"])

    def test_the_ignore_conn_typo_is_caught(self):
        # The report's §6 bug: the wrong attribute name means nothing is
        # ever passed through.
        with open(ADDON) as f:
            src = f.read()
        self.assertIn("data.ignore_connection = True", src)
        broken = src.replace("data.ignore_connection = True", "data.ignore_conn = True")
        with tempfile.NamedTemporaryFile("w", suffix=".py", dir=os.path.join(REPO, "dpi"),
                                         delete=False) as f:
            f.write(broken)
        try:
            privacy_canary.ADDON_PATH = f.name
            addon = self._addon()
            wrong = [h for h, must in privacy_canary.expected_decisions(addon._rules)
                     if privacy_canary.will_decrypt(h, addon) != must]
            self.assertIn("example.com", wrong)
            self.assertIn("notyoutube.com", wrong)
        finally:
            os.remove(f.name)


if __name__ == "__main__":
    unittest.main()

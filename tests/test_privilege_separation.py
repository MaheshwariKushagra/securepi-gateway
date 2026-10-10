#!/usr/bin/env python3
"""
SecurePi Gateway - privilege separation tests (ENHANCEMENT-PLAN.md step 3.3).

Structural regression guards, the same "not a functional test - this
needs root and a real gateway to actually exercise" honesty
test_hostapd_config.py and test_console_tls_config.py already use.
gateway/setup-privilege-separation.sh (user/group creation, file moves,
chown/chmod) can only be run and verified live, on the gateway - see
EVALUATION-RESULTS-2.md 3.3 for that.

What these confirm from the Mac: app/quarantine.py and
app/dpi_enroll.py never call `nft` directly any more (the whole point
of this step - finding G9), the systemd unit actually drops root and
does NOT set the one hardening flag that would silently break the
helper it still needs, and the sudoers rule only allows that one
program.

Run via `make test`, or directly: python3 -m unittest tests.test_privilege_separation -v
"""

import os
import re
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class NoDirectNftCallsTests(unittest.TestCase):
    """The web app's only two nft-calling modules must route through the
    privileged helper (via sudo), never `nft` itself - that's the
    security boundary this whole step exists to create."""

    def _source(self, relpath):
        with open(os.path.join(REPO_ROOT, relpath)) as fh:
            return fh.read()

    def test_quarantine_py_never_invokes_nft_directly(self):
        src = self._source("app/quarantine.py")
        self.assertNotIn('"nft"', src)
        self.assertIn("securepi-web-helper", src)

    def test_dpi_enroll_py_never_invokes_nft_directly(self):
        src = self._source("app/dpi_enroll.py")
        self.assertNotIn('"nft"', src)
        self.assertIn("securepi-web-helper", src)

    def test_both_modules_invoke_the_helper_through_sudo(self):
        for relpath in ("app/quarantine.py", "app/dpi_enroll.py"):
            src = self._source(relpath)
            self.assertIn('"sudo"', src, "%s must invoke the helper via sudo" % relpath)


class SystemdUnitTests(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(REPO_ROOT, "gateway", "securepi-web.service")) as fh:
            self.unit = fh.read()

    def test_the_service_runs_as_the_unprivileged_user(self):
        self.assertIn("User=securepi-web", self.unit)
        self.assertIn("Group=securepi", self.unit)

    def test_no_new_privileges_is_not_set(self):
        # A common hardening default that would silently break sudo -
        # and therefore the one privileged path this service still
        # legitimately needs - since sudo itself relies on its own
        # setuid bit to gain root. See the unit file's own comment for
        # why this is a deliberate omission, not an oversight a future
        # "harden this service" pass should just add back. Checked as
        # an actual directive line, not a bare substring search - the
        # file's own explanatory comment mentions the setting by name,
        # which a naive "not in" check would misfire on.
        directive_lines = [l.strip() for l in self.unit.splitlines()
                            if l.strip().lower().startswith("nonewprivileges")]
        self.assertEqual(directive_lines, [], "NoNewPrivileges must not be set: %s" % directive_lines)


class SudoersTests(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(REPO_ROOT, "gateway", "securepi-web-sudoers")) as fh:
            self.sudoers = fh.read()

    def test_only_the_one_helper_program_is_allowlisted(self):
        rule_lines = [l for l in self.sudoers.splitlines()
                      if l.strip() and not l.strip().startswith("#") and "securepi-web ALL=" in l]
        self.assertEqual(len(rule_lines), 1, "expected exactly one securepi-web sudoers rule")
        self.assertIn("NOPASSWD: /usr/local/sbin/securepi-web-helper", rule_lines[0])
        # No trailing wildcard/extra command on the same rule - the
        # allowlist is the program itself, not a pattern that could
        # accidentally also match something else.
        self.assertNotIn(",", rule_lines[0])


class HelperScriptTests(unittest.TestCase):
    def test_the_helper_hardcodes_every_family_table_and_set(self):
        # A regression guard against a future edit accidentally taking
        # the nftables family/table/set from caller-controlled input -
        # every verb's target must be a literal in the source, not
        # derived from `args`.
        with open(os.path.join(REPO_ROOT, "gateway", "securepi-web-helper")) as fh:
            src = fh.read()
        for literal in ('"inet", "filter", "quarantine"', '"ip", "nat", "enrolled"'):
            self.assertIn(literal, src)



class CodeAndDataSeparationTests(unittest.TestCase):
    """Audit.md C1: root services import Python from /opt/securepi and
    /opt/securepi-dpi, so nothing the unprivileged console WRITES may live
    there - a directory the console can create files in is a directory it
    can plant a module in. Structural guards only; the real permissions
    can only be checked on the gateway (gateway/migrate-data-dirs.sh
    prints anything in those directories not owned by root)."""

    WRITABLE_PATH_CONSTANTS = (
        ("app/webapp.py", "DB_PATH"), ("app/webapp.py", "DPI_RULES_PATH"),
        ("app/ingest.py", "DB_PATH"), ("app/correlation.py", "DB_PATH"),
        ("app/health.py", "DB_PATH"), ("app/intel.py", "DB_PATH"),
        ("app/orchestrator.py", "LOCK_PATH"), ("app/status.py", "DB"),
        ("dpi/privacy_canary.py", "DB_PATH"), ("dpi/securepi_adfilter.py", "RULES_PATH"),
    )

    def _source(self, relpath):
        with open(os.path.join(REPO_ROOT, relpath)) as fh:
            return fh.read()

    def test_every_writable_path_lives_under_var_lib(self):
        for relpath, name in self.WRITABLE_PATH_CONSTANTS:
            m = re.search(r'^%s = "([^"]+)"' % name, self._source(relpath), re.M)
            self.assertIsNotNone(m, "%s not found in %s" % (name, relpath))
            self.assertTrue(m.group(1).startswith("/var/lib/securepi"),
                            "%s.%s = %s is not in a data directory" % (relpath, name, m.group(1)))

    def test_setup_script_never_makes_a_code_directory_group_writable(self):
        src = self._source("gateway/setup-privilege-separation.sh")
        for line in src.splitlines():
            if line.strip().startswith("#"):
                continue
            self.assertNotRegex(line, r"chmod\s+\d*7[57]\s+/opt/securepi",
                                "code directory made group-writable: %s" % line.strip())

    def test_setup_script_makes_the_code_directories_root_owned(self):
        src = self._source("gateway/setup-privilege-separation.sh")
        # Recursively since Audit10Oct M19: every file inside, not just
        # the directory itself.
        self.assertIn('sudo chown -R root:root "$d"', src)
        self.assertIn('sudo chmod -R go-w "$d"', src)
        self.assertIn('for d in /opt/securepi /opt/securepi-dpi; do', src)


if __name__ == "__main__":
    unittest.main()

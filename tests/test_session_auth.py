#!/usr/bin/env python3
"""
SecurePi Gateway - session authentication tests (ENHANCEMENT-PLAN.md
step 3.1).

Exercises app/session_auth.py directly against a real temp SQLite
database (tests/fixtures.py's temp_db()), the same pattern
test_suppression.py/test_registry.py already use - not through FastAPI's
TestClient, which needs the `httpx` package this project's Mac
environment doesn't have installed. Timeouts are tested by writing an
already-expired timestamp straight into the table, the same way
test_suppression.py's expires_at=time.time()-10 tests an already-expired
suppression rule, rather than sleeping in a test.

Run via `make test`, or directly: python3 -m unittest tests.test_session_auth -v
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

import session_auth  # noqa: E402


class PasswordHashingTests(unittest.TestCase):
    def test_a_hashed_password_verifies_against_the_same_password(self):
        stored = session_auth.hash_password("correct horse battery staple")
        self.assertTrue(session_auth.verify_password("correct horse battery staple", stored))

    def test_a_hashed_password_does_not_verify_against_a_different_one(self):
        stored = session_auth.hash_password("correct horse battery staple")
        self.assertFalse(session_auth.verify_password("wrong password", stored))

    def test_two_hashes_of_the_same_password_are_not_identical(self):
        # A fresh random salt each time (os.urandom) - proves the salt is
        # actually being used, not silently constant.
        a = session_auth.hash_password("same password")
        b = session_auth.hash_password("same password")
        self.assertNotEqual(a, b)

    def test_a_legacy_plaintext_password_still_verifies(self):
        # Every gateway deployed before this step stores a bare plaintext
        # password. Refusing it would lock out every existing install.
        self.assertTrue(session_auth.verify_password("old-basic-auth-password", "old-basic-auth-password"))

    def test_a_legacy_plaintext_password_needs_rehash(self):
        self.assertTrue(session_auth.needs_rehash("old-basic-auth-password"))

    def test_a_freshly_hashed_password_does_not_need_rehash(self):
        stored = session_auth.hash_password("correct horse battery staple")
        self.assertFalse(session_auth.needs_rehash(stored))

    def test_a_hash_with_outdated_cost_parameters_needs_rehash(self):
        stored = "pbkdf2_sha256$1000$%s$%s" % ("aa" * 16, "bb" * 32)
        self.assertTrue(session_auth.needs_rehash(stored))

    def test_a_malformed_hash_string_fails_closed(self):
        self.assertFalse(session_auth.verify_password("anything", "pbkdf2_sha256$not-enough-fields"))

    def test_an_empty_stored_password_never_matches(self):
        # Audit C2: an emptied password file used to accept an empty login.
        self.assertFalse(session_auth.verify_password("", ""))
        self.assertFalse(session_auth.verify_password("anything", ""))

    def test_an_empty_submitted_password_never_matches(self):
        stored = session_auth.hash_password("correct horse battery staple")
        self.assertFalse(session_auth.verify_password("", stored))

    def test_a_non_numeric_iteration_count_fails_closed(self):
        self.assertFalse(session_auth.verify_password("x", "pbkdf2_sha256$abc$%s$%s" % ("aa" * 16, "bb" * 32)))

    def test_a_zero_iteration_count_fails_closed(self):
        self.assertFalse(session_auth.verify_password("x", "pbkdf2_sha256$0$%s$%s" % ("aa" * 16, "bb" * 32)))

    def test_a_non_ascii_legacy_password_verifies_instead_of_crashing(self):
        self.assertTrue(session_auth.verify_password("café-password", "café-password"))


class PasswordFileTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._dir.name, "console-password")
        with open(self.path, "w") as fh:
            fh.write("old-value")

    def tearDown(self):
        self._dir.cleanup()

    def test_write_replaces_the_contents(self):
        session_auth.write_password_file(self.path, "pbkdf2_sha256$1$aa$bb")
        with open(self.path) as fh:
            self.assertEqual(fh.read(), "pbkdf2_sha256$1$aa$bb")

    def test_write_leaves_no_temporary_files_behind(self):
        session_auth.write_password_file(self.path, "pbkdf2_sha256$1$aa$bb")
        self.assertEqual(os.listdir(self._dir.name), ["console-password"])

    def test_write_keeps_group_read_write_permissions(self):
        session_auth.write_password_file(self.path, "pbkdf2_sha256$1$aa$bb")
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o660)

    def test_an_empty_value_is_refused_and_the_old_file_kept(self):
        with self.assertRaises(ValueError):
            session_auth.write_password_file(self.path, "")
        with open(self.path) as fh:
            self.assertEqual(fh.read(), "old-value")


class SessionLifecycleTests(unittest.TestCase):
    def test_a_fresh_session_is_valid(self):
        conn = fixtures.temp_db()
        token = session_auth.create_session(conn, "securepi")
        row = session_auth.get_session(conn, token)
        self.assertIsNotNone(row)
        self.assertEqual(row["username"], "securepi")

    def test_an_unknown_token_is_not_a_session(self):
        conn = fixtures.temp_db()
        self.assertIsNone(session_auth.get_session(conn, "not-a-real-token"))

    def test_an_empty_token_is_not_a_session(self):
        conn = fixtures.temp_db()
        self.assertIsNone(session_auth.get_session(conn, ""))
        self.assertIsNone(session_auth.get_session(conn, None))

    def test_an_idle_timed_out_session_is_rejected_and_removed(self):
        conn = fixtures.temp_db()
        token = session_auth.create_session(conn, "securepi")
        # Idle timeout defaults to 1800s - back-date last_active well past it.
        conn.execute("UPDATE sessions SET last_active = ? WHERE token = ?",
                     (time.time() - 3600, token))
        conn.commit()
        self.assertIsNone(session_auth.get_session(conn, token))
        remaining = conn.execute("SELECT count(*) FROM sessions WHERE token = ?", (token,)).fetchone()[0]
        self.assertEqual(remaining, 0)

    def test_an_absolute_timed_out_session_is_rejected_even_if_recently_active(self):
        conn = fixtures.temp_db()
        token = session_auth.create_session(conn, "securepi")
        conn.execute("UPDATE sessions SET expires_at = ?, last_active = ? WHERE token = ?",
                     (time.time() - 1, time.time(), token))
        conn.commit()
        self.assertIsNone(session_auth.get_session(conn, token))

    def test_touch_session_refreshes_last_active(self):
        conn = fixtures.temp_db()
        token = session_auth.create_session(conn, "securepi")
        conn.execute("UPDATE sessions SET last_active = ? WHERE token = ?", (time.time() - 1000, token))
        conn.commit()
        session_auth.touch_session(conn, token)
        row = conn.execute("SELECT last_active FROM sessions WHERE token = ?", (token,)).fetchone()
        self.assertGreater(row["last_active"], time.time() - 5)

    def test_delete_session_removes_it(self):
        conn = fixtures.temp_db()
        token = session_auth.create_session(conn, "securepi")
        session_auth.delete_session(conn, token)
        self.assertIsNone(session_auth.get_session(conn, token))

    def test_delete_other_sessions_keeps_only_the_callers_session(self):
        conn = fixtures.temp_db()
        mine = session_auth.create_session(conn, "securepi")
        other = session_auth.create_session(conn, "securepi")
        session_auth.delete_other_sessions(conn, mine)
        self.assertIsNotNone(session_auth.get_session(conn, mine))
        self.assertIsNone(session_auth.get_session(conn, other))

    def test_cleanup_expired_removes_stale_sessions_but_keeps_valid_ones(self):
        conn = fixtures.temp_db()
        stale = session_auth.create_session(conn, "securepi")
        fresh = session_auth.create_session(conn, "securepi")
        conn.execute("UPDATE sessions SET last_active = ? WHERE token = ?", (time.time() - 3600, stale))
        conn.commit()
        session_auth.cleanup_expired(conn)
        remaining = {r["token"] for r in conn.execute("SELECT token FROM sessions")}
        self.assertNotIn(stale, remaining)
        self.assertIn(fresh, remaining)


class RateLimitTests(unittest.TestCase):
    def test_a_clean_address_may_attempt_login(self):
        conn = fixtures.temp_db()
        self.assertTrue(session_auth.check_rate_limit(conn, "10.10.0.50"))

    def test_repeated_failures_are_eventually_rate_limited(self):
        conn = fixtures.temp_db()
        ip = "10.10.0.50"
        for _ in range(10):  # login_rate_limit_max_attempts default
            self.assertTrue(session_auth.check_rate_limit(conn, ip))
            session_auth.record_failed_attempt(conn, ip)
        self.assertFalse(session_auth.check_rate_limit(conn, ip))

    def test_the_limit_is_scoped_per_address(self):
        conn = fixtures.temp_db()
        for _ in range(10):
            session_auth.record_failed_attempt(conn, "10.10.0.50")
        self.assertFalse(session_auth.check_rate_limit(conn, "10.10.0.50"))
        self.assertTrue(session_auth.check_rate_limit(conn, "10.10.0.99"))

    def test_a_successful_login_clears_the_counter(self):
        conn = fixtures.temp_db()
        ip = "10.10.0.50"
        for _ in range(10):
            session_auth.record_failed_attempt(conn, ip)
        self.assertFalse(session_auth.check_rate_limit(conn, ip))
        session_auth.clear_attempts(conn, ip)
        self.assertTrue(session_auth.check_rate_limit(conn, ip))

    def test_failures_outside_the_window_do_not_count(self):
        conn = fixtures.temp_db()
        ip = "10.10.0.50"
        old = time.time() - 3600  # window default is 900s
        for _ in range(10):
            conn.execute("INSERT INTO login_attempts (ip, ts) VALUES (?, ?)", (ip, old))
        conn.commit()
        self.assertTrue(session_auth.check_rate_limit(conn, ip))


class LoginAdmissionTests(unittest.TestCase):
    """Audit10Oct H5: attempts were only counted after the (slow) password
    check finished, so a burst of concurrent logins all passed the limit
    check before any of them was recorded. reserve_login_attempt() checks
    and records in one step, before the password is checked."""

    def test_a_burst_cannot_pass_the_limit_before_anything_is_recorded(self):
        conn = fixtures.temp_db()
        ip = "10.10.0.50"
        admitted = [session_auth.reserve_login_attempt(conn, ip) for _ in range(25)]
        self.assertEqual(admitted.count(True), 10)   # login_rate_limit_max_attempts default
        self.assertFalse(admitted[-1])

    def test_a_successful_login_still_clears_the_counter(self):
        conn = fixtures.temp_db()
        ip = "10.10.0.50"
        for _ in range(10):
            session_auth.reserve_login_attempt(conn, ip)
        self.assertFalse(session_auth.reserve_login_attempt(conn, ip))
        session_auth.clear_attempts(conn, ip)
        self.assertTrue(session_auth.reserve_login_attempt(conn, ip))

    def test_a_large_declared_body_is_refused(self):
        self.assertTrue(session_auth.content_length_too_large(str(5 * 1024 * 1024)))
        self.assertTrue(session_auth.content_length_too_large(str(session_auth.LOGIN_BODY_MAX_BYTES + 1)))
        self.assertFalse(session_auth.content_length_too_large("120"))
        self.assertFalse(session_auth.content_length_too_large(None))      # chunked: capped while reading
        self.assertFalse(session_auth.content_length_too_large("nonsense"))


class PasswordRaceTests(unittest.TestCase):
    """Audit10Oct H6: a login that read the old password, then lost the
    race to a password change, could still be issued a session - and a
    legacy rehash could write the OLD password back over the new one."""

    def setUp(self):
        import tempfile
        self._dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._dir.name, "console-password")
        with open(self.path, "w") as fh:
            fh.write("old-hash")

    def tearDown(self):
        self._dir.cleanup()

    def test_the_file_is_recognised_as_unchanged(self):
        self.assertTrue(session_auth.password_file_unchanged(self.path, "old-hash"))

    def test_a_change_during_the_check_is_noticed(self):
        session_auth.replace_password(self.path, "new-hash")
        self.assertFalse(session_auth.password_file_unchanged(self.path, "old-hash"))

    def test_a_missing_file_never_counts_as_unchanged(self):
        os.remove(self.path)
        self.assertFalse(session_auth.password_file_unchanged(self.path, "old-hash"))

    def test_a_rehash_never_overwrites_a_newer_password(self):
        session_auth.replace_password(self.path, "new-hash")
        self.assertFalse(session_auth.rehash_if_unchanged(self.path, "old-hash", "rehash-of-old"))
        with open(self.path) as fh:
            self.assertEqual(fh.read(), "new-hash")

    def test_a_rehash_still_happens_when_nothing_changed(self):
        self.assertTrue(session_auth.rehash_if_unchanged(self.path, "old-hash", "rehashed"))
        with open(self.path) as fh:
            self.assertEqual(fh.read(), "rehashed")


class LoginWiringTests(unittest.TestCase):
    """Structural, like test_security_headers.py: FastAPI isn't installed
    on the Mac, so /login's handler is read as text."""

    def setUp(self):
        import re
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "app", "webapp.py")) as fh:
            src = fh.read()
        m = re.search(r"async def do_login\(request: Request\):\n(.*?)\n\n\n", src, re.DOTALL)
        self.assertIsNotNone(m, "do_login not found")
        self.body = m.group(1)
        m = re.search(r"def api_settings_password\(.*?\n(.*?)\n\n\n", src, re.DOTALL)
        self.assertIsNotNone(m, "api_settings_password not found")
        self.change = m.group(1)

    def test_the_attempt_is_reserved_before_the_password_check(self):
        reserve = self.body.index("session_auth.reserve_login_attempt(")
        verify = self.body.index("session_auth.verify_password")
        self.assertLess(reserve, verify)
        self.assertNotIn("record_failed_attempt", self.body)

    def test_the_body_is_read_with_a_cap(self):
        self.assertNotIn("await request.body()", self.body)
        self.assertIn("_read_body_capped(", self.body)
        self.assertIn("content_length_too_large(", self.body)

    def test_the_password_file_is_re_read_before_a_session_is_issued(self):
        unchanged = self.body.index("session_auth.password_file_unchanged(")
        create = self.body.index("session_auth.create_session(")
        self.assertLess(unchanged, create)
        self.assertIn("session_auth.rehash_if_unchanged(", self.body)
        self.assertNotIn("write_password_file", self.body)

    def test_a_password_change_goes_through_the_same_lock(self):
        self.assertIn("session_auth.replace_password(", self.change)


class OriginCheckTests(unittest.TestCase):
    def test_a_missing_origin_header_is_allowed(self):
        self.assertTrue(session_auth.origin_is_allowed(None, "10.10.0.1:8000"))

    def test_a_null_origin_is_allowed(self):
        # Real Safari behavior, not hypothetical: it sends this exact
        # literal string on a same-origin form POST when the page also
        # has Referrer-Policy: no-referrer.
        self.assertTrue(session_auth.origin_is_allowed("null", "10.10.0.1:8000"))

    def test_a_matching_origin_is_allowed(self):
        self.assertTrue(session_auth.origin_is_allowed("http://10.10.0.1:8000", "10.10.0.1:8000"))

    def test_a_cross_origin_request_is_rejected(self):
        self.assertFalse(session_auth.origin_is_allowed("http://attacker.example", "10.10.0.1:8000"))

    def test_a_different_port_on_the_same_host_is_rejected(self):
        # The Origin header includes the port; a different port is a
        # different origin even though the hostname matches.
        self.assertFalse(session_auth.origin_is_allowed("http://10.10.0.1:9999", "10.10.0.1:8000"))


if __name__ == "__main__":
    unittest.main()

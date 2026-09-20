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

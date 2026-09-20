#!/usr/bin/env python3
"""
SecurePi Gateway - session authentication (ENHANCEMENT-PLAN.md step 3.1).

Through Stage 2 the console used plain HTTP Basic Auth: a single shared
password, sent by the browser on literally every request (including every
static asset), checked with a plaintext comparison against a file. This
module replaces all of that with what F§11.1 actually asked for:

- The password on disk is now hashed, never plaintext. A password file
  left over from before this step (still plaintext) is still accepted
  once, then transparently rehashed on that same successful login - see
  verify_password()/needs_rehash() below - so deploying this step never
  locks anyone out.
- A random per-login session token replaces resending the password, kept
  in an HttpOnly, SameSite=Strict cookie the browser cannot expose to
  JavaScript and will not attach to any cross-site request at all.
- Sessions live in the database, not a process-memory dict - the same
  reasoning audit_log/device_hourly/settings are tables and not globals
  (ENHANCEMENT-PLAN.md step 1.2's "central config" precedent): a
  `securepi-web` restart (part of every `make deploy`) would otherwise
  silently sign everyone out, and the console is a single process, so
  there's no multi-worker consistency problem a database avoids either.
- A login-attempt rate limit and an Origin check on state-changing
  requests are implemented here as small, independently testable
  functions; app/webapp.py wires them into its one auth middleware.

Kept as its own module - the same "business logic lives outside
webapp.py, which just wires it to routes" shape audit.py/settings.py/
suppression.py already use - specifically so it can be unit-tested
directly against a temp database (tests/test_session_auth.py) without
needing FastAPI's TestClient, which needs the `httpx` package this
project's Mac environment doesn't have installed.
"""

import hashlib
import hmac
import os
import secrets
import time

import settings

SESSION_COOKIE = "sp_session"
CONSOLE_USERNAME = "securepi"

# ENHANCEMENT-PLAN.md step 3.1 originally called for a scrypt hash.
# Checked live before writing this: the Mac's own Python (/usr/bin/
# python3, Apple's system build, linked against LibreSSL 2.8.3, not
# OpenSSL 1.1+) has no hashlib.scrypt at all - AttributeError, caught by
# this step's own test run rather than assumed. The `cryptography`
# package (whose Scrypt KDF doesn't depend on hashlib) isn't installed
# on the Mac either. Since "tests pass on the Mac" is this project's own
# stated definition of done, and the Mac is the one place every step
# must actually run, PBKDF2-HMAC-SHA256 is used instead - built into
# hashlib.pbkdf2_hmac on every Python, LibreSSL or OpenSSL alike, and
# still one of OWASP's currently recommended password-hashing choices
# when scrypt/bcrypt/argon2 aren't available. PBKDF2_ITERATIONS below is
# OWASP's 2023 recommendation for PBKDF2-HMAC-SHA256 specifically -
# measured at ~0.18s per hash on this Mac, comfortably fast enough for
# an interactive login.
PBKDF2_ITERATIONS = 600_000
PBKDF2_KEYLEN = 32


def hash_password(password):
    """A self-describing 'pbkdf2_sha256$iterations$salt_hex$hash_hex'
    string, so a future change to PBKDF2_ITERATIONS doesn't break
    checking a password hashed under the old count (needs_rehash()
    catches that case and upgrades it on the next successful login)."""
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS, dklen=PBKDF2_KEYLEN)
    return "pbkdf2_sha256$%d$%s$%s" % (PBKDF2_ITERATIONS, salt.hex(), digest.hex())


def verify_password(password, stored):
    """True if `password` matches `stored`. `stored` may still be a bare
    plaintext password left over from Basic Auth, from before this step
    existed - this project has run with that file since Day 1, and a
    console that refuses the current, correct password until someone
    manually re-hashes it by hand offline would be a worse outcome than
    this one conditional. The caller (app/webapp.py's /login) rehashes
    right after a successful plaintext match, so this branch is only
    ever exercised once per deployment."""
    if not stored.startswith("pbkdf2_sha256$"):
        return hmac.compare_digest(password, stored)
    try:
        _, iterations, salt_hex, hash_hex = stored.split("$")
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except ValueError:
        return False
    computed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations), dklen=len(expected))
    return hmac.compare_digest(computed, expected)


def needs_rehash(stored):
    """True for a legacy plaintext password, or a hash made with fewer
    iterations than this module's current PBKDF2_ITERATIONS."""
    if not stored.startswith("pbkdf2_sha256$"):
        return True
    return int(stored.split("$")[1]) != PBKDF2_ITERATIONS


# ------------------------------------------------------------- sessions --

def create_session(conn, username):
    """A new random session token, recorded server-side, to put in the
    cookie. The cookie itself carries no information - a stolen cookie
    file is useless once the row here is deleted (logout, or the
    idle/absolute timeout expiring it)."""
    token = secrets.token_urlsafe(32)
    now = time.time()
    absolute_timeout = settings.get(conn, "session_absolute_timeout_seconds")
    conn.execute(
        "INSERT INTO sessions (token, username, created_at, last_active, expires_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (token, username, now, now, now + absolute_timeout),
    )
    conn.commit()
    return token


def get_session(conn, token):
    """The session row for `token`, if it's still valid (not past its
    absolute expiry, not idle-timed-out), else None. Deletes and returns
    None for an expired row rather than leaving it to a caller to
    notice. Does NOT refresh last_active itself - call touch_session()
    once the caller has decided this request counts as real
    authenticated activity, not just a probe with a stale cookie."""
    if not token:
        return None
    row = conn.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()
    if row is None:
        return None
    now = time.time()
    idle_timeout = settings.get(conn, "session_idle_timeout_seconds")
    if now > row["expires_at"] or now - row["last_active"] > idle_timeout:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        return None
    return row


def touch_session(conn, token):
    """Refresh the idle-timeout clock. Called once per authenticated
    request, after get_session() has already confirmed the session is
    still valid."""
    conn.execute("UPDATE sessions SET last_active = ? WHERE token = ?", (time.time(), token))
    conn.commit()


def delete_session(conn, token):
    """Sign out: remove the session row so the cookie (wherever it still
    sits in a browser) can never be used again."""
    conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()


def cleanup_expired(conn):
    """Sweep every session past its absolute expiry or idle timeout. This
    console has no background scheduler of its own (unlike
    app/engine.py's correlation cycle), so this is called once per login
    attempt instead of on a timer - a stray expired row costs nothing
    but a few bytes until the next login sweeps it."""
    now = time.time()
    idle_timeout = settings.get(conn, "session_idle_timeout_seconds")
    conn.execute("DELETE FROM sessions WHERE expires_at < ? OR last_active < ?",
                 (now, now - idle_timeout))
    conn.commit()


# --------------------------------------------------------- rate limiting --

def check_rate_limit(conn, ip):
    """True if `ip` may attempt another login right now. Counts only
    FAILED attempts in the trailing window (see record_failed_attempt/
    clear_attempts) - a legitimate user who fumbles their password a
    couple of times is never penalised, only a sustained guessing
    pattern from one address."""
    window = settings.get(conn, "login_rate_limit_window_seconds")
    max_attempts = settings.get(conn, "login_rate_limit_max_attempts")
    cutoff = time.time() - window
    count = conn.execute(
        "SELECT count(*) FROM login_attempts WHERE ip = ? AND ts > ?", (ip, cutoff)
    ).fetchone()[0]
    return count < max_attempts


def record_failed_attempt(conn, ip):
    conn.execute("INSERT INTO login_attempts (ip, ts) VALUES (?, ?)", (ip, time.time()))
    conn.commit()


def clear_attempts(conn, ip):
    """Called on a successful login. Without this, a legitimate user who
    mistyped their password a few times would sit needlessly close to
    the limit even though they just proved who they are."""
    conn.execute("DELETE FROM login_attempts WHERE ip = ?", (ip,))
    conn.commit()


# ------------------------------------------------------------ CSRF/Origin --

def origin_is_allowed(origin_header, host_header):
    """True if a state-changing request may proceed. Rejects a request
    that carries an Origin header naming a different host than the one
    it was addressed to (ENHANCEMENT-PLAN.md step 3.1's "Cross-origin
    POST rejected" exit criterion) - the shape of request a page on
    another site would send if it tried to submit to this console using
    a victim's browser.

    Absence of the header is allowed through deliberately, not because
    it's assumed safe on its own, but because the session cookie's own
    SameSite=Strict attribute already closes that gap more broadly: a
    Strict cookie is never attached to a cross-site request AT ALL,
    Origin header or not, so an attacker page can't reach an
    authenticated endpoint in the first place regardless of what this
    function decides. This check is defense in depth for browsers or
    proxies that might not honour SameSite, not the only thing standing
    between a cross-site page and this console."""
    if not origin_header:
        return True
    origin_host = origin_header.split("://", 1)[-1].rstrip("/")
    return origin_host == host_header

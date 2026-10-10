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
import tempfile
import threading
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
    ever exercised once per deployment.

    An empty password, or an empty stored value, is ALWAYS a mismatch.
    Without this guard the plaintext branch compared "" with "" and said
    yes - so a password file that was empty (truncated mid-write, or
    created empty by hand) let anyone in with a blank password. Failing
    closed here means a damaged password file locks the console instead
    of opening it."""
    if not password or not stored:
        return False
    if not stored.startswith("pbkdf2_sha256$"):
        # Compared as bytes: hmac.compare_digest() refuses two str values
        # containing non-ASCII characters (TypeError), which would turn a
        # password like "café" into a server error instead of a login.
        return hmac.compare_digest(password.encode(), stored.encode())
    try:
        _, iterations, salt_hex, hash_hex = stored.split("$")
        iterations = int(iterations)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except ValueError:
        return False
    # A malformed hash (zero/negative/absurd iteration count, empty hash)
    # is treated as "no valid password stored", not computed.
    if iterations < 1 or iterations > 10 * PBKDF2_ITERATIONS or not expected:
        return False
    computed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=len(expected))
    return hmac.compare_digest(computed, expected)


def write_password_file(path, encoded):
    """Replace the password file at `path` with `encoded` (an already
    computed hash_password() string) in one atomic step.

    The old code did open(path, "w") and THEN hashed the password: "w"
    empties the file immediately, and hashing takes a fraction of a
    second, so for that whole time the file was empty - and a login
    arriving in that window read an empty password. This version writes
    the new hash to a temporary file next to the real one, flushes it to
    disk, and only then renames it over the old file. A rename within
    one directory is atomic on Linux: any reader sees either the whole
    old file or the whole new one, never an empty or half-written one,
    even if the process crashes part-way through.

    Needs write access to the DIRECTORY (to create the temporary file),
    not just the file - gateway/setup-privilege-separation.sh makes
    /etc/securepi group-writable for exactly this reason."""
    if not encoded:
        raise ValueError("refusing to write an empty password")
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".console-password.", dir=directory)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(encoded)
            fh.flush()
            os.fsync(fh.fileno())
        # mkstemp creates the file readable by its owner only; keep the
        # same owner+group read/write the setup script gives the original.
        os.chmod(tmp_path, 0o660)
        os.replace(tmp_path, path)
    except BaseException:
        # Never leave a stray temporary file behind on failure.
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


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


def delete_other_sessions(conn, keep_token):
    """Sign out every session except `keep_token` (the one making the
    request). Called after a password change: if the password was
    changed because someone else learned it, their already-open session
    must stop working too - otherwise changing the password would keep
    them out only until their session expired on its own."""
    conn.execute("DELETE FROM sessions WHERE token != ?", (keep_token or "",))
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


# ------------------------------------------- password file, under a lock --
# Audit10Oct H6: a login reads the password file, then spends a fraction of
# a second checking the password. If the password is changed in that time,
# the login must not go on to issue a session for the OLD password, and a
# legacy rehash must not write the old password back over the new one.
# Both writers (a password change, a rehash) take this lock, and a login
# re-reads the file before it issues a session.
_password_file_lock = threading.Lock()


def password_file_unchanged(path, expected):
    """True if the password file still holds exactly `expected` (what a
    login read before checking the password). A missing or unreadable file
    is never "unchanged"."""
    try:
        with open(path) as f:
            return f.read().strip() == expected
    except OSError:
        return False


def replace_password(path, encoded):
    """A password change: write_password_file() under the lock."""
    with _password_file_lock:
        write_password_file(path, encoded)


def rehash_if_unchanged(path, expected_old, encoded):
    """A login's rehash of a legacy or outdated hash. Writes `encoded` only
    if the file still holds `expected_old`; returns whether it wrote."""
    with _password_file_lock:
        if not password_file_unchanged(path, expected_old):
            return False
        write_password_file(path, encoded)
        return True


# --------------------------------------------------------- rate limiting --

# The login form has two short fields. Anything bigger than this is not a
# login (Audit10Oct H5: the body used to be read whole, however large).
LOGIN_BODY_MAX_BYTES = 4096


def content_length_too_large(header_value, limit=LOGIN_BODY_MAX_BYTES):
    """True if a Content-Length header declares more than `limit` bytes.
    No header (a chunked body) or a garbled one returns False - the body
    is still capped while it is read."""
    try:
        return int(header_value) > limit
    except (TypeError, ValueError):
        return False


def reserve_login_attempt(conn, ip):
    """Check the limit and count this attempt in one step, BEFORE the
    password is checked. Returns False if `ip` is over the limit.

    Attempts used to be counted only after a failed check. The check is
    slow (PBKDF2) and runs on a worker thread, so a burst of concurrent
    logins all passed check_rate_limit() before the first failure was
    recorded (Audit10Oct H5). The console's login handler calls this with
    no `await` between the check and the insert, so on its single event
    loop nothing else can slip in between. A successful login clears the
    count (clear_attempts), as before."""
    if not check_rate_limit(conn, ip):
        return False
    record_failed_attempt(conn, ip)
    return True


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
    between a cross-site page and this console.

    A literal "null" Origin is treated the same as no header at all,
    for the same reason - found live, not guessed: Safari sends
    `Origin: null` on an ordinary same-origin form POST when the page
    also carries a `Referrer-Policy: no-referrer` header (step 3.4's
    own hardening addition), a real WebKit interoperability quirk, not
    a sign of a cross-site request. A genuine sandboxed/cross-site
    request that produces `Origin: null` is still fully stopped by
    SameSite=Strict never attaching the cookie in the first place, so
    accepting "null" here loses no real protection."""
    if not origin_header or origin_header == "null":
        return True
    origin_host = origin_header.split("://", 1)[-1].rstrip("/")
    return origin_host == host_header

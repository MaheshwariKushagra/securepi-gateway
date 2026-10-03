#!/usr/bin/env python3
"""
SecurePi Gateway - Tier 2 privacy-scope canary.

Turns the report's own §6 lesson - the `ignore_conn`/`ignore_connection`
typo that would have silently decrypted every connection instead of only
YouTube's - into an automated, ongoing control rather than something only
caught by a careful code review. See ENHANCEMENT-PLAN.md step 5.7.

Every CHECK_INTERVAL_S, this asks the addon file actually on disk at
ADDON_PATH - the same file mitmproxy loads - what it would decide for two
hostnames: one that must stay passed-through (not on DECRYPT_SUFFIXES) and
one that must be decrypted (on it). If either comes back wrong, Tier 2
fails safe: every enrolled device is unenrolled at once, and a high-
severity incident is raised.

Scope reduction from the plan, and why
-----------------------------------------
The plan describes "a canary client in a test namespace... through the
real redirect" - i.e. exercising the actual nftables PREROUTING rule and
a live TLS handshake against mitmproxy, not just calling a function.
Investigating this live (via `ip netns exec ns_victim ...` and a direct
`openssl s_client` probe against 127.0.0.1:8080) found that isn't safely
buildable in this pass:

1. gateway/setup-test-harness.sh's ns_victim sits on `br-test`, which
   evaluate.py's own comments already establish has no path to the DNS filter or
   the internet - it is NOT bridged onto `ap0`, the interface the
   dpi-redirect rule matches on (`iifname "ap0" ip saddr @enrolled tcp
   dport 443 ...`). Traffic from ns_victim never reaches that rule at
   all, so it cannot exercise it.
2. Connecting directly to 127.0.0.1:8080 (mitmproxy's redirect target)
   without a genuine nftables REDIRECT was tried live and confirmed to
   fail outright for BOTH an allowlisted and a non-allowlisted SNI -
   mitmproxy's transparent mode relies on the kernel's original-
   destination info that only a real REDIRECT'd connection carries, so
   this path can't distinguish the two cases at all.
3. Actually wiring a synthetic client onto the real `ap0` ingress path
   would mean network-topology surgery on the interface a live AP and two
   real phones depend on - not something to improvise mid-session. Using
   one of the two REAL enrolled devices as an unwitting automated canary
   target every 15 minutes was also rejected: it would mean silently
   inspecting real traffic on a schedule the device's owner never chose,
   which runs against this project's own opt-in, privacy-by-design
   stance.

What this DOES still test, and why it's a meaningful substitute rather
than a downgrade to "the addon's log": it imports and calls
`tls_clienthello()` - the actual deployed decision method, freshly loaded
from disk every cycle - directly, and inspects the `ignore_connection`
attribute it sets. This is precisely the code path (and precisely the
attribute) the report's own `ignore_conn` typo broke; a regression of
that exact shape is caught here just as reliably as it would be by a
network-level test, without needing a live TLS handshake to prove it.
What it can NOT catch, and this is a real, honestly-scoped gap: a bug in
the nftables redirect rule itself, or in how mitmproxy's transparent mode
reads the original destination - those sit entirely outside this check.
That gap is why 5.7's own plan note still lists "verify against the real
redirect path" as unfinished, not resolved by this substitute.

Run on the gateway as root (matches securepi-dpi's own privilege level,
since flush() below calls `nft` directly):
    sudo python3 privacy_canary.py
"""

import importlib.util
import sys
import time

sys.path.insert(0, "/opt/securepi")
import correlation  # noqa: E402  (path must be set up first)
import dbconn       # noqa: E402
import dpi_enroll    # noqa: E402

DB_PATH = "/var/lib/securepi/securepi.db"
ADDON_PATH = "/opt/securepi-dpi/securepi_adfilter.py"
CHECK_INTERVAL_S = 15 * 60

SIGNAL_TYPE = "privacy_scope"                    # signal_state row the console reads for freshness
INCIDENT_SIGNAL_TYPE = "privacy_scope_failure"    # incidents row the console reads for pass/fail

NON_ALLOWLISTED_HOST = "example.com"   # must stay passed-through, undecrypted
ALLOWLISTED_HOST = "youtube.com"       # must be decrypted (see DECRYPT_SUFFIXES)


class _FakeClientHello:
    def __init__(self, sni):
        self.sni = sni


class _FakeClient:
    # An RFC 5737 documentation-range address: obviously synthetic, and
    # guaranteed to never collide with a real device on this network.
    # This never touches the actual network - it only labels the fake
    # data object passed straight into the addon's own Python method.
    peername = ("203.0.113.1", 55555)


class _FakeContext:
    client = _FakeClient()


class _FakeTlsData:
    """Just enough of mitmproxy's real TlsClienthelloHookData shape for
    SecurePiAdFilter.tls_clienthello() to run unmodified: it reads
    client_hello.sni and context.client.peername, and sets
    ignore_connection itself (deliberately not pre-set here, so its
    absence after the call is the same "will decrypt" signal the real
    code relies on)."""
    def __init__(self, sni):
        self.client_hello = _FakeClientHello(sni)
        self.context = _FakeContext()


def _load_addon_fresh():
    """Import the addon file currently on disk as a brand new module every
    check - the same file mitmproxy loads, not a cached copy from an
    earlier cycle - so a fix (or a reintroduced bug) is picked up on the
    very next run."""
    spec = importlib.util.spec_from_file_location("securepi_adfilter_canary", ADDON_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Never let these synthetic checks land in the real Tier 2 telemetry
    # the analytics pages read (step 5.3) - _log_event writes to whatever
    # this module-level path says.
    module.DPI_EVENTS_PATH = "/dev/null"
    return module


def will_decrypt(sni):
    """True if the addon's real tls_clienthello() would decrypt this SNI;
    False if it would pass it through untouched."""
    module = _load_addon_fresh()
    addon = module.SecurePiAdFilter()
    data = _FakeTlsData(sni)
    addon.tls_clienthello(data)
    return not getattr(data, "ignore_connection", False)


def db():
    # The same open path as the gateway's own services (long busy timeout,
    # WAL size cap) - see app/dbconn.py. DB_PATH stays defined here because
    # tests/test_privilege_separation.py checks every service's path.
    return dbconn.connect(DB_PATH)


def _raise_or_touch_incident(conn, description):
    """A sustained failure should read as ONE ongoing incident, not a new
    one every CHECK_INTERVAL_S forever - but correlation.raise_incident's
    own dedup window (600s) is shorter than this canary's 15-minute
    cycle, so calling it directly would create a fresh incident every
    single failed check. This instead touches any still-open incident of
    this signal type regardless of how long ago it was last seen."""
    now = time.time()
    existing = conn.execute(
        "SELECT id FROM incidents WHERE signal_type=? AND status='new'"
        " ORDER BY last_seen DESC LIMIT 1", (INCIDENT_SIGNAL_TYPE,)).fetchone()
    if existing:
        conn.execute(
            "UPDATE incidents SET last_seen=?, updated_at=?, description=? WHERE id=?",
            (now, now, description, existing["id"]))
    else:
        correlation.raise_incident(conn, None, INCIDENT_SIGNAL_TYPE, "high",
                                    "Tier 2 privacy-scope check failed", description,
                                    now, now, [])


def run_check():
    """One pass. Returns True if privacy scope is intact."""
    try:
        stays_encrypted = not will_decrypt(NON_ALLOWLISTED_HOST)
        gets_decrypted = will_decrypt(ALLOWLISTED_HOST)
        failure_detail = None
        if not stays_encrypted:
            failure_detail = ("%s was NOT left passed-through - the addon would decrypt a "
                               "non-allowlisted host, which is exactly the class of bug this "
                               "check exists to catch (see report §6)" % NON_ALLOWLISTED_HOST)
        elif not gets_decrypted:
            failure_detail = ("%s was NOT decrypted - the addon would pass through an "
                               "allowlisted host untouched, so ad removal is not working"
                               % ALLOWLISTED_HOST)
    except Exception as exc:
        # The check itself breaking is ALSO grounds to fail safe - an
        # addon file that can't even be imported is not one to trust.
        failure_detail = "the canary itself could not run: %s" % exc

    ok = failure_detail is None
    conn = db()
    correlation.set_window_start(conn, SIGNAL_TYPE, time.time())

    if not ok:
        try:
            dpi_enroll.flush()
            flushed_note = "Every enrolled device has been unenrolled (Tier 2 is now off for everyone)."
        except dpi_enroll.DpiEnrollError as exc:
            flushed_note = "The fail-safe flush ALSO failed (%s) - check the enrolled set manually." % exc
        _raise_or_touch_incident(conn, "%s. %s" % (failure_detail, flushed_note))
        print("securepi-privacy-canary: FAIL - %s" % failure_detail, flush=True)
    else:
        print("securepi-privacy-canary: ok - passthrough and decrypt decisions both correct", flush=True)

    conn.commit()
    conn.close()
    return ok


def main():
    print("securepi-privacy-canary: starting, checking every %ds" % CHECK_INTERVAL_S, flush=True)
    while True:
        run_check()
        time.sleep(CHECK_INTERVAL_S)


if __name__ == "__main__":
    main()

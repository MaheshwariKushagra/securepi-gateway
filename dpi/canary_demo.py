#!/usr/bin/env python3
"""
SecurePi Gateway - turn the privacy-scope canary red on purpose, and back
(ENHANCEMENT-PLAN.md step 8.3; used by docs/DEMO.md).

Run on the gateway as root, with the proxy's own Python (the addon imports
mitmproxy):

    sudo /opt/securepi-dpi/bin/python3 /opt/securepi-dpi/canary_demo.py break
    sudo /opt/securepi-dpi/bin/python3 /opt/securepi-dpi/canary_demo.py restore

break
    Copies the live addon to a temporary file and puts back, in the copy,
    the exact bug REPORT-adblocking.md §6 describes: `ignore_conn` instead
    of `ignore_connection`. mitmproxy never reads the misspelt attribute,
    so that addon would decrypt every connection, not just the allowlisted
    sites. Then it runs the canary's real check (privacy_canary.run_check)
    once against the copy. The check fails, and the canary's real
    fail-safe acts: every enrolled device is unenrolled (HTTPS inspection
    off for everyone), and a high-severity "Tier 2 privacy-scope check
    failed" incident is raised. The console's privacy-scope badge turns red.

    The live addon - the file mitmproxy loads, and reloads whenever it
    changes - is never touched. Breaking that file would really decrypt
    everything for an enrolled device until the canary noticed.

restore
    Runs the same real check against the live addon (it passes), and
    lists the open privacy-scope incidents. Resolve them on the console
    (Incidents -> the incident -> Resolved); the badge is green again once
    none is open and the last check is recent. Nobody is re-enrolled: HTTPS
    inspection comes back for a device only when a person switches it on
    from that device's page.
"""

import os
import shutil
import sqlite3
import sys
import tempfile

# privacy_canary.py sits next to this file in /opt/securepi-dpi.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import privacy_canary as canary  # noqa: E402

GOOD = "data.ignore_connection = True"
BROKEN = "data.ignore_conn = True"     # the report §6 typo


def open_incidents():
    conn = sqlite3.connect("file:%s?mode=ro" % canary.DB_PATH, uri=True)
    rows = conn.execute(
        "SELECT id, status FROM incidents WHERE signal_type=? AND status NOT IN ('resolved', 'false_positive')",
        (canary.INCIDENT_SIGNAL_TYPE,)).fetchall()
    conn.close()
    return rows


def break_it():
    live = canary.ADDON_PATH
    with open(live) as f:
        source = f.read()
    if GOOD not in source:
        sys.exit("%s has no '%s' line - this script does not match the addon" % (live, GOOD))
    workdir = tempfile.mkdtemp(prefix="securepi-canary-demo-")
    try:
        copy = os.path.join(workdir, "securepi_adfilter_broken.py")
        with open(copy, "w") as f:
            f.write(source.replace(GOOD, BROKEN))
        print("addon copy with the report-6 typo: %s (the live addon is untouched)" % copy, flush=True)
        canary.ADDON_PATH = copy          # point the real check at the copy
        ok = canary.run_check()           # prints its own FAIL/ok line
    finally:
        canary.ADDON_PATH = live
        shutil.rmtree(workdir, ignore_errors=True)
    if ok:
        sys.exit("unexpected: the check PASSED against the broken copy")
    print("open privacy-scope incident(s): %s" % ", ".join("#%d" % r[0] for r in open_incidents()), flush=True)


def restore():
    ok = canary.run_check()
    rows = open_incidents()
    if rows:
        print("resolve on the console to turn the badge green: %s"
              % ", ".join("incident #%d (%s)" % r for r in rows), flush=True)
    else:
        print("no open privacy-scope incident", flush=True)
    if not ok:
        sys.exit(1)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("break", "restore"):
        sys.exit("usage: sudo /opt/securepi-dpi/bin/python3 %s break|restore" % sys.argv[0])
    if os.geteuid() != 0:
        sys.exit("run as root (the fail-safe calls nft)")
    if sys.argv[1] == "break":
        break_it()
    else:
        restore()


if __name__ == "__main__":
    main()

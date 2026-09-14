#!/usr/bin/env python3
"""
SecurePi Gateway - runtime-tunable settings (ENHANCEMENT-PLAN.md step
6.3, and the minimal slice of Stage 1's F2 "central config" this step
needs, built the same way 6.1 built device_hourly and 6.2 built
dhcp_params: the smallest real prerequisite, not the full stage).

SETTINGS_SCHEMA below is the complete, honest list of what this project
actually lets an operator tune without a redeploy: four of
correlation.py's detection thresholds (finding C5: "every threshold is
hard-coded... no Settings page yet", wired up in step 6.3) plus, as of
step 1.2, five of its window durations (how far back each signal looks,
and how long a dedup window merges repeated firings into one incident).

Deliberately NOT included: every DPI-addon-side constant
(PIN_FAILURE_THRESHOLD, PIN_BYPASS_HOURS, EFFECTIVENESS_*) - those would
need the SAME kind of cross-process, hot-reloadable mechanism step 5.9
built for adfilter-rules.json, a real, separate piece of work, not
something to silently half-do here. Also not included:
BASELINE_MIN_SAMPLES and BASELINE_MIN_BYTES_FLOOR (behavioral_baseline_signal's
learning-period and noise-floor constants) and the two product-effectiveness
constants in adblock_effectiveness_signal - these shape WHEN a signal is
even eligible to judge a device, not how sensitive its judgment is once
eligible, and conflating "detection windows" with "learning/eligibility
gates" in one settings list would make the Settings page harder to
reason about, not easier. See ENHANCEMENT-PLAN.md's note on this step
for the full reasoning behind both boundaries.

Values are read fresh from the database on every get() call, not
cached - correlation.py's signals already re-run their own SQL query
fresh every cycle rather than keeping in-memory state (see that file's
own header), and a setting change taking effect on the very next
15-second cycle, with no process to restart, is a natural extension of
that same design rather than a special case.
"""

import json
import time

# key -> {"default", "type", "min", "max", "label", "help"}. `type` is
# the Python type value must be an instance of after JSON-decoding;
# min/max apply to int/float types only.
SETTINGS_SCHEMA = {
    "port_scan_threshold": {
        "default": 8, "type": int, "min": 2, "max": 100,
        "label": "Port scan threshold",
        "help": "Distinct ports touched on one host, in the signal's window, before it's flagged.",
    },
    "brute_force_threshold": {
        "default": 6, "type": int, "min": 2, "max": 100,
        "label": "Brute-force threshold",
        "help": "Failed auth-port connection attempts, in the signal's window, before it's flagged.",
    },
    "malicious_domain_threshold": {
        "default": 15, "type": int, "min": 2, "max": 1000,
        "label": "Malicious-domain threshold",
        "help": "Distinct blocked domains from one device, in the signal's window, before it's "
                "flagged - not raw lookup count, so retrying the same ad domain doesn't count "
                "toward it (finding G3).",
    },
    "baseline_z_threshold": {
        "default": 3.0, "type": float, "min": 1.0, "max": 10.0,
        "label": "Volume-anomaly z-score threshold",
        "help": "How many standard deviations above a device's own hour-of-day average counts as unusual.",
    },
    "port_scan_window_seconds": {
        "default": 300, "type": int, "min": 30, "max": 3600,
        "label": "Port scan window",
        "help": "How far back (seconds) the port-scan signal looks when counting distinct ports touched.",
    },
    "network_sweep_threshold": {
        "default": 8, "type": int, "min": 2, "max": 100,
        "label": "Network sweep threshold",
        "help": "Distinct hosts touched on one port, in the signal's window, before it's flagged.",
    },
    "network_sweep_window_seconds": {
        "default": 300, "type": int, "min": 30, "max": 3600,
        "label": "Network sweep window",
        "help": "How far back (seconds) the network-sweep signal looks when counting distinct hosts touched.",
    },
    "slow_scan_threshold": {
        "default": 8, "type": int, "min": 2, "max": 100,
        "label": "Slow-scan threshold",
        "help": "Same distinct-count threshold as the fast port-scan/network-sweep signals, "
                "applied over the slow-scan window instead - catches a scan paced too slowly "
                "for the fast signals' shorter window to ever contain enough of it at once.",
    },
    "slow_scan_window_seconds": {
        "default": 7200, "type": int, "min": 600, "max": 86400,
        "label": "Slow-scan window",
        "help": "How far back (seconds) the slow-scan signal looks - deliberately much longer "
                "than the fast port-scan/network-sweep windows, to catch nmap-style paranoid/"
                "sneaky timing templates built to stay under a short window's threshold.",
    },
    "brute_force_window_seconds": {
        "default": 120, "type": int, "min": 30, "max": 3600,
        "label": "Brute-force window",
        "help": "How far back (seconds) the brute-force signal looks when counting connection attempts.",
    },
    "malicious_domain_window_seconds": {
        "default": 600, "type": int, "min": 30, "max": 3600,
        "label": "Malicious-domain window",
        "help": "How far back (seconds) the malicious-domain signal looks when counting blocked lookups.",
    },
    "new_device_lookback_seconds": {
        "default": 3600, "type": int, "min": 300, "max": 86400,
        "label": "New-device lookback",
        "help": "How far back (seconds) a device's first_seen can be and still count as \"new\".",
    },
    "dns_bypass_threshold": {
        "default": 3, "type": int, "min": 1, "max": 100,
        "label": "DNS-bypass threshold",
        "help": "Combined DoT/DoH/QUIC/Private-Relay bypass attempts from one device, in the "
                "signal's window, before it's flagged. Combines nftables reject-rule hits, "
                "Firefox/Apple canary-domain queries, and Suricata TLS SNI matches on known "
                "DoH providers into one count.",
    },
    "dns_bypass_window_seconds": {
        "default": 300, "type": int, "min": 30, "max": 3600,
        "label": "DNS-bypass window",
        "help": "How far back (seconds) the DNS-bypass signal looks when counting bypass attempts.",
    },
    "ids_alert_threshold": {
        "default": 3, "type": int, "min": 1, "max": 1000,
        "label": "IDS-alert threshold",
        "help": "Suricata/ET alerts of the same category from one device, in the signal's "
                "window, before it's flagged. Keeps a single stray alert from becoming an "
                "incident on its own; a sustained pattern still gets one, per category.",
    },
    "ids_alert_window_seconds": {
        "default": 300, "type": int, "min": 30, "max": 3600,
        "label": "IDS-alert window",
        "help": "How far back (seconds) the IDS-alert signal looks when counting alerts of one category.",
    },
    "threat_intel_threshold": {
        "default": 1, "type": int, "min": 1, "max": 100,
        "label": "Threat-intel match threshold",
        "help": "Matches against a confirmed-malicious IP/domain from one device, in the "
                "signal's window, before it's flagged. Unlike a blocklist-hit-volume signal, "
                "even one confirmed match is significant, so this defaults to 1.",
    },
    "threat_intel_window_seconds": {
        "default": 3600, "type": int, "min": 60, "max": 86400,
        "label": "Threat-intel window",
        "help": "How far back (seconds) the threat-intel signal looks when counting IOC matches.",
    },
    "dedup_window_seconds": {
        "default": 600, "type": int, "min": 60, "max": 86400,
        "label": "Incident dedup window",
        "help": "How long a repeated signal firing for the same device extends an existing incident, "
                "instead of raising a new one. Shared by every signal - this is what turns a flurry of "
                "detections into one incident.",
    },
}


class SettingsError(Exception):
    """A setting key doesn't exist, or a value fails validation."""


def get(conn, key):
    """The setting's current value: whatever's stored in the `settings`
    table if a row exists, else SETTINGS_SCHEMA's own default. Raises
    SettingsError for an unknown key - never silently returns None for a
    typo'd key name, which a caller could easily mistake for "unset"."""
    if key not in SETTINGS_SCHEMA:
        raise SettingsError("unknown setting: %s" % key)
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if row is None:
        return SETTINGS_SCHEMA[key]["default"]
    return json.loads(row["value"])


def validate(key, value):
    """Raise SettingsError with a specific reason if `value` isn't valid
    for `key`. Returns `value` unchanged so this can be used inline."""
    if key not in SETTINGS_SCHEMA:
        raise SettingsError("unknown setting: %s" % key)
    spec = SETTINGS_SCHEMA[key]
    # bool is a subclass of int in Python - explicitly reject it for an
    # int/float setting, since True/False silently passing as 1/0 would
    # be a confusing way to set a threshold.
    if spec["type"] is int and (isinstance(value, bool) or not isinstance(value, int)):
        raise SettingsError("%s must be a whole number" % key)
    if spec["type"] is float and (isinstance(value, bool) or not isinstance(value, (int, float))):
        raise SettingsError("%s must be a number" % key)
    if "min" in spec and value < spec["min"]:
        raise SettingsError("%s must be at least %s" % (key, spec["min"]))
    if "max" in spec and value > spec["max"]:
        raise SettingsError("%s must be at most %s" % (key, spec["max"]))
    return value


def set_value(conn, key, value):
    """Validate and store an override. Commits - callers don't need to."""
    validate(key, value)
    conn.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, json.dumps(value), time.time()),
    )
    conn.commit()


def reset_to_default(conn, key):
    """Remove any override, reverting to SETTINGS_SCHEMA's default."""
    if key not in SETTINGS_SCHEMA:
        raise SettingsError("unknown setting: %s" % key)
    conn.execute("DELETE FROM settings WHERE key=?", (key,))
    conn.commit()


def all_settings(conn):
    """Every known setting's current value, default, and whether it's
    been overridden - what the console's Settings page renders."""
    overrides = {r["key"]: json.loads(r["value"]) for r in conn.execute("SELECT key, value FROM settings")}
    out = {}
    for key, spec in SETTINGS_SCHEMA.items():
        out[key] = {
            "value": overrides.get(key, spec["default"]),
            "default": spec["default"],
            "overridden": key in overrides,
            "label": spec["label"],
            "help": spec["help"],
            "min": spec.get("min"),
            "max": spec.get("max"),
        }
    return out

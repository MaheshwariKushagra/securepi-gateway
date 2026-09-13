#!/usr/bin/env python3
"""
SecurePi Gateway - runtime-tunable settings (ENHANCEMENT-PLAN.md step
6.3, and the minimal slice of Stage 1's F2 "central config" this step
needs, built the same way 6.1 built device_hourly and 6.2 built
dhcp_params: the smallest real prerequisite, not the full stage).

SETTINGS_SCHEMA below is the complete, honest list of what this project
actually lets an operator tune without a redeploy - four of
correlation.py's detection thresholds (finding C5: "every threshold is
hard-coded... no Settings page yet"). It is deliberately NOT every
constant this codebase has: window-duration constants
(PORT_SCAN_WINDOW_SECONDS and friends) and every DPI-addon-side constant
(PIN_FAILURE_THRESHOLD, PIN_BYPASS_HOURS, EFFECTIVENESS_*) stay
hardcoded for now. The addon ones specifically would need the SAME kind
of cross-process, hot-reloadable mechanism step 5.9 built for
adfilter-rules.json - a real, separate piece of work, not something to
silently half-do here. See ENHANCEMENT-PLAN.md's note on this step for
the full reasoning.

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
        "help": "Blocked DNS lookups from one device, in the signal's window, before it's flagged.",
    },
    "baseline_z_threshold": {
        "default": 3.0, "type": float, "min": 1.0, "max": 10.0,
        "label": "Volume-anomaly z-score threshold",
        "help": "How many standard deviations above a device's own hour-of-day average counts as unusual.",
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

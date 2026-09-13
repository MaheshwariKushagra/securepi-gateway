#!/usr/bin/env python3
"""
SecurePi Gateway - native OS/vendor telemetry profiles.

Third-party ad SDKs are what tracker_entities.py is about. This file is
different: it's the telemetry a phone's own operating system or vendor
skin sends home, independent of any app - the kind of thing HaGeZi's
"native" list family (native.apple, native.samsung, native.xiaomi,
native.winoffice, native.tiktok) targets. See ENHANCEMENT-PLAN.md step
5.5.

This is a deliberately SMALL, cautious starting list, not a copy of any
of those - a handful of domains per vendor that are consistently
described as telemetry-only across multiple independent public write-ups,
picked to avoid anything that looks like it could also carry update,
activation, or core-function traffic. It has NOT been checked against a
real device of each vendor - the plan's own exit criterion for this step
is that a profile "blocks vendor telemetry without breaking updates
(checked)", and that checking has to happen against a real device before
a profile is trusted, not assumed from this list existing. Apply a new or
edited profile to the test-harness device first, the same way MAC
rotation and per-device rules were verified earlier in this project -
never to a real device as the first test.
"""

NATIVE_PROFILES = {
    "apple": {
        "label": "Apple (iOS/macOS) telemetry",
        "domains": [
            "metrics.icloud.com",
            "gsp-analytics.apple.com",
            "analytics.itunes.apple.com",
        ],
    },
    "samsung": {
        "label": "Samsung (One UI) telemetry",
        "domains": [
            "wips.samsungapps.com",
            "dip.shealth.samsung.com",
        ],
    },
    "xiaomi": {
        "label": "Xiaomi / MIUI telemetry",
        "domains": [
            "tracking.miui.com",
            "data.mistat.xiaomi.com",
            "sdkconfig.ad.xiaomi.com",
        ],
    },
    "windows": {
        "label": "Windows telemetry",
        "domains": [
            "vortex.data.microsoft.com",
            "settings-win.data.microsoft.com",
            "watson.telemetry.microsoft.com",
        ],
    },
    "tiktok": {
        "label": "TikTok analytics",
        "domains": [
            "log.tiktokv.com",
            "log.byteoversea.com",
            "analytics.tiktok.com",
        ],
    },
}


def profile(vendor):
    return NATIVE_PROFILES.get(vendor)


# Maps a fingerprint.py vendor/os string (step 6.2) to the matching
# NATIVE_PROFILES key, so the console can auto-suggest "this looks like a
# Samsung phone - apply the Samsung native-tracker profile?" instead of
# an operator having to know the mapping exists. Deliberately a small,
# explicit dict rather than a fuzzy match - a wrong auto-suggestion is
# worse than none, and fingerprint.py's own vendor/os strings are a
# small, known set (see its HOSTNAME_PATTERNS).
SUGGEST_PROFILE_FOR = {
    "Samsung": "samsung",
    "Xiaomi": "xiaomi",
    "Apple": "apple",
    "Microsoft": "windows",
    "Windows": "windows",
}


def suggest_profile(vendor, os_name):
    """Return (vendor_key, profile) if fingerprint.py's classify() result
    maps to a known native-tracker profile, else (None, None). Checked by
    vendor first (more specific), then by os as a fallback (a "Windows"
    OS match with no vendor evidence still suggests the windows profile)."""
    key = SUGGEST_PROFILE_FOR.get(vendor) or SUGGEST_PROFILE_FOR.get(os_name)
    if key is None:
        return None, None
    return key, NATIVE_PROFILES.get(key)

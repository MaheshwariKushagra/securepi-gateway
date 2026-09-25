#!/usr/bin/env python3
"""
SecurePi Gateway - filtering profiles (ENHANCEMENT-PLAN.md step 4.3).

A profile is a named bundle of per-device DNS filtering settings: whether
filtering is on at all, safe search, which services are always blocked,
which are blocked only during a daily time window (for example "no gaming
21:00-07:00"), and whether the vendor-telemetry block lists from step 5.5
are applied. A device is given a profile by an orchestrator policy
(app/orchestrator.py); this module only defines the profiles and turns
one into the exact AdGuard Home client settings it means right now.

What AdGuard Home can and cannot do per device
-----------------------------------------------
AdGuard applies its blocklists to every device - there is no per-client
list selection. What it does have per client (confirmed against the live
gateway's v0.107.79 API) is: filtering on/off, safe search per engine,
and a list of "blocked services" (TikTok, Steam, Discord and about 140
more, grouped into categories like gaming and social_network). Profiles
are built only from those real per-client controls, plus per-device
$client rules for the vendor-telemetry domains. Nothing here pretends a
per-device blocklist exists.

Why schedules are enforced by the orchestrator, not AdGuard's own schedule
--------------------------------------------------------------------------
AdGuard's per-client `blocked_services_schedule` describes when blocked
services are PAUSED, and it pauses the client's whole blocked-services
list at once, allowing one range per day. That can't express "TikTok
always, games only at night" (the pause would unblock TikTok too), and it
can't express a daytime window like 09:00-15:00 (that would need two
unblocked ranges in one day). So the orchestrator works out the
blocked-services list for the current minute (always-blocked services
plus scheduled ones while the window is open) and applies it. It runs
every engine cycle (15 seconds), so a scheduled block starts within one
cycle of its start time.

Group references
----------------
A profile can list whole categories as "group:gaming" rather than every
game by name. They're expanded against AdGuard's own service catalogue at
apply time, so a service AdGuard adds to a category later is included
automatically.
"""

import json
import re
import time

# AdGuard's safe-search engines, as its client object names them
# (confirmed from the live gateway's /control/clients output).
SAFE_SEARCH_ENGINES = ("bing", "duckduckgo", "ecosia", "google", "pixabay", "yandex", "youtube")

BUILTIN_PROFILES = {
    "standard": {
        "label": "Standard",
        "description": "Network blocklists only. The default for every device.",
        "filtering": True,
        "safe_search": False,
        "blocked_services": [],
        "schedule": None,
        "native_trackers": False,
    },
    "kids": {
        "label": "Kids",
        "description": "Safe search on every engine, gambling and dating blocked, "
                       "games and social media off overnight.",
        "filtering": True,
        "safe_search": True,
        "blocked_services": ["group:gambling", "group:dating", "tiktok", "snapchat", "onlyfans", "4chan"],
        "schedule": {"services": ["group:gaming", "group:social_network"], "start": "21:00", "end": "07:00"},
        "native_trackers": False,
    },
    "iot": {
        "label": "IoT restricted",
        "description": "For TVs, cameras and smart-home devices: blocks social, gaming, messaging, "
                       "shopping, AI and VPN/proxy services a device like this has no reason to use.",
        "filtering": True,
        "safe_search": False,
        "blocked_services": ["group:social_network", "group:gaming", "group:dating", "group:gambling",
                             "group:messenger", "group:shopping", "group:ai", "group:privacy"],
        "schedule": None,
        "native_trackers": False,
    },
    "strict_privacy": {
        "label": "Strict privacy",
        "description": "Standard, plus every vendor-telemetry block list (Apple, Samsung, Xiaomi, "
                       "Windows, TikTok) applied to this device.",
        "filtering": True,
        "safe_search": False,
        "blocked_services": [],
        "schedule": None,
        "native_trackers": True,
    },
    "unrestricted": {
        "label": "Unrestricted",
        "description": "DNS filtering off for this device. Quarantine and detection still apply.",
        "filtering": False,
        "safe_search": False,
        "blocked_services": [],
        "schedule": None,
        "native_trackers": False,
    },
}

PROFILE_ORDER = ["standard", "kids", "iot", "strict_privacy", "unrestricted"]
DEFAULT_PROFILE = "standard"

_TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_SERVICE_RE = re.compile(r"^(group:)?[a-z0-9_]{1,40}$")


class ProfileError(Exception):
    """An unknown profile, or a profile edit that fails validation."""


# ------------------------------------------------------------ definitions

def get_profile(conn, key):
    """The profile's current definition: the built-in one with any saved
    edit (filter_profiles table) laid over it."""
    if key not in BUILTIN_PROFILES:
        raise ProfileError("unknown profile: %s" % key)
    prof = dict(BUILTIN_PROFILES[key])
    row = conn.execute("SELECT config FROM filter_profiles WHERE key=?", (key,)).fetchone()
    if row is not None:
        prof.update(json.loads(row["config"]))
    prof["key"] = key
    prof["customized"] = row is not None
    return prof


def all_profiles(conn):
    return [get_profile(conn, k) for k in PROFILE_ORDER]


# The fields an operator may change. label/description stay as written
# here so the console always explains a profile the same way.
EDITABLE_FIELDS = ("safe_search", "blocked_services", "schedule")


def validate_edit(key, edit):
    """Check an edit to a profile. Returns the cleaned edit, or raises
    ProfileError with a reason the console can show as-is."""
    if key not in BUILTIN_PROFILES:
        raise ProfileError("unknown profile: %s" % key)
    if key == "unrestricted":
        raise ProfileError("the Unrestricted profile turns filtering off entirely, so there is nothing to edit")
    clean = {}
    for field, value in edit.items():
        if field not in EDITABLE_FIELDS:
            raise ProfileError("%s can't be changed" % field)
        if field == "safe_search":
            if not isinstance(value, bool):
                raise ProfileError("safe_search must be true or false")
            clean[field] = value
        elif field == "blocked_services":
            clean[field] = _validate_services(value)
        elif field == "schedule":
            clean[field] = _validate_schedule(value)
    return clean


def _validate_services(value):
    if not isinstance(value, list) or len(value) > 200:
        raise ProfileError("blocked_services must be a list of at most 200 service ids")
    out = []
    for s in value:
        if not isinstance(s, str) or not _SERVICE_RE.match(s):
            raise ProfileError("not a valid service id: %r" % (s,))
        if s not in out:
            out.append(s)
    return out


def _validate_schedule(value):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ProfileError("schedule must be an object with services, start and end")
    start, end = value.get("start"), value.get("end")
    for label, t in (("start", start), ("end", end)):
        if not isinstance(t, str) or not _TIME_RE.match(t):
            raise ProfileError("schedule %s must be a time like 21:00" % label)
    if start == end:
        raise ProfileError("schedule start and end can't be the same time")
    services = _validate_services(value.get("services") or [])
    if not services:
        raise ProfileError("a schedule needs at least one service to block")
    return {"services": services, "start": start, "end": end}


def save_edit(conn, key, edit):
    """Validate and store an edit, merged over any earlier one."""
    clean = validate_edit(key, edit)
    row = conn.execute("SELECT config FROM filter_profiles WHERE key=?", (key,)).fetchone()
    merged = json.loads(row["config"]) if row else {}
    merged.update(clean)
    conn.execute(
        "INSERT INTO filter_profiles (key, config, updated_at) VALUES (?, ?, ?)"
        " ON CONFLICT(key) DO UPDATE SET config=excluded.config, updated_at=excluded.updated_at",
        (key, json.dumps(merged), time.time()))
    conn.commit()
    return get_profile(conn, key)


def reset_profile(conn, key):
    if key not in BUILTIN_PROFILES:
        raise ProfileError("unknown profile: %s" % key)
    conn.execute("DELETE FROM filter_profiles WHERE key=?", (key,))
    conn.commit()


# --------------------------------------------------------------- schedule

def _minutes(hhmm):
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def in_window(schedule, now_struct):
    """True if the local time in `now_struct` (a time.struct_time) is
    inside the schedule's daily window. start < end is a daytime window
    (09:00-15:00); start > end wraps past midnight (21:00-07:00). The
    start minute is inside the window, the end minute is not."""
    if not schedule:
        return False
    start, end = _minutes(schedule["start"]), _minutes(schedule["end"])
    now = now_struct.tm_hour * 60 + now_struct.tm_min
    if start < end:
        return start <= now < end
    return now >= start or now < end


# ------------------------------------------------- AdGuard client settings

def expand_services(names, catalog):
    """Turn "group:gaming"-style references into the service ids AdGuard
    actually knows. `catalog` is AdGuard's own list (id -> group id). A
    plain id AdGuard doesn't know is dropped: sending AdGuard an unknown
    id would make it reject the whole client update."""
    out = set()
    for n in names:
        if n.startswith("group:"):
            group = n[len("group:"):]
            out.update(sid for sid, gid in catalog.items() if gid == group)
        elif n in catalog:
            out.add(n)
    return sorted(out)


def client_settings(profile, catalog, now_struct, paused=False):
    """The AdGuard client fields this profile means at this moment - the
    orchestrator's desired state for one device's client entry.

    `paused` is a per-device "pause filtering for N minutes" (step 4.3),
    which turns filtering off on top of whatever the profile says."""
    services = set(expand_services(profile.get("blocked_services") or [], catalog))
    sched = profile.get("schedule")
    if sched and in_window(sched, now_struct):
        services.update(expand_services(sched["services"], catalog))
    safe = bool(profile.get("safe_search"))
    return {
        "filtering_enabled": bool(profile.get("filtering")) and not paused,
        "safesearch_enabled": safe,
        "safe_search": dict({"enabled": safe}, **{e: safe for e in SAFE_SEARCH_ENGINES}),
        "use_global_blocked_services": False,
        "blocked_services": sorted(services),
        "parental_enabled": False,
        "safebrowsing_enabled": False,
        "use_global_settings": False,
    }


def client_matches(desired, actual):
    """True if an AdGuard client object already has every field `desired`
    asks for. Compares lists as sets (AdGuard may return them in its own
    order) and only the safe-search keys we set."""
    if actual is None:
        return False
    for key, want in desired.items():
        have = actual.get(key)
        if key == "blocked_services":
            if sorted(have or []) != sorted(want):
                return False
        elif key == "safe_search":
            have = have or {}
            if any(bool(have.get(k)) != v for k, v in want.items()):
                return False
        elif bool(have) != bool(want):
            return False
    return True


def describe_schedule(schedule):
    if not schedule:
        return None
    return "%s-%s daily" % (schedule["start"], schedule["end"])

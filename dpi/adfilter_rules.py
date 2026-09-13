#!/usr/bin/env python3
"""
SecurePi Gateway - Tier 2 ad-filter rule set: shared shape, defaults and
validation.

ENHANCEMENT-PLAN.md step 5.9 moves what used to be four hardcoded tuples
in dpi/securepi_adfilter.py (DECRYPT_SUFFIXES, AD_FIELDS, AD_RENDERERS,
BLOCKED_PATHS - exactly the plan's own list) into a single versioned
JSON file, dpi/adfilter-rules.json, so an operator can edit them from
the console without redeploying code, and the addon can pick up a
change without a restart.

A fifth constant, HTML_PLAYER_PAGES, existed in the old file too but was
never actually read anywhere in the addon's logic - dead code that
predates this refactor. Rather than migrate an unused field into a
new, console-editable config (where an operator would reasonably assume
editing it does something), it was dropped here rather than carried
forward.

This module holds only the parts BOTH the addon and the console need:
the default rule set (used if the JSON file is missing or broken) and
the validation logic (used by the addon's own loader, and by the
console's edit endpoint, so a bad edit is refused before it's ever
written to disk).

Deliberately deployed to TWO locations, not one - this is the one real
wrinkle in an otherwise ordinary "shared module" story
------------------------------------------------------------------------
dpi/securepi_adfilter.py runs inside the DPI venv (it needs mitmproxy).
app/webapp.py runs under the system Python (it must NOT need mitmproxy -
pulling that whole dependency into the console process just to read a
JSON file's shape would be backwards). This file itself imports nothing
but the standard library, so it's safe for both - but since this
project's deployment has no shared site-packages between those two
environments, the one source file in git (here) gets installed to BOTH
/opt/securepi-dpi/adfilter_rules.py (for the addon) and
/opt/securepi/adfilter_rules.py (for the console). Keep it dependency-free
if it's ever edited, or this stops working for one side or the other.
"""

import json

REQUIRED_RULE_KEYS = ("decrypt_suffixes", "ad_fields", "ad_renderers", "blocked_paths")

# ENHANCEMENT-PLAN.md step 5.11 (optional; Path 1 only - see the plan's
# own record of Path 2, cosmetic AND scriptlet injection, and why
# scriptlet injection was deferred rather than built). These two keys are
# NOT in REQUIRED_RULE_KEYS: cosmetic injection is off by default
# (cosmetic_injection_enabled=False) until an operator turns it on, and
# adfilter-rules.json files written before this step exist without these
# keys at all - apply_defaults() below fills them in rather than making
# every existing deployment's file suddenly fail validation.
OPTIONAL_RULE_DEFAULTS = {
    "cosmetic_injection_enabled": False,
    # Custom-element tag names YouTube's web frontend uses for ad
    # placements, matching the plausible naming convention (kebab-case of
    # the JSON renderer keys in ad_renderers above) documented across
    # public ad-blocking filter lists over several years. NOT verified
    # against a live youtube.com page this session (no enrolled device
    # was available to check) - see the plan's note on this step. Hiding
    # the wrong (nonexistent) selector is a silent no-op, not a breakage
    # risk, which is exactly why CSS-only injection was judged safe to
    # ship without that live check, unlike a JS scriptlet would be.
    "cosmetic_selectors": [
        "ytd-display-ad-renderer",
        "ytd-ad-slot-renderer",
        "ytd-in-feed-ad-layout-renderer",
        "ytd-promoted-sparkles-web-renderer",
        "ytd-companion-slot-renderer",
        "ytd-banner-promo-renderer",
        "ytd-statement-banner-renderer",
        "ytd-primetime-promo-renderer",
    ],
}


def apply_defaults(rules):
    """Fill in any missing OPTIONAL_RULE_DEFAULTS keys in place, without
    touching a key that's already present (even if empty) - an operator
    who has deliberately set cosmetic_selectors to [] gets that choice
    respected, not silently overwritten back to the defaults. Returns
    `rules` for inline use, matching validate_rules's own convention."""
    for key, default in OPTIONAL_RULE_DEFAULTS.items():
        if key not in rules:
            rules[key] = default
    return rules

# Exactly what was hardcoded in dpi/securepi_adfilter.py before this step -
# used as the addon's fallback if adfilter-rules.json is missing or
# invalid, so a bad or absent rules file degrades to "keep blocking ads
# with the last known-good set" rather than doing nothing at all. Also
# what a fresh deploy seeds dpi/adfilter-rules.json with.
DEFAULT_RULES = {
    "version": 1,
    "updated_at": None,
    "decrypt_suffixes": [
        "youtube.com",
        "youtubei.googleapis.com",
        "googlevideo.com",
        "ytimg.com",
    ],
    "ad_fields": [
        "adPlacements",
        "playerAds",
        "adSlots",
        "adBreakHeartbeatParams",
    ],
    "ad_renderers": [
        "adSlotRenderer",
        "inFeedAdLayoutRenderer",
        "aboutThisAdRenderer",
        "promotedSparklesWebRenderer",
        "promotedSparklesTextSearchRenderer",
        "promotedVideoRenderer",
        "compactPromotedVideoRenderer",
        "compactPromotedItemRenderer",
        "displayAdRenderer",
        "adsEngagementPanelRenderer",
        "bannerPromoRenderer",
        "statementBannerRenderer",
        "brandVideoShelfRenderer",
        "brandVideoSingletonRenderer",
    ],
    "blocked_paths": [
        "/get_midroll_",
        "/api/stats/ads",
        "/pagead/",
        "/ptracking",
        "/youtubei/v1/log_event",
    ],
    "cosmetic_injection_enabled": OPTIONAL_RULE_DEFAULTS["cosmetic_injection_enabled"],
    "cosmetic_selectors": list(OPTIONAL_RULE_DEFAULTS["cosmetic_selectors"]),
}


def validate_rules(rules):
    """Raise ValueError with a clear, specific reason if `rules` isn't a
    usable rule set: every required key present, each one a list of
    non-empty strings. Returns `rules` unchanged so this can be used
    inline (`rules = validate_rules(json.load(f))`).

    The step 5.11 optional keys (cosmetic_injection_enabled,
    cosmetic_selectors) are validated for TYPE when present, but are not
    required - a rules file written before this step, with neither key
    at all, is still valid; load_rules() below fills in the defaults
    afterward rather than this function inventing them."""
    if not isinstance(rules, dict):
        raise ValueError("rules must be a JSON object")
    for key in REQUIRED_RULE_KEYS:
        if key not in rules:
            raise ValueError("missing required key: %s" % key)
        value = rules[key]
        if not isinstance(value, list) or not value:
            raise ValueError("%s must be a non-empty list" % key)
        if not all(isinstance(v, str) and v.strip() for v in value):
            raise ValueError("%s must contain only non-empty strings" % key)

    if "cosmetic_injection_enabled" in rules and not isinstance(rules["cosmetic_injection_enabled"], bool):
        raise ValueError("cosmetic_injection_enabled must be true or false")
    if "cosmetic_selectors" in rules:
        selectors = rules["cosmetic_selectors"]
        if not isinstance(selectors, list):
            raise ValueError("cosmetic_selectors must be a list")
        if not all(isinstance(v, str) and v.strip() for v in selectors):
            raise ValueError("cosmetic_selectors must contain only non-empty strings")

    return rules


def load_rules(path):
    """Read, validate and apply-defaults-to the rules file at `path`.
    Raises OSError, json.JSONDecodeError or ValueError - callers decide
    what to fall back to; this function never guesses on their behalf."""
    with open(path) as f:
        rules = json.load(f)
    return apply_defaults(validate_rules(rules))

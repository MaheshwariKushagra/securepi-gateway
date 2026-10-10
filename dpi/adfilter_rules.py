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

import copy
import ipaddress
import json
import re

# Schema 2: per-site modules (ADBLOCK-ENHANCEMENT-PLAN.md B1).
# Schema 1 was one flat rule set, which only ever described YouTube.
# Schema 2 groups the same keys under `modules`, one per site, so a later
# site (X, Instagram...) gets its own hosts and rules and can never have
# YouTube's rules applied to it, or the other way round:
#
#     {"schema": 2, "version": N, "updated_at": ...,
#      "pin_failure_threshold": 2, "pin_bypass_hours": 24,
#      "modules": {"youtube": {"decrypt_suffixes": [...], "ad_fields": [...],
#                              "ad_renderers": [...], "blocked_paths": [...],
#                              "cosmetic_injection_enabled": false,
#                              "cosmetic_selectors": [...]}}}
#
# `version` is still the edit counter the console bumps on every save;
# `schema` is the file format. A schema 1 file (the live gateway's, until
# its first save from the console) still loads: normalize() turns its
# flat keys into the `youtube` module, unchanged.
SCHEMA = 2

# Keys every module must have. The YouTube module has always had all
# four, non-empty; other sites' modules (ADBLOCK-ENHANCEMENT-PLAN.md B1)
# remove ads with `prune` instead, so of these only decrypt_suffixes must
# be non-empty for them - see validate_module().
REQUIRED_RULE_KEYS = ("decrypt_suffixes", "ad_fields", "ad_renderers", "blocked_paths")

# Optional per-module lists of strings (ADBLOCK-ENHANCEMENT-PLAN.md B1):
#   passthrough_suffixes  hosts never decrypted even if a decrypt suffix
#                         covers them (live-message hosts, say); checked
#                         across ALL modules before any decrypt suffix
#   json_endpoints        path prefixes whose responses may be rewritten;
#                         empty means every path (YouTube's behaviour)
#   query_names           GraphQL query-name prefixes (the request's
#                         x-fb-friendly-name header); if non-empty, only
#                         responses to those queries are rewritten
#   never_touch_paths     path prefixes never blocked, rewritten or logged
#   html_json_pages       exact page paths whose embedded
#                         <script type="application/json"> data gets the
#                         drop_items operations (the first screen of a feed)
OPTIONAL_LIST_KEYS = ("passthrough_suffixes", "json_endpoints", "query_names", "never_touch_paths",
                      "html_json_pages")

# Declarative ways to remove ads from JSON (`prune`, a list of these):
#   {"op": "drop_items", "list_key": K, "where": "a.b"}
#       in every list stored under key K, drop the objects in which the
#       dotted path a.b leads to a value (Instagram: edges whose node has
#       an `ad`)
#   {"op": "drop_items", "list_key": K, "contains_key": X}
#       ... drop the objects that contain key X, with a non-null value, at
#       any depth
#   either drop_items form may add "innermost": true - children are pruned
#       first, so only the SMALLEST item containing the match is dropped,
#       never an ancestor that merely holds it somewhere below (Facebook's
#       page wraps every prefetched feed chunk in nested "require" lists)
#   {"op": "drop_documents", "contains_key": X}
#       in a streamed response (several JSON documents), drop each document
#       containing key X, non-null, at any depth (Facebook: a sponsored feed
#       story arrives as its own streamed chunk, marked by th_dat_spo)
PRUNE_OPS = ("drop_items", "drop_documents")

MODULE_NAME_RE = re.compile(r"^[a-z0-9_]{1,32}$")

# Pinning-aware auto-passthrough (step 5.8), now in the rules file so it
# can be tuned without a redeploy (plan A1). The threshold was 3: the
# 7.5 tablet test found a YouTube app version that retries each host only
# twice, so it never reached 3 and stayed broken. 2 covers both app
# versions seen; the cost is that a browser with two genuinely failed
# handshakes to one host also loses ad removal there for the bypass
# period.
TOP_LEVEL_DEFAULTS = {
    "pin_failure_threshold": 2,
    "pin_bypass_hours": 24,
}
PIN_FAILURE_THRESHOLD_RANGE = (1, 10)
PIN_BYPASS_HOURS_RANGE = (1, 168)

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
    """Fill in missing optional keys in place: the pin settings at the
    top level, and OPTIONAL_RULE_DEFAULTS, the B1 lists and `prune` in
    each module. A key that's already present (even if empty) is never
    touched - an operator who has deliberately set cosmetic_selectors to
    [] gets that choice respected, not silently overwritten back to the
    defaults. The default cosmetic selectors are YouTube's, so only the
    youtube module gets them; any other module defaults to none. Expects
    a schema 2 rule set (see normalize()). Returns `rules` for inline use."""
    for key, default in TOP_LEVEL_DEFAULTS.items():
        if key not in rules:
            rules[key] = default
    for name, module in rules.get("modules", {}).items():
        for key, default in OPTIONAL_RULE_DEFAULTS.items():
            if key not in module:
                module[key] = copy.deepcopy(default) if name == "youtube" or key != "cosmetic_selectors" else []
        for key in REQUIRED_RULE_KEYS + OPTIONAL_LIST_KEYS + ("prune",):
            module.setdefault(key, [])
    return rules

# Exactly what was hardcoded in dpi/securepi_adfilter.py before step 5.9,
# now as the `youtube` module - used as the addon's fallback if
# adfilter-rules.json is missing or invalid, so a bad or absent rules file
# degrades to "keep blocking ads with the last known-good set" rather than
# doing nothing at all. Also what a fresh deploy seeds
# dpi/adfilter-rules.json with. It is nested: use default_rules() for a
# copy that is safe to change.
DEFAULT_YOUTUBE_MODULE = {
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

DEFAULT_RULES = {
    "schema": SCHEMA,
    "version": 1,
    "updated_at": None,
    "pin_failure_threshold": TOP_LEVEL_DEFAULTS["pin_failure_threshold"],
    "pin_bypass_hours": TOP_LEVEL_DEFAULTS["pin_bypass_hours"],
    "modules": {"youtube": DEFAULT_YOUTUBE_MODULE},
}


def default_rules():
    """A fresh, independent copy of DEFAULT_RULES, safe to change."""
    return copy.deepcopy(DEFAULT_RULES)


def normalize(rules):
    """Return `rules` as schema 2. A schema 1 file (flat keys, no
    `modules`) becomes one `youtube` module holding exactly those keys;
    `version`, `updated_at` and the pin settings stay at the top level.
    A schema 2 rule set comes back as a deep copy. Anything that isn't
    a JSON object is returned as is, for validate_rules() to refuse."""
    if not isinstance(rules, dict):
        return rules
    if "modules" in rules:
        out = copy.deepcopy(rules)
        out["schema"] = SCHEMA
        return out
    top = ("version", "updated_at") + tuple(TOP_LEVEL_DEFAULTS)
    out = {"schema": SCHEMA}
    out.update({k: copy.deepcopy(rules[k]) for k in top if k in rules})
    out["modules"] = {"youtube": {k: copy.deepcopy(v) for k, v in rules.items()
                                  if k not in top and k != "schema"}}
    return out


def _check_strings(key, value, allow_empty):
    if not isinstance(value, list) or (not value and not allow_empty):
        raise ValueError("%s must be a %slist" % (key, "" if allow_empty else "non-empty "))
    if not all(isinstance(v, str) and v.strip() for v in value):
        raise ValueError("%s must contain only non-empty strings" % key)


def _validate_prune(ops):
    if not isinstance(ops, list):
        raise ValueError("prune must be a list")
    for op in ops:
        if not isinstance(op, dict) or op.get("op") not in PRUNE_OPS:
            raise ValueError("each prune entry needs op = %s" % " or ".join(PRUNE_OPS))
        for key, value in op.items():
            if key == "innermost":
                if not isinstance(value, bool):
                    raise ValueError("prune %s: innermost must be true or false" % op["op"])
            elif key != "op" and not (isinstance(value, str) and value.strip()):
                raise ValueError("prune %s: %s must be a non-empty string" % (op["op"], key))
        if op["op"] == "drop_items":
            if not op.get("list_key") or bool(op.get("where")) == bool(op.get("contains_key")):
                raise ValueError("drop_items needs list_key and exactly one of where / contains_key")
            allowed = {"op", "list_key", "where", "contains_key", "innermost"}
        else:
            if not op.get("contains_key"):
                raise ValueError("drop_documents needs contains_key")
            allowed = {"op", "contains_key"}
        if set(op) - allowed:
            raise ValueError("prune %s: unknown key(s) %s" % (op["op"], ", ".join(sorted(set(op) - allowed))))


def validate_module(name, module):
    """Raise ValueError with a clear, specific reason if one module isn't
    usable. decrypt_suffixes must be a non-empty list of names. The
    youtube module must have all four REQUIRED_RULE_KEYS non-empty, as it
    always has (the console edits it, and an empty list there is a
    mistake); another site's module may leave ad_fields, ad_renderers and
    blocked_paths empty or out, but must remove ads SOMEHOW - with one of
    those or with `prune`. The step 5.11 optional keys
    (cosmetic_injection_enabled, cosmetic_selectors) and the B1 keys are
    checked for type when present - apply_defaults() fills them in."""
    if not isinstance(name, str) or not MODULE_NAME_RE.match(name):
        raise ValueError("module name %r must be 1-32 lowercase letters, digits or _" % (name,))
    if not isinstance(module, dict):
        raise ValueError("module %s must be a JSON object" % name)
    for key in REQUIRED_RULE_KEYS:
        if key not in module and (name == "youtube" or key == "decrypt_suffixes"):
            raise ValueError("missing required key: %s" % key)
        if key in module:
            _check_strings(key, module[key], allow_empty=name != "youtube" and key != "decrypt_suffixes")
    for key in OPTIONAL_LIST_KEYS:
        if key in module:
            _check_strings(key, module[key], allow_empty=True)
    if "prune" in module:
        _validate_prune(module["prune"])
    if not any(module.get(k) for k in ("ad_fields", "ad_renderers", "blocked_paths", "prune")):
        raise ValueError("module %s removes nothing: give it ad_fields, ad_renderers, blocked_paths or prune"
                         % name)
    for key in ("label", "privacy_note"):
        if key in module and not isinstance(module[key], str):
            raise ValueError("%s must be text" % key)

    if "cosmetic_injection_enabled" in module and not isinstance(module["cosmetic_injection_enabled"], bool):
        raise ValueError("cosmetic_injection_enabled must be true or false")
    if "cosmetic_selectors" in module:
        selectors = module["cosmetic_selectors"]
        if not isinstance(selectors, list):
            raise ValueError("cosmetic_selectors must be a list")
        if not all(isinstance(v, str) and v.strip() for v in selectors):
            raise ValueError("cosmetic_selectors must contain only non-empty strings")
        # Each selector is pasted into a <style> element inside other
        # sites' pages (inject_cosmetic_css in securepi_adfilter.py). A
        # selector must only ever SELECT, never end the style element
        # ("</style><script>...") or add CSS rules of its own ("{", "}",
        # ";", "@import", comments, escapes). None of these characters is
        # needed for the plain element/class/attribute selectors this
        # feature uses; ">" (the child combinator) is still allowed.
        for v in selectors:
            for bad in SELECTOR_FORBIDDEN:
                if bad in v:
                    raise ValueError("cosmetic selector %r contains %r, which is not allowed" % (v, bad))


def _check_int(rules, key, bounds):
    if key not in rules:
        return
    value = rules[key]
    # bool is a subclass of int in Python; `true` is not a threshold.
    if isinstance(value, bool) or not isinstance(value, int) or not bounds[0] <= value <= bounds[1]:
        raise ValueError("%s must be a whole number from %d to %d" % (key, bounds[0], bounds[1]))


def validate_rules(rules):
    """Raise ValueError with a clear, specific reason if `rules` isn't a
    usable rule set. Accepts schema 1 or 2 and returns the schema 2 form
    (see normalize()), so it can be used inline
    (`rules = validate_rules(json.load(f))`).

    Beyond each module's own checks: at least one module, and no decrypt
    suffix claimed by two modules - a host must belong to exactly one
    site's rules, or which rules apply to it would depend on dict order."""
    if not isinstance(rules, dict):
        raise ValueError("rules must be a JSON object")
    rules = normalize(rules)
    modules = rules["modules"]
    if not isinstance(modules, dict) or not modules:
        raise ValueError("modules must be a non-empty JSON object")
    _check_int(rules, "pin_failure_threshold", PIN_FAILURE_THRESHOLD_RANGE)
    _check_int(rules, "pin_bypass_hours", PIN_BYPASS_HOURS_RANGE)

    owner = {}
    for name, module in modules.items():
        validate_module(name, module)
        for suffix in module["decrypt_suffixes"]:
            suffix = suffix.strip().lower().rstrip(".")
            if suffix in owner and owner[suffix] != name:
                raise ValueError("decrypt suffix %s is in both %s and %s" % (suffix, owner[suffix], name))
            owner[suffix] = name
    # A suffix that COVERS another module's suffix is the same problem one
    # level down: "example.com" in one module and "ads.example.com" in
    # another would both claim ads.example.com, and which module's rules
    # (and which device switch) applied would depend on dict order
    # (Audit10Oct M7).
    for suffix, name in owner.items():
        for other, other_name in owner.items():
            if other_name != name and other.endswith("." + suffix):
                raise ValueError("decrypt suffix %s (%s) covers %s (%s) - a host must belong to one module"
                                 % (suffix, name, other, other_name))
    return rules


def edited_module(current, edits):
    """The module the console's rule editor saves: a copy of `current` with
    only the fields in `edits` replaced. A value of None means "not sent,
    keep what is there". Every field the editor doesn't show - passthrough
    carve-outs, never-touch paths, endpoint and query limits, prune
    operations - is kept. The editor used to rebuild the module from its
    own six fields and drop the rest (Audit10Oct H10)."""
    new = copy.deepcopy(current)
    for key, value in edits.items():
        if value is not None:
            new[key] = value
    return new


def needs_scope_confirmation(old, new):
    """True if an edit changes what the gateway is able to decrypt, so the
    console must ask for an explicit confirmation: the decrypt suffixes
    changed, or a passthrough carve-out was removed (which lets hosts it
    protected be decrypted again)."""
    if set(new.get("decrypt_suffixes", [])) != set(old.get("decrypt_suffixes", [])):
        return True
    removed = set(old.get("passthrough_suffixes", [])) - set(new.get("passthrough_suffixes", []))
    return bool(removed)


def all_decrypt_suffixes(rules):
    """Every decrypt suffix across all modules - the gateway's whole
    decryption scope."""
    return sorted({s for m in rules["modules"].values() for s in m["decrypt_suffixes"]})


def _covers(host, suffix):
    suffix = suffix.strip().lower().rstrip(".")
    return host == suffix or host.endswith("." + suffix)


def module_for_host(rules, host):
    """(name, module) for the module whose decrypt_suffixes cover `host`
    (an exact match or a subdomain), or (None, None). An IP address never
    matches: only a name can say which site a connection is for. A host
    any module lists in passthrough_suffixes never matches, whichever
    module's decrypt suffix would otherwise cover it."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return None, None
    try:
        ipaddress.ip_address(host.strip("[]"))
        return None, None
    except ValueError:
        pass
    for module in rules["modules"].values():
        if any(_covers(host, s) for s in module.get("passthrough_suffixes", [])):
            return None, None
    for name, module in rules["modules"].items():
        for suffix in module["decrypt_suffixes"]:
            suffix = suffix.strip().lower().rstrip(".")
            if host == suffix or host.endswith("." + suffix):
                return name, module
    return None, None


# Characters and sequences a cosmetic selector may never contain - see
# validate_rules() for why.
SELECTOR_FORBIDDEN = ("<", "{", "}", ";", "@", "\\", "/*", "*/")


def load_rules(path):
    """Read, validate and apply-defaults-to the rules file at `path`,
    returning schema 2 whatever schema the file is in. Raises OSError,
    json.JSONDecodeError or ValueError - callers decide what to fall back
    to; this function never guesses on their behalf."""
    with open(path) as f:
        rules = json.load(f)
    return apply_defaults(validate_rules(rules))

"""
SecurePi Gateway - selective HTTPS inspection for first-party ad removal.

WHY THIS EXISTS
---------------
DNS filtering cannot remove YouTube ads. YouTube sends the advertisement video
from the same domain as the real video, so a per-domain block would break the
site rather than clean it. The only place the difference is visible is INSIDE
the encrypted stream, in a JSON response that tells the player which ads to
show. This addon decrypts that one response, deletes the ad instructions, and
forwards it. The player then believes the video has no ads scheduled.

This is the same result the uBlock Origin browser extension achieves with its
"json-prune" scriptlet. uBO does it inside the browser; we do it in the proxy.

PRIVACY DESIGN - THE IMPORTANT PART
-----------------------------------
We decrypt as little as possible. The tls_clienthello hook below inspects the
hostname a client is asking for BEFORE any decryption happens, and lets every
non-YouTube connection pass through as raw, still-encrypted bytes. Banking,
email and messaging are never decrypted, no certificate is ever presented for
them, and the gateway never holds their plaintext.

Scope is therefore two-dimensional: by device (only enrolled devices are
redirected here at all, via nftables) and by destination (only the hostnames
listed below are decrypted).
"""

import json
import logging
import os
import time

from mitmproxy import http

from adfilter_rules import DEFAULT_RULES, load_rules

logger = logging.getLogger(__name__)

# One JSON line per decrypt/passthrough decision and per removal, for
# ingest.py's read_dpi_events() to pick up (see ENHANCEMENT-PLAN.md step
# 5.1). This is separate from the human-readable logger.info() calls
# throughout this file, which still go to the systemd journal as before -
# this file is the machine-readable feed the console's ad-blocking
# analytics and the privacy-scope check (step 5.7) read from instead.
DPI_EVENTS_PATH = "/var/log/securepi/dpi-events.jsonl"

# Pinning-aware auto-passthrough (ENHANCEMENT-PLAN.md step 5.8). Some apps
# pin the server certificate they expect and will never trust ours, no
# matter how many times we try - the YouTube app is the example the plan
# names. Without this, that app would be permanently broken on an
# enrolled device: every attempt decrypts, every handshake fails.
#
# After PIN_FAILURE_THRESHOLD consecutive TLS failures for the exact same
# (device, host) pair, that pair is passed through undecrypted (no ad
# removal, but the app works) for PIN_BYPASS_HOURS. Both are plain
# constants, not read from any config - see finding C5 in
# ENHANCEMENT-PLAN.md; a Settings page to tune these belongs to Stage 1.
PIN_FAILURE_THRESHOLD = 3
PIN_BYPASS_HOURS = 24

# ENHANCEMENT-PLAN.md step 5.9: DECRYPT_SUFFIXES, AD_FIELDS, AD_RENDERERS
# and BLOCKED_PATHS used to be hardcoded tuples right here. They now live
# in adfilter-rules.json (loaded by _ensure_rules_fresh below), editable
# from the console and hot-reloaded without a restart - see
# adfilter_rules.py for the shared default/validation logic, why that
# lives in its own mitmproxy-free module, and why a fifth constant that
# used to live here (HTML_PLAYER_PAGES) was dropped rather than migrated.
RULES_PATH = "/var/lib/securepi-dpi/adfilter-rules.json"

# Where the addon writes per-rule hit counts (step 5.9) for the console's
# "dead rules" view. A plain JSON snapshot, not the database - like
# DPI_EVENTS_PATH's telemetry, this is a nice-to-have the console reads,
# not part of the enforcement path.
RULE_STATS_PATH = "/var/log/securepi/dpi-rule-stats.json"


def strip_ads(node, ad_fields, ad_renderers, hits=None):
    """
    Walk a decoded JSON tree and remove advertising in place.

    Two things are removed:
      1. Ad-scheduling fields (adPlacements and friends) wherever they appear.
         YouTube nests these at varying depths, so a top-level check is not
         enough - this is why the earlier version missed some.
      2. List entries that are advertisement renderers. A feed is a list of
         items, each a dict with one key naming its type; dropping the entries
         whose type is an ad renderer removes the ad and leaves the feed valid.

    `ad_fields` and `ad_renderers` are passed in explicitly - rather than
    read from a module-level constant - so this function has no hidden
    dependency on the currently-loaded rules and stays trivially unit
    testable with plain lists (see tests/test_adfilter.py). `hits`, if
    given, is a {"ad_fields": {...}, "ad_renderers": {...}} dict of
    counters this function increments in place, one entry per rule name
    that actually matched something - the data behind step 5.9's "dead
    rules" view.

    Returns the number of removals, so callers can log whether anything
    happened.
    """
    removed = 0

    if isinstance(node, dict):
        for field in ad_fields:
            if field in node:
                del node[field]
                removed += 1
                if hits is not None:
                    hits["ad_fields"][field] = hits["ad_fields"].get(field, 0) + 1
        for value in node.values():
            removed += strip_ads(value, ad_fields, ad_renderers, hits)

    elif isinstance(node, list):
        keep = []
        for item in node:
            matched = None
            if isinstance(item, dict):
                for r in ad_renderers:
                    if r in item:
                        matched = r
                        break
            if matched:
                removed += 1
                if hits is not None:
                    hits["ad_renderers"][matched] = hits["ad_renderers"].get(matched, 0) + 1
                continue          # drop this entry entirely
            keep.append(item)
        if len(keep) != len(node):
            node[:] = keep
        for item in node:
            removed += strip_ads(item, ad_fields, ad_renderers, hits)

    return removed


def inject_cosmetic_css(html_text, selectors):
    """
    ENHANCEMENT-PLAN.md step 5.11, Path 1 (cosmetic CSS injection only -
    see the plan's own record of Path 2, scriptlet injection, and why it
    was deferred rather than built).

    Insert a <style> block that hides each selector with `display:none`,
    for leftover ad-placeholder containers that survive strip_ads() (the
    JSON instruction telling YouTube to show an ad is gone, but the
    custom element YouTube's own client-side JS still renders for it can
    remain, as an empty box). Placed right before </head> when present -
    ahead of first paint - falling back to right after the opening <body>
    tag, and as a last resort prepended to the whole document. A CSS
    selector that never matches anything on a given page is a silent
    no-op, not a breakage risk - this is deliberately the lowest-risk
    form of in-page modification this addon does, unlike a JS scriptlet
    would be (see Path 2's record).

    Returns (new_text, injected). `injected` is False, and `new_text` is
    `html_text` unchanged, when `selectors` is empty - there is nothing
    to hide, so nothing is inserted.
    """
    if not selectors:
        return html_text, False

    style_block = "<style>%s</style>" % "".join(
        "%s{display:none!important}" % sel for sel in selectors
    )

    lower = html_text.lower()
    head_close = lower.find("</head>")
    if head_close != -1:
        return html_text[:head_close] + style_block + html_text[head_close:], True

    body_open = lower.find("<body")
    if body_open != -1:
        tag_end = html_text.find(">", body_open)
        if tag_end != -1:
            return html_text[:tag_end + 1] + style_block + html_text[tag_end + 1:], True

    return style_block + html_text, True


def loosen_csp_for_inline_style(csp_header):
    """
    Given a Content-Security-Policy header value, return a new value that
    additionally allows the inline <style> tag inject_cosmetic_css() just
    added - browsers block injected inline styles under a CSP that
    restricts style-src (or default-src, when there's no style-src
    directive) unless 'unsafe-inline' is present. Loosens ONLY the style
    policy, never script-src or anything else - this addon injects CSS,
    not JavaScript (see Path 2's record for why that line matters).

    How, per case:
      - style-src present: 'unsafe-inline' is added to it.
      - style-src-elem present: 'unsafe-inline' is added there too - it
        governs <style> elements specifically and overrides style-src.
      - neither style-src nor style-src-elem, but default-src present: a
        NEW style-src directive is added, copying default-src's sources
        plus 'unsafe-inline'. default-src itself is NEVER changed. It is
        also the fallback for script-src, so adding 'unsafe-inline' to it
        (what this function used to do) quietly allowed inline SCRIPTS on
        any page without its own script-src (Audit.md, ad-blocking #1).

    Returns `csp_header` completely unchanged if it already allows inline
    styles, or if it restricts neither style-src nor default-src (nothing
    to loosen). Returns falsy input unchanged.
    """
    if not csp_header:
        return csp_header

    directives = [d.strip() for d in csp_header.split(";") if d.strip()]
    new_directives = []
    found_style_src = False
    default_src_sources = None

    for d in directives:
        parts = d.split()
        name = parts[0].lower()
        if name in ("style-src", "style-src-elem"):
            if name == "style-src":
                found_style_src = True
            if "'unsafe-inline'" not in parts:
                parts.append("'unsafe-inline'")
            new_directives.append(" ".join(parts))
        else:
            if name == "default-src":
                default_src_sources = parts[1:]
            new_directives.append(d)

    if not found_style_src and default_src_sources is not None:
        # 'none' can't be combined with other sources, so it's dropped
        # from the copy - the result then allows inline styles only.
        sources = [p for p in default_src_sources if p.lower() != "'none'"]
        if "'unsafe-inline'" not in sources:
            sources.append("'unsafe-inline'")
        new_directives.append("style-src " + " ".join(sources))

    return "; ".join(new_directives)


class SecurePiAdFilter:
    def __init__(self):
        self.decrypted = 0       # connections we chose to inspect
        self.passed_through = 0  # connections left encrypted
        self.cleaned = 0         # player responses stripped of ads
        self.blocked_urls = 0    # ad/telemetry endpoints refused by path
        self._last_report = 0
        self._events_fh = None   # opened lazily - see _log_event

        # Pinning-aware auto-passthrough state (step 5.8). Plain in-process
        # dicts, not the database: this is consulted on every single TLS
        # handshake decision, and only ever holds entries for the small
        # number of (enrolled device, DECRYPT_SUFFIXES host) pairs this
        # addon could ever decrypt in the first place - not arbitrary
        # untrusted input, so unbounded growth isn't a real concern here.
        # Resets on a service restart, which is an acceptable, honest
        # trade-off: a fresh process makes no promises about a bypass that
        # started under a previous run.
        self._pin_fail_count = {}    # (src_ip, sni) -> consecutive TLS failures
        self._pin_bypass_until = {}  # (src_ip, sni) -> epoch time the bypass ends

        # Rule set state (step 5.9). Starts on the built-in defaults so the
        # addon works even before adfilter-rules.json has ever been read
        # successfully; _ensure_rules_fresh(force=True) below then tries to
        # load the real file immediately.
        self._rules = dict(DEFAULT_RULES)
        self._rules_mtime = None
        self._rule_hits = {"ad_fields": {}, "ad_renderers": {}, "blocked_paths": {}}
        self._ensure_rules_fresh(force=True)

    def _ensure_rules_fresh(self, force=False):
        """Reload RULES_PATH if it changed since last checked - this is
        what makes a rule edit from the console take effect without
        restarting the proxy (step 5.9's own exit criterion). Called at
        the top of every hook that consumes rules; an os.stat() is cheap
        enough to do unconditionally rather than on a timer.

        A missing or invalid file is never fatal: this logs a warning and
        keeps whatever rules were already loaded (the built-in defaults,
        on a fresh start) rather than breaking ad-blocking over a bad
        edit or a file that hasn't been deployed yet."""
        try:
            mtime = os.stat(RULES_PATH).st_mtime
        except OSError:
            if force:
                logger.warning("securepi: %s not found, using built-in default rules", RULES_PATH)
            return
        if not force and mtime == self._rules_mtime:
            return
        try:
            self._rules = load_rules(RULES_PATH)
            self._rules_mtime = mtime
            logger.info("securepi: rules reloaded from %s (version %s)",
                        RULES_PATH, self._rules.get("version"))
        except Exception as exc:
            logger.warning("securepi: could not load %s (%s) - keeping the rules already in use",
                            RULES_PATH, exc)

    def _write_rule_stats(self):
        """Snapshot current per-rule hit counts to RULE_STATS_PATH for the
        console's "dead rules" view (step 5.9). Written via a temp file
        plus an atomic rename, so the console never reads a half-written
        file mid-write. Called only when a hit count actually changes -
        ad-stripping and path-blocking are both naturally infrequent
        enough events that this adds no meaningful I/O load."""
        try:
            payload = {
                "written_at": time.time(),
                "rules_version": self._rules.get("version"),
                "hits": self._rule_hits,
            }
            tmp_path = RULE_STATS_PATH + ".tmp"
            os.makedirs(os.path.dirname(RULE_STATS_PATH), exist_ok=True)
            with open(tmp_path, "w") as f:
                json.dump(payload, f)
            os.replace(tmp_path, RULE_STATS_PATH)
        except Exception as exc:
            logger.warning("securepi: could not write rule stats: %s", exc)

    def _log_event(self, src_ip, decision, sni=None, ads_removed=None, blocked_path=None):
        """Append one telemetry line. Failures here (disk full, permissions)
        must never take down ad-blocking itself, so they are swallowed after
        one journal warning - this is a nice-to-have analytics feed, not the
        enforcement path.

        `ads_removed` does double duty for decision='pin_bypass' (step
        5.8): it carries the epoch timestamp the bypass ends, not a count
        of anything removed. Same reasoning as schema.sql reusing tls_sni/
        block_reason for DPI purposes - one shape, read differently
        depending on `decision`, rather than a field per decision type."""
        try:
            if self._events_fh is None:
                os.makedirs(os.path.dirname(DPI_EVENTS_PATH), exist_ok=True)
                self._events_fh = open(DPI_EVENTS_PATH, "a")
            now = time.time()
            line = json.dumps({
                "ts": now,
                "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "src_ip": src_ip,
                "decision": decision,
                "sni": sni,
                "ads_removed": ads_removed,
                "blocked_path": blocked_path,
            })
            self._events_fh.write(line + "\n")
            self._events_fh.flush()
        except Exception as exc:
            logger.warning("securepi: could not write DPI telemetry: %s", exc)
            self._events_fh = None

    def tls_clienthello(self, data):
        """
        Runs once per HTTPS connection, before any decryption takes place.

        The client announces the hostname it wants in the TLS handshake, in
        the clear - this field is called SNI. We read it and decide whether to
        inspect or step aside. Setting ignore_conn makes mitmproxy act as a
        plain TCP relay for this connection: it never decrypts, and never
        presents a certificate.
        """
        self._ensure_rules_fresh()
        sni = data.client_hello.sni or ""

        wanted = False
        for suffix in self._rules["decrypt_suffixes"]:
            if sni == suffix or sni.endswith("." + suffix):
                wanted = True
                break

        src_ip = None
        try:
            src_ip = data.context.client.peername[0]
        except Exception:
            pass  # telemetry is best-effort; never let this break the decision below

        # Pinning-aware auto-passthrough (step 5.8): even though this host
        # is one we'd normally decrypt, back off if this exact (device,
        # host) pair has recently failed the handshake too many times in a
        # row - see tls_failed_client below for where the bypass gets set.
        bypass_until = self._pin_bypass_until.get((src_ip, sni))
        if wanted and bypass_until and bypass_until > time.time():
            data.ignore_connection = True
            self.passed_through += 1
            self._log_event(src_ip, "pin_bypass", sni=sni, ads_removed=int(bypass_until))
            return

        if not wanted:
            # NOTE: the attribute is ignore_connection in mitmproxy 12.
            # Setting the wrong name silently does nothing - Python creates a
            # new attribute and mitmproxy never reads it, so every connection
            # gets decrypted. Verify against mitmproxy behaviour, not our log.
            data.ignore_connection = True
            self.passed_through += 1
            self._log_event(src_ip, "passthrough", sni=sni)
        else:
            self.decrypted += 1
            self._log_event(src_ip, "decrypt", sni=sni)

    def tls_failed_client(self, data):
        """
        Runs when the TLS handshake between mitmproxy and the CLIENT fails,
        on a connection we chose to decrypt above. The most common real
        cause on this project is a device that hasn't installed (or has
        removed) the SecurePi CA: it doesn't trust the certificate we
        present, so the handshake never completes.

        This is the ad-blocking equivalent of tls_clienthello's telemetry,
        feeding the console's CA-trust check (ENHANCEMENT-PLAN.md step
        5.6b/e) and pinning-aware auto-passthrough (step 5.8) - both need
        to know which (device, host) pairs are failing, not just that
        ad-blocking itself is still working. NOT yet exercised against a
        real failed handshake as of this deploy - see the plan's note on
        step 5.6 for what specifically still needs checking.

        Certificate pinning is the other real cause besides a missing CA,
        and the two look identical from here: repeated failures for the
        exact same (device, host) pair. After PIN_FAILURE_THRESHOLD of
        them, that pair backs off into auto-passthrough - see
        tls_clienthello above - rather than trying, and failing, forever.
        """
        sni = None
        try:
            sni = data.client_hello.sni
        except Exception:
            pass
        src_ip = None
        try:
            src_ip = data.context.client.peername[0]
        except Exception:
            pass
        self._log_event(src_ip, "tls_failed", sni=sni)

        if src_ip is None or not sni:
            return  # nothing to key a (device, host) pair on
        key = (src_ip, sni)
        self._pin_fail_count[key] = self._pin_fail_count.get(key, 0) + 1
        if self._pin_fail_count[key] >= PIN_FAILURE_THRESHOLD:
            self._pin_bypass_until[key] = time.time() + PIN_BYPASS_HOURS * 3600
            self._pin_fail_count[key] = 0
            logger.info("securepi: %s failed the handshake for %s %d times in a row - "
                        "bypassing (undecrypted) for %dh, likely certificate pinning",
                        src_ip, sni, PIN_FAILURE_THRESHOLD, PIN_BYPASS_HOURS)

    def request(self, flow):
        """
        Runs before each request on a decrypted connection.

        Some ad and tracking endpoints live on hostnames we have to allow, so
        the only place to stop them is here, by looking at the path.
        """
        self._ensure_rules_fresh()

        # Every 100 connections, report the decrypt/passthrough ratio. This is
        # the number that demonstrates the privacy scope is actually holding.
        total = self.decrypted + self.passed_through
        if total and total % 100 == 0 and total != self._last_report:
            self._last_report = total
            logger.info(
                "securepi: scope check - decrypted %d, passed through %d (%.1f%% untouched)",
                self.decrypted, self.passed_through,
                100.0 * self.passed_through / total,
            )

        for path in self._rules["blocked_paths"]:
            if path in flow.request.path:
                flow.response = http.Response.make(204)  # empty, no content
                self.blocked_urls += 1
                blocked_path = flow.request.path.split("?")[0]
                logger.info("securepi: blocked ad endpoint %s", blocked_path)
                try:
                    src_ip = flow.client_conn.address[0]
                except Exception:
                    src_ip = None
                self._log_event(src_ip, "path_blocked", blocked_path=blocked_path)
                self._rule_hits["blocked_paths"][path] = self._rule_hits["blocked_paths"].get(path, 0) + 1
                self._write_rule_stats()
                return

    def response(self, flow):
        """
        Runs for each response on a connection we chose to decrypt.

        Rather than targeting specific endpoints, we clean every JSON response
        from YouTube. Ads turned out to appear in several places - the player
        API, the watch page, and the feed - so a general sweep is both simpler
        and harder to evade than a list of special cases.
        """
        self._ensure_rules_fresh()
        content_type = flow.response.headers.get("content-type", "")
        path = flow.request.path.split("?")[0]

        try:
            text = flow.response.get_text()
        except Exception:
            return
        if not text:
            return

        # JSON responses: parse, strip recursively, re-serialise.
        if "json" in content_type or text.lstrip().startswith("{"):
            try:
                body = json.loads(text)
            except Exception:
                return
            removed = strip_ads(body, self._rules["ad_fields"], self._rules["ad_renderers"],
                                 self._rule_hits)
            if removed:
                flow.response.set_text(json.dumps(body))
                self.cleaned += removed
                logger.info(
                    "securepi: stripped %d ad object(s) from %s", removed, path
                )
                try:
                    src_ip = flow.client_conn.address[0]
                except Exception:
                    src_ip = None
                self._log_event(src_ip, "ads_stripped",
                                 sni=flow.request.host, ads_removed=removed)
                self._write_rule_stats()
            return

        # HTML pages embed the same structures as text. We cannot parse those
        # safely, so we neutralise the field names the way uBlock Origin does.
        if "html" in content_type:
            changed = False
            for field in self._rules["ad_fields"]:
                marker = '"%s"' % field
                if marker in text:
                    text = text.replace(marker, '"no_ads"')
                    changed = True
                    self._rule_hits["ad_fields"][field] = self._rule_hits["ad_fields"].get(field, 0) + 1

            # Cosmetic CSS injection (step 5.11, Path 1 - off by default,
            # see adfilter_rules.py's OPTIONAL_RULE_DEFAULTS). Independent
            # of the field-neutralisation above: hides leftover empty ad
            # containers even on a page where no ad_fields marker matched.
            if self._rules.get("cosmetic_injection_enabled") and self._rules.get("cosmetic_selectors"):
                text, injected = inject_cosmetic_css(text, self._rules["cosmetic_selectors"])
                if injected:
                    changed = True
                    csp = flow.response.headers.get("content-security-policy")
                    if csp:
                        loosened = loosen_csp_for_inline_style(csp)
                        if loosened != csp:
                            flow.response.headers["content-security-policy"] = loosened
                    try:
                        src_ip = flow.client_conn.address[0]
                    except Exception:
                        src_ip = None
                    self._log_event(src_ip, "cosmetic_injected", sni=flow.request.host,
                                     ads_removed=len(self._rules["cosmetic_selectors"]))

            if changed:
                flow.response.set_text(text)
                self.cleaned += 1
                logger.info("securepi: neutralised ad fields / injected cosmetic CSS in %s", path)
                self._write_rule_stats()


addons = [SecurePiAdFilter()]

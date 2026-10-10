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

import hashlib
import ipaddress
import json
import logging
import os
import re
import time

from mitmproxy import http

from adfilter_rules import default_rules, load_rules, module_for_host

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
# After `pin_failure_threshold` consecutive TLS failures for the exact
# same (device, host) pair, that pair is passed through undecrypted (no ad
# removal, but the app works) for `pin_bypass_hours`. Both come from the
# rules file and are hot-reloaded with it (ADBLOCK-ENHANCEMENT-PLAN.md A1);
# see adfilter_rules.TOP_LEVEL_DEFAULTS for why the threshold is 2.

# ENHANCEMENT-PLAN.md step 5.9: DECRYPT_SUFFIXES, AD_FIELDS, AD_RENDERERS
# and BLOCKED_PATHS used to be hardcoded tuples right here. They now live
# in adfilter-rules.json, one set per site under `modules` since schema 2
# (loaded by _ensure_rules_fresh below), editable
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

# Which site modules each enrolled device has switched on
# (ADBLOCK-ENHANCEMENT-PLAN.md B2): {"10.10.0.53": ["youtube", "instagram"]},
# written by the orchestrator from the active enroll policies. A device
# missing from it gets DEFAULT_SITES - YouTube only, which is what
# enrolment meant before there were other sites - so another site is only
# ever decrypted for a device it was deliberately switched on for.
SITE_MAP_PATH = "/var/lib/securepi-dpi/device-sites.json"
DEFAULT_SITES = ("youtube",)


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


def _resolve(node, dotted):
    for key in dotted.split("."):
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def _contains_key(node, key):
    """True if `key` appears at any depth with a non-null value. A key
    present but null doesn't count: Facebook's organic stories carry some
    ad-shaped keys set to null (measured 10 October 2026)."""
    if isinstance(node, dict):
        return node.get(key) is not None or any(_contains_key(v, key) for v in node.values())
    if isinstance(node, list):
        return any(_contains_key(v, key) for v in node)
    return False


def _drop_item(item, op):
    if not isinstance(item, (dict, list)):
        return False
    if op.get("where"):
        return isinstance(item, dict) and _resolve(item, op["where"]) is not None
    return _contains_key(item, op["contains_key"])


def prune(node, ops, hits=None):
    """Apply a module's drop_items operations (adfilter_rules.PRUNE_OPS)
    to one JSON document in place: in every list stored under an op's
    list_key, at any depth, drop the items the op matches. An op marked
    innermost prunes the list's children first, so only the smallest
    matching item goes, never an ancestor that merely contains it.
    Returns the number of items dropped. `hits`, if given, counts per op."""
    removed = 0
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, list):
                for op in ops:
                    if op["op"] != "drop_items" or op["list_key"] != key:
                        continue
                    if op.get("innermost"):
                        for item in value:
                            removed += prune(item, ops, hits)
                    keep = [x for x in value if not _drop_item(x, op)]
                    if len(keep) != len(value):
                        n = len(value) - len(keep)
                        removed += n
                        value[:] = keep
                        if hits is not None:
                            label = "%s %s" % (key, op.get("where") or op.get("contains_key"))
                            hits[label] = hits.get(label, 0) + n
            removed += prune(value, ops, hits)
    elif isinstance(node, list):
        for item in node:
            removed += prune(item, ops, hits)
    return removed


_JSON_PREFIXES = ("for (;;);", ")]}'")


def parse_json_documents(text):
    """(prefix, documents, separator) for a response body that is one JSON
    value, or several on separate lines (streamed GraphQL - Facebook sends
    a feed this way), optionally after an anti-hijacking prefix. Returns
    None if the body isn't JSON at all."""
    stripped = text.lstrip()
    prefix = ""
    for p in _JSON_PREFIXES:
        if stripped.startswith(p):
            prefix, stripped = p, stripped[len(p):]
            break
    try:
        return prefix, [json.loads(stripped)], None
    except Exception:
        pass
    separator = "\r\n" if "\r\n" in stripped else "\n"
    docs = []
    for line in stripped.split(separator):
        if not line.strip():
            continue
        try:
            docs.append(json.loads(line))
        except Exception:
            return None
    return (prefix, docs, separator) if docs else None


def serialise_json_documents(prefix, docs, separator):
    if separator is None:
        return prefix + json.dumps(docs[0])
    return prefix + separator.join(json.dumps(d) for d in docs)


_JSON_SCRIPT_RE = re.compile(r'(<script type="application/json"[^>]*>)(.*?)(</script>)', re.S)


def prune_html_json(html_text, ops, hits=None):
    """Apply drop_items operations to the JSON a page embeds in
    <script type="application/json"> blocks (B1: Instagram and Facebook put
    the first screen of the feed, ads included, in the page itself). Only
    blocks that mention one of the ops' keys are parsed; a block is
    rewritten only if something was dropped, with every "<" escaped so the
    JSON can't end the script element, and its data-content-len attribute
    (the content's length, which the page checks) updated. Returns
    (new_text, removed)."""
    needles = ['"%s"' % (op.get("list_key") or op.get("contains_key")) for op in ops
               if op["op"] == "drop_items"]
    if not needles:
        return html_text, 0
    removed = 0

    def repl(m):
        nonlocal removed
        open_tag, content, close = m.groups()
        if not any(n in content for n in needles):
            return m.group(0)
        try:
            doc = json.loads(content)
        except Exception:
            return m.group(0)
        n = prune(doc, ops, hits)
        if not n:
            return m.group(0)
        removed += n
        new = json.dumps(doc, separators=(",", ":")).replace("<", "\\u003c")
        open_tag = re.sub(r'data-content-len="\d+"', 'data-content-len="%d"' % len(new), open_tag)
        return open_tag + new + close

    return _JSON_SCRIPT_RE.sub(repl, html_text), removed


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


# TLS ClientHello fingerprint (ADBLOCK-ENHANCEMENT-PLAN.md F4). The pin
# bypass used to be keyed on (device, host) only, so an app that rejects
# our certificate (the YouTube app, say) switched decryption off for every
# client on that device - the browser included - for the whole bypass
# period. Keyed on the client too, a bypass only covers clients that offer
# the same TLS hello as the one that failed.
#
# What goes in: the offered cipher suites, extension types and ALPN list,
# each sorted (Chrome shuffles its extension order on every connection),
# without GREASE values (random by design) and without the extensions that
# come and go between connections from the same client: padding (21),
# pre_shared_key (41) and early_data (42), which appear only when a session
# is resumed or the hello needs padding.
_GREASE = frozenset(0x0A0A + 0x1010 * i for i in range(16))
_VOLATILE_EXTENSIONS = frozenset((21, 41, 42))


def client_fingerprint(client_hello):
    """A short, stable label for the kind of client that sent this hello,
    or None if it can't be read (then the bypass falls back to device and
    host only, as before)."""
    try:
        ciphers = sorted(c for c in client_hello.cipher_suites if c not in _GREASE)
        exts = sorted(t for t, _ in client_hello.extensions
                      if t not in _GREASE and t not in _VOLATILE_EXTENSIONS)
        alpn = [a.decode("ascii", "replace") if isinstance(a, bytes) else str(a)
                for a in (client_hello.alpn_protocols or [])]
    except Exception:
        return None
    raw = "%s|%s|%s" % (",".join(map(str, ciphers)), ",".join(map(str, exts)), ",".join(alpn))
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _looks_like_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


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
        # Keys are (src_ip, sni, client fingerprint) since F4; the
        # fingerprint is None when it couldn't be read.
        self._pin_fail_count = {}    # key -> consecutive TLS failures
        self._pin_bypass_until = {}  # key -> epoch time the bypass ends
        self._conn_fp = {}           # client connection id -> its fingerprint

        # Rule set state (step 5.9). Starts on the built-in defaults so the
        # addon works even before adfilter-rules.json has ever been read
        # successfully; _ensure_rules_fresh(force=True) below then tries to
        # load the real file immediately.
        self._rules = default_rules()
        self._rules_mtime = None
        self._rule_hits = {"ad_fields": {}, "ad_renderers": {}, "blocked_paths": {}, "prune": {}}
        self._site_map = {}
        self._site_map_mtime = None
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

    def _sites_for(self, ip):
        """The site modules switched on for this device - see SITE_MAP_PATH.
        Re-read when the file changes. A missing or unreadable map means
        DEFAULT_SITES for everyone: never more decryption, only less."""
        try:
            mtime = os.stat(SITE_MAP_PATH).st_mtime
            if mtime != self._site_map_mtime:
                with open(SITE_MAP_PATH) as f:
                    raw = json.load(f)
                self._site_map = {str(k): [str(x) for x in v] for k, v in raw.items()
                                  if isinstance(v, list)}
                self._site_map_mtime = mtime
        except (OSError, ValueError, AttributeError):
            self._site_map, self._site_map_mtime = {}, None
        return self._site_map.get(ip) or list(DEFAULT_SITES)

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

    def _flow_module(self, flow):
        """(name, module) of the rules module for one decrypted request,
        or (None, None).

        Decided by the request's own host name (the Host header, or :authority
        in HTTP/2), not only the connection's SNI. A browser can reuse one
        connection for several host names the certificate covers, so the
        SNI alone could apply YouTube's rules to another site's request on
        that connection. Before modules, every request on a decrypted
        connection got the rules; now a request whose host no module covers
        is left untouched. The SNI is used only when the request carries no
        host name (in transparent mode request.host can be the IP)."""
        req = flow.request
        host = getattr(req, "pretty_host", None) or getattr(req, "host", None) or ""
        name, module = module_for_host(self._rules, host)
        if name is None and (not host or _looks_like_ip(host)):
            sni = getattr(getattr(flow, "client_conn", None), "sni", None)
            name, module = module_for_host(self._rules, sni)
        return name, module

    @staticmethod
    def _never_touch(module, path):
        return any(path.startswith(p) for p in module.get("never_touch_paths", []))

    @staticmethod
    def _may_rewrite(module, flow, path):
        """json_endpoints and query_names (B1): which responses of a module
        may be read and rewritten at all. Anything else passes unparsed."""
        endpoints = module.get("json_endpoints") or []
        if endpoints and not any(path.startswith(p) for p in endpoints):
            return False
        names = module.get("query_names") or []
        if names:
            try:
                query = flow.request.headers.get("x-fb-friendly-name", "")
            except Exception:
                query = ""
            if not query or not any(query.startswith(n) for n in names):
                return False
        return True

    def _prune_page(self, flow, name, module):
        """A page listed in html_json_pages: prune the JSON it embeds."""
        try:
            text = flow.response.get_text()
        except Exception:
            return
        if not text:
            return
        new_text, removed = prune_html_json(text, module["prune"], self._rule_hits["prune"])
        if removed:
            flow.response.set_text(new_text)
            self.cleaned += removed
            try:
                src_ip = flow.client_conn.address[0]
            except Exception:
                src_ip = None
            self._log_event(src_ip, "ads_stripped", sni=flow.request.host, ads_removed=removed, module=name)
            self._write_rule_stats()

    def _log_event(self, src_ip, decision, sni=None, ads_removed=None, blocked_path=None, module=None,
                   client_fp=None):
        """Append one telemetry line. Failures here (disk full, permissions)
        must never take down ad-blocking itself, so they are swallowed after
        one journal warning - this is a nice-to-have analytics feed, not the
        enforcement path.

        `ads_removed` does double duty for decision='pin_bypass' (step
        5.8): it carries the epoch timestamp the bypass ends, not a count
        of anything removed. Same reasoning as schema.sql reusing tls_sni/
        block_reason for DPI purposes - one shape, read differently
        depending on `decision`, rather than a field per decision type.

        `module` is the site module the decision belongs to
        (ADBLOCK-ENHANCEMENT-PLAN.md B5); None for a passthrough."""
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
                "module": module,
                "client_fp": client_fp,
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

        # Decrypt only a host some site module claims (schema 2 rules)...
        module_name = module_for_host(self._rules, sni)[0]
        wanted = module_name is not None

        src_ip = None
        try:
            src_ip = data.context.client.peername[0]
        except Exception:
            pass  # telemetry is best-effort; never let this break the decision below

        # ...and only for a device that has that site switched on (B2).
        site_off = wanted and module_name not in self._sites_for(src_ip)
        if site_off:
            wanted = False

        # The client's fingerprint, remembered for this connection so a
        # failed handshake can be pinned on this kind of client (F4).
        fp = client_fingerprint(data.client_hello)
        try:
            if len(self._conn_fp) > 20000:
                self._conn_fp.clear()
            self._conn_fp[data.context.client.id] = fp
        except Exception:
            pass

        # Pinning-aware auto-passthrough (step 5.8): even though this host
        # is one we'd normally decrypt, back off if this kind of client on
        # this device has recently failed the handshake for this host too
        # many times in a row - see tls_failed_client below for where the
        # bypass gets set.
        bypass_until = self._pin_bypass_until.get((src_ip, sni, fp))
        if wanted and bypass_until and bypass_until > time.time():
            data.ignore_connection = True
            self.passed_through += 1
            self._log_event(src_ip, "pin_bypass", sni=sni, ads_removed=int(bypass_until),
                            module=module_name, client_fp=fp)
            return

        if not wanted:
            # NOTE: the attribute is ignore_connection in mitmproxy 12.
            # Setting the wrong name silently does nothing - Python creates a
            # new attribute and mitmproxy never reads it, so every connection
            # gets decrypted. Verify against mitmproxy behaviour, not our log.
            data.ignore_connection = True
            self.passed_through += 1
            self._log_event(src_ip, "passthrough", sni=sni, module=module_name if site_off else None)
        else:
            self.decrypted += 1
            self._log_event(src_ip, "decrypt", sni=sni, module=module_name, client_fp=fp)

    @staticmethod
    def _tls_pair(data):
        """(device IP, server name) for a tls_failed_client or
        tls_established_client event. Both hooks receive mitmproxy's
        TlsData - NOT the ClientHelloData tls_clienthello gets - and the
        server name the client asked for is on the client connection,
        data.conn.sni. This used to read data.client_hello.sni, which
        TlsData doesn't have: the error was swallowed, the name was always
        None, and the automatic bypass below could never trigger
        (Audit.md H8)."""
        src_ip = sni = None
        try:
            src_ip = data.context.client.peername[0]
        except Exception:
            pass
        try:
            sni = data.conn.sni
        except Exception:
            pass
        return src_ip, sni

    def tls_established_client(self, data):
        """
        Runs when the TLS handshake with the CLIENT succeeds. Clears that
        (device, host) pair's failure count, so the pin threshold
        really means that many failures IN A ROW, as documented - not that
        many failures in total, however many successes came in between.
        """
        src_ip, sni = self._tls_pair(data)
        fp = self._conn_fp.pop(getattr(data.conn, "id", None), None)
        if src_ip is not None and sni:
            self._pin_fail_count.pop((src_ip, sni, fp), None)

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
        exact same (device, host) pair. After `pin_failure_threshold` of
        them, that pair backs off into auto-passthrough - see
        tls_clienthello above - rather than trying, and failing, forever.
        """
        src_ip, sni = self._tls_pair(data)
        fp = self._conn_fp.pop(getattr(data.conn, "id", None), None)
        self._log_event(src_ip, "tls_failed", sni=sni, module=module_for_host(self._rules, sni)[0],
                        client_fp=fp)

        if src_ip is None or not sni:
            return  # nothing to key a (device, host) pair on
        key = (src_ip, sni, fp)
        # Keep this state small: forget bypasses that have run out, and
        # start counting afresh if a flood of distinct pairs piles up.
        now = time.time()
        for old_key in [k for k, until in self._pin_bypass_until.items() if until <= now]:
            del self._pin_bypass_until[old_key]
        if len(self._pin_fail_count) > 5000:
            self._pin_fail_count.clear()
        self._pin_fail_count[key] = self._pin_fail_count.get(key, 0) + 1
        self._ensure_rules_fresh()
        threshold = self._rules["pin_failure_threshold"]
        hours = self._rules["pin_bypass_hours"]
        if self._pin_fail_count[key] >= threshold:
            self._pin_bypass_until[key] = time.time() + hours * 3600
            self._pin_fail_count[key] = 0
            logger.info("securepi: %s (client %s) failed the handshake for %s %d times in a row - "
                        "bypassing that client (undecrypted) for %dh, likely certificate pinning",
                        src_ip, fp, sni, threshold, hours)

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

        # Match against the path only, never the query string after "?":
        # a harmless request like "/search?q=/pagead/" used to be blocked
        # just because the query happened to contain a rule's text.
        name, module = self._flow_module(flow)
        if module is None:
            return
        request_path = flow.request.path.split("?")[0]
        if self._never_touch(module, request_path):
            return
        for path in module["blocked_paths"]:
            if path in request_path:
                flow.response = http.Response.make(204)  # empty, no content
                self.blocked_urls += 1
                blocked_path = request_path
                logger.info("securepi: blocked ad endpoint %s", blocked_path)
                try:
                    src_ip = flow.client_conn.address[0]
                except Exception:
                    src_ip = None
                self._log_event(src_ip, "path_blocked", blocked_path=blocked_path, module=name)
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
        name, module = self._flow_module(flow)
        if module is None:
            return
        content_type = flow.response.headers.get("content-type", "")
        path = flow.request.path.split("?")[0]
        # Never-touch paths and responses outside the module's endpoints or
        # queries are not even read (B1): an inbox response passes through
        # without being parsed.
        if self._never_touch(module, path):
            return
        if path in (module.get("html_json_pages") or []) and "html" in content_type and module.get("prune"):
            self._prune_page(flow, name, module)
            return
        if not self._may_rewrite(module, flow, path):
            return

        try:
            text = flow.response.get_text()
        except Exception:
            return
        if not text:
            return

        # JSON responses (one document, or several streamed): parse, strip
        # recursively, re-serialise.
        stripped = text.lstrip()
        if "json" in content_type or stripped.startswith("{") or stripped.startswith(_JSON_PREFIXES):
            parsed = parse_json_documents(text)
            if parsed is None:
                return
            prefix, docs, separator = parsed
            removed = 0
            ops = module.get("prune") or []
            for op in ops:
                if op["op"] == "drop_documents" and separator is not None:
                    keep = [d for d in docs if not _contains_key(d, op["contains_key"])]
                    if len(keep) != len(docs):
                        n = len(docs) - len(keep)
                        removed += n
                        label = "documents %s" % op["contains_key"]
                        self._rule_hits["prune"][label] = self._rule_hits["prune"].get(label, 0) + n
                        docs = keep
            for body in docs:
                removed += strip_ads(body, module["ad_fields"], module["ad_renderers"], self._rule_hits)
                if ops:
                    removed += prune(body, ops, self._rule_hits["prune"])
            if removed and docs:
                flow.response.set_text(serialise_json_documents(prefix, docs, separator))
                self.cleaned += removed
                logger.info(
                    "securepi: stripped %d ad object(s) from %s", removed, path
                )
                try:
                    src_ip = flow.client_conn.address[0]
                except Exception:
                    src_ip = None
                self._log_event(src_ip, "ads_stripped",
                                 sni=flow.request.host, ads_removed=removed, module=name)
                self._write_rule_stats()
            return

        # HTML pages embed the same structures as text. We cannot parse those
        # safely, so we neutralise the field names the way uBlock Origin does.
        if "html" in content_type:
            changed = False
            neutralised = 0
            for field in module["ad_fields"]:
                marker = '"%s"' % field
                if marker in text:
                    neutralised += text.count(marker)
                    text = text.replace(marker, '"no_ads"')
                    changed = True
                    self._rule_hits["ad_fields"][field] = self._rule_hits["ad_fields"].get(field, 0) + 1
            # Logged like a JSON strip (plan B5). Mobile YouTube embeds the
            # ad schedule in the watch page's HTML, and this branch used to
            # write no telemetry line, so the console under-counted and the
            # effectiveness watchdog saw "decrypting, never stripping" on a
            # device whose ads were being removed here.
            if neutralised:
                try:
                    src_ip = flow.client_conn.address[0]
                except Exception:
                    src_ip = None
                self._log_event(src_ip, "ads_stripped", sni=flow.request.host,
                                 ads_removed=neutralised, module=name)

            # Cosmetic CSS injection (step 5.11, Path 1 - off by default,
            # see adfilter_rules.py's OPTIONAL_RULE_DEFAULTS). Independent
            # of the field-neutralisation above: hides leftover empty ad
            # containers even on a page where no ad_fields marker matched.
            if module.get("cosmetic_injection_enabled") and module.get("cosmetic_selectors"):
                text, injected = inject_cosmetic_css(text, module["cosmetic_selectors"])
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
                                     ads_removed=len(module["cosmetic_selectors"]), module=name)

            if changed:
                flow.response.set_text(text)
                self.cleaned += 1
                logger.info("securepi: neutralised ad fields / injected cosmetic CSS in %s", path)
                self._write_rule_stats()


addons = [SecurePiAdFilter()]

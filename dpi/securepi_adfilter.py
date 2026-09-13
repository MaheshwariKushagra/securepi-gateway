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

logger = logging.getLogger(__name__)

# One JSON line per decrypt/passthrough decision and per removal, for
# ingest.py's read_dpi_events() to pick up (see ENHANCEMENT-PLAN.md step
# 5.1). This is separate from the human-readable logger.info() calls
# throughout this file, which still go to the systemd journal as before -
# this file is the machine-readable feed the console's ad-blocking
# analytics and the privacy-scope check (step 5.7) read from instead.
DPI_EVENTS_PATH = "/var/log/securepi/dpi-events.jsonl"


# Only these hostnames are ever decrypted. Everything else passes through
# untouched. Keep this list as short as possible - each entry is a domain
# whose traffic the gateway becomes able to read.
DECRYPT_SUFFIXES = (
    "youtube.com",
    "youtubei.googleapis.com",
    "googlevideo.com",
    "ytimg.com",
)

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

# Fields inside the YouTube player JSON that schedule advertisements.
# Removing them leaves a valid response describing a video with no ads.
#
# These field names come from uBlock Origin's own YouTube rules, e.g.
#   ||www.youtube.com/youtubei/v1/player?$xhr,1p,replace=/"adPlacements"/"no_ads"/
# uBO renames the field; we delete it. Same effect, and deleting is tidier.
AD_FIELDS = (
    "adPlacements",
    "playerAds",
    "adSlots",
    "adBreakHeartbeatParams",
)

# Ad-telemetry and midroll endpoints. These sit on hostnames we must allow
# (blocking youtube.com would break the site), so DNS filtering cannot touch
# them - only a proxy that sees the URL path can. Taken from uBO's filter list.
BLOCKED_PATHS = (
    "/get_midroll_",
    "/api/stats/ads",
    "/pagead/",
    "/ptracking",
    "/youtubei/v1/log_event",
)

# Pages that embed the player JSON inside their HTML rather than returning it
# from the API. uBO rewrites these too; we do the same by text substitution,
# because parsing the whole HTML document would be slower and more fragile.
HTML_PLAYER_PAGES = ("/watch", "/playlist")


# Renderer names YouTube uses to place advertisements inside feeds and
# watch pages. Observed live on this network in /youtubei/v1/browse responses.
AD_RENDERERS = (
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
)


def strip_ads(node):
    """
    Walk a decoded JSON tree and remove advertising in place.

    Two things are removed:
      1. Ad-scheduling fields (adPlacements and friends) wherever they appear.
         YouTube nests these at varying depths, so a top-level check is not
         enough - this is why the earlier version missed some.
      2. List entries that are advertisement renderers. A feed is a list of
         items, each a dict with one key naming its type; dropping the entries
         whose type is an ad renderer removes the ad and leaves the feed valid.

    Returns the number of removals, so we can log whether anything happened.
    """
    removed = 0

    if isinstance(node, dict):
        for field in AD_FIELDS:
            if field in node:
                del node[field]
                removed += 1
        for value in node.values():
            removed += strip_ads(value)

    elif isinstance(node, list):
        keep = []
        for item in node:
            if isinstance(item, dict) and any(r in item for r in AD_RENDERERS):
                removed += 1
                continue          # drop this entry entirely
            keep.append(item)
        if len(keep) != len(node):
            node[:] = keep
        for item in node:
            removed += strip_ads(item)

    return removed


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
        sni = data.client_hello.sni or ""

        wanted = False
        for suffix in DECRYPT_SUFFIXES:
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

        for path in BLOCKED_PATHS:
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
                return

    def response(self, flow):
        """
        Runs for each response on a connection we chose to decrypt.

        Rather than targeting specific endpoints, we clean every JSON response
        from YouTube. Ads turned out to appear in several places - the player
        API, the watch page, and the feed - so a general sweep is both simpler
        and harder to evade than a list of special cases.
        """
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
            removed = strip_ads(body)
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
            return

        # HTML pages embed the same structures as text. We cannot parse those
        # safely, so we neutralise the field names the way uBlock Origin does.
        if "html" in content_type:
            changed = False
            for field in AD_FIELDS:
                marker = '"%s"' % field
                if marker in text:
                    text = text.replace(marker, '"no_ads"')
                    changed = True
            if changed:
                flow.response.set_text(text)
                self.cleaned += 1
                logger.info("securepi: neutralised ad fields in %s", path)


addons = [SecurePiAdFilter()]

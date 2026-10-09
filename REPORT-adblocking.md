# SecurePi Gateway — Ad Blocking Subsystem
### Report material: design, implementation, results and findings

Working session, 12 September 2026. All figures below are measured on the project
network, not estimated.

---

## 1. Objective

Provide network-level advertisement and tracker blocking for a small-enterprise network,
covering every connected device, and determine the boundary of what network-level
filtering can and cannot achieve.

The second half of that objective turned out to be the more valuable one.

---

## 2. The layered filtering problem

Advertising is delivered in two structurally different ways, and they require different
techniques:

| | Third-party ads | First-party ads |
|---|---|---|
| Served from | Dedicated ad domains (`doubleclick.net`, `googlesyndication.com`) | The same domain as the content (`googlevideo.com`) |
| Distinguishable by hostname? | **Yes** | **No** |
| Blockable by DNS? | Yes | **No** |
| Examples | Banner ads, trackers, analytics, telemetry | YouTube pre-rolls, X promoted posts |

A DNS resolver's only possible verdict is per-domain. When advertisement and content share
a domain, blocking that domain removes the service rather than the advertising. This is a
property of first-party ad delivery, not a deficiency of any particular blocklist.

**This distinction drove the entire architecture.**

---

## 3. Architecture: two-tier filtering

Two tiers were implemented, differing in coverage, capability and privacy cost.

```
                    ┌──────────────────────────────────────────┐
                    │        SecurePi Gateway                  │
   All devices ────▶│  TIER 1: DNS filtering                   │──▶ internet
                    │  655,974 rules, 5 blocklists             │
                    │  Blocks third-party ad/tracker domains   │
                    │  Zero privacy cost, no device config     │
                    ├──────────────────────────────────────────┤
   Enrolled  ──────▶│  TIER 2: Selective HTTPS inspection      │──▶ internet
   devices only     │  Decrypts allowlisted hostnames ONLY     │
                    │  Removes first-party ad scheduling       │
                    │  Requires a trusted CA on the device     │
                    └──────────────────────────────────────────┘
```

### Tier 1 — DNS filtering (all devices, no opt-in)

| Component | Choice |
|---|---|
| Resolver | DNS filter, headless, UI bound to `127.0.0.1` and never exposed |
| Blocklists | Default DNS filter list, AdAway, HaGeZi Pro, OISD Big, Peter Lowe — **655,974 rules** |
| Upstream | DNS-over-TLS to `1.1.1.1` / `1.0.0.1` |

Three firewall controls were added, because filtering is only effective if it cannot be
circumvented:

| Control | Purpose | Measured |
|---|---|---|
| DNAT of all port 53 to the gateway | Defeats hardcoded resolvers in IoT firmware | 0 attempts observed |
| DoH/DoT resolver blocking | Prevents Chrome and apps tunnelling DNS past the filter | 0 attempts observed |
| QUIC (UDP/443) rejection | Forces TLS-over-TCP so SNI stays observable | 112 packets blocked in 30 min |

The two zero results are themselves a finding: on this network, DNS filtering was **not**
being bypassed, so the persistence of YouTube ads could be attributed to the first-party
problem rather than to leakage. Ruling out the cheap explanation mattered.

### Tier 2 — selective HTTPS inspection (enrolled devices only)

`mitmproxy` in transparent mode, with **two-dimensional scoping**:

1. **By device** — an `nftables` set named `enrolled`, empty by default. Traffic from
   non-enrolled devices is never redirected to the proxy at all.
2. **By destination** — the TLS `ClientHello` is inspected *before* any decryption. Only
   allowlisted hostnames (`youtube.com`, `googlevideo.com`, `youtubei.googleapis.com`,
   `ytimg.com`) are decrypted. Every other connection is relayed as raw bytes: no
   certificate is presented, no key is held, no plaintext exists.

The certificate authority is generated on the gateway, named `SecurePi Gateway` rather
than exposing the underlying tool, with its private key held at mode `600`, root-only.

---

## 4. Implementation: removing first-party ads

YouTube signals scheduled advertisements in JSON fields within its API responses. Deleting
those fields yields a valid response describing a video with no advertising, and the
player behaves accordingly.

This is the same effect uBlock Origin achieves in-browser with its `json-prune` scriptlet;
uBO's own published rule is:

```
||www.youtube.com/youtubei/v1/player?$xhr,1p,replace=/"adPlacements"/"no_ads"/
```

uBO renames the field. The gateway deletes it. Same outcome, applied in the proxy rather
than in the page.

Two removal strategies were implemented in sequence. The difference between them is the
main engineering result of this work.

---

## 5. Principal finding: a structural sweep outperformed the curated rule list

**Attempt 1 — targeted, following uBO's published rules.** Ad-scheduling fields were
removed from the specific endpoints named in uBO's filter list, principally
`/youtubei/v1/player`. Result: almost nothing removed, advertisements continued to play.

**Diagnosis.** Instrumenting the proxy to dump real response structures showed that the
mobile web client schedules advertisements through **`/youtubei/v1/get_watch`** — an
endpoint that does not appear in uBO's rules, which are written for the desktop client.
The hardcoded path list missed it silently.

**Attempt 2 — recursive structural sweep.** Every decrypted JSON response is walked in
full. Ad-scheduling fields are deleted wherever they appear at any depth, and list entries
whose type is an advertisement renderer (`adSlotRenderer`, `inFeedAdLayoutRenderer` and
similar) are dropped. No endpoint knowledge is required.

Result, measured over one browsing session:

```
stripped 3 ad object(s) from /youtubei/v1/get_watch    x7
stripped 4 ad object(s) from /youtubei/v1/get_watch    x3
stripped 2 ad object(s) from /youtubei/v1/player       x1
blocked ad endpoint /youtubei/v1/log_event             x18
blocked ad endpoint /ptracking                         x10
blocked ad endpoint /pagead/adview                     x8
```

**YouTube pre-roll advertisements no longer play in Chrome on the enrolled device.**

### Why this matters beyond the immediate feature

Published filter rules encode the endpoints a maintainer has observed. When a client uses
a different endpoint — a different platform, a newer app version, a regional variant —
a rule list fails **silently**: no error, no warning, simply no effect. A structural sweep
requires no such knowledge and degrades gracefully.

This is a defensible general result: **for adversarial, frequently-changing targets,
structural approaches are more robust than enumerated ones.**

---

## 6. Second finding: a verification failure, and the lesson from it

The destination allowlist was implemented by setting `data.ignore_conn` in mitmproxy's
`tls_clienthello` hook. **The correct attribute in mitmproxy 12 is `ignore_connection`.**
Python does not raise on assignment to an unknown attribute — it creates a new one — so
the code ran without error, logged `PASSTHROUGH` for every non-allowlisted host, and
decrypted all of them regardless.

The bug persisted because verification relied on the addon's own log line, which proved
only that a decision had been *reached*, never that the proxy had *honoured* it.

It surfaced only indirectly, when certificate-pinned mobile applications began failing TLS
handshakes against a certificate they should never have been offered.

| | Before fix | After fix |
|---|---|---|
| Non-allowlisted hosts decrypted | **95** | **0** |
| TLS handshake failures | 97 | 1 |
| Passthrough : decrypt ratio | — | 42 : 14 |

Exposure was bounded: the proxy ran without a flow-capture flag, so no request or response
bodies were written to disk, and the journal contained request lines only — zero
credential-shaped entries.

**Lesson, stated for the report: verify a security property from the observable behaviour
of the component that enforces it, never from the intent expressed by the component that
requests it.** The correct evidence — absence of decrypted URLs for non-allowlisted hosts
— was available throughout and went unexamined.

This finding is more valuable to the report than the feature itself. It is a concrete,
first-hand example of a silent security-control failure and of how verification method
determines whether such failures are caught.

---

## 7. Results summary

| Capability | Coverage | Status |
|---|---|---|
| Third-party ads and trackers | All devices | ✅ 655,974 rules active |
| DNS bypass prevention (hardcoded, DoH, DoT, QUIC) | All devices | ✅ enforced, 0 bypasses observed |
| YouTube first-party pre-roll ads | Enrolled browser devices | ✅ blocked |
| Ad telemetry endpoints | Enrolled devices | ✅ blocked (36 in one session) |
| Feed advertisement renderers | Enrolled devices | ✅ removed |
| Non-allowlisted traffic privacy | Enrolled devices | ✅ 0 hosts decrypted |
| YouTube **app** advertisements | — | ❌ certificate pinning; out of reach by design |
| Instagram and Facebook **web** feed ads | Devices with that site switched on | ✅ removed (§13: 0/10 runs each) |
| Instagram, Facebook, X, Spotify **apps** | — | ❌ pinning; pass through with ads |
| Spotify web player ads | — | ❌ no-go (needs Widevine DRM; ads from the main API host) |
| X web ads | — | not verified (test login failed) |

---

## 8. Limitations, stated plainly

| Limitation | Cause |
|---|---|
| Mobile apps unaffected by ad removal | Certificate pinning; apps refuse a gateway certificate outright. Android 7+ additionally distrusts user-installed CAs for app traffic. Since ENHANCEMENT-PLAN.md step 5.8, a pinned app is detected after a few failed handshakes and auto-passed-through so it still *works* (with ads) rather than being left permanently broken - it just never gets ad removal |
| Browser-only, enrolled devices only | Deliberate: coverage was traded for privacy |
| Device trusts a gateway CA until removed | Inherent to interception. Must be uninstalled after the demonstration |
| Fragile against upstream change | Depends on response structures YouTube may alter without notice |
| QUIC blocked network-wide | Forces TCP fallback so traffic stays observable; a standard enterprise practice, but a deliberate degradation |
| Server-side ad insertion (SSAI) would end first-party removal entirely | Not a bug to fix - a structural boundary of the whole approach. See below |
| Instagram/Facebook removal decrypts that site's whole host for the device - inbox list and login included, in memory | The inbox list is served from the same host as the feed. Live messages are on separate, never-decrypted hosts; inbox responses are never parsed or stored (§13) |

### Server-side ad insertion (SSAI): the expected end state, not just another upstream change

The "fragile against upstream change" row above understates what SSAI specifically
would mean. Every fix this project can make - the JSON field/renderer rules (§4),
their move to a console-editable, hot-reloadable file (ENHANCEMENT-PLAN.md step 5.9) -
assumes the ad is *scheduled by a distinguishable instruction* somewhere in a response
this addon can see: a field like `adPlacements`, or a feed item tagged as an ad renderer.
Removing that instruction removes the ad because the ad was never part of the media
stream itself.

SSAI removes that assumption. It splices the advertisement into the *same* video
segments as the real content, server-side, before either ever reaches the client. There
is no longer a distinct "play this ad here" instruction anywhere in the response for a
proxy to delete - the ad **is** the content, indistinguishable at the level this addon
operates on (structured JSON responses) without decoding and re-encoding the media
stream itself, which is a different order of engineering entirely and out of scope for
a project of this size. No rule edit, however fast the console makes one now, can
restore first-party removal once YouTube serves an ad this way for a given
stream - this is a structural end state for the technique, not a bug this codebase can
be evolved out of.

**What this project does instead of pretending otherwise:** rather than silently
degrade with nobody noticing, ENHANCEMENT-PLAN.md step 5.10 adds an effectiveness
watchdog to the correlation engine (`adblock_effectiveness_signal` in
`app/correlation.py`) - if a device is actively decrypting YouTube traffic but nothing
is ever stripped from any of it over a sustained window, that is flagged as an incident
("YouTube ad removal may no longer be effective") rather than left to be discovered by
a user noticing ads have quietly come back. The watchdog cannot distinguish "YouTube
switched to SSAI" from "a format change broke the field names" by itself - both look
identical from outside (decrypting, never stripping) - but either way, the honest
signal a user or operator needs is the same one: *ad removal has stopped working, go
look*, not a dashboard that keeps reporting success on data it hasn't actually checked.

---

## 9. Suggested evaluation metrics

| Metric | Method | Result obtained |
|---|---|---|
| Blocklist size | Query the resolver API | 655,974 rules, 5 lists |
| Third-party block rate | Fixed set of ad-heavy sites, filtering on vs. off | **−83% requests, −99% tracker companies** (7.5, 240 loads) |
| First-party block rate, DNS only | YouTube with Tier 1 alone | **0%** — the measured boundary |
| First-party block rate, Tier 2 | YouTube with inspection enabled | **Effective** — pre-rolls removed (7.5: 30/30 → 0/29) |
| First-party block rate, Tier 2, Instagram web | Feed ads reaching the browser, site off vs on (§13) | **10/10 runs → 0/10** (44 ads → 0) |
| First-party block rate, Tier 2, Facebook web | Sponsored stories reaching the browser, site off vs on (§13) | **7/10 runs → 0/10** (15 → 0); breakage not excluded |
| Privacy scope | Hosts decrypted vs. passed through | 0 non-allowlisted of 56 connections |
| DNS bypass attempts | Firewall counters | 0 hardcoded, 0 DoH, 0 DoT |
| QUIC downgrade | Firewall counter | 112 packets in 30 min |

Report the two first-party figures **side by side**. A single headline percentage invites
"so why do I still see YouTube ads?" and leaves it to be answered live. Presenting 0% for
DNS alongside an effective result for Tier 2, with the reason for each, demonstrates that
the boundary was measured and understood rather than merely encountered.

---

## 10. Demonstration script

1. **Ad-heavy page, filtering off then on** — immediate, visual, needs no explanation
2. **`dig doubleclick.net`** → `0.0.0.0`, versus `dig youtube.com` → resolves normally.
   Shows precisely why a domain-level verdict cannot separate first-party advertising
3. **YouTube on a non-enrolled device** — ads present. The DNS-only boundary
4. **YouTube on the enrolled device** — ads absent. Tier 2 in effect
5. **Live gateway log** — `stripped 3 ad object(s) from /youtubei/v1/get_watch`
6. **Privacy proof** — visit any non-YouTube site; show the log records no decryption and
   no certificate was presented
7. **The pinning boundary** — YouTube in the *app* still shows ads. Demonstrating a
   documented limitation deliberately is more convincing than avoiding it
8. **A second site, switched on for one device** (§13) — on the device page, tick
   Instagram (its privacy note shows on hover): the feed's "Sponsored" posts are gone,
   the inbox still loads, and the canary still passes. Untick it and they come back

Step 6 is the one that distinguishes this from a naive interception proxy.

---

## 11. Security and ethical considerations

- Interception is **opt-in per device** and **restricted per destination**; the enrolled
  set is empty by default
- Financial, messaging and authentication traffic was verified never to be decrypted
  **for YouTube-only enrolment** (the default). A device that has Instagram or Facebook
  switched on (§13) also has that site's own host decrypted, including its inbox list
  and login - held in the proxy's memory only, never parsed or stored; live message
  delivery stays on separate, never-decrypted hosts. Each site needed its own written
  privacy review and the user's sign-off (`docs/adblock-feasibility.md`)
- No request or response bodies are written to disk
- The CA private key is root-only, mode `600`, and never leaves the gateway
- **The CA must be uninstalled from every enrolled device after the demonstration.** A
  forgotten trusted CA from a student project is a durable liability
- All testing was conducted on a dedicated project network using the author's own devices

---

## 12. Anticipated questions

**"Why not just use uBlock Origin?"** It is a browser extension with no server mode. It
works because it runs inside the browser process, after TLS termination and DOM parsing,
with access to full URLs, the DOM, and the JavaScript context. A gateway has none of
those. Its *lists* and *techniques* were reused; the software itself cannot be deployed
at a network location.

**"Isn't intercepting TLS invasive?"** Yes, which is why the scope is two-dimensional:
one enrolled device, and only YouTube hostnames decrypted. This was verified empirically —
zero non-allowlisted hosts decrypted.

**"Why does the YouTube app still show ads?"** Certificate pinning. The app rejects any
certificate not matching its embedded expectation, so it cannot be intercepted at all.
This is a deliberate boundary, not an unfinished feature.

**"Doesn't removing Instagram or Facebook ads mean reading people's messages?"** Not
reading, but they do pass through decrypted. Live messages use separate hosts
(`edge-chat.*`, `gateway.*`) that are never decrypted. The inbox *list* comes from the
same host as the feed, so on a device with the site switched on it crosses the proxy in
plaintext, in memory. The addon only parses responses to the feed's named queries, so an
inbox response passes through unparsed and unlogged. That residual exposure is why each
site is a separate, per-device, time-limited switch with its own signed-off review.

**"How do you know the privacy scope actually works?"** Because it did not, initially, and
we caught it. See section 6 — measured before and after: 95 hosts decrypted, then 0.

---

## 13. Beyond YouTube: Instagram and Facebook (October 2026)

**Approach.** ENHANCEMENT-PLAN Stage 7A (`ADBLOCK-ENHANCEMENT-PLAN.md`) turned the YouTube-only rules into **per-site modules**. A module states:
- which host(s) it may decrypt, and which hosts it must never decrypt (live-message hosts, by name);
- which endpoints and GraphQL query names it may rewrite;
- which paths it must never touch;
- how ads are marked: declarative "drop items / drop streamed documents" rules, no site-specific code.

Each site is switched on **per device**. Enrolment alone still means YouTube only. The canary checks both "every site on" and "nothing extra on" every 15 minutes.

**Feasibility** (`docs/adblock-feasibility.md`). A logged-in browser recorded only the structure of each site's traffic.

| Site | Where its feed ads are | Messages | Verdict |
|---|---|---|---|
| Instagram | feed items whose `node.ad` is set, in `PolarisFeed…` GraphQL queries and in the home page's embedded JSON; story ads on their own endpoint | separate hosts; inbox list on the feed's host | built |
| Facebook | streamed GraphQL chunks marked by `th_dat_spo`, only in `CometNewsFeedPaginationQuery` | separate hosts; inbox list on the same path, different query names | built |
| Spotify | audio breaks during playback | n/a | **no-go**: needs Widevine DRM to play; ads come from the main API host; the app pins |
| X | not observed | not observed | **not verified**: the test login failed |

**Results** (the Dell test browser through a localhost test proxy running the production addon; the gateway itself untouched):
- **Instagram:** feed ads reached the browser in 10 of 10 runs with the site off and **0 of 10** with it on (44 ads → 0, visible "Sponsored" labels 3 → 0). Posts and the inbox rendered normally.
- **Facebook:** 7 of 10 → **0 of 10** (15 sponsored stories → 0), with no page errors and the inbox rendering. Breakage can't be excluded at this sample size (one "on" run loaded no feed; not reproduced).

**On a real phone** (the A33's Chrome, through the real redirect):
- **Instagram:** ads reached the phone in 4 of 6 runs with the site off, **0 of 6** with it on.
- **YouTube:** pre-rolls on 10 of 10 videos with YouTube switched off, **0 of 30** with it on.
- **Privacy:** the scope check found 0 unexpected decryptions with Instagram on.
- **Apps:** the YouTube app plays, passed through after two failed handshakes per host. The Instagram app is untouched; it never contacts the decrypted host.

**What measuring taught**, in the spirit of section 6:
- **The first screen of a feed isn't fetched; it's embedded in the page.** A rule that only rewrote the GraphQL API left one sponsored post per load. The module now also prunes the page's embedded JSON, updating the length attribute the page checks.
- **Ad-shaped keys appear on organic content, set to null.** Matching "has key `sponsored_data`" would have dropped organic stories. The marker that held was a *non-null* `th_dat_spo`: 6 of 6 sponsored chunks, 0 of 135 organic ones.

**Boundaries:**
- **Reach:** web only. Every app pins its certificate, and Android apps don't trust a user CA at all; they pass through after two failed handshakes, with ads.
- **Privacy:** a device with a site switched on has that site's own host decrypted, inbox list and login included, in memory.
- **Measurement:** one browser and one account per site, and not through a phone's real redirect path, so mobile web may differ.

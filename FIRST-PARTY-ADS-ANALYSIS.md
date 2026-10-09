# Why SecurePi Gateway Cannot Block First-Party Ads

**Question:** is there *any* way for a network-level gateway to block YouTube video ads
or X promoted posts, and why can uBlock Origin not be integrated into the platform?

**Answer:** at the network layer, no — and the reason is an information limit, not an
effort limit. The data required to distinguish an advertisement from content does not
exist in what the gateway can observe. One technique (TLS interception) would partially
recover that data, and it is defeated in practice by certificate pinning and excluded on
privacy grounds.

---

## 1. What the gateway can actually observe

Every blocking decision must be made from information the gateway physically has.

| Layer | What is visible | Granularity |
|---|---|---|
| DNS query | `googlevideo.com` | **Domain only** |
| IP header | `142.250.67.46` | Address only, shared CDN |
| TCP header | port 443 | Nothing semantic |
| TLS ClientHello (SNI) | `rr1---sn-gwpa-cagy.googlevideo.com` | **Hostname only** |
| TLS ClientHello with ECH | *encrypted* | Nothing |
| TLS record payload | *encrypted* | Nothing |
| **URL path** (`/videoplayback?...&ad=1`) | **not visible** | — |
| **HTTP headers, body, DOM** | **not visible** | — |

The finest granularity available is **the hostname**. Every possible network-level
blocking decision is therefore a per-hostname verdict: allow all traffic to this host, or
block all traffic to this host. There is no third option.

## 2. Why that granularity is fatal for first-party ads

Measured on this gateway, from the project LAN:

```
allowed   rr1---sn-gwpa-cagy.googlevideo.com     ← video content AND ad video
allowed   rr1---sn-gwpa-cagr.googlevideo.com     ← video content AND ad video
allowed   rr3---sn-gwpa-cagek.googlevideo.com    ← video content AND ad video
BLOCKED   ads.youtube.com                        ← third-party style, blocked fine
```

YouTube delivers advertisement video segments and content video segments from the **same
`googlevideo.com` hosts, over the same TLS connection, through the same DASH manifest.**
X serves promoted posts from the **same `api.x.com` endpoint** as ordinary timeline posts,
in the same JSON response.

Since the only available verdict is per-hostname, and the ad and the content share a
hostname, the two possible outcomes are:

| Verdict on `googlevideo.com` | Result |
|---|---|
| Allow | Ads play, content plays |
| Block | **YouTube stops working entirely** |

There is no configuration of blocklists, no number of rules, and no DNS product that
changes this. It is a property of first-party ad delivery, not a deficiency of the filter.

## 3. Every approach considered

| # | Approach | Blocks first-party ads? | Why not |
|---|---|---|---|
| 1 | DNS blocklists (current) | **No** | Per-domain verdict only; ad and content share the domain |
| 2 | IP/CIDR blocking | **No** | Shared anycast CDN addresses; also serves unrelated Google services |
| 3 | SNI-based filtering | **No** | SNI carries the same hostname as DNS. Also being eliminated by Encrypted Client Hello |
| 4 | Encrypted-traffic classification (statistical) | **Detect only** | Research can *infer* ad segments from size/timing patterns, but you cannot drop a segment mid-stream without tearing down the TLS session |
| 5 | TLS interception (MITM CA) | **Partially — then fails** | See §4 |
| 6 | Transparent HTTP proxy | **No** | Everything relevant is HTTPS; without decryption a proxy sees no more than the gateway |
| 7 | Patched clients (ReVanced etc.) | Yes | Client-side, per-device, not network-level; outside project scope and legally questionable |
| 8 | **Browser extension (uBlock Origin)** | **Yes** | Works — but it is not a network technique. See §5 |

## 4. TLS interception — the only technically conceivable network approach

MITM would decrypt traffic, exposing URL paths, and in principle allow blocking ad
requests. It fails for four independent reasons, each sufficient on its own:

**Certificate pinning.** The YouTube and X mobile apps pin their expected certificates.
Presented with a gateway-issued certificate, they do not warn — they **refuse to connect
at all**. The apps simply stop working. Pinning specifically exists to defeat this.

**Platform CA restrictions.** Android 7+ does not trust user-installed CAs for app traffic
by default; iOS behaves comparably. Installing a CA on each device does not even restore
browser-equivalent visibility for apps.

**The ad is not a separable request.** Even with full decryption, YouTube ad segments
arrive through the same DASH manifest as content. Blocking them requires parsing the
manifest and rewriting the stream — deep, YouTube-specific protocol logic that Google
actively and continuously breaks. It is an arms race, not a feature.

**Privacy.** The gateway would hold plaintext for every device on the network — banking
sessions, messages, credentials. For a monitoring platform intended to *protect* users,
this is the wrong trade at any price.

This is why TLS interception appears in the project's explicit exclusion list.

## 5. Why uBlock Origin cannot be integrated

This is the question worth answering precisely, because "integrate uBO" sounds like an
engineering task and is in fact a category error.

**uBlock Origin is a browser extension.** It is not a daemon, a proxy, or a service. It
has no server mode and no network API. There is no artifact that could be installed on a
gateway.

More fundamentally, it works because of *where it runs*. Loaded into the browser's own
process, after TLS termination and after the DOM is parsed, it has:

| uBO has access to | Gateway has |
|---|---|
| Full request URL including path and query | Hostname only |
| The initiating document and frame context | Nothing |
| The parsed, live DOM, to hide elements it can actually see rendered | A response body it can inject *blind* CSS selectors into - see the correction below |
| JavaScript execution context, for scriptlet injection | The ability to inject or rewrite `<script>` tags in a response body - technically possible, deliberately not done. See the correction below |
| Per-request blocking before the request is issued | Post-hoc packet visibility only |

uBO's three main techniques each depend on information the gateway does not possess, or
capability it deliberately does not use:

1. **Network filtering** by full URL path — the gateway sees no paths.
2. **Cosmetic filtering**, injecting CSS to hide elements — the gateway *can* inject CSS
   targeting known selectors, without ever seeing the live DOM; this is weaker than uBO's
   live, DOM-aware hiding, not impossible. **Corrected 2026, see below.**
3. **Scriptlet injection**, neutralising ad logic in JavaScript — technically possible for
   a MITM proxy (it can inject or rewrite `<script>` content the same way it can inject
   CSS), but deliberately not built here: an injected script that gets something wrong can
   break the page outright, in a way this project has no way to verify without a real
   device actively browsing through the gateway. A risk-based decision, not a technical
   barrier - see the correction below.

So the barrier is not licensing, packaging, or effort. **The gateway does not have the
per-request, per-frame inputs uBO's *network-filtering* algorithm consumes** (item 1
above). Porting that specific engine would mean inventing data that doesn't exist at this
vantage point. Cosmetic and scriptlet injection are a different story, addressed below.

The correct relationship between the two is complementary, not integrated:

| Layer | Tool | Covers |
|---|---|---|
| Network | SecurePi Gateway | All devices, all apps; third-party ads, tracking, telemetry, malicious domains |
| Browser | uBlock Origin | One browser on one device; first-party ads, cosmetic elements |

Neither replaces the other. A gateway protects the smart TV and the IoT sensor that can
never run an extension; an extension handles what only in-page code can reach.

## 5.1 "uBlock Origin is open source — why not run its engine centrally?"

A reasonable objection, and partly correct. It deserves a precise answer because the
obstacle is not the one people expect.

**The engine really is portable.** uBO's static network filtering engine is close to a
pure function, and it has already been extracted for reuse: Brave's `adblock-rust` is a
standalone library built on exactly this premise, with bindings available for other
languages. Compiling such an engine into a gateway is a couple of days' work. Licensing
is not the barrier either — uBO is GPLv3, and a self-hosted deployment triggers no
distribution obligation.

**The barrier is the function's inputs.** The engine's signature is effectively:

```
verdict = match(full_URL, resource_type, originating_document, frame_context)
```

The gateway possesses none of these four arguments. Running the engine there produces a
correctly functioning matcher with nothing to evaluate. This is not an implementation
gap that more work would close; the arguments do not exist at that location.

**Can the inputs be manufactured?** Only by TLS interception — and that is a real,
shipping architecture, not a hypothetical one. The DNS filter's desktop products, `mitmproxy`
filtering plugins, and Squid with SSL-bump all do URL-level filtering centrally.

Note where those products run: **on the endpoint**, where they can install a CA into the
local trust store. Relocating the same design to a router serving mobile devices fails:

| Obstacle | Consequence |
|---|---|
| Certificate pinning in the YouTube and X apps | Apps refuse to connect; they do not degrade, they stop |
| Android 7+ CA policy | User-installed CAs are not trusted for app traffic at all |
| 15 heterogeneous devices | Manual CA installation on each; IoT devices cannot accept one |
| No DOM after MITM | Cosmetic hiding is *blind* - selectors are injected without ever seeing whether they match anything real - not impossible. **Corrected 2026, see below** |

> **Correction (2026), on the "No DOM after MITM" row above:** this originally read
> "Cosmetic filtering remains impossible." That overstated it. A MITM proxy cannot see the
> rendered DOM, so it cannot do what uBO does - observe which elements actually exist and
> hide exactly those, adapting live as the page changes. But it CAN still inject a
> `<style>` block targeting known, stable selectors (custom element tag names, in
> YouTube's case) into the HTML response before the browser ever renders it. A selector
> that doesn't match anything on a given page is a silent no-op, not a failure - which is
> exactly why this was judged low-risk enough to actually build: ENHANCEMENT-PLAN.md step
> 5.11, `inject_cosmetic_css()` in `dpi/securepi_adfilter.py`, shipped and tested. It is
> real, but strictly weaker than browser-side cosmetic filtering, not equivalent to it -
> "limited" is the accurate word this table should have used, not "impossible."

**The decisive point: even paying all of those costs does not fully achieve the goal.**
YouTube advertisement segments are not a distinct URL for a matching engine to reject.
They arrive inside the same DASH manifest as the content. Fully removing every trace of
them the way uBO's *scriptlet injection* does - rewriting JavaScript within the page -
is technically *possible* for a MITM proxy (it can rewrite any response body, JS
included, the same way this project already rewrites JSON and HTML), but was
deliberately not attempted: an injected script that gets something wrong against a
target this complex and actively-changing can break the page outright, with no way to
verify the fix short of a real device actively browsing through the gateway. That is a
risk-management decision this project made explicitly (see ENHANCEMENT-PLAN.md's record
of "Path 2" under step 5.11), not evidence that TLS interception structurally cannot
confer the capability.

| Effort | Gain |
|---|---|
| MITM proxy, CAs on 15 devices, engine port, perpetual breakage | Marginally better third-party blocking than DNS already provides |
| | **YouTube and X first-party ads: still visible** |

**Conclusion.** Centralisation is the right instinct — one control point covering every
device, including those that can never run an extension, is precisely why network
filtering is worth building. But the ceiling of centralisation is the hostname. Anything
finer requires being inside the page, and being inside the page means being on the device.

---

## 6. Verdict

**There is no way to block first-party ads at the network layer.** The distinguishing
information — which request within an encrypted, first-party stream is an advertisement —
is not present in anything the gateway can observe, and the one technique that would
partially expose it is defeated by certificate pinning and rejected on privacy grounds.

This is a boundary of the technique, and it is worth stating as one.

## 7. How to present this in the report

Report **two** ad-blocking figures, never one:

| Metric | Expected | Meaning |
|---|---|---|
| Third-party ad/tracker block rate | High | What DNS filtering genuinely achieves |
| First-party ad block rate | **0%** | The measured boundary, with the reason |

A single headline percentage invites the question "so why do I still see YouTube ads?"
and leaves you answering it live. Presenting both numbers, with §2's evidence that ad and
content share a hostname, demonstrates that the limitation was measured, understood, and
correctly attributed to the layer rather than to the implementation.

It also retroactively justifies excluding TLS interception: that exclusion is not an
omission, it is the specific technique that would be required, evaluated and rejected for
stated reasons.

---

## 8. CORRECTION - first-party ads WERE blocked, on the browser

Sections 1-6 conclude that first-party ads cannot be blocked. **That conclusion was
wrong for browser traffic, and this section supersedes it.** It is retained above
because the reasoning is correct for the DNS layer and for pinned mobile apps, and
because the correction is itself the interesting result.

### What was built and measured

Selective HTTPS inspection on the gateway: `mitmproxy` in transparent mode, redirecting
only enrolled devices, decrypting only allowlisted hostnames, and recursively removing
ad-scheduling objects from decrypted JSON responses.

**Result: YouTube pre-roll advertisements no longer play in Chrome on the enrolled
device.** Verified by direct observation and by the gateway log.

### Why the earlier attempt failed, and what actually worked

The first implementation targeted specific endpoints, using the paths named in uBlock
Origin's published filter rules - principally `/youtubei/v1/player`. It removed almost
nothing, and ads continued to play.

Measurement showed why: the phone's mobile web client schedules advertisements through
**`/youtubei/v1/get_watch`**, an endpoint absent from uBO's desktop-oriented rules. A
hardcoded path list missed it silently.

Replacing the path list with a recursive sweep - walk every decrypted JSON response,
delete ad-scheduling fields wherever they occur at any depth, and drop list entries
whose type is an advertisement renderer - caught it immediately:

```
stripped 3 ad object(s) from /youtubei/v1/get_watch   x7
stripped 4 ad object(s) from /youtubei/v1/get_watch   x3
stripped 2 ad object(s) from /youtubei/v1/player      x1
```

**The general method outperformed the curated rule list.** Published filter rules encode
the endpoints a maintainer has observed; a structural sweep needs no such knowledge and
does not silently fail when a client uses a different endpoint. This is a defensible
engineering result and worth stating as one.

### What remains true from sections 1-6

| Claim | Status |
|---|---|
| DNS filtering cannot block first-party ads | **Still true** - hostname granularity is insufficient |
| Pinned mobile apps cannot be intercepted | **Still true** - untested here, but the mechanism is unchanged |
| uBlock Origin itself cannot be integrated | **Still true** - no server mode; but its *technique* can be reimplemented |
| First-party ads cannot be blocked at all | **FALSE for browser traffic** - see above |

### Cost, stated honestly

| | |
|---|---|
| Scope | One enrolled device; YouTube hostnames only; everything else passed through undecrypted |
| Privacy | The device trusts a gateway-issued CA until removed |
| Coverage | Browser only. Mobile apps remain unaffected |
| Fragility | Depends on response structure YouTube can change without notice |

### The verification failure, which belongs in the report

The first implementation of the SNI allowlist set `data.ignore_conn`; mitmproxy 12 reads
`data.ignore_connection`. Python created a new attribute rather than raising, so the code
logged "PASSTHROUGH" while decrypting every connection - including banking and messaging
traffic. The bug was invisible for as long as verification relied on the addon's own log
line, which only proved a decision had been reached, not that the proxy had honoured it.

It surfaced only when pinned mobile apps began failing TLS handshakes against a
certificate they should never have been offered.

**Lesson: verify a security property from the behaviour of the component that enforces
it, never from the intent expressed by the component that requests it.** The correct
evidence was the absence of decrypted URLs for non-allowlisted hosts, which was available
throughout and went unexamined. After the fix: 95 non-allowlisted hosts decrypted became
0, and TLS handshake failures fell from 97 to 1.

## 9. Update, October 2026: Instagram and Facebook web too

The YouTube result generalises to sites that schedule ads with a distinguishable marker in a response the gateway can decrypt. Instagram and Facebook's **web** feeds were measured with their ads removed: 0 of 10 runs each with any ad reaching the browser (REPORT-adblocking.md §13).

Every point in sections 1-6 still holds for their **apps**: pinning, and Android's refusal of user CAs, keep app traffic out of reach. Spotify is the opposite case: its ads are audio breaks served from the same API host as everything else, behind DRM, which is the same structural boundary as YouTube's SSAI.


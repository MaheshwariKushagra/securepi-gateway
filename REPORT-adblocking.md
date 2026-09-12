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
| Resolver | AdGuard Home, headless, UI bound to `127.0.0.1` and never exposed |
| Blocklists | AdGuard DNS filter, AdAway, HaGeZi Pro, OISD Big, Peter Lowe — **655,974 rules** |
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

---

## 8. Limitations, stated plainly

| Limitation | Cause |
|---|---|
| Mobile apps unaffected | Certificate pinning; apps refuse a gateway certificate outright. Android 7+ additionally distrusts user-installed CAs for app traffic |
| Browser-only, enrolled devices only | Deliberate: coverage was traded for privacy |
| Device trusts a gateway CA until removed | Inherent to interception. Must be uninstalled after the demonstration |
| Fragile against upstream change | Depends on response structures YouTube may alter without notice |
| QUIC blocked network-wide | Forces TCP fallback so traffic stays observable; a standard enterprise practice, but a deliberate degradation |

---

## 9. Suggested evaluation metrics

| Metric | Method | Result obtained |
|---|---|---|
| Blocklist size | Query the resolver API | 655,974 rules, 5 lists |
| Third-party block rate | Fixed set of ad-heavy sites, filtering on vs. off | to be measured |
| First-party block rate, DNS only | YouTube with Tier 1 alone | **0%** — the measured boundary |
| First-party block rate, Tier 2 | YouTube with inspection enabled | **Effective** — pre-rolls removed |
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

Step 6 is the one that distinguishes this from a naive interception proxy.

---

## 11. Security and ethical considerations

- Interception is **opt-in per device** and **restricted per destination**; the enrolled
  set is empty by default
- Financial, messaging and authentication traffic was verified never to be decrypted
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

**"How do you know the privacy scope actually works?"** Because it did not, initially, and
we caught it. See section 6 — measured before and after: 95 hosts decrypted, then 0.

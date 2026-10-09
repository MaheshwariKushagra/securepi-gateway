# Tier 2 beyond YouTube: feasibility and privacy reviews

ADBLOCK-ENHANCEMENT-PLAN.md steps B0 (feasibility) and B3 (privacy review).
Captured 10 October 2026.

## Method

**Browser:** a logged-in Chromium 155 (Ubuntu's snap, headless, sandbox on) ran on the Dell, capped at 900 MB of memory. The user logged in to dedicated test accounts through Chrome's remote inspector; Claude never saw a password.

**Capture:** `tools/feasibility_capture.py` loaded each site's feed, scrolled 10 times, then opened its messages page. It recorded **structure only**:
- hosts, and request paths with the query string removed and runs of 5+ digits redacted;
- the JSON paths at which ad-looking keys or values appear;
- WebSocket hosts.

No bodies, messages or names were kept. Summaries are in `eval/results/feasibility/`.

**Not covered:** this browser was not behind the gateway. That doesn't matter for where ads are marked, but it means nothing here was measured through Tier 2.

## Results

| Site | Login | Where feed ads are marked | Messages | Verdict |
|---|---|---|---|---|
| **Instagram** | yes | `www.instagram.com /graphql/query`: a feed edge whose `node` has an `ad` object (`ad.label=ad`, `ad.items[].product_type=ad`, `ad_id`). Story ads: a separate endpoint, `/ads/igwww_ads_graphql/` | Live: WebSockets on **separate hosts** (`edge-chat.instagram.com`, `gateway.instagram.com`). Inbox list: `www.instagram.com /api/graphql`, the **same host** as the feed but a **different path** | **Go**, subject to the review below |
| **Facebook** | yes | `www.facebook.com /api/graphql/`, streamed (several JSON documents per response). A sponsored story carries `sponsored_data`, `metadata[].label=ad` and `th_dat_spo.ad_id`, often as its own streamed document | Live: WebSockets on **separate hosts** (`gateway.facebook.com`). Inbox list: `/api/graphql/`, the **same path** as the feed | **Conditional go**: rewriting must be limited by the request's query name, not its path; higher breakage risk |
| **X** | **no**: the login didn't complete (Google sign-in finished, X did not) | not observed | not observed | **Not verified** |
| **Spotify** | yes | Ads are audio breaks during playback. The web player fetches `spclient.wg.spotify.com /ads/v2/config`, and `spclient.wg.spotify.com` is also its main API host | n/a | **No-go here.** The web player needs Widevine DRM, which this Chromium lacks, so nothing plays. The tablet's Chrome 77 is too old for the current player, and the app pins its certificate. Ad breaks couldn't be observed, let alone removed |

**Common to all four:**
- **Reach is web only.** The apps don't trust a user-installed certificate (Android 7+) and also pin their own. Enrolling a phone for a site therefore means its app fails a handshake twice per host, then passes through untouched, with ads (A1's threshold).
- **Facebook's "Sponsored" label is unreadable in the page.** The capture counted 0 visible labels on Facebook because it scrambles that text; Instagram showed 2 per scroll. Measuring Facebook ads must therefore count sponsored stories in the responses, not on screen.

## Rules each go site would need

**Instagram:**
- `decrypt_suffixes: ["www.instagram.com"]` only: not `instagram.com`, and no CDN (`*.fbcdn.net`, `static.cdninstagram.com`).
- `passthrough_suffixes: ["edge-chat.instagram.com", "gateway.instagram.com"]`.
- `json_endpoints: ["/graphql/query"]`, with a prune operation that drops a feed edge whose `node` contains `ad`.
- `blocked_paths: ["/ads/igwww_ads_graphql/"]`.
- `never_touch_paths: ["/api/graphql", "/direct/", "/accounts/", "/api/v1/"]`: not rewritten, not logged, no path stored.

**Facebook:**
- `decrypt_suffixes: ["www.facebook.com"]` only.
- `passthrough_suffixes: ["gateway.facebook.com", "edge-chat.facebook.com"]`.
- Rewrite `/api/graphql/` responses **only** when the request's `x-fb-friendly-name` header names a news-feed query (names to be confirmed from a capture). Every other GraphQL response, the inbox included, passes through unparsed.
- Remove a streamed document whose story carries `sponsored_data`.
- Needs NDJSON-aware rewriting in the addon (planned in B1, second half).

## Privacy reviews (B3)

**Signed off by the user on 10 October 2026:** Instagram approved; Facebook approved, to be built after Instagram. X stays "not verified". Measurement on the tablet.

### Instagram

**What would be decrypted:** every HTTPS request from an enrolled device to `www.instagram.com`. That includes:
- the feed;
- the inbox **list** (conversation names and previews, via `/api/graphql`);
- the login request, if the person logs in while enrolled.

None of it is decrypted for any other device, or for this device once its enrolment ends (24 h by default).

**What would not be decrypted:**
- live message delivery (`edge-chat.instagram.com`, `gateway.instagram.com`: carved out by name and checked by the canary);
- photos and video (CDN hosts);
- every other site.

**What would be read or changed:** only responses on `/graphql/query` (the feed), and only to drop items marked as ads. Plus one blocked path, `/ads/igwww_ads_graphql/`.

**What would be stored:**
- per connection: the decision, with host name and time;
- per removal: a count;
- the blocked ads path.

No other paths, no bodies, nothing from `never_touch_paths`.

**Residual risk:** inbox previews and login credentials exist in plaintext in the proxy's memory while they pass through. Someone who controlled the gateway at that moment could read them. This is the same kind of exposure YouTube has today, but YouTube carries no private messages.

**Recommendation:** acceptable for a deliberate, per-device, time-limited test. Not as a default.

### Facebook

The same as Instagram, with two differences:
- **The inbox shares the feed's path**, so the addon has to look at a request header to leave inbox responses unparsed. A mistake in that gate would mean parsing, though still not storing, message-list responses.
- **More of Facebook runs over `www.facebook.com`** than Instagram's equivalent: Marketplace, groups, notifications and settings would all be decrypted, though not touched.

**Recommendation:** go only if the user accepts the larger decrypted surface. Build it after Instagram, reusing its framework.

## Still open

- **X:** the login didn't complete. It can be retried (a username and password works better than Google sign-in from a remotely controlled browser), or X can stay "not verified".
- **Measurement device:** the user chose the tablet. Its Chrome 77 loads all three sites' login pages, so measuring needs the test accounts logged in **on the tablet**. Mobile web may also mark ads differently from desktop, so the structure needs one more capture there before rules are written.
- **App behaviour (B0 part d):** needs each app on an enrolled phone. Expected: 2 failed handshakes per host, then passthrough.

## Built and measured (10 October 2026)

Both go sites were built as modules (rules version 7 on the gateway), switched on for no device by default. They were measured with this same browser through a localhost test proxy running the production addon (`EVALUATION-RESULTS-2.md`, Stage 7A, phase C):

| Site | Runs with ads reaching the browser, off → on | Notes |
|---|---|---|
| Instagram | 10/10 → **0/10** (44 ads → 0) | Needed a second rule: the first screen of the feed is embedded in the home page |
| Facebook | 7/10 → **0/10** (15 → 0) | Marker is a non-null `th_dat_spo`; breakage not excluded at this sample size |

**Changes to the rules above, made before the counted runs:**
- Both modules gained `html_json_pages: ["/"]`.
- Both have `query_names` set: Instagram `PolarisFeed`, Facebook `CometNewsFeedPaginationQuery`.
- Facebook's prune keys on `th_dat_spo`, not `sponsored_data`.


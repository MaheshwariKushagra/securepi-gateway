# Ad-blocking enhancement plan (before Stage 8)

*Approved 9 October 2026. Runs before Stage 8 of `ENHANCEMENT-PLAN.md`; progress is tracked in that file's §8.*

## Context

Ad blocking has two tiers:
- **Tier 1:** DNS filtering for every device.
- **Tier 2:** opt-in HTTPS inspection that removes YouTube's own ads in the browser.

The 7.5 benchmark showed both work:
- Tier 1: −83% requests, −99% tracker companies, 0/48 sites broken.
- Tier 2: pre-rolls 30/30 → 0/29.

It also found specific gaps:
- 5.8's pin bypass doesn't rescue a YouTube app version that retries only twice.
- Turning inspection on mid-session doesn't take effect until the browser reconnects, and the console doesn't say so.
- The cosmetic CSS (5.11 Path 1) is built but switched off and has never been checked on a live page.
- The privacy canary checks only the add-on's decision, not the real redirect path.
- OISD Big and AdAway add 0.6% between them.
- VPNs bypass everything without being noticed.

The user wants these gaps closed **before Stage 8**. They also want a **feasibility check, then an attempt to extend Tier 2 to Instagram, X, Facebook and Spotify**. Stage 8's report and demo then describe the improved system.

### Ground truths that shape the expansion
Recorded so the feasibility step tests them rather than assumes them:

1. **Only browsers can be reached.** Android 7+ apps don't trust user-installed CAs, and the four apps pin as well. Expected reach for every new site is the **web version in a browser on an enrolled device** (mobile Chrome or the Mac). The apps must keep working, with ads, through passthrough.
2. **Each new host carries private content.** Today only YouTube hosts are decrypted. `x.com`, `instagram.com` and `facebook.com` also carry logins and, possibly, DMs. Decrypting them means private messages could pass through the proxy in plaintext, in memory. This is why stretch S.5 requires a **written privacy review per site** before any of them is decrypted.
3. **The add-on is YouTube-shaped.** Its rules are global:
   - `decrypt_suffixes`, `ad_fields`, `ad_renderers`, `blocked_paths`, cosmetic selectors.
   - `response()` sweeps *every* JSON body on *every* decrypted host.

   For social sites that is unacceptable. Rules must be scoped per site and per endpoint, and must never touch or log messaging paths.
4. **Licence.** The implementation stays our own. No uBO scriptlet code (GPLv3), as decided in 5.11.

---

## Phase A — Close the measured gaps (~2 days)

| # | Work | Files | Exit criteria |
|---|---|---|---|
| A1 | **Configurable pin bypass.** Move `PIN_FAILURE_THRESHOLD`/`PIN_BYPASS_HOURS` into the rules file (hot-reloaded, validated). Default threshold 2, with per-site override later in B1. Check on the gateway whether `data.client_hello` exposes ciphers and extensions; if it does, record a browser-vs-app ClientHello fingerprint as telemetry only (input to B4) | `dpi/securepi_adfilter.py`, `dpi/adfilter_rules.py`, `tests/test_adfilter.py` | Tests cover threshold from rules. On the A33, the YouTube app plays after ≤2 failures per host and Chrome YouTube stays ad-free |
| A2 | **Reconnect hint.** On enroll, the console says "Takes effect for new connections: restart the browser or wait a few minutes". Also in `securepi enroll` output | `app/templates/` (filtering/device page), `app/static/app.js`, `gateway/securepi` | Shown on enroll; wording matches the 7.5 finding |
| A3 | **Cosmetic CSS, verified live.** On the A33's Chrome (enrolled, deliberately), check every `cosmetic_selectors` entry against real youtube.com and drop dead ones. Enable it, then run the 7.5 YouTube check (`tools/youtube_tier2.py`, 30 videos) plus a 10-video breakage pass | `dpi/adfilter-rules.json`, rules on gateway via console | Empty ad boxes gone, 0 breakage in 10 videos, pre-roll result unchanged (0/N) |
| A4 | **Trim lists using the measurements.** Show the user the 5.4 data: OISD Big + AdAway = 0.6%, HaGeZi Pro = 21.3%. **If they agree**, disable OISD Big and AdAway through the console. Measure DNS-filter memory and refresh time before and after | live config only; record in `EVALUATION-RESULTS-2.md` | Decision recorded. If applied, memory delta measured and `doubleclick.net` still blocked |
| A5 | **Scope check through the real redirect, by hand, per deploy.** A script runs on an enrolled real device that the user enrolled on purpose, never on a timer. It loads a host list and asserts the certificate issuer: SecurePi only for decrypt hosts; real issuer for everything else, including near-miss names. Reuses the issuer capture in `tools/tls_latency_tablet.py`. Continuous coverage still needs a dedicated test SSID/namespace on `ap0`; that stays deferred, as recorded in 5.7's follow-up | new `tools/scope_check_device.py` | Passes for the current YouTube scope. Becomes a required gate after every B/C deploy |
| A6 | *(Optional)* **VPN visibility.** A low-severity, informational device flag (not an incident) for a long-lived UDP flow to one address with a WireGuard/OpenVPN handshake shape, from IDS flow records. Closes the matrix's "detected: no" | `app/correlation.py`, `tests/test_correlation.py` | The bypass_vpn.py WARP packets produce the flag; the 7.2 battery shows no new false positives |

## Phase B — Feasibility and framework (~3 days)

| # | Work | Exit criteria |
|---|---|---|
| B0 | **Feasibility study per site**, written to `docs/adblock-feasibility.md`. For each of X, Instagram, Facebook and Spotify (web), on a **dedicated test account** (the user logs in; Claude never handles passwords), record:<br>(a) hosts the web app uses;<br>(b) where sponsored items appear: endpoint, response format (JSON / NDJSON / streamed multipart), the marker that identifies an ad (e.g. X timeline entries with promoted metadata, Instagram/Facebook feed items flagged as ads or sponsored, Spotify ad-break endpoints);<br>(c) whether DMs, chat and login use **separate hosts** (which can stay in passthrough) or the **same host**;<br>(d) app behaviour when its hosts are enrolled (handshake-failure count, so A1's threshold covers it);<br>(e) ad-blocker detection and breakage risk;<br>(f) ToS note. Responses are captured only into the scratchpad, redacted, and never committed | One row per site with a **go / no-go** and the reason |
| B1 | **Per-site rule modules.** Rules file v2: `modules: {youtube: {...}, x: {...}, ...}`. Each module has:<br>- `decrypt_suffixes`, `passthrough_suffixes` (explicit carve-outs such as chat hosts);<br>- `json_endpoints`: the only path prefixes whose responses may be rewritten;<br>- `never_touch_paths`: messaging and login paths, which are not rewritten or logged and have no path stored;<br>- a small declarative prune spec: `drop_keys`, `drop_items_with_keys`, `drop_items_where {key: prefix}`;<br>- `blocked_paths`, `cosmetic_selectors` and pin threshold.<br>Migrate the existing global rules into the `youtube` module unchanged. `validate_rules` keeps v1 files loading | `make test`: existing 46 addon tests still pass; new fixtures for each prune op; a v1 file still loads; the YouTube benchmark result doesn't change |
| B2 | **Per-device, per-site enrolment.** Today enrolment is per device (nft `enrolled` set) and the site choice is global. Add a device → modules map, written by the root helper to a file the add-on hot-reads. `tls_clienthello` decrypts only if the SNI matches a module **enabled for that device**. Console: one toggle per site on the device page, each showing that site's privacy summary from B3. Changes go through the orchestrator and audit log | `app/dpi_enroll.py`, `gateway/securepi-web-helper`, `app/webapp.py`, device template | Device with only YouTube enabled: x.com passes through (issuer check, A5). With X enabled: decrypts |
| B3 | **Written privacy review per go site** (S.5 requirement), as a section of the feasibility doc. Covers what is decrypted, what is logged (path prefixes only, never `never_touch_paths`), what transits in memory (e.g. DMs on a shared host), and the residual risk. **The user approves each review before that module ships** | Signed-off review per site |
| B4 | **Privacy canary extended.** `dpi/privacy_canary.py` iterates every module: each decrypt host must decrypt (when enabled); each `passthrough_suffixes` entry, sibling and near-miss name must not, and the same for a device with the module disabled. If B0 found a reliable app fingerprint, add a pre-handshake passthrough for non-browser clients so apps never see a failed handshake | Smoke test: deleting one carve-out triggers fail-safe within one cycle |
| B5 | **Telemetry and watchdog per site.** Add `module` to `dpi_events` and ingest. Console Tier 2 panel broken down by site. Generalise `adblock_effectiveness_signal` (`app/correlation.py:1504`) to per (device, module) | Panel shows per-site counts; watchdog test fires for a module with traffic but zero strips |

## Phase C — Per-site modules, go sites only (~1–1.5 days each)

Expected order, easiest first. B0 confirms it:
1. **X:** cleanest JSON markers.
2. **Instagram web.**
3. **Facebook web:** obfuscated and streamed GraphQL, which needs NDJSON / multipart-aware parsing in `response()`.
4. **Spotify web player:** audio ads; least certain, and may stop at "no-go".

For each site:
- Write the module rules and fixture tests built from redacted captured shapes.
- Deploy with the module **off**, then enable it on one device.
- Run A5's scope check, including DM/chat hosts and near-miss names.
- Measure.
- Record results and limits in `EVALUATION-RESULTS-2.md` and the report.

**Measurement method (same as 7.5):**
- **Setup:** the Mac on SecurePi-Test with the CA trusted, Playwright with saved logged-in state for the test account (git-ignored), module off vs on.
- **Ad count:**
  - Feed sites: N=30 feed loads with fixed scroll depth, counting items labelled Sponsored / Promoted / Ad in the DOM.
  - Spotify: ad breaks over a fixed playlist.
  - Report the rate with a 95% Wilson interval.
- **Breakage checklist:** feed loads, a post/tweet opens, video plays, search works, **DM inbox loads and sends**, login/logout works.
- **App check on the A33:** the app still works after ≤ threshold failures.
- **Watchdog:** removing the module's marker rule makes the watchdog fire.

**Stop rule per site:** any of the following → the module stays off and the result is written up as a finding (like SSAI for YouTube):
- breakage that can't be fixed in one rule iteration;
- detection by the site;
- a DM path that can't be carved out and that the privacy review rejects.

## Phase D — Fold into Stage 8 inputs (~0.5 day)

- Update `REPORT-adblocking.md`:
  - the results table and limitations;
  - a per-site table (reach = web only; apps pass through);
  - privacy-review summaries;
  - feasibility no-gos with reasons.
- Update `FIRST-PARTY-ADS-ANALYSIS.md` and the 8.3 demo script: per-site toggle, canary covering every module, unbreak in 30 s.
- Update the 8.4 close-out: remove test-account sessions and saved logins, and disable all modules.
- Commit and push after each phase.

## Prerequisites from the user
- Dedicated test accounts for X, Instagram, Facebook and Spotify (free tier, to get ads). The user logs in themselves.
- The A33 rejoined to SecurePi-Test, with auto-reconnect to Babu_Home off, for A1, A3, A5 and the app checks.
- A yes/no on A4's list trim, and sign-off on each B3 privacy review.

## Verification (end to end)
- `make test` on the Mac: addon fixtures per module, rules v1→v2 migration, correlation watchdog, VPN flag.
- `make deploy`, then `sudo securepi status`. The privacy canary is green for every module, and the smoke test (deleting a carve-out) fails safe.
- After each deploy, A5's device scope check: the issuer is SecurePi only on enabled decrypt hosts.
- Regression: rerun the YouTube Tier 2 check (30 videos) and one Tier 1 benchmark pass (`tools/bench_run.sh`, tier1 condition) to confirm nothing regressed.
- Per-site numbers and the breakage checklist, as in Phase C, recorded in `EVALUATION-RESULTS-2.md`.

**Estimate:** A ~2 d, B ~3 d, C ~1–1.5 d per go site, D ~0.5 d. About 9–12 days if all four sites pass feasibility; fewer if any are no-go.

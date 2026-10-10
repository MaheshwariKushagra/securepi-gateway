# Audit10Oct remediation plan (Stage 7B, before Stage 8)

*Written 10 October 2026. Triage of `Audit10Oct.md`, a static, read-only
audit made with OpenAI Codex. Runs before Stage 8 of `ENHANCEMENT-PLAN.md`.
Progress is tracked in that file's §8. Nothing in this file has been
implemented yet.*

## How this triage was done

Every finding was checked against the code at the cited lines, on commit
`0707bcb`. The auditor did not run anything, so two things were run here:

- **Test baseline:** `make test` → **641 tests, all passing** (6 s on the Mac).
  `py_compile` is clean for `app/ dpi/ gateway/ tools/`.
  `node --check app/static/app.js` is clean. `shellcheck -S warning` is clean
  for the three deploy scripts this plan touches.
- **C2 reproduced in memory.** `_domain_matches()` was given a rule and an
  enrolled IP that the backend "deleted" but kept:
  - with the previous ownership record, verification fails (correct);
  - with the new record, which is what the code passes today, it passes.

This repo has no `CLAUDE.md`. The standing constraints in
`ENHANCEMENT-PLAN.md` ("How to follow this plan") apply instead:
- plain, synchronous, commented Python;
- the gateway has 3.6 GiB of RAM;
- inspection stays opt-in, narrow and verified;
- the Mac is the development machine.

Verdicts:
- **ACCEPT:** the finding and its suggested fix are both right.
- **MODIFY:** the problem is real, but a different fix fits better.
- **REJECT:** the finding is wrong, by design, or not worth the churn now.

The severity column shows the audit's rating, then ours where it differs.

## Triage summary

### Critical and high

| ID | Finding | Severity | Verdict | Why |
|---|---|---|---|---|
| C1 | Inspection scope fails open (`_sites_for` falls back to YouTube); a failed site-map write reports success; nft is changed before the map | Critical | **MODIFY** | Confirmed at `dpi/securepi_adfilter.py:503` and `app/orchestrator.py:403-443,964-988`. "Never more decryption, only less" stopped being true when 7A added Instagram-only enrollment. The audit's one-line patch is right but incomplete. The map write, its read-back and revocation also need fixing, and the CLI enroll path depends on the fallback (it's adopted within one cycle, see 7B.2) |
| C2 | Removal verification uses the new ownership record, so leftovers pass | Critical | **ACCEPT** | Confirmed at `orchestrator.py:1057,1377` and reproduced. Rollback is not read back either. The audit's "save ownership only after verifying" is already the case (`_save_applied` runs only when `error is None`) |
| H1 | DNS-filter failure in `desired_state()` blocks every domain, quarantine included, and raises no incident | High | **ACCEPT** | Confirmed at `orchestrator.py:678-735,1350-1354,1409`. It also means a console quarantine fails and rolls back while the DNS filter is down |
| H2 | DNS backlog past 20×500 records is lost when the watermark jumps | High → **Medium** | **ACCEPT** | Logic confirmed at `ingest.py:838-883`. Measured volume is about 8,000 events/day, so it needs a multi-day ingest gap or a flood |
| H3 | One structurally bad record stalls its source; a bad timestamp becomes "now" | High → **Low** | **MODIFY** | Confirmed. `run_step` already isolates sources, and the producers are our own addon and Suricata. A per-record try/except with a counter is enough; no schema validator |
| H4 | Sync SQLite in async auth middleware can freeze the event loop. Health and intel hold write locks across subprocess and network calls | High | **ACCEPT** | Confirmed at `webapp.py:149-165`, `health.py:117-135,305-315` and `intel.py:202-227`. `run_in_threadpool` is already used in `/login` |
| H5 | Concurrent logins pass the rate check before failures are recorded; the body is unbounded | High → **Medium** | **MODIFY** | Confirmed. The fix is simpler than "atomic reservation": record the attempt before the `await`. The handler runs on one event loop, so check plus insert with no `await` between them is already atomic. Add a size cap |
| H6 | A login racing a password change can survive revocation; rehash can overwrite a new password | High → **Low** | **MODIFY** | Real but needs sub-second timing and the old password. Re-read the file after verifying instead of adding a credential-generation scheme |
| H7 | Hostname merge can move enrollment, profiles and exceptions to another physical device | High → **Medium** | **MODIFY** | Confirmed at `registry.py:195-206`. Default hostnames ("iPhone", "Galaxy-A33-5G") collide by accident, not only by attack. But "every new MAC is a new device" would break randomization continuity. Narrow the merge instead |
| H8 | A partial DNS fail-open leaves a UDP bypass after recovery because recovery trusts the DB flag | High | **ACCEPT** | Confirmed at `dns_failopen.py:103-111` and `health.py:390-394`. Filtering stays silently bypassed |
| H9 | mitmdump's default flow output can write decrypted request URLs to the journal | High | **ACCEPT** | `deploy-dpi.sh:52` sets no `flow_detail`, and nothing in the repo does. Read-only check on the gateway first |
| H10 | The DPI rule editor drops module fields it doesn't own | High → **Low** | **ACCEPT** | Confirmed at `webapp.py:2131-2147`. Latent: the edited `youtube` module has none of those fields today. The privacy confirmation should also cover `passthrough_suffixes` |

### Medium

| ID | Finding | Verdict | Why |
|---|---|---|---|
| M1 | Enrollment extension doesn't renew the kernel timeout | **ACCEPT** | Confirmed. `_converge_enrolled` skips IPs already present, and verification checks presence only. At the old expiry the policy ends as "removed outside the console" and raises a false drift incident |
| M2 | Privacy canary replaces `_sites_for`; canary unit not in `services.list` | **MODIFY** | Confirmed at `privacy_canary.py:169`. Make it drive the real loader against a temp map, and add the unit to `services.list`. Staleness is already shown in the console (`PRIVACY_SCOPE_STALE_AFTER`). A live probe of the running proxy is deferred |
| M3 | Engine `run_step` doesn't roll back; helpers commit internally | **MODIFY** | Add the rollback that ingest and correlation already have. Leave `audit.log()`'s own commit alone, since changing it touches every endpoint |
| M4 | Serial notification sends can delay the engine cycle | **MODIFY** | A per-channel "failed once, skip for this cycle" rule plus a per-cycle time budget. No separate worker |
| M5 | Large decrypted responses are fully buffered and decoded | **ACCEPT** | Confirmed: no `responseheaders` hook, and `googlevideo.com` is in scope. Stream non-rewritable content types |
| M6 | An all-ad streamed response goes through unchanged (`if removed and docs`) | **MODIFY** | Confirmed at `securepi_adfilter.py:867`. Don't invent an "empty" GraphQL body. Fall back to in-document pruning, checked against a captured fixture |
| M7 | Parent/child decrypt suffixes across modules are accepted | **ACCEPT** | Confirmed at `adfilter_rules.py:365-374`. No overlap exists today. Cheap validation |
| M8 | DNS-over-QUIC (UDP 853) is allowed; IPv6 needs explicit treatment | **ACCEPT** (UDP 853) / **REJECT** (IPv6, unless forwarding is on) | UDP 853 falls through to `lan-out`. IPv6: one read-only sysctl check |
| M9 | Firewall logging and journal reads have no volume bound | **MODIFY** | Measure first. Change only if `quic-blocked` volume is material. Journal reads already advance past every kernel line |
| M10 | `attribute_events(limit)` is unused, and unmatchable events are rescanned forever | **MODIFY** | Use a time window instead of a batching scheme, and remove the dead parameter |
| M11 | Device and incident listing scale with history | **REJECT** (for now) | 7.8 measured `/api/devices` at 124/462 ms (p50/p95) and incidents at 43-122 ms. Incidents are bounded by retention. Revisit if volume grows |
| M12 | Console polls overlap; stale incident responses win; page timers ignore Live | **ACCEPT** | Confirmed at `app.js:117-126,3051,3229,3782,3957` |
| M13 | Background polling keeps sessions alive past the idle timeout | **ACCEPT**, needs your decision | Idle is 30 min and absolute is 12 h, so an unattended tab stays signed in for 12 h. Recommended: timer-driven polls don't count as activity |
| M14 | Dashboard "open" counts exclude `investigating` | **ACCEPT** | `webapp.py:779,872` use `status='new'`; `risk.LIVE_STATUSES` includes investigating |
| M15 | Correlation matches indicators of any age | **ACCEPT** | `correlation.py:787` has no freshness condition, but the blocklist does (`intel.py:181`). This causes high-severity false positives on cleaned-up sites |
| M16 | CSV export allows formula injection | **ACCEPT** | Hostnames are device-controlled (DHCP) |
| M17 | Blocklist utility builds a remote shell string from a URL | **ACCEPT** (Low) | Needs an admin-controlled URL, but quoting is a one-liner |
| M18 | DPI and canary deploy scripts don't restart running units | **ACCEPT** | `enable --now` doesn't restart. mitmproxy hot-reloads the addon file, but unit-file changes and the canary script need a restart |
| M19 | Privilege setup hardens directories, not the files in them | **ACCEPT** (Low) | Files arrive root-owned via `sudo rsync --no-owner`, so this is a check rather than a known hole |
| M20 | Chaos tool ignores the undo timer's return code and cancels before verifying | **ACCEPT** (Low) | Matters again if the 8.3 demo runs chaos scenarios |
| M21 | `evaluate.py` measures latency after the attack ends; it maps 10.10.0.1 to the attacker | **MODIFY** (latency) / **REJECT** (mapping) | The 7.2 headline numbers come from `battery.py`, which measures from start, so annotate the old numbers instead. The 10.10.0.1 → test-attacker mapping is deliberate and documented (`battery.py:33-36,618`) |
| M22 | Declared foreign keys are not enforced | **REJECT** | Turning it on changes delete behaviour on a live database for little gain in a single-writer appliance. An optional one-off `PRAGMA foreign_key_check` is noted |
| E1 | Incident retention builds one large `IN (...)` list | **ACCEPT** (Low) | A subquery removes the limit; the project is under a year old, so this is latent |
| E2 | `heldout_replay` divides by zero exposure | **ACCEPT** (Low) | Trivial guard |

### Cleanup, tests, architecture

| ID | Finding | Verdict | Why |
|---|---|---|---|
| Q1 | Shared transport and nft parser for quarantine, firewall sets and DPI enroll | **REJECT** | Three small, separately tested modules on the enforcement path. Merging them adds coupling and no behaviour change |
| Q2 | Two schema authorities (`SCHEMA_MIGRATIONS` and `schema.sql`) | **MODIFY** | No migration framework. Add a test that a migrated database has the same columns as a fresh one |
| Q3 | Demo loader rewrites `webapp.py` source | **REJECT** | Demo-only screenshot tool, works, isolated. An app factory would refactor production constants |
| Q4 | Unused `placeholders` in `fingerprint.py:193` | **ACCEPT** | Confirmed dead |
| Q5 | Stale "stopgap" docstring at `webapp.py:2121-2123` | **ACCEPT** | The audit log exists and is called three lines below |
| Q6 | README badge says 362 tests, table says 641 | **ACCEPT** | 641 confirmed today |
| Q7 | No Python dependency manifest | **ACCEPT**, folded into 8.2 | Capture the gateway's two environments (`pip freeze`) as part of the installer step |
| T | Fake backend deletions always succeed; tests encode the YouTube default and accept reset failure | **ACCEPT**, inside 7B.1 and 7B.2 | These are the tests that hid C1 and C2 |
| A | Split `webapp.py` (3,452 lines) and `app.js` (4,142 lines) | **REJECT** (for now) | No defect. It conflicts with the plain, linear-file preference, and Stage 8 is documentation |

## The plan (Stage 7B)

The order below follows the severity of the verified findings. The groups are:
1. Consent and enforcement.
2. Privacy and security.
3. Reliability.
4. Correctness and data quality.
5. Tooling and docs.

Each step is small enough to be one commit.

### Rules for every step

These are the master plan's rules plus a few specific to this stage.

1. **Prove the defect first.** Each fix starts with a test that fails on the
   current code, then the change that makes it pass.
2. **Run the gate after each group** (and after any step that is deployed on
   its own):
   - `make test`: all pass. 641 today, plus the new ones.
   - `python3 -m py_compile` on every changed Python file.
   - `node --check app/static/app.js` if the JS changed.
   - `shellcheck -S warning` on any changed shell script (all clean today).
   - `sudo nft -c -f gateway/nftables.conf` on the gateway before any firewall
     load, with the runbook's lockout insurance.

   The project has no linter or type checker. Adding one is out of scope here.
3. **Deploy as usual.** Take a `.bak-` copy first. App code goes out with
   `make deploy`, and DPI files through `dpi/deploy-dpi.sh` once 7B.2 makes
   it restart properly. Then run `sudo securepi status` and the step's live
   check.
4. **Close the step.** Write a short plain-language note, put any results in
   `EVALUATION-RESULTS-2.md`, update the §8 tracker, then commit and push
   with no attribution trailer.
5. **No new attack traffic against real devices.** Live failure-path checks
   use the test harness, or the fake backends where a live check would
   disrupt the network. Those cases are marked below.

### Group 1: Consent and enforcement (Critical, about 2 days)

**7B.1 Removal verification checks what used to be managed (C2, T)**
- `_apply_and_verify` and the reconcile re-check pass the previous `applied`
  record to `_domain_matches`, not `new_applied`.
- After a rollback, read every restored domain back and compare it with the
  snapshot:
  - "rolled back, nothing was changed" is reported only when they match;
  - otherwise report "partly rolled back: <domains> still differ" and raise
    the existing `policy_enforcement_failed` incident.
- The `FakeBackends` in `tests/test_orchestrator.py` get a "sticky" mode in
  which `unenroll`, `mac_del`, `ip_del` and rule removal return normally but
  change nothing.
- New cases:
  - removed DNS rule still present;
  - unenrolled IP still present;
  - client not restored to standard;
  - rollback that doesn't take.
- *Exit:* the new cases fail on `0707bcb` and pass after; nothing else changes.

**7B.2 Unknown scope means no inspection (C1, M2, M18, T)**
- **Addon:**
  - `_sites_for()` returns `[]` for a missing or unreadable map, an absent
    device or an empty list. Update the docstring and the `SITE_MAP_PATH`
    comment.
  - `request()` and `response()` re-check the flow's module against the
    device's current sites, and skip (no rewrite, no telemetry) when it is
    no longer switched on. A revoked site then stops being touched even if
    the connection reset fails.
- **Orchestrator:**
  - `write_site_map()` raises a new `SiteMapError`, added to
    `BACKEND_ERRORS`, instead of printing and returning `[]`. A failed write
    then rolls back or shows on the policy.
  - `_converge_enrolled` writes the map *before* adding new IPs to the nft
    set, and only after removing ones that leave.
  - Verifying the `enrolled` domain also reads the map back and compares the
    sites.
  - A failed `reset_https` during a revocation goes into the policy's
    `last_error`, and the next reconcile retries it.
- **Before deploying the addon:** confirm on the gateway that
  `/var/lib/securepi-dpi/device-sites.json` has an entry for every IP in
  `sudo securepi status`. If one is missing, that device stops being inspected
  when the new addon loads.
- **CLI:** `securepi enroll` still works. Reconcile adopts the IP within one
  cycle and writes its YouTube entry; until then there's no inspection. Say
  so in the CLI's usage text.
- **Canary:** stop replacing `_sites_for`. Write a temporary map for the
  synthetic device and point the freshly imported addon's `SITE_MAP_PATH` at
  it. Add the cases missing map, corrupt map, device absent and empty list:
  each must decrypt nothing. Add `securepi-privacy-canary` to
  `app/services.list`.
- **Deploy scripts:** `deploy-dpi.sh` and `deploy-privacy-canary.sh` use
  `enable` followed by an explicit `restart`.
- **Tests:**
  - `test_default_is_youtube_only` becomes `test_unknown_device_is_not_inspected`;
  - add a failed map write, ordering, and revocation with a failing reset;
  - add the canary cases.
- **Live (A33, per the 7A protocol):**
  - YouTube-only enrollment: pre-rolls are still removed.
  - Switch to Instagram-only: YouTube shows `passthrough` lines within
    seconds.
  - With the map moved aside, every SNI passes through.
  - The canary is green after its restart.

**7B.3 Extending an enrollment renews the kernel timeout (M1)**
- In `_converge_enrolled`, an IP that is still present but whose kernel
  timeout is shorter than the policy's remaining time is re-added with the
  new hours. That renews a live enrollment. It does not re-enable one:
  `_reconcile_enrolled` still runs first and ends flushed ones.
- Enrollment verification checks the remaining seconds the way
  `_set_matches` does.
- Tests:
  - extension renews;
  - an IP flushed after a privacy flush is still not re-added;
  - shortening needs no renewal.
- *Live:* on the test device, enroll for 1 h, extend to 3 h, and check that
  `nft list set ip nat enrolled` shows about 3 h.

**7B.4 Firewall enforcement doesn't depend on the DNS filter (H1)**
- In `desired_state()`, the DNS-filter calls (`clients()`, `catalog()`) can
  fail without failing the whole call. On failure, the `rules` and `clients`
  domains are marked unavailable. `macs`, `ips` and `enrolled` are still
  computed.
- `reconcile()` records the unavailable domains as per-domain errors ("DNS
  filter unreachable"), so the existing `policy_enforcement_failed` incident
  fires. A failure that is neither per-domain nor a per-domain error is also
  included in the incident text.
- `create_policy("quarantine")` no longer fails because the DNS filter is
  down.
- Tests:
  - a fake backend whose `clients()` and `catalog()` raise;
  - a quarantine still applied and verified;
  - the incident names DNS rules and clients.
- *Live:* only the normal path (quarantine and release the test-harness
  device). Running the failure path live means a DNS outage. That waits for
  your OK, as a repeat of 7.7's "DNS filter down" scenario.

*Group 1 gate*, then deploy.

### Group 2: Privacy and security (High, about 1½ days)

**7B.5 No request URLs in the proxy's journal (H9)**
- Read-only check first:
  `sudo journalctl -u securepi-dpi --since -14d | grep -cE '(GET|POST) https?://'`.
- Add `--set flow_detail=0` to the mitmdump `ExecStart` in `deploy-dpi.sh`.
  The addon's own `logger` lines are unaffected. Then restart.
- *Live:* load a YouTube URL with a unique query token from the Dell test
  browser. Zero journal hits for the token.
- If the check finds old URL lines, purging the journal is destructive and
  waits for your OK. Step 8.4 already plans a purge.

**7B.6 DNS fail-open recovery uses the live firewall state (H8)**
- `activate()` installs both rules in one `nft -f -` transaction, so either
  both go in or neither does.
- On recovery, `check_dns_failopen()` calls `deactivate()` whenever
  `dns_failopen.is_active()` reports a rule, whatever the database flag says,
  and writes an audit line if it removed a stray rule.
- Tests:
  - a fake `nft` where the TCP add fails;
  - recovery removes the leftover UDP rule;
  - a healthy check with a stray rule cleans it up.
- *Live:* `nft -a list chain ip nat prerouting` has no `dns-failopen` rule. A
  full fail-open cycle waits for your OK (a 7.7 repeat).

**7B.7 Block DNS-over-QUIC (M8)**
- In `nftables.conf`, add
  `iifname "ap0" udp dport 853 counter log prefix "doq-bypass: " reject comment "doq-bypass"`
  next to the DoT rule.
- Add the prefix to `ingest.NFT_LOG_PREFIXES` and count it in
  `dns_bypass_signal`. Update `test_firewall_config`.
- IPv6: read-only `sysctl net.ipv6.conf.all.forwarding`. If it's 0, record
  "not routed, no change". If it's 1, open a follow-up.
- *Live:* from the test-harness namespace, send UDP to port 853. It is
  rejected, a `doq-bypass` event is ingested, and normal DNS is unaffected.

**7B.8 Login admission (H5, H6)**
- In `/login`:
  - `record_failed_attempt` runs *before* the password-check `await`, and
    `clear_attempts` runs on success. With no `await` between the check and
    the insert, a burst can't get past the limit.
  - Refuse a body over 4 KiB with 413, using `Content-Length` and a bounded
    read.
- After a successful verify, re-read the password file. If it changed during
  the check, refuse with "the password was just changed, sign in again".
- A legacy rehash writes only if the file still holds the hash that was
  checked.
- Tests: plain functions in `session_auth.py`, no TestClient.
- *Live:* six parallel wrong passwords from the Mac get no more than the
  configured limit before 429.

**7B.9 Small security fixes (H10, M7, M16, M17, M19)**
- **H10:** start `new_module` from a deep copy of the current module. Removing
  any `passthrough_suffixes` entry also needs `confirm_privacy_scope_change`.
- **M7:** `validate_rules` rejects a suffix that equals or covers another
  module's suffix.
- **M16:** `csvCell` prefixes `'` to values starting with `= + - @`, tab or CR.
- **M17:** `shlex.quote` the URL and check `curl`'s return code.
- **M19:** `setup-privilege-separation.sh` runs `chown -R root:root` and
  `chmod -R go-w` on the code directories only, and lists any file it had to
  fix.

*Group 2 gate.* The firewall change (7B.7) deploys on its own, through the
runbook.

### Group 3: Reliability (about 2 days)

**7B.10 Keep the console responsive (H4, M13)**
- The middleware calls one plain function, `_check_session(token)`, through
  `run_in_threadpool`. That function:
  - opens its own connection;
  - checks the session;
  - updates `last_active` only if it is more than 60 s old;
  - closes the connection in `finally`.
- **Your decision (M13):** recommended is that timer-driven polls send
  `X-SP-Background: 1` and never refresh `last_active`. An unattended console
  then signs out after 30 min instead of 12 h. The poll's 401 already sends
  the browser to the login page; confirm that during the step.
- `health.check_services` collects every service's state first, then writes
  them in one short transaction. `check_platform_health` commits after each
  check.
- `intel.refresh_all` commits after each feed, so no network fetch runs with
  a write open.
- Tests:
  - the touch throttle;
  - fake probe and fetch functions assert `conn.in_transaction` is False when
    they're called.
- *Live:* re-run 7.8's console latency script while a health check runs.

**7B.11 Ingestion never loses or stalls (H2, H3)**
- **DNS catch-up:**
  - When the page cap is reached before the watermark, save a catch-up
    cursor in `ingest_state`: the next `older_than`, the old watermark as
    the floor, and the oldest fetched time as the ceiling. The new columns go
    in through `SCHEMA_MIGRATIONS`.
  - Later polls drain it a few pages at a time, inserting only entries
    between the floor and the ceiling, and clear it when done.
- **Per-record isolation:**
  - Each record's flatten and stats step is in its own try/except for the IDS,
    DPI and DNS readers. A non-object or missing field adds to
    `parse_errors` and is skipped.
  - `parse_rfc3339()` returns `None` on failure. Callers skip that record and
    never move a watermark with it.
- Tests:
  - a fake API with a 25-page backlog leaves no gaps;
  - a `[]` line in the eve fixture doesn't stall;
  - a bad timestamp is skipped and counted.
- *Live:* after deploying, events keep flowing and `parse_errors` stays flat.
  Stopping ingest on purpose to create a backlog also pauses the fail-open
  check, so it waits for your OK.

**7B.12 Engine and notification failures stay contained (M3, M4)**
- `engine.run_step` rolls back on failure, the same way ingest and
  correlation already do.
- `notify.dispatch` handles failures within one cycle like this:
  - a channel that fails once is skipped for the rest of the cycle, and its
    rows stay `failed` for the normal retry;
  - after 20 s of sending, the remaining sends wait for the next cycle.
- Tests:
  - a step that raises leaves no pending writes;
  - a raising sender gets one attempt per channel per cycle.

**7B.13 Proxy memory and edge cases (M5, M6)**
- Add a `responseheaders` hook. On a decrypted flow it sets
  `flow.response.stream = True` in two cases:
  - the content type isn't JSON, HTML, JavaScript or text;
  - the declared length is over 8 MiB.

  `response()` returns early for a streamed flow.
- When `drop_documents` would remove every document, keep them and rely on
  in-document pruning. Test this with a captured Instagram or Facebook
  multi-document response.
- *Live (A33, 7A protocol):*
  - 10-video YouTube pre-roll check;
  - Instagram feed check;
  - mitmproxy RSS during playback, before and after.

*Group 3 gate*, then deploy.

### Group 4: Correctness and data quality (about 1 day)

**7B.14 Narrow the hostname merge (H7)**
- `resolve_device` no longer merges a new MAC into an existing device by
  hostname when either of these is true:
  - the device holds an active device-scoped policy other than a trust
    quarantine (enroll, profile, pause, domain rules, vendor profile, or a
    person's quarantine);
  - another of its MACs was seen in the last 10 minutes.
- Otherwise the randomization merge stays. Print the reason, as the
  approved-device branch does.
- Tests in `test_registry.py` for each case.

**7B.15 One meaning of "open"; current intel only (M14, M15)**
- The dashboard counts, the active feed, the device list and the DPI
  effectiveness query use `risk.LIVE_STATUSES`. The quiet message in
  `app.js` follows it.
- The freshness condition moves into a small helper in `intel.py`, used by
  both the blocklist writer and the correlation join. Stale indicators no
  longer raise incidents.
- *Re-run:* the battery's `threat_intel` runs (5/5) and the held-out replay,
  to confirm detection is unchanged.

**7B.16 Bounded attribution and retention (M10, E1)**
- `attribute_events` only considers events newer than a setting
  (`attribution_window_hours`, default 24). Older unattributed events are left
  as they are. Remove the unused `limit` parameter.
- `prune_incidents` deletes with subqueries instead of an ID list.
- Tests.

**7B.17 Console polling (M12)**
- Each refresh function skips a tick while its previous request is still
  running.
- The incident list ignores responses older than the latest request.
- The page-level 20–30 s timers also check `SP.live`.
- *Live:* through `mac-tunnel.sh`, no overlapping requests in the network
  panel. Filter switching shows the latest choice.

*Group 4 gate*, then deploy.

### Group 5: Tooling and docs (about ½ day)

**7B.18 Evaluation tools (M20, M21, E2)**
- `chaos.py` refuses to inject a fault unless `systemd-run` succeeded, and
  cancels the undo only after restoring.
- `heldout_replay.rate()` guards zero exposure.
- Add a note in `EVALUATION-RESULTS.md` that `evaluate.py`'s detection times
  are measured from the end of the attack, and that the 7.2 battery numbers
  are the reference.

**7B.19 Cleanup (Q2, Q4, Q5, Q6, Q7)**
- Schema parity test: Day-14 base plus `SCHEMA_MIGRATIONS` has the same
  columns as a fresh `schema.sql`.
- Remove the unused variable in `fingerprint.py`.
- Fix the stale docstring in `webapp.py`.
- Set the README badge to the real test count after this stage.
- Note in step 8.2 that the installer ships `requirements` files taken from
  the gateway's two environments.

**7B.20 Measure firewall log volume (M9)**
- Read-only: kernel log lines per prefix per hour over the last 7 days.
- If `quic-blocked` is above about 1,000 an hour, split it into a
  rate-limited logging rule plus an unlogged reject, and re-check
  `dns_bypass_signal`'s threshold. Otherwise record the number and close.

*Group 5 gate.*

### Decisions this plan needs from you

1. **M13:** should timer-driven polling count as activity? Recommended: no.
2. **H9:** if URLs are already in the journal, may they be purged now, or
   should that wait for 8.4?
3. **H1, H8, H2 live failure-path checks:** each means a short DNS or ingest
   outage on the real network. Should they run as 7.7-style chaos repeats, or
   stay unit-tested only?

### Acceptance cases from the audit, and where each is covered

| Audit acceptance case | Step |
|---|---|
| Failed backend deletions can't produce success | 7B.1 |
| Missing, corrupt, stale or unwritable scope maps never expand consent | 7B.2 |
| Scope revocation handles established connections | 7B.2 |
| DNS outage leaves firewall reconciliation working | 7B.4 |
| Backlogs over 10,000 DNS records drain without gaps | 7B.11 |
| Bad records don't stall a source | 7B.11 |
| SQLite contention doesn't freeze unrelated requests | 7B.10 |
| Concurrent logins respect the limit | 7B.8 |
| An old password can't issue a session after a change | 7B.8 |
| Extensions match the kernel expiry | 7B.3 |
| Partial fail-open is removed after recovery | 7B.6 |
| Deployment checks use the running proxy and the real loader | 7B.2 (real loader, restart on deploy). A live probe of the running proxy is deferred |

## Progress

*Unattended run, started 08:00 IST on 10 Oct 2026, on the local branch
`audit-7b`. Nothing is pushed: `origin/main` stays at `0707bcb`. Defaults
used for the open decisions: M13 timer polls don't refresh the idle clock;
H9 no journal purge; no deliberate outages on the real network.*

- **Step 0** - branch `audit-7b` created; plan documents committed.
- **7B.1 (C2) done** - `_apply_and_verify` and reconcile's re-check now verify against the previous ownership record. Rollbacks are read back. "Nothing was changed" is said only when that's true; otherwise the message says "rolling back did not fully take" and a `policy_enforcement_failed` incident is raised. The fake backend gained sticky deletes and ignored client writes. 5 new tests failed on the old code and pass now. One existing test had been asserting "rolled back" for a rollback that could not have worked (its fake ignores every add); it now expects the honest message. 647 tests pass.
- **7B.2 (C1, M2, M18) done in code** (deployed with Group 1).
  - **Addon:** a missing or unreadable map, an absent device or an empty entry now means nothing is decrypted. `request()` and `response()` re-check the device's sites on every flow (client IP read from `peername`, falling back to `address`; checked against mitmproxy 12.2.3 on the gateway).
  - **Orchestrator:** `write_site_map` raises `SiteMapError` (now one of the backend errors), and `_converge_enrolled` removes redirects, then writes the map, then adds redirects. The "enrolled" read-back includes the map. Failed connection resets are kept in `orchestrator_state.extra.pending_resets`, retried every reconcile, audited once (`policy.reset_failed`) and shown as `last_error` on the enrollment.
  - **Canary:** drives the real `_sites_for` against temporary map files across six cases (all sites, one site, no map, unreadable map, device absent, empty entry). A test shows it now catches the old YouTube fallback.
  - **Other:** `securepi-privacy-canary` added to `services.list`. Both DPI deploy scripts restart explicitly. The CLI says a CLI enrollment starts inspecting once the engine adopts it (about 15 s).
  - **Tests:** 13 existing addon tests relied on the old default; their fake device now has sites switched on explicitly. The new deny-by-default tests fail on the old addon (5/5). Gateway baseline before changes: the live addon and canary match `0707bcb`, nothing is enrolled, the live map is `{}`, the canary is green. 659 tests pass.
- **7B.3 (M1) done in code** - an enrolled IP whose kernel timeout would run out before its policy is re-added with the new hours (renewal, not re-enabling: flushed IPs were already dropped from `want`). Enrollment verification now checks the timeout as well as presence. 2 of 3 new tests failed on the old code (the shortening test is a control). 662 tests pass.
- **7B.4 (H1) done in code** - `desired_state()` asks the DNS filter for clients and the service catalogue once, up front, and only if a device-scoped DNS policy needs them. If that fails, `rules` and `clients` are marked unavailable (not converged, since a half-known rule list would delete rules), and the firewall domains are still worked out. Reconcile reports the unavailable domains as per-domain errors, so `policy_enforcement_failed` fires. An error in working out the desired state is now included in that incident too. A quarantine now applies while the DNS filter is down. 3 of 4 new tests failed on the old code (the fourth is a control). Group 1 gate: 666 tests, py_compile, shellcheck and node --check all clean.
- **Group 1 deployed and verified live (08:09-08:10).**
  - **Backups:** `/var/backups/securepi-7B/pre-group1-20261010-080905.tar.gz` plus `.bak-7B-g1-20261010-080905` copies of each changed file.
  - **Deploy:** `make deploy` for app/; DPI addon and canary installed, compiled with the DPI venv's Python and both units restarted; `securepi` CLI installed. `securepi status` shows all services active, including the canary, which is now listed.
  - **Canary:** the new canary passes on the gateway.
  - **Live checks, test-harness device only** (`[TEST HARNESS] test-victim`, id 5, 10.10.0.221, on the isolated test bridge):
    - enroll for Instagram only: nft element with about 1 h timeout, map `{"10.10.0.221": ["instagram"]}`;
    - the deployed addon, using the real map, decrypts Instagram for it but **not YouTube**, and nothing for 10.10.0.50 (not in the map);
    - extend to 3 h: kernel timeout 10,799 s;
    - reconcile: no errors, no drift;
    - end: set and map both empty;
    - quarantine and release: MAC in and out of the set;
    - orchestrator healthy, no pending resets.
  - **Journals:** no errors in engine, ingest or web since deploy. Console: login 200, unauthenticated API 401.
  - **Not done live:** the DNS-filter-down path of 7B.4 (no deliberate outages) and the A33 checks (phone not connected).
  - **Note for the user:** the Dell went from charger to battery between 06:32 and 08:08 (96% at 08:10). The Mac is on AC, so it isn't a power cut.
  - **Note for the user:** the Dell test proxy's `~/securepi-browser/test-sites.json` is `{}`. Under deny-by-default it now decrypts nothing until it lists `"127.0.0.1": ["youtube", ...]`.
- **7B.5 (H9) done and deployed (08:12).**
  - **Read-only check:** **5,163 journal lines in the last 14 days** carry full decrypted request URLs (for example `10.10.0.50: GET https://www.youtube.com/<path> HTTP/2.0`), plus response lines. Cause: mitmdump's default `flow_detail` is 1 (confirmed with `mitmdump --options`). **Not purged** (default decision); this is left for the user or 8.4. The proxy journal is part of the 409.6 MB system journal, going back to 12 Sep.
  - **Fix:** `--set flow_detail=0` in `deploy-dpi.sh`'s unit. The live unit file matched the script byte for byte before the change; it was regenerated from the script and installed (`.bak-7B5-*` kept), then daemon-reload and restart. The running command line now shows `--set flow_detail=0`.
  - **Proof, on the Dell's localhost test proxy** (same binary, production addon): a YouTube request carrying a unique token printed the URL and token with `flow_detail=1` (1 line), and nothing with `0` (0 lines). Only `client connect` / `server connect` lines (address and hostname) remain.
  - **Test proxy:** `~/securepi-browser/test-sites.json` set to `{"127.0.0.1": ["youtube"]}` (the old effective behaviour under deny-by-default); `.bak-7B5` kept.
- **7B.6 (H8) done in code** (deployed with Group 2).
  - `dns_failopen.activate()` installs both rules in one `nft -f -` batch, so both go in or neither does; the batch syntax was validated on the gateway with `nft -c` (check only, nothing applied).
  - On recovery, `check_dns_failopen()` removes any fail-open rule still in the firewall even when the database says inactive, and writes `platform.dns_failopen_leftover_removed` to the audit log. If nft can't be read, the healthy path still works.
  - 4 new or rewritten tests failed on the old code.
  - Live state now: no fail-open rule, DB inactive.
- **7B.7 (M8) done in code and staged. Live firewall load: waiting for user** (the unattended run doesn't touch the live ruleset).
  - `gateway/nftables.conf` gets `iifname "ap0" udp dport 853 counter log prefix "doq-bypass: " reject comment "doq-bypass"` right after the DoT rule. `ingest.NFT_LOG_PREFIXES` gets `doq-bypass: ` (ships with Group 2; harmless until the rule exists). `dns_bypass_signal` already counts every bypass reason except `quic-blocked`, so it needed no change.
  - **Gateway checks:** `nft -c -f` on the full new ruleset passes. The live `/etc/nftables.conf` differs from the new file only by this rule. IPv6 forwarding is 0, so not routed and no change needed.
  - **Staged** at `~/nft-staged/nftables-7B7-doq.conf` on the Dell.
  - **To apply without a full reload** (keeps quarantine and enrollment sets), insert after the DoT rule (handle 32 at 08:14):
    `sudo nft add rule inet filter forward position 32 iifname "ap0" udp dport 853 counter log prefix \"doq-bypass: \" reject comment \"doq-bypass\"`
    then `sudo cp ~/nft-staged/nftables-7B7-doq.conf /etc/nftables.conf` so it survives a reboot.
  - 3 new tests failed on the old code.
- **7B.8 (H5, H6) done in code** (deployed with Group 2).
  - `session_auth.reserve_login_attempt()` checks the limit and counts the attempt in one step, before the password check, with no `await` in between. `clear_attempts` on success is unchanged.
  - The login body is refused (413) over 4 KiB, by declared length or while being read (`_read_body_capped`).
  - After a successful check, `/login` re-reads the password file and issues no session if it changed meanwhile.
  - A legacy rehash writes only if the file is unchanged (`rehash_if_unchanged`), under the same lock a password change takes (`replace_password`).
  - FastAPI isn't on the Mac, so the wiring is guarded by structural tests like `test_security_headers`. 12 new tests failed on the old code.
- **7B.9 (H10, M7, M16, M17, M19) done in code.**
  - **H10:** the rule editor saves `adfilter_rules.edited_module(current, edits)`, which keeps every field it doesn't show. `needs_scope_confirmation()` also asks for confirmation when a passthrough carve-out is removed.
  - **M7:** `validate_rules` refuses a decrypt suffix that covers another module's suffix; the seed rules have none.
  - **M16:** `csvCell` prefixes `'` to values starting with `= + - @`, tab or CR. Tested by running the function under node (`tests/test_console_js.py`).
  - **M17:** `fetch_from_gateway()` quotes the URL for the remote shell (`shlex.quote`) and stops on a failed curl.
  - **M19:** `setup-privilege-separation.sh` fixes ownership and write permission recursively and lists what it fixed (not run unattended). Read-only check of the gateway: no writable code. Two stray top-level copies `/opt/securepi/app.js` and `app.css` (`maheshwari:staff` 644, not served; the console serves `static/`), and four 7A `.bak` rule-file backups in `/opt/securepi-dpi` that the `securepi` group can write.
  - Also fixed: the stale "stopgap" docstring (Q5).
  - **Tests:** 15 new, which failed on the old code; one structural test updated for the recursive `chown`. **Group 2 gate:** 697 tests, py_compile, node --check and shellcheck all clean.

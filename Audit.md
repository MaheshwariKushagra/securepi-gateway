# SecurePi architectural and code-quality audit

This report records the preceding read-only audit. No application fixes were applied. File references describe the source inspected during that audit; subsequent edits may shift line numbers. Suggested code is for review and manual implementation.

## Scope and verification

Reviewed the application, gateway configuration and scripts, DPI components, tests, replay/evaluation tooling, and demo/deployment code. No `CLAUDE.md` or `AGENTS.md` was found inside the repository. Static parsing of 59 Python files succeeded, and a static application import-graph check found no cycles. In-memory reproductions confirmed the empty-password comparison and text-file iterator/tell failure described below.

No builds, application services, or test suite were run. Some tests write files, so executing them would have violated the audit's read-only restriction. Findings involving deployment permissions and network traffic require verification on the deployed gateway. This is a static audit, not a live penetration test or dependency vulnerability certification.

## Architecture and structural integrity

The primary flow is IDS/DNS-filter/DPI ingestion → registry and SQLite → correlation and incidents → policy orchestration through nftables/DNS filter → notifications. The FastAPI console also accesses SQLite and backend controls directly.

Useful foundations include predominantly parameterized SQL, evidence linked to incidents, narrow privileged helpers with validation, and desired-state reconciliation with locking and rollback attempts. No static application import cycles were detected.

The main structural weakness is inconsistent ownership of state and transactions. The orchestrator is intended to own policy, but web routes retain direct backend mutations. Database helpers sometimes commit caller-owned work. Notifications perform network operations inside write transactions. Filesystem deployment mixes mutable data with privileged Python import locations.

Large modules amplify these problems: `app/webapp.py` is approximately 3,359 lines, `app/correlation.py` 1,544, `app/orchestrator.py` 1,327, and `app/ingest.py` 1,076. The console JavaScript is approximately 4,091 lines. Extract boundaries around policy commands, database transactions, authentication, ingestion checkpoints, and notification delivery before introducing more abstraction.

## Critical findings

### C1. Writable privileged Python import directories

**References:** `gateway/setup-privilege-separation.sh:68–88`, `dpi/privacy_canary.py:71`, `app/orchestrator.py:54–58`.

The setup script assigns `/opt/securepi` and the DPI directory to the `securepi` group and gives directories mode `1775`. The console runs with that group. A sticky directory still permits creation of previously absent filenames. Root processes import Python code from these locations, including the canary's explicit `/opt/securepi` import path.

On a deployment with these permissions, a compromised console process can potentially plant a module that a privileged process later imports. The sticky bit does not establish a safe code/data boundary.

**Recommendation:** Make privileged code directories root-owned and non-writable by application identities. Put mutable databases and rules under dedicated data directories and locks under `/run/securepi`. Audit every privileged process's import path and writable ancestor directories.

### C2. Password replacement creates an empty-password login window

**References:** `app/webapp.py:128–130`, `app/webapp.py:228–230`, `app/webapp.py:2429–2430`, `app/session_auth.py:92–109`.

Password replacement opens the password file with mode `w`, truncating it before computing the replacement PBKDF2 hash. A concurrent login can read an empty stored value. Legacy plaintext verification accepts `verify_password("", "")`, confirmed in memory. A crash after truncation can leave this condition persistent. The login-time rehash path also needs safe replacement.

**Recommendation:** Reject empty stored credentials and empty submitted passwords; calculate the hash before persistence; serialize replacement; atomically replace the credential through an appropriately scoped privileged storage operation. Revoke existing sessions when changing credentials.

## High-priority findings

### H1. Redirected HTTPS bypasses forward-chain enforcement

**References:** `gateway/nftables.conf:69–103`, `gateway/nftables.conf:146`.

Quarantine, blocked-IP, and related restrictions are in the forward chain. Enrolled HTTPS is redirected to local port 8080, traversing local input instead. Input and output policies accept traffic, allowing the proxy path to bypass those forward rules, including for passthrough connections.

**Recommendation:** Enforce applicable source and destination restrictions before the HTTPS redirect. Verify actual traffic through enrolled, unenrolled, quarantined, passthrough, and established-connection cases. Netfilter's routing distinction is documented in [Configuring chains](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains).

### H2. Hostname-based identity merging can transfer trust

**References:** `app/registry.py:125–144`, `app/ingest.py:973`.

After a MAC lookup misses, matching an existing hostname can return that device's identity. Hostnames are client-controlled and are not proof that a new MAC represents the same device. The merge can transfer approved trust and combine unrelated policy and evidence histories.

**Recommendation:** Register an unfamiliar MAC as a distinct unknown device. Treat hostname similarity as a suggestion for explicitly confirmed association, not an authorization decision.

### H3. Historical IP addresses are treated as current ownership

**References:** `app/orchestrator.py:301–305`, `app/orchestrator.py:531–554`, `app/orchestrator.py:619–622`, `app/orchestrator.py:711–718`, `app/webapp.py:536–554`.

Selecting the latest address previously seen for a device does not establish that it still owns that address. Reassigned DHCP addresses can cause enforcement or DPI enrollment to affect another device. Client matching accepts overlapping identifiers, while domain convergence's subset comparison can leave stale extra identifiers in place.

**Recommendation:** Model current address ownership with freshness and reassignment handling. Validate ownership before enforcement and compare the exact managed identifier set during reconciliation.

### H4. A partial log line can abort ingestion and recovery work

**References:** `app/ingest.py:529–548`, `app/ingest.py:627–639`, `app/ingest.py:845–857`, `app/ingest.py:1022–1068`.

Readers iterate a text file using `for line in fh`, break on an incomplete line, and then call `fh.tell()`. Python can raise `OSError: telling position disabled by next() call` in this situation; this was reproduced in memory. The shared outer error boundary allows one reader failure to skip other sources, attribution, health updates, and DNS fail-open checks.

**Recommendation:** Use explicit `readline()` calls and checkpoint only complete records. Bound batches and isolate source failures. Schedule DNS recovery independently of ingestion success.

### H5. The DNS filter polling can lose bursts and replay history

**References:** `app/ingest.py:353`, `app/ingest.py:737–784`, `app/ingest.py:794–803`.

The API reader fetches at most 500 entries and advances to the newest timestamp. More than 500 arrivals between polls can be lost. Deduplication uses timestamp, client, and name without query type; timestamp parsing also reduces precision. File fallback runs only on API failure and has a separate checkpoint, so it does not repair normal API overflow and can replay already imported history during an outage.

**Recommendation:** Paginate back to the previous watermark, preserve stable event identity, and explicitly reconcile overlap between API and file sources.

### H6. Notification delivery holds a database write transaction across network calls

**References:** `app/notify.py:52`, `app/notify.py:349–380`, `app/engine.py:43`.

Delivery records are inserted before synchronous external requests, and the transaction commits after processing the batch. Network waits therefore hold SQLite's writer slot and delay ingestion or authentication writes. Inline dispatch delays detection. A crash after an external send but before commit can cause duplicate delivery.

**Recommendation:** Commit an outbox entry before contacting external services. Deliver in a separate worker, with short result transactions and stable delivery identifiers. Account for the unavoidable ambiguity of a remote send succeeding before local acknowledgement is persisted.

### H7. Telegram tokens can leak through persisted error messages

**References:** `app/notify.py:223–225`, `app/notify.py:244`, `app/notify.py:323`, `app/notify.py:143`, `app/notify.py:386`.

HTTP error formatting strips URL query parameters but retains the path. Telegram embeds its bot token in that path. The resulting error is stored and exposed through notification data. Raw provider response bodies can also disclose sensitive request details.

**Recommendation:** Record provider type, hostname, and status only. Never persist raw credential-bearing URLs or uncontrolled provider bodies.

### H8. TLS failure handling uses the wrong mitmproxy event object

**References:** `dpi/securepi_adfilter.py:406–421`.

The failure hook reads `data.client_hello.sni`. The documented `tls_failed_client` argument is `TlsData`, not `ClientHelloData`. The exception path produces no SNI and returns, preventing the intended failure counter and bypass behavior. Once corrected, the counter also needs successful-connection resets to represent consecutive failures.

**Recommendation:** Read the server name from the appropriate connection object, test with actual event contracts, and expire/reset counters. See the official [event documentation](https://docs.mitmproxy.org/stable/api/events.html) and [TLS types](https://docs.mitmproxy.org/stable/api/mitmproxy/tls.html).

### H9. Health checks can mistake their own activity for engine health

**References:** `app/health.py:154`, `app/health.py:245`, `app/health.py:344`.

Taking the maximum timestamp across all signal-state rows includes timestamps maintained by platform health and DNS fail-open checks. Those updates can make a stalled correlation engine appear healthy.

**Recommendation:** Maintain an explicit successful engine-cycle heartbeat and separate source/signal health indicators, with a defined startup grace period.

### H10. Direct DNS-filter rule mutations race with orchestration

**References:** `app/webapp.py:1501–1516`, `app/adguard.py:107–118`, `app/orchestrator.py:771`, `app/orchestrator.py:262`.

Console endpoints read and replace the complete DNS-filter rule list outside the orchestrator's policy lock. Concurrent updates can overwrite one another. Removing an orchestrator-managed rule can report success only for reconciliation to restore it. Validation also differs from the orchestrator's domain normalization.

**Recommendation:** Route managed changes through one policy command boundary and one locking/ownership model. Validate domains consistently and distinguish user-owned rules from generated policy rules.

### H11. The DGA heuristic misses generated apex-domain bursts

**References:** `app/correlation.py:863–897`.

Grouping by the last two labels and excluding apex names from entropy analysis misses a device querying many generated apex domains. Each domain forms a separate group and contributes no non-apex entropy sample. A last-two-label approximation also mishandles public suffixes such as multi-label country suffixes.

**Recommendation:** Separate per-device NXDOMAIN/registrable-domain burst detection from subdomain-tunneling detection. Use a public suffix-aware domain boundary and evaluate both signal families independently.

## Medium-priority findings

| Finding | Location | Impact and recommendation |
| --- | --- | --- |
| Partial DNS fail-open installation is considered active | `app/dns_failopen.py:94–103` | If only one transport rule is installed, a nonempty handle list prevents repair. Apply both atomically or verify each required rule. |
| Rollup watermark misses late data | `app/rollup.py:59` | A global maximum completed hour prevents repair of late events and late attribution; empty hours do not advance useful progress. Store explicit progress and recompute a bounded recent window. |
| Flat baselines disable volume anomaly detection | `app/correlation.py:1494` | A zero standard deviation causes the detector to skip even a later large increase. Introduce a variance floor and an absolute/relative threshold. |
| Exceptions can leave partial database work to be committed later | `app/correlation.py:1525–1531`, `app/ingest.py:1069` | Catching errors without rollback obscures transaction boundaries. Use explicit transactions or savepoints per stage. |
| Database connections rely on garbage collection | `app/webapp.py:156`, `app/webapp.py:524` | Early returns and route helpers lack consistent closure. Use request-scoped acquisition with `finally` cleanup. |
| Blocking work runs inside async request handling | `app/webapp.py:147`, `app/webapp.py:191` | SQLite writes, file reads, and password hashing can stall the event loop. Bound inputs and move blocking operations to suitable synchronous workers. |
| Background polling refreshes idle sessions | `app/session_auth.py:148`, console JavaScript polling near line 117 | A five-second poll can keep an unattended session active until its absolute expiry. Define inactivity using meaningful user activity. |
| Negative limits bypass result caps | `app/webapp.py:1093`, `app/webapp.py:1178`, `app/audit.py:35` | `min(limit, cap)` permits SQLite's negative unlimited limit. Enforce positive lower and upper bounds. |
| Device views repeatedly aggregate historical data | `app/webapp.py:994–1009`, `app/registry.py:214`, `app/registry.py:297` | Per-device queries and unbounded historical work grow with deployment age. Batch queries, use rollups, and make limits effective. Attribution's reported count should describe newly attributed rows. |
| Journal progress ignores skipped records | `app/ingest.py:985–991` | Quiet periods can repeatedly scan unrelated history. Advance a journal cursor independently of matching records and check command return codes. |
| Rules replacement uses a shared temporary filename | `app/webapp.py:2111` | Concurrent saves can interfere with each other's rename/content. Use unique temporary files plus serialized or version-checked updates. |
| CSS selectors are inserted into raw HTML without a sufficient contract | `dpi/adfilter_rules.py:160`, `dpi/securepi_adfilter.py:162` | A selector containing a closing style tag can exceed the intended CSS-only capability. Validate a restricted selector grammar and prevent HTML termination. |
| Retention leaves related records behind | `app/retention.py:54`, `app/retention.py:120` | Incident cleanup omits related notification records; several tables lack defined retention. Define lifecycle rules before enabling and relying on foreign-key enforcement. |
| Retry/digest paths apply delivery policies inconsistently | `app/notify.py:392`, `app/notify.py:410` | Retries and digests do not consistently honor rate/quiet controls. Centralize delivery eligibility. |
| Expired intelligence remains in generated blocking state | `app/intel.py:147–170` | Historical indicators are retained and reused as active membership. Separate retained history from unexpired enforcement data. |
| DoH refresh can mask nftables failure | `gateway/refresh-doh-set.sh:14`, `gateway/refresh-doh-set.sh:53–55` | Weak pipeline failure handling permits a final success-looking echo. Explicitly propagate command failures. |
| Demo mode is not fully isolated | `docs/demo/serve.py:126`, `docs/demo/serve.py:148` | Demo rules point at the real source-tree rules file and notification dispatch remains real. Use isolated demo data and a fake delivery transport. |
| Evaluation threads can fail without failing the overall result | `gateway/battery.py:503`, `gateway/battery.py:576` | Joining threads does not propagate their exceptions; summaries can omit failed tracks. Capture every expected track outcome and guarantee cleanup. |
| Replay campaign assertions are not bounded by the run window | `tools/replay.py:249`, `tools/replay.py:345` | Later evidence can satisfy an earlier campaign expectation. Bound both timestamps and supporting evidence to the intended replay interval. |

## Additional policy guarantees to clarify

- **Unknown-device admission:** `app/ingest.py:973` applies restrictions after discovery/reconciliation, while `gateway/nftables.conf:104` accepts ordinary LAN forwarding. This provides eventual restriction, not immediate admission control. If immediate denial is required, enforce an approved-device set before allowing access.
- **Enrollment after reboot:** `app/orchestrator.py:1118` conditions removal on the stored and current IP matching, while `app/orchestrator.py:869` can converge enrollment at a new address. A changed address can undermine an intended unconditional “off after reboot” guarantee. Model boot identity explicitly and test address changes across reboot.

## AI-generated technical debt and dead code

These are observable maintenance issues; authorship alone does not establish their cause.

- `app/adguard.py:313` retains a legacy client-rule format with trailing comments, although `app/adguard.py:465` describes that format as broken. No active call sites were found. Related legacy paths around lines 202 and 394 deserve removal or explicit ownership.
- Unused imports include `quarantine` in `app/webapp.py:96` and `sys` in `app/status.py:3`. `get_window_start` at `app/correlation.py:68` had no references in the inspected source.
- Privileged-helper wrappers repeat similar logic in `app/quarantine.py:51`, `app/dpi.py:67`, and `app/firewall.py:34`. Device-label/address resolution and hour bucketing also have multiple implementations. Consolidate only after defining their contracts.
- Schema declarations and `SCHEMA_MIGRATIONS` duplicate schema intent without a clear migration ledger. Introduce explicit versioned migrations with upgrade-path checks.
- `app/webapp.py:85` imports a shared DPI rules module, but `Makefile:60` deploys the application tree and `dpi/deploy-dpi.sh:14` deploys the addon without fully expressing the shared-module dependency. Fresh deployment currently depends on out-of-band copying described in comments.
- Deployment uses `rsync -a`; preserving source permissions can undo target permission assumptions. Code and writable data should not share a directory or rely on a later manual permission repair.
- There is no production Python dependency manifest sufficient to reproduce the runtime. The Node package manifest serves the screenshot tooling, not the gateway application.
- Structural security tests, such as `tests/test_privilege_separation.py:38`, inspect source strings rather than exercising the actual filesystem and process boundary. Such checks cannot prove the intended privilege separation.
- Authentication route testing is incomplete; comments note missing TestClient support dependencies. Tests should cover full request behavior, concurrent password replacement, and invalid stored credentials.

## Prioritized action plan

### [Critical]

1. Separate root-imported code from all application-writable directories; inspect deployed ownership and permissions.
2. Close empty-password acceptance immediately, then implement atomic credential replacement and session invalidation.

### [High]

3. Enforce network restrictions before local proxy redirection and validate them using real gateway traffic.
4. Remove hostname-based trust inheritance and establish current IP ownership.
5. Repair log checkpointing and DNS-filter pagination; isolate recovery scheduling from reader failures.
6. Move external notifications outside database write transactions and sanitize stored provider errors.
7. Correct TLS event handling and define counter/reset behavior.
8. Make engine health independent of health-check activity.
9. Centralize policy mutations and fix DGA signal coverage.

### [Medium]

10. Make transaction ownership explicit, close connections reliably, and remove blocking work from async handlers.
11. Repair late-data rollups, retention, retry policy consistency, and unbounded historical queries.
12. Make deployment reproducible and isolate demo/evaluation environments.

### [Quick Wins]

13. Reject negative query limits; sanitize notification errors; propagate shell failures.
14. Remove verified unused imports and unused legacy rule helpers.
15. Add focused regression coverage for partial log lines, actual TLS event shapes, flat baselines, and failed evaluation tracks.

## Suggested fixes — reviewable examples only

The examples below illustrate the intended changes. They were not applied or runtime-tested and do not substitute for complete integration work.

### Reject invalid empty credentials

Before, the legacy comparison can accept two empty strings:

```python
return hmac.compare_digest(password, stored)
```

After, guard before selecting either verification path:

```python
if not password or not stored:
    return False

# For the explicitly supported legacy plaintext format only:
return hmac.compare_digest(password.encode("utf-8"), stored.encode("utf-8"))
```

Retain the hashed-password branch and reject malformed hashes safely. Validate stored iteration counts and hash structure before expensive computation.

### Compute credentials before replacing storage

Before:

```python
with open(CONSOLE_PASSWORD_FILE, "w") as fh:
    fh.write(hash_password(new_password))
```

After, as an interface sketch:

```python
encoded = hash_password(new_password)
password_store.replace_atomically(encoded)
session_store.revoke_all()
```

The storage operation must serialize updates, use a unique temporary file in the destination filesystem, set permissions, flush/fsync as appropriate, and atomically rename. The console's current directory permissions do not allow it to implement this safely by simply creating a neighboring file; use a narrowly scoped storage helper. Define failure behavior across credential replacement and session revocation.

### Separate privileged code and writable data

Proposed layout:

```text
/opt/securepi/            root-owned application code; no app-group writes
/opt/securepi-dpi/        root-owned DPI code; no app-group writes
/var/lib/securepi/        database and mutable application data
/var/lib/securepi-dpi/    validated mutable DPI rules
/run/securepi/           explicitly provisioned runtime locks/state
```

Changing directory permissions alone will break writers that currently place files beside code. Move those paths and update service configuration as part of the same reviewed change.

### Checkpoint only complete log records

Before:

```python
for line in fh:
    if not line.endswith("\n"):
        break
    process_complete_line(line)
offset = fh.tell()
```

After:

```python
offset = fh.tell()
while True:
    line = fh.readline()
    if not line or not line.endswith("\n"):
        break
    process_complete_line(line)
    offset = fh.tell()
```

Persist the checkpoint with the corresponding database changes. Add a batch bound, validate record shape, and define whether malformed complete records are quarantined or intentionally skipped. This example does not itself solve rotation handling.

### Stop deriving trusted identity from hostname

Before, conceptually:

```python
device = lookup_mac(mac) or lookup_hostname(hostname)
```

After, conceptually:

```python
device = lookup_mac(mac)
if device is None:
    device = create_device(mac=mac, hostname=hostname, trust="unknown")
```

Keep any association workflow separate and explicit; do not silently inherit authorization from descriptive metadata.

### Filter before HTTPS redirection

Illustrative addition inside the existing appropriate nftables table, using its existing sets:

```nft
chain before_https_redirect {
    type filter hook prerouting priority -110; policy accept;
    iifname "ap0" tcp dport 443 ip saddr @quarantine drop
    iifname "ap0" tcp dport 443 ether saddr @quarantine_mac drop
    iifname "ap0" tcp dport 443 ip daddr @blocked_ip drop
    iifname "ap0" tcp dport 443 ip daddr @doh_resolvers drop
}
```

This illustrates enforcing restrictions before destination NAT; it is not a complete replacement ruleset. Confirm table/set types, hook ordering, IPv6 policy, other proxy ports, and established-connection behavior on the deployed configuration. The prerouting example intentionally uses `drop`, not `reject`.

### Read TLS failure metadata from the actual event contract

Before:

```python
sni = data.client_hello.sni
```

After, subject to the supported mitmproxy version's connection contract:

```python
sni = data.conn.sni
if not sni:
    return
```

Test the failure hook with `TlsData`, reset relevant counts on successful handshakes, and expire old entries. Fixing the attribute alone does not make the counter consecutive.

### Bound API limits at validation time

Before:

```python
limit = min(limit, 300)
```

After, for a FastAPI route:

```python
limit: int = Query(default=100, ge=1, le=300)
```

Apply equivalent validation to internal helpers that can be called outside the HTTP route.

### Sanitize notification transport errors

Before:

```python
message = "HTTP %d from %s" % (status, url.split("?")[0])
```

After:

```python
host = urllib.parse.urlsplit(url).hostname or "unknown-host"
message = "HTTP %d from %s" % (status, host)
```

Keep raw URLs, tokens, and provider response bodies out of persisted errors and console responses.

## Acceptance criteria for follow-up work

- A compromised console identity cannot add or replace anything on a privileged Python import path.
- Concurrent or interrupted password updates never allow an empty credential and have defined session-revocation behavior.
- Quarantine and destination restrictions hold across direct forwarding, redirected HTTPS, and proxy passthrough.
- A new MAC cannot inherit trust through a hostname, and a reassigned IP cannot inherit another device's enforcement or enrollment.
- Partial records, malformed records, API bursts, and backend outages do not lose events or starve DNS recovery.
- Slow notification providers do not hold SQLite write transactions or pause detection; persisted errors contain no credentials.
- Engine health reflects completed engine work, and TLS failure handling is tested against the supported mitmproxy event types.

## Ad-blocking improvement recommendations

Added following a focused review of `dpi/securepi_adfilter.py`, `dpi/adfilter_rules.py`, `dpi/adfilter-rules.json`, and the DNS-filter integration. These are recommendations only; no filtering code or configuration was changed. The highest-value improvement is to make filtering precise, measurable, and reversible before adding more rules.

### 1. [Critical when cosmetics are enabled] Preserve the site's Content Security Policy

**Location:** `dpi/securepi_adfilter.py:180–224`, `dpi/securepi_adfilter.py:522–536`.

`loosen_csp_for_inline_style()` claims to loosen only styles, but when `style-src` is absent it adds `'unsafe-inline'` to `default-src`. That directive also supplies defaults for other resource types, potentially allowing inline scripts when a separate script directive is absent. This is a security regression caused by an ad-blocking feature. The shipped rules disable cosmetics, so exposure depends on enabling it.

Do not change `default-src` to authorize injected CSS. Prefer an exact hash of the injected style block in the applicable style directive, preserving existing permissions. Account for `style-src-elem`, multiple enforcing CSP headers, and policies in HTML meta tags. If policy handling is ambiguous, skip cosmetic injection and record the reason. Avoid a blanket `'unsafe-inline'` relaxation. MDN documents [style hashes and nonces](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/style-src) and the separate [style-src-elem directive](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/style-src-elem).

Also restrict the selector grammar in `dpi/adfilter_rules.py:160–165`: nonempty strings are not sufficient validation for interpolation inside a `<style>` element. Reject HTML terminators and CSS that escapes the intended selector-only contract. Keep cosmetics disabled until these protections and browser tests exist.

### 2. [High] Give DNS filtering and content filtering distinct responsibilities

**Locations:** `app/adguard.py:73–118`, `dpi/adfilter-rules.json`, `dpi/securepi_adfilter.py:336–382`.

Use the DNS filter as the broad baseline for dedicated advertising/tracking domains. Maintain a small, reviewed set of complementary DNS-compatible subscriptions and optional regional coverage. Record update health, enabled state, rule count, and the source of each blocking decision. Adding overlapping lists without measuring new coverage increases maintenance and false positives.

Keep selective HTTPS inspection an explicit per-device feature for cases DNS cannot distinguish. Blocking a shared video/content hostname cannot selectively remove advertising carried on that hostname. Display this limitation in the console; do not promise universal YouTube or native-app ad removal.

The DNS filter supports specific DNS filtering syntax; do not import full browser cosmetic/scriptlet lists into the DNS layer or interpret them using substring matching. Use the [DNS-filter blocklist syntax documentation](https://github.com/AdguardTeam/AdGuardHome/wiki/Hosts-Blocklists) as the compatibility contract. Browser-side filtering can be an optional complementary layer on user-controlled browsers, with separate reporting of what the gateway actually blocked.

### 3. [High] Replace global substring rules with host- and endpoint-scoped rules

**Locations:** `dpi/securepi_adfilter.py:449–460`, `dpi/adfilter-rules.json` (`blocked_paths`).

The current `if path in flow.request.path` check searches the whole request path, including query parameters, across every inspected host. A harmless query containing `/pagead/` can match. The same path fragment may have different meanings on different hosts. Every match receives HTTP 204 regardless of the endpoint's response contract.

Introduce stable rule IDs with explicit host boundaries, methods, path match type, action, category, and exceptions. Normalize hostnames consistently, use the parsed pathname unless a rule explicitly targets a query parameter, and make per-device/site exceptions take precedence. Keep rule interpretation deterministic and document precedence.

Illustrative schema, requiring implementation and validation:

```json
{
  "id": "youtube-ad-stats-v1",
  "hosts": ["www.youtube.com"],
  "methods": ["GET", "POST"],
  "path": {"type": "exact", "value": "/api/stats/ads"},
  "action": "empty_204",
  "category": "ad_measurement"
}
```

Use 204 only for endpoints tested to tolerate it. Choose any substitute response from a verified endpoint contract. Put broad telemetry rules such as `/youtubei/v1/log_event` in a separate optional tracking category: suppressing a telemetry request is not evidence that a visible ad was removed.

### 4. [High] Make body transformations specific and preserve playback data

**Locations:** `dpi/securepi_adfilter.py:78–134`, `dpi/securepi_adfilter.py:464–541`.

The addon recursively removes matching keys from every decoded JSON response and replaces quoted field names throughout HTML with `"no_ads"`. Global string replacement can alter unrelated scripts/text and create repeated property names. Expanding the decrypt-host list currently expands where these transformations run as well.

Separate the decision to decrypt a connection from the decision to modify a response. Create small site adapters with explicit hosts, endpoints, MIME types, known JSON paths/renderer shapes, and transformation versions. For HTML, target identified bootstrap-data structures with a proper extraction/parser strategy; preserve the original response when extraction is uncertain. Avoid broad regular expressions or whole-document key replacement as the primary parser.

Transform a copy and publish the new body only after parsing, transformation, and serialization succeed. Preserve playback URLs, captions, authentication data, continuation tokens, and non-ad recommendations. Add idempotence checks: applying the same transformation twice should not further change the result. Bound JSON depth/node count and preserve the original on budget exhaustion.

### 5. [High] Avoid buffering and decoding video traffic

**Locations:** `dpi/adfilter-rules.json` (`googlevideo.com`, `ytimg.com`), `dpi/securepi_adfilter.py:473–485`.

`get_text()` runs before checking whether the response is suitable for transformation. Decrypting broad media host suffixes can impose substantial processing and buffering costs even when no rule can usefully edit the response.

Measure which hosts actually require inspection, and remove media-only hosts from the decrypt set where evidence shows no required transformation. Decide buffering versus streaming in `responseheaders`, before the body is accumulated. Stream irrelevant MIME types and large/media responses unchanged; buffer only eligible HTML/JSON with an explicit size budget. Enforce a decoded-size limit as well as a wire-size limit, and handle missing Content-Length/chunked responses explicitly.

A limit checked only inside `response()` is too late to prevent initial buffering. Mitmproxy documents that [streaming changes body availability and modification behavior](https://docs.mitmproxy.org/stable/overview/features/#streaming). Do not enable global streaming and assume the current JSON rewriter will still work.

For modified responses, verify compression and Content-Length handling through mitmproxy's supported APIs, remove or regenerate body-dependent validators such as ETag, and define safe conditional-request/cache behavior. Leave HEAD, 204, 304, partial-content, and unsupported encodings unchanged unless explicitly handled. Never share transformed personalized responses between clients.

### 6. [High] Make compatibility recovery visible and narrowly scoped

**Locations:** `dpi/securepi_adfilter.py:384–427`, `app/orchestrator.py:301–305`, `app/orchestrator.py:619–622`.

Fix the TLS event-contract bug described in H8 before relying on automatic bypass. Reset failure counts on successful handshakes, expire old entries, and cap state size. Report a TLS compatibility failure rather than asserting certificate pinning: missing CA trust and other handshake failures can look similar.

Offer a time-limited, per-device/per-site exception with a reason and a restore action. Distinguish pausing cosmetic rules, body rewriting, tracking rules, and HTTPS inspection; a website exception must not silently disable quarantine or unrelated security restrictions. Use validated current device identity so DHCP reassignment cannot transfer enrollment or an exception to another device.

Show separate states for DNS filtering, inspection enrollment, observed handshake success, bypass status, and recent matching rule activity. An enrolled device is not proof that filtering is working. Define the supported IPv4/IPv6 and HTTP/2/HTTP/3 paths and verify whether each is inspected, deliberately passed through, or blocked; display unsupported coverage honestly.

### 7. [Medium] Treat rule updates as versioned releases

**Locations:** `dpi/securepi_adfilter.py:256–282`, `dpi/adfilter_rules.py:136–170`, `app/webapp.py:2111`.

Keep the existing last-known-good behavior, but add a schema version, immutable rule IDs, provenance, content digest, and validation limits for rule counts/string lengths. Validate domain syntax and match modes. Stage a candidate, run a fixture corpus, then activate it atomically with rollback to the previous version. Serialize concurrent console edits or reject stale versions.

Use a bounded reload interval or explicit change notification rather than filesystem checks in every hook. Remember the last rejected file revision and rate-limit its warning so an invalid edit does not cause repeated parsing/logging on every request. Display the loaded version separately from the requested version and show reload failures.

Do not automatically delete rules with zero observed hits: a quiet device, a short measurement window, or a site experiment can all produce zero hits without proving a rule obsolete. Include observation duration, rule revision, and eligible traffic counts.

### 8. [Medium] Measure effectiveness without inflating results

**Locations:** `dpi/securepi_adfilter.py:284–303`, `dpi/securepi_adfilter.py:305–334`, `dpi/securepi_adfilter.py:535–536`.

The cosmetic event currently records the number of injected selectors as `ads_removed`. The proxy cannot tell whether any selector matched an element in the browser. JSON fields removed, blocked telemetry requests, and visible ads prevented are also different measurements.

Report separate counters for DNS blocks, endpoint blocks by category, JSON objects removed, responses rewritten, cosmetic styles injected, eligible responses, skipped transformations with reasons, TLS failures, and active bypasses. Label visual ad-removal results only when measured in a browser test. Attribute counters to a rule revision and observation window.

Buffer rule statistics and flush periodically instead of replacing the statistics file on every hit. Bound logging, support log rotation, and avoid recording cookies, tokens, response bodies, or full query strings. Track CPU, resident memory, added request latency, playback-start latency, stalls, and breakage reports alongside filtering counters.

### 9. [High] Add a reproducible effectiveness and breakage test matrix

**Starting point:** `tests/test_adfilter.py`; extend it with adapter fixtures and real mitmproxy/browser integration coverage.

| Test family | Required assertions |
| --- | --- |
| Rule precision | Exact host/path boundaries; harmless matching text in query parameters; exceptions; method constraints; unrelated hosts remain unchanged. |
| JSON/HTML integrity | Only expected fields change; playback/caption/continuation data survive; malformed/deep/large payloads remain intact; repeated transformation is stable. |
| HTTP handling | gzip/Brotli as supported, chunked bodies, partial responses, HEAD/204/304, validators, streaming, and payload-size limits behave correctly. |
| Cosmetic security | No default/script policy weakening; style-src-elem and multiple CSP policies; selector injection attempts rejected; unknown policy formats skip safely. |
| TLS and identity | Actual supported mitmproxy hook types; trusted/untrusted CA; simulated failures; success resets; bypass expiry; DHCP reassignment. |
| User experience | Home/feed, search, watch, Shorts, live streams, seeking, captions, login, and playlists; desktop/mobile browsers and explicitly supported native apps. |
| Operational resilience | Invalid rule updates, rollback, concurrent edits, proxy restart, DNS outage, log rotation, and sustained media traffic. |

Use sanitized fixtures without credentials or personalized response data. For live trials, record client/browser versions, account state, region, rule version, and observed ad opportunities; site experiments make a single ad-free playback weak evidence. Compare DNS-only and DNS-plus-DPI runs using a documented repeated procedure. Define acceptance thresholds from the device's measured baseline, including a maximum acceptable playback failure rate, memory use, and added latency.

### Recommended implementation order

1. Fix CSP handling, selector validation, and TLS failure recovery; retain cosmetics as opt-in until verified.
2. Introduce scoped rule matching and precise metrics, with regression fixtures for false positives and preserved playback.
3. Add response eligibility, streaming/size budgets, and conservative site adapters; reduce unnecessary media-host inspection based on measurements.
4. Add versioned updates, rollback, and per-device/site troubleshooting controls.
5. Expand DNS lists and site-specific rules only when repeated tests show additional coverage without unacceptable breakage or resource cost.

Success should mean fewer observed ads and trackers with reliable playback and bounded resource use—not simply a higher counter of deleted fields or blocked requests.

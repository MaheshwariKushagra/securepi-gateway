No files were changed. The audit found serious gaps in consent enforcement, policy verification, ingestion reliability, and concurrency.

The overall architecture is appropriate for a small gateway appliance. The main problem is that several components report success or safety more confidently than their implementation supports.

**Scope and verification**

I inspected the application, gateway configuration and deployment scripts, DPI components, browser code, tests, and evaluation tooling. No `CLAUDE.md` or `AGENTS.md` was found.

- All 100 inspected Python files parsed successfully.
- The test sources contain 641 test functions. I did **not** run the suite: its fixtures create databases and temporary files.
- Isolated, in-memory checks confirmed four defects: false-success policy verification, ignored enrollment duration differences, inspection fallback outside the selected site scope, and DNS pagination loss.
- Live firewall behavior, deployed permissions, installed dependency versions, and Git history remain unverified. The initial Git inspection encountered a sandbox-denied macOS cache-write attempt; I avoided further Git commands.

“Critical” below denotes a broken consent or enforcement guarantee.

---

**1. Architecture and structural integrity**

The intended design is coherent:

| Component | Responsibility | Assessment |
|---|---|---|
| `ingest.py` and registry | Collect telemetry and attribute devices | Appropriate separation, but ingestion also owns migrations and platform supervision. |
| `correlation.py`, risk, rollups | Detect activity and summarize evidence | Explainable detection is a strength; transaction and scheduling boundaries need work. |
| `orchestrator.py` | Translate policies into enforcement | Correct centralization concept, undermined by incomplete verification and cross-backend coupling. |
| FastAPI console | Authentication, configuration, analytics, actions | Too many responsibilities in one 3,452-line module. |
| DPI addon and canary | Selective interception and scope checks | Consent state spans several components without one verified transaction. |
| Browser application | Poll APIs and render controls | A 4,142-line global script has accumulated independent refresh mechanisms. |

I found no circular dependencies in the inspected Python import graph. The problem is primarily **behavioral coupling**, rather than import cycles.

The most consequential boundaries to improve are:

- **Desired policy calculation versus external access.** Computing desired firewall state currently depends on AdGuard availability.
- **Database transactions versus network operations.** Some modules correctly commit before network calls; others retain write locks throughout them.
- **Consent versus best-effort telemetry.** Device scope files and connection resets are essential enforcement operations, but failures are treated like optional logging.
- **Application configuration versus deployment paths.** The demo rewrites Python source to substitute paths, indicating missing configuration seams.

Keep the existing process model and SQLite initially. Extract route groups, introduce explicit transaction ownership, and give each enforcement backend an independently testable contract before considering larger architectural changes.

---

**2. Critical findings**

**C1 — [Critical] Inspection scope fails open, and failed scope changes can report success**

Locations: [DPI scope lookup](/Users/maheshwari/blah/dpi/securepi_adfilter.py:489), [scope-map writer](/Users/maheshwari/blah/app/orchestrator.py:403), [connection resets](/Users/maheshwari/blah/app/orchestrator.py:432), [enrollment ordering](/Users/maheshwari/blah/app/orchestrator.py:964).

`_sites_for()` returns YouTube when:

- The map is missing or unreadable.
- The device has no entry.
- Its entry is an empty list.

For a device enrolled only for Instagram, this enables an unselected inspection scope. The in-memory reproduction returned `['youtube']` after a simulated map-read failure.

There is a second failure mode: `write_site_map()` catches write errors and returns `[]`. That means “nothing changed” to its caller. An older, broader map remains active, connection resets are skipped, and the policy can be reported as applied.

Enrollment also changes nftables **before** publishing the scope map, creating an interval where the new redirect uses absent or stale consent data.

**Recommendation:** Unknown scope must mean no inspection. Include the scope map, nftables enrollment, and existing-connection handling in the verified enforcement operation. For revocation, narrow the scope and terminate affected sessions; retain an explicit failure state if either operation fails.

---

**C2 — [Critical] Read-back verification can approve a removal that never happened**

Locations: [matching logic](/Users/maheshwari/blah/app/orchestrator.py:798), [immediate verification](/Users/maheshwari/blah/app/orchestrator.py:1053), [reconciliation verification](/Users/maheshwari/blah/app/orchestrator.py:1376).

Removal verification needs the **previously managed** rules, clients, and enrollments. Both verification paths instead pass `new_applied`, after removed entries have already disappeared from that record.

Example:

1. Previously managed enrollment contains `10.10.0.50`.
2. Desired enrollment becomes empty.
3. Backend deletion returns successfully but leaves the element present.
4. `new_applied["enrolled"]` is empty.
5. Verification returns `True`.

The same problem affects removed DNS rules and restoration of client settings.

The isolated checks demonstrated:

| Backend state after attempted removal | Previous ownership supplied | New ownership supplied |
|---|---:|---:|
| Deleted rule still present | Verification fails | Verification passes |
| Unenrolled IP still present | Verification fails | Verification passes |

Additionally, [rollback](/Users/maheshwari/blah/app/orchestrator.py:995) is not read-back verified before [claiming that nothing changed](/Users/maheshwari/blah/app/orchestrator.py:1077). Its snapshot also excludes the scope map.

**Recommendation:** Verify against the previous ownership record; save new ownership only after successful verification. Verify rollback too, and distinguish complete restoration from partial recovery.

---

**3. High-priority bugs and security issues**

**H1 — [High] AdGuard failure can prevent unrelated firewall enforcement**

Locations: [desired-state backend calls](/Users/maheshwari/blah/app/orchestrator.py:678), [profile catalogue lookup](/Users/maheshwari/blah/app/orchestrator.py:730), [reconciliation failure handling](/Users/maheshwari/blah/app/orchestrator.py:1350), [incident filtering](/Users/maheshwari/blah/app/orchestrator.py:1409).

With a device profile or client-specific DNS policy active, `desired_state()` calls AdGuard. If that fails, reconciliation skips **every** enforcement domain, including MAC quarantine and IP blocking.

The error is stored under `"desired"`, but the enforcement-failure incident only includes domain-named errors. Consequently, this failure can also escape the intended incident path.

**Fix:** Compute and reconcile independent domains separately. AdGuard failure should affect DNS policy enforcement while firewall reconciliation continues.

---

**H2 — [High] DNS backlog beyond 10,000 records is silently discarded**

Locations: [paging limits](/Users/maheshwari/blah/app/ingest.py:42), [pagination](/Users/maheshwari/blah/app/ingest.py:838), [watermark advancement](/Users/maheshwari/blah/app/ingest.py:879).

The reader fetches newest-first, stops after 20 × 500 records, then advances the watermark to the newest fetched timestamp—even if it never reached the previous watermark.

Older, unfetched records now fall below the watermark and are permanently skipped.

A reduced in-memory example fetched timestamps `10, 9, 8, 7`, advanced the watermark to `10`, and stranded timestamps `1–6`.

**Fix:** Persist a catch-up cursor and batch boundary. Advance the completed watermark only after the whole intervening range has been drained. Make batch insertion resumable and duplicate-safe.

---

**H3 — [High] One structurally invalid record can repeatedly stall an ingestion source**

Locations: [Suricata loop](/Users/maheshwari/blah/app/ingest.py:594), [flattening](/Users/maheshwari/blah/app/ingest.py:419), [batch insertion](/Users/maheshwari/blah/app/ingest.py:504), [DPI loop](/Users/maheshwari/blah/app/ingest.py:952).

Only JSON decoding is protected per record. Valid JSON such as `[]`, unexpected nested field types, or an object missing required fields can raise afterward.

The outer step rolls back, leaving the cursor unchanged. The same record then fails every subsequent pass.

Separately, [timestamp parsing](/Users/maheshwari/blah/app/ingest.py:375) substitutes the current time on failure. This manufactures apparently valid event times and can incorrectly advance an API watermark.

**Fix:** Validate record shape and required fields before batching. Count rejected records explicitly, continue past them under a documented policy, and commit valid events and cursor progress together. Reject invalid timestamps rather than inventing them.

---

**H4 — [High] SQLite contention can freeze the entire web event loop**

Locations: [async authentication middleware](/Users/maheshwari/blah/app/webapp.py:149), [session touch](/Users/maheshwari/blah/app/session_auth.py:200), [30-second database timeout](/Users/maheshwari/blah/app/dbconn.py:41).

Every authenticated request performs synchronous SQLite work, including a committed update, inside async middleware.

If another process holds the write lock, that operation can block the ASGI event loop for up to 30 seconds. Requests unrelated to the contended operation also stop progressing.

Two producers of prolonged contention are:

- [Health checks](/Users/maheshwari/blah/app/health.py:124): write one service result, then continue subprocess probes before the final [commit](/Users/maheshwari/blah/app/health.py:315).
- [Threat-feed refresh](/Users/maheshwari/blah/app/intel.py:202): write one feed, fetch subsequent feeds, and commit after the loop.

Connections opened in the middleware are also not explicitly closed.

**Fix:** Run authentication database work in a worker thread that opens and closes its own connection. Throttle session-touch writes. Collect external results before starting short database write transactions.

---

**H5 — [High] Concurrent login attempts bypass the intended admission limit**

Locations: [rate check](/Users/maheshwari/blah/app/webapp.py:219), [awaited password verification](/Users/maheshwari/blah/app/webapp.py:236), [failure recording](/Users/maheshwari/blah/app/webapp.py:258).

Attempts are counted only after password verification finishes. A concurrent burst can therefore pass the limit check before any failures are recorded, scheduling substantially more expensive password checks than intended.

The login handler also reads the entire request body without an application-level bound at [line 209](/Users/maheshwari/blah/app/webapp.py:209).

**Fix:** Atomically reserve an attempt before expensive verification; bound concurrent verification and input size. This is an admission-control defect, not evidence that incorrect passwords authenticate.

---

**H6 — [High] A login racing a password change can survive session revocation**

Locations: [login credential read and session creation](/Users/maheshwari/blah/app/webapp.py:226), [password replacement and revocation](/Users/maheshwari/blah/app/webapp.py:2510).

A login can read the old password hash, suspend during verification, then create a session **after** a password change has revoked other sessions.

Legacy-password rehashing can also write an older credential after another request changes the password.

**Fix:** Introduce a credential generation/version. Session issuance and credential replacement must coordinate so verification against an obsolete generation cannot create a valid session. Rehashing needs a compare-and-swap check.

---

**H7 — [High] Hostname-based device merging can transfer policies and inspection consent**

Locations: [identity merge](/Users/maheshwari/blah/app/registry.py:195), [enrollment validation](/Users/maheshwari/blah/app/orchestrator.py:367), [enrollment follows device IP](/Users/maheshwari/blah/app/orchestrator.py:715).

A new MAC claiming the hostname of an unapproved device is merged into that device’s identity.

The check protects approval status, but unapproved devices can still hold enrollment, profiles, and exceptions. Those policies follow the merged identity. A hostname collision can therefore transfer security state or inspection consent to another physical device.

**Fix:** Treat a new MAC as a new identity. Offer an explicit identity-linking operation with separately reviewed policy and consent transfer.

---

**H8 — [High] Partial DNS fail-open activation can leave filtering bypassed after recovery**

Locations: [sequential rule installation](/Users/maheshwari/blah/app/dns_failopen.py:103), [recovery decision](/Users/maheshwari/blah/app/health.py:390), [active-state update](/Users/maheshwari/blah/app/health.py:410).

If UDP rule installation succeeds and TCP installation fails, a live bypass rule exists but the database still says `active=0`.

If DNS recovers before another activation attempt, recovery skips `deactivate()` because it trusts that database flag. The UDP bypass can remain indefinitely.

**Fix:** Apply both rules atomically where possible. Recovery must reconcile actual firewall state, including partially installed rules, rather than relying solely on the database flag.

---

**H9 — [High] Default proxy logging can undermine the privacy policy**

Location: [generated proxy command](/Users/maheshwari/blah/dpi/deploy-dpi.sh:52).

The shipped command does not disable mitmdump’s flow output. Its documented default includes shortened request URLs. Consequently, request paths and query fragments can reach service logs even when the custom addon avoids recording them. This depends on whether the deployed confdir overrides those defaults. [Mitmproxy options](https://docs.mitmproxy.org/stable/concepts/options/)

**Fix:** Explicitly disable generic flow output, retain only the intended structured telemetry, and verify the actual journal output using synthetic sensitive-looking URLs.

---

**H10 — [High, conditional] Editing DPI rules can delete existing privacy carve-outs**

Location: [module reconstruction](/Users/maheshwari/blah/app/webapp.py:2129).

The editor replaces the selected module with six fields. Other supported fields—such as `passthrough_suffixes`, `never_touch_paths`, endpoint restrictions, and pruning configuration—are discarded.

If such restrictions are configured on the edited module, an unrelated edit can remove them. Privacy confirmation only compares `decrypt_suffixes`, so it would not catch removal of a passthrough exception.

**Fix:** Preserve existing fields and update only the editor’s owned fields. Compare effective inspection scope, including exclusions, when deciding whether renewed confirmation is necessary.

---

**4. Additional correctness, security, and performance findings**

| Priority | Finding and impact | Location and recommendation |
|---|---|---|
| **[Medium]** | **Enrollment extensions do not renew an existing kernel timeout.** Presence alone passes verification. A policy extended to 24 hours can disappear at its previous expiry and then be classified as externally removed. | [Convergence](/Users/maheshwari/blah/app/orchestrator.py:975), [verification](/Users/maheshwari/blah/app/orchestrator.py:838), [extension endpoint](/Users/maheshwari/blah/app/webapp.py:2788). Renew and verify the timeout for explicit authorized duration changes, while preserving the rule against automatic re-enrollment after a privacy flush. |
| **[Medium]** | **The privacy canary bypasses the actual scope-map loader.** It replaces `_sites_for` with a lambda, so it cannot catch C1. It checks freshly imported disk code, which may differ from the running proxy. Its service is also absent from the central health list. | [Canary override](/Users/maheshwari/blah/dpi/privacy_canary.py:162), [fresh import](/Users/maheshwari/blah/dpi/privacy_canary.py:115), [service list](/Users/maheshwari/blah/app/services.list:11). Exercise real scope loading and deployed behavior; monitor canary freshness and service health. |
| **[Medium]** | **Engine exception handling leaves partial transactions pending.** A later step may commit an earlier failed step’s writes. Transaction ownership also leaks into helpers that commit internally. | [Engine wrapper](/Users/maheshwari/blah/app/engine.py:15), [audit helper](/Users/maheshwari/blah/app/audit.py:23). Roll back failed steps and centralize transaction ownership. The correlation runner already provides a better [pattern](/Users/maheshwari/blah/app/correlation.py:1768). |
| **[Medium]** | **Notification delivery can delay detection and policy reconciliation.** Sends run serially in the engine cycle; each network operation can wait seconds, and unsuccessful sends do not consume the successful-send rate limit. | [Engine scheduling](/Users/maheshwari/blah/app/engine.py:56), [dispatch loops](/Users/maheshwari/blah/app/notify.py:382), [timeout](/Users/maheshwari/blah/app/notify.py:52). Give notification processing a separate worker or a strict per-cycle budget. |
| **[Medium]** | **Large intercepted responses are buffered and decoded without a clear budget.** The addon calls `get_text()` before determining whether the body is JSON/HTML. The default scope includes video hosts. | [Response processing](/Users/maheshwari/blah/dpi/securepi_adfilter.py:824), [video scope](/Users/maheshwari/blah/dpi/adfilter_rules.py:181). Select streaming at response-header time and impose size/depth limits on rewritten bodies. Mitmproxy buffers bodies by default. [Streaming documentation](https://docs.mitmproxy.org/stable/overview/features/#streaming) |
| **[Medium]** | **An all-ad streamed response is forwarded unchanged.** Dropping every document leaves `docs=[]`; `if removed and docs` then skips replacing the original body. | [Document filtering](/Users/maheshwari/blah/dpi/securepi_adfilter.py:855), [write condition](/Users/maheshwari/blah/dpi/securepi_adfilter.py:867). Define and test the protocol-valid empty response for this case. |
| **[Medium]** | **Overlapping site suffixes are accepted despite an exclusivity invariant.** `example.com` and `ads.example.com` in different modules pass validation, but runtime assignment depends on dictionary order. | [Validation](/Users/maheshwari/blah/dpi/adfilter_rules.py:365), [matching](/Users/maheshwari/blah/dpi/adfilter_rules.py:404). Reject parent/child overlap across modules, or define explicit precedence and consent semantics. |
| **[Medium]** | **DNS-over-QUIC on UDP 853 remains allowed.** The firewall blocks TCP 853 and UDP 443 before broadly allowing LAN egress. IPv6 enforcement also needs explicit treatment if routed IPv6 is enabled. | [Firewall rules](/Users/maheshwari/blah/gateway/nftables.conf:172). Cover UDP 853 and test IPv4/IPv6 independently. UDP 853 is the standard DoQ port. [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250.html#section-4.1.1) |
| **[Medium]** | **Packet logging and journal ingestion lack explicit volume bounds.** Every matching bypass packet requests a log; ingestion captures the whole kernel-journal interval into memory. | [Firewall logging](/Users/maheshwari/blah/gateway/nftables.conf:172), [journal collection](/Users/maheshwari/blah/app/ingest.py:1057). Rate-limit logs separately from enforcement and use bounded, resumable journal reads. |
| **[Medium]** | **Device attribution’s `limit` argument is unused.** Each pass performs broad updates over unattributed events, plus an IPv6 scan. Repeatedly unmatchable events continue contributing work. | [Attribution](/Users/maheshwari/blah/app/registry.py:284), [updates](/Users/maheshwari/blah/app/registry.py:319). Process bounded candidate batches with appropriate indexes and a strategy for late-arriving identity information. |
| **[Medium]** | **Console queries scale with retained history.** Device listing performs multiple queries per device, including full retained-event aggregation. Incident listing has no pagination. | [Device listing](/Users/maheshwari/blah/app/webapp.py:1019), [incident listing](/Users/maheshwari/blah/app/webapp.py:1068). Batch device aggregates, use existing rollups where appropriate, and paginate incidents. |
| **[Medium]** | **Polling can overlap and render stale responses.** A new timer tick starts without awaiting the previous one. Older incident-filter requests can overwrite newer results. Independent timers also continue after the main Live control is paused. | [Scheduler](/Users/maheshwari/blah/app/static/app.js:117), [incident refresh](/Users/maheshwari/blah/app/static/app.js:900), [independent timer](/Users/maheshwari/blah/app/static/app.js:3051). Centralize polling, cancel obsolete requests, and reject stale generations. |
| **[Medium]** | **Background polling defeats human-idle session expiry.** Every authenticated poll refreshes `last_active`, so an unattended open tab keeps the session active until its absolute expiry. | [Middleware touch](/Users/maheshwari/blah/app/webapp.py:165), [idle check](/Users/maheshwari/blah/app/session_auth.py:192). Define whether “idle” means no requests or no operator activity, and implement that definition consistently. |
| **[Medium]** | **Investigating incidents disappear from “open” dashboard counts.** The dashboard queries only `status='new'` while risk scoring treats investigating incidents as live. The UI can say the network is quiet during an investigation. | [Counts](/Users/maheshwari/blah/app/webapp.py:779), [active feed](/Users/maheshwari/blah/app/webapp.py:872), [quiet message](/Users/maheshwari/blah/app/static/app.js:817), [risk statuses](/Users/maheshwari/blah/app/risk.py:33). Share one definition of open statuses. |
| **[Medium]** | **Historical threat indicators remain eligible for current high-severity detections indefinitely.** DNS blocklist generation applies freshness, while correlation does not. | [Correlation join](/Users/maheshwari/blah/app/correlation.py:787), [blocklist freshness](/Users/maheshwari/blah/app/intel.py:181). Separate historical attribution from current actionable intelligence; show indicator freshness in evidence. |
| **[Medium]** | **CSV exports permit spreadsheet formula interpretation.** CSV quoting handles delimiters but does not neutralize formula-leading device names or other exported strings. | [CSV cell encoder](/Users/maheshwari/blah/app/static/app.js:1026), [exported identity fields](/Users/maheshwari/blah/app/static/app.js:4111). Define a spreadsheet-safe export format; quoting alone is insufficient. [OWASP guidance](https://community.owasp.org/attacks/CSV_Injection) |
| **[Medium]** | **The blocklist utility constructs a remote shell command from a configured URL.** Local argument-array use does not protect the remote SSH command string. A malicious configured URL can introduce shell syntax. | [Remote curl command](/Users/maheshwari/blah/tools/blocklist_utility.py:98). Parse and validate the URL, quote the remote argument, and check command status. Exploitation requires influence over the configured list URL and execution of this utility. |
| **[Medium]** | **DPI deployment does not reload an already running process.** Files are replaced, but `enable --now` starts services rather than explicitly restarting active ones. The canary deployment has the same pattern. | [DPI deployment](/Users/maheshwari/blah/dpi/deploy-dpi.sh:73), [canary deployment](/Users/maheshwari/blah/dpi/deploy-privacy-canary.sh:39). Restart explicitly and verify deployed code identity. [Systemd command documentation](https://raw.githubusercontent.com/systemd/systemd/main/man/systemctl.xml) |
| **[Medium]** | **Privilege-separation setup hardens directories without verifying contained executable files.** Existing writable Python files would remain writable despite the script’s root-only-code claim. | [Permission setup](/Users/maheshwari/blah/gateway/setup-privilege-separation.sh:102). Verify ownership and modes throughout the executable/importable tree. This is conditional on existing file permissions. |
| **[Medium]** | **Chaos tests can proceed without successfully scheduling recovery.** The recovery timer’s return code is ignored. Cleanup also cancels the timer before verifying recovery. | [Undo scheduling](/Users/maheshwari/blah/gateway/chaos.py:86), [cleanup](/Users/maheshwari/blah/gateway/chaos.py:176). Refuse fault injection unless recovery is armed; cancel it only after successful restoration. |
| **[Medium]** | **The older evaluation harness understates detection latency and contaminates identity data.** Its timer starts after the attack command completes. Its DNS test persistently associates the gateway address with the attacker identity. | [Latency helper](/Users/maheshwari/blah/gateway/evaluate.py:79), [scan invocation](/Users/maheshwari/blah/gateway/evaluate.py:88), [identity mutation](/Users/maheshwari/blah/gateway/evaluate.py:161). Measure from the trigger and isolate/restore test mappings. Reassess results produced by this harness. |
| **[Medium]** | **Declared foreign keys are not explicitly enabled.** The connection factory sets a journal option but never enables FK enforcement. | [Connection factory](/Users/maheshwari/blah/app/dbconn.py:47), [example relationships](/Users/maheshwari/blah/app/schema.sql:238). Audit existing integrity and delete ordering, then enable enforcement on every connection. SQLite documents that enforcement must be enabled explicitly under normal defaults. [SQLite documentation](https://www.sqlite.org/foreignkeys.html) |

Two further edge cases deserve targeted regression coverage:

- [Incident retention](/Users/maheshwari/blah/app/retention.py:57) expands all expired IDs into one parameter list. A sufficiently large backlog can exceed the database’s parameter limit. Delete in bounded batches or use subqueries.
- [Held-out replay rates](/Users/maheshwari/blah/tools/heldout_replay.py:86) divide by exposure without guarding zero. A dataset whose devices each have only one event has nonzero event count but zero summed span at [line 153](/Users/maheshwari/blah/tools/heldout_replay.py:153).

---

**5. AI-generated debt, duplication, and test quality**

The strongest evidence of iterative-prompt debt is **local fixes that do not establish a shared invariant**:

- Ingestion and correlation roll back failed steps; the engine wrapper does not.
- Notification delivery avoids network calls inside write transactions; health and intel refresh do not.
- Approval inheritance through hostnames was addressed, but policy and consent inheritance remain.
- DNS pagination was expanded from one page to twenty without fixing the completion-watermark model.
- Multi-site inspection was added while preserving a YouTube-default assumption throughout fallback behavior and tests.

These are architectural consistency problems, even where individual functions are readable.

Specific cleanup opportunities:

| Issue | Evidence | Suggested change |
|---|---|---|
| Repeated privileged-helper invocation and nft parsing | [quarantine](/Users/maheshwari/blah/app/quarantine.py:51), [firewall sets](/Users/maheshwari/blah/app/firewall_sets.py:34), [DPI enrollment](/Users/maheshwari/blah/app/dpi_enroll.py:67) | Share the transport/error-handling layer and canonical set-element parser; retain separate domain APIs. |
| Two schema authorities | [migration list](/Users/maheshwari/blah/app/ingest.py:59), [schema](/Users/maheshwari/blah/app/schema.sql:1) | Introduce numbered migrations and test both fresh creation and upgrades. |
| Source-rewriting demo scaffolding | [demo loader](/Users/maheshwari/blah/docs/demo/serve.py:166) | Use an application factory with injected paths and adapters. |
| Unused local computation | [fingerprint placeholders](/Users/maheshwari/blah/app/fingerprint.py:193) | Remove the unused variable; the surrounding query also merits a clearer identity rationale. |
| Historical comments contradict current implementation | [audit-log “stopgap” comment](/Users/maheshwari/blah/app/webapp.py:2123) | Move chronology into documentation; keep current contracts beside code. |
| Inconsistent test-count documentation | [362 badge](/Users/maheshwari/blah/README.md:14), [641 table](/Users/maheshwari/blah/README.md:81) | Generate or update the count from one source. |
| Deployment is not reproducible from a dependency specification | [deployment recipe](/Users/maheshwari/blah/Makefile:70) | Add explicit Python dependency/version declarations and deployable version metadata. No Python requirements or lock manifest was found. |

I did not find a broad unused-import problem in the core modules. The identifiable dead code is smaller than the behavioral debt.

The test suite is substantial, but its confidence has limits:

- The fake backend can ignore additions, while its [deletions always work](/Users/maheshwari/blah/tests/test_orchestrator.py:87). That misses C2.
- A test explicitly accepts [connection-reset failure](/Users/maheshwari/blah/tests/test_orchestrator.py:508).
- Tests preserve the [default YouTube behavior](/Users/maheshwari/blah/tests/test_adfilter_modules.py:281).
- The privacy canary substitutes the very scope lookup that needs verification.

Retain these tests, but revise incorrect expectations and add adversarial backend behavior. Passing tests should demonstrate the user-facing guarantee, including failure paths.

Security strengths worth preserving include the unprivileged web service, constrained privileged helper, parameterized SQL in the reviewed paths, hashed console credentials, and deliberate output escaping. I found no obvious embedded production credential in the inspected source. That does not establish the cleanliness of Git history or live configuration.

---

**6. Prioritized action plan and suggested patches**

| Order | Priority | Work |
|---|---|---|
| 1 | **[Critical]** | Make inspection scope deny-by-default; verify complete consent changes and revocations. |
| 2 | **[Critical]** | Correct removal verification and verify rollback. |
| 3 | **[High]** | Isolate enforcement domains; repair DNS recovery reconciliation. |
| 4 | **[High]** | Repair pagination/cursor handling and malformed-record isolation. |
| 5 | **[High]** | Remove blocking SQLite work from async middleware; shorten write transactions. |
| 6 | **[High]** | Coordinate login admission, credential changes, and session issuance. |
| 7 | **[Medium]** | Fix duration renewal, deployment reloads, bounded workloads, and browser polling. |
| 8 | **[Quick Wins]** | Correct open-incident counts, preserve unedited rule fields, monitor the canary, remove unused variables, and reconcile documentation. |

The following are proposed changes only.

**A. Preserve previous ownership during verification**

Apply in both verification paths in [orchestrator.py](/Users/maheshwari/blah/app/orchestrator.py:1057):

```diff
- if not _domain_matches(d, desired[d], after[d], new_applied, now)
+ if not _domain_matches(d, desired[d], after[d], applied, now)
```

And at [the reconciliation check](/Users/maheshwari/blah/app/orchestrator.py:1378):

```diff
- if not _domain_matches(d, desired[d], after, new_applied, now):
+ if not _domain_matches(d, desired[d], after, applied, now):
```

Add cases where deletion returns normally but leaves the rule, enrollment, or old client settings intact.

**B. Make absent device scope disable inspection**

In [securepi_adfilter.py](/Users/maheshwari/blah/dpi/securepi_adfilter.py:503):

```diff
- return self._site_map.get(ip) or list(DEFAULT_SITES)
+ return list(self._site_map.get(ip, []))
```

Update the corresponding docstring and tests. Existing authorized YouTube enrollments should receive explicit map entries.

This fixes the missing/empty-map fallback. The stale-map write failure still requires the coordinated enforcement changes described in C1.

**C. Preserve module fields the editor does not own**

In [webapp.py](/Users/maheshwari/blah/app/webapp.py:2131):

```diff
  new_module = {
+     **copy.deepcopy(current_module),
      "decrypt_suffixes": body.decrypt_suffixes,
      "ad_fields": body.ad_fields,
      "ad_renderers": body.ad_renderers,
      "blocked_paths": body.blocked_paths,
```

Keep the existing cosmetic-field logic. Add a regression case proving that editing ad fields preserves passthrough hosts and never-touch paths.

**D. Move authentication database work into one worker-owned connection**

Current pattern:

```python
conn = db()
session = session_auth.get_session(conn, token)
session_auth.touch_session(conn, token)
```

Suggested helper:

```python
from contextlib import closing

def authenticate_and_touch(token):
    with closing(db()) as conn:
        session = session_auth.get_session(conn, token)
        if session is None:
            return False
        session_auth.touch_session(conn, token)
        return True
```

The middleware then uses:

```python
authenticated = await run_in_threadpool(
    authenticate_and_touch, token
)
```

Use `authenticated` for the existing redirect/401 branch and remove the old synchronous calls. Creating the connection inside the worker avoids transferring a SQLite connection across threads. Follow this with throttled touches and explicit connection lifetimes throughout the routes.

**E. Explicitly reload deployed DPI code**

In [deploy-dpi.sh](/Users/maheshwari/blah/dpi/deploy-dpi.sh:72):

```diff
  sudo systemctl daemon-reload
- sudo systemctl enable --now securepi-dpi
+ sudo systemctl enable securepi-dpi
+ sudo systemctl restart securepi-dpi
```

Apply the equivalent change to the canary deployment. Verify process startup and behavior after restarting; an `is-active` check alone does not establish that the intended version and configuration are operating correctly.

**Required acceptance cases before treating these guarantees as reliable**

- Failed backend deletions cannot produce a successful policy result.
- Missing, corrupt, stale, and unwritable scope maps never expand consent.
- Scope revocation handles already established connections.
- DNS outage leaves firewall reconciliation operational.
- Backlogs above 10,000 DNS records drain without omissions.
- Structurally invalid records do not permanently stall a source.
- SQLite contention does not freeze unrelated web requests.
- Concurrent login attempts respect admission limits.
- Verification of an old password cannot issue a session after credential replacement.
- Enrollment extensions match actual kernel expiry.
- Partial DNS fail-open installation is removed after recovery.
- Deployment checks exercise the running proxy and real scope loader.

All findings and suggested changes above are provided as text; no patches, test artifacts, or configuration changes were written.

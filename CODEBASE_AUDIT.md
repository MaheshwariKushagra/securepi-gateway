# CODEBASE AUDIT

**Repository:** SecurePi Gateway (`/Users/maheshwari/blah`, branch `main`, HEAD `c65d9b0`)
**Audit date:** 26 September 2026
**Mode:** Read-only. No repository files were changed. `git status` is clean after the audit.

**Verification performed**
- Read every module in `app/`, the DPI add-on and its rules, the privileged helper and its sudoers rule, `nftables.conf`, deploy and setup scripts, the templates, and the security-relevant parts of `app/static/app.js`.
- Ran the full test suite on a `git archive` copy in a scratch directory (`PYTHONDONTWRITEBYTECODE=1`). Result: **465 tests, all passing** on the Mac's Python 3.14.7.
- Wrote three small reproduction scripts in the scratch directory. They confirmed H1, L1 and L5. They ran against the real `app/orchestrator.py`, `app/settings.py` and `app/adguard.py`, using the project's own test fakes.
- Nothing was run against the live gateway. Findings about listeners, systemd units and live permissions are marked as needing runtime verification.

---

## 1. Executive Summary

The codebase is careful work overall. SQL is parameterised throughout. The privileged helper validates every argument and never uses a shell. The front end escapes untrusted strings consistently. Most of the earlier `Audit.md` findings have been fixed: the empty-password window, the text-mode `tell()` crash, notification network calls held inside transactions, Telegram token leakage, the engine heartbeat, the TLS-failure hook, and root-writable code directories.

This second audit found **no Critical issues**, **2 High**, **20 Medium** and **24 Low** findings. The most important:

1. **Privacy guarantee violation (High, confirmed by reproduction).** The privacy canary can flush the HTTPS-inspection set, and a reboot empties it. Before the engine's next reconcile, any console enroll or unenroll action re-enrolls *every* device whose enrollment was just wiped. If the engine is down, that window has no time limit. This breaks the documented rule that inspection is "only ever turned on deliberately".
2. **No host firewall on the gateway (High, config confirmed).** The `input` chain has `policy accept` on every interface, including the WAN uplink. Every service that listens on a wildcard address can be reached from the upstream network and from quarantined LAN devices.
3. **Fail-open DNS can silently disable filtering (Medium ×2).**
   - The health probe treats an upstream SERVFAIL as "the DNS filter is down". An upstream outage therefore turns filtering off for the whole network.
   - The recovery path trusts a database flag rather than nftables. A crash in the wrong place can leave the bypass rule in place indefinitely while the console reports fail-open as inactive.
4. **Detection quality problems that grow over time (Medium).**
   - Ordinary QUIC attempts count as "DNS bypass". This was confirmed live with Chrome.
   - Campaigns can never be closed, so auto-response fires at most once per device, ever.
   - Threat-intel matching uses every indicator ever seen, forever.
   - The DNS filter is flagged "stale" after 60 s with no queries, on a network measured at about 950 queries a day.
5. **Operational robustness (Medium).**
   - The engine loop is not protected against a locked database.
   - Ingest reads unbounded batches.
   - Dashboard polling scans entire time windows every 5 s.
   - `/login` accepts request bodies of any size before rate limiting.
   - The session idle timeout never fires while any console tab is open.

---

## 2. Repository / Architecture Overview

**Processes on the gateway** (Ubuntu 24.04 with Python 3.12 on the gateway; tests run on the Mac's Python 3.14):

| Process | Runs as | Entry point | Responsibilities |
|---|---|---|---|
| `securepi-ingest` | root (unit not in repo) | `app/ingest.py:main` | Tails the IDS `eve.json`, polls the DNS-filter query-log API (falls back to the file), tails DPI telemetry, reads the kernel log via `journalctl -k`, refreshes the device registry, attributes events to devices, runs the **platform health checks** and the **DNS fail-open** check |
| `securepi-engine` | root (unit not in repo) | `app/engine.py` | Every 15 s: hourly rollups, daily retention, 14 correlation signals, **policy orchestrator** reconcile, notifications, heartbeat |
| `securepi-web` | `securepi-web` (group `securepi`) | `uvicorn webapp:app` on `10.10.0.1:8000` over TLS | FastAPI console, session auth, JSON APIs. Reaches nftables only through `sudo /usr/local/sbin/securepi-web-helper` |
| `securepi-dpi` | root | `mitmdump` plus `dpi/securepi_adfilter.py` | Selective TLS interception on port 8080 for enrolled IPs |
| `securepi-privacy-canary` | root | `dpi/privacy_canary.py` | Imports the add-on every 15 min. Flushes the enrolled set if the scope check fails |
| `securepi-ca-server` | **root** (no `User=`) | `python3 -m http.server 8081` | Serves the inspection CA certificate |
| Timers | root | `app/intel.py`, `gateway/refresh-doh-set.sh` | Threat-intel feeds; the DoH IP set |

**Shared state:** one SQLite database in WAL mode at `/var/lib/securepi/securepi.db`, owned `root:securepi`, mode 664, in a directory with mode 2770. Two root daemons and the unprivileged console write to it concurrently. Cross-process coordination for enforcement uses `fcntl.flock` on `/var/lib/securepi/orchestrator.lock`.

**Main execution paths traced:**
- **Request lifecycle:** Origin check → session lookup (sync SQLite inside an async middleware) → route (sync handlers in the threadpool) → `orchestrator.create_policy` / `end_policy` (holds the lock, then apply → read back → roll back) → privileged helper or DNS-filter API.
- **Detection:** readers → `events` → `registry.attribute_events` → `correlation.run_all` → `raise_incident` (dedup) → `campaign_signal` → `orchestrator.auto_response` → `notify.dispatch`.
- **Enforcement drift:** `orchestrator.reconcile` compares three states per enforcement point: desired, last applied, and observed.
- **Availability safety nets:** `health.check_dns_failopen` (a DNAT to 1.1.1.1), `health.check_dpi_proxy` / `dpi_gate` (the inspection fails-open gate), and the canary flush.
- **Deploy:** `make deploy` rsyncs `app/` and `dpi/adfilter_rules.py` to `/opt/securepi`. The systemd units for ingest, engine, canary, static and the timers are **not in the repository**.
- **Build/CI:** none. No dependency manifest, and no CI workflow.

---

## 3. Critical Findings

None found. The candidates considered and downgraded are listed in §14.

---

## 4. High-Severity Findings

### H1. A console enroll or unenroll re-enables HTTPS inspection that the canary flushed or a reboot cleared

- **Severity:** High
- **Confidence:** Confirmed. Reproduced against the real orchestrator with the project's `FakeBackends`.
- **Location:** `app/orchestrator.py:891` `_converge_enrolled`, called from `_apply_and_verify` (`:949`), which `create_policy` (`:419`) and `end_policy` (`:466`) use. The guard exists only in `_reconcile_enrolled` (`:1142`), which only `reconcile()` calls.
- **What is wrong:**
  - The docstring of `_converge_enrolled` says it re-adds an IP "only if this policy hasn't been applied at that IP before". The code does not check this. For every active enroll policy whose IP is missing from the live set, it calls `b.enroll(ip, …)`.
  - The "never re-enable" rule is enforced only by `_reconcile_enrolled`, and that function is not on the console's apply path.
- **Why it matters:** The canary's fail-safe (`dpi_enroll.flush()`) and a reboot both exist to guarantee that inspection stays off until an operator acts on purpose. A console action on an *unrelated* device undoes that guarantee for every flushed device.
- **Reproduction:** Enroll A → reconcile → clear the set (the canary flush) → `create_policy("enroll", B)`. Result: `['10.10.0.31', '10.10.0.32']`, so A is enrolled again. The same happens on `end_policy` for any enroll policy.
- **Failure scenario:**
  1. The canary detects that the add-on would decrypt a non-allowlisted host and flushes the set.
  2. Within 15 s, or at any time while `securepi-engine` is down, the operator enrolls or unenrolls a phone.
  3. Every previously enrolled device goes back to being decrypted by the add-on the canary just judged unsafe.
- **Recommended fix:**
  - Move the "applied before and now missing → end the policy, don't re-add" logic into `_converge_enrolled` itself, or call `_reconcile_enrolled` inside `_apply_and_verify` before converging `enrolled`.
  - Consider having the canary also mark enroll policies ended in the database. Right now it only flushes nftables.
- **Tests to add:**
  - `create_policy("enroll", B)` after an external flush must not re-add A, and must end A's policy.
  - The same for `end_policy`.
  - The same after a boot-id change.

### H2. The gateway's `input` and `output` chains accept everything, on every interface including the WAN uplink

- **Severity:** High
- **Confidence:** High confidence. The configuration is confirmed. Actual exposure depends on which services listen on wildcard addresses; check with `ss -tulpn`.
- **Location:** `gateway/nftables.conf:69-93` (`chain input { … policy accept; }`, `chain output { … policy accept; }`)
- **What is wrong:** There is no default-deny for traffic addressed to the gateway itself. The four `input` rules only cover proxied port 8080. Nothing restricts `iifname "wlp2s0"` (WAN) or `ap0` (untrusted LAN) from reaching SSH, the DNS filter's port 53, DHCP, the CA server, the proxy, or anything installed later.
- **Why it matters:** This is the perimeter device. The uplink is Wi-Fi, which in practice means a shared or hotspot network. Quarantined devices are dropped only in `forward`, so they can still reach every gateway listener.
- **Failure scenario:** Another device on the uplink Wi-Fi brute-forces `sshd` on the gateway's WAN address, or uses the DNS filter as an open resolver. A quarantined device keeps probing gateway services.
- **Recommended fix:**
  - Set `policy drop` on `input` and allow only what is needed:
    - `ct state established,related`
    - `lo`
    - `enp1s0` → SSH
    - `ap0` → DHCP (67/udp), DNS (53), 8000/tcp, 8081/tcp, 8080/tcp only when redirected
  - Drop everything new from `wlp2s0`.
  - Keep the "quarantined device can still reach the console" behaviour as explicit allow rules.
- **Tests to add:** Extend the string-level config tests to assert `policy drop` on `input`. Add a live checklist item: a WAN-side `nmap` shows no open ports.

---

## 5. Medium-Severity Findings

### M1. The fail-open recovery trusts a database flag, so an orphaned DNAT rule can bypass DNS filtering indefinitely

- **Confidence:** High confidence in the logic. The trigger needs a failure between `activate()` and the state update.
- **Location:** `app/health.py:351-400` `check_dns_failopen` (the `resolving` branch at `:374-381`); `app/dns_failopen.py`
- **What is wrong:** When the DNS filter answers again, the rules are removed only `if row["active"]`. If `activate()` added the nft rules but the `UPDATE dns_failopen_state SET active=1` never committed, the rules stay forever. Causes include a `database is locked` error that then also fails the `signal_state` insert, so `run_step` rolls back; a database restored from backup; or migration.
- **Why it matters:** All plaintext DNS from the LAN is silently sent to 1.1.1.1, unfiltered. `/api/dns-status` reports fail-open as *inactive*. This contradicts the module's own promise that "a crash … must not orphan a rule".
- **Recommended fix:** In the resolving branch, call `dns_failopen.deactivate()` whenever `dns_failopen.is_active()` is true, whatever the database says. Also reconcile once at ingest start-up.
- **Tests to add:** State `active=0` with the fake nft reporting two fail-open handles, and a resolving probe. Expect both deletes.

### M2. The fail-open probe mistakes upstream failure for "the DNS filter is down"

- **Confidence:** High confidence (from `dig` semantics: SERVFAIL gives exit 0 and empty `+short` output).
- **Location:** `app/health.py:332-345` `_dns_resolves`
- **What is wrong:** `dig +short @10.10.0.1 example.com` returns exit code 0 with empty output when the DNS filter answers SERVFAIL, for example because its DoT upstreams are unreachable or DNSSEC validation fails. That counts as "not resolving", so after the grace period all LAN DNS is sent around the filter.
- **Why it matters:**
  - An upstream-only outage, such as DoT to 1.1.1.1 being blocked while plain UDP 53 works, silently turns off ad and malware filtering for the whole network.
  - A WAN outage raises a misleading "DNS filter not answering" high-severity incident.
- **Recommended fix:**
  - Probe liveness with a query the filter answers locally: a local rewrite, a `$dnsrewrite` canary it already has, or `use-application-dns.net` expecting NXDOMAIN.
  - Or use `dig` without `+short` and check that a response arrived at all.
  - Treat SERVFAIL as "the filter is alive".
- **Tests to add:** A SERVFAIL response must not count as down.

### M3. Every QUIC attempt counts as a "DNS bypass", producing constant false positives that feed campaign and auto-response logic

- **Confidence:** Confirmed. `EVALUATION-RESULTS-2.md:660` records Chrome's 51 QUIC attempts raising `dns_bypass` incident #447.
- **Location:** `app/correlation.py:523-600` `dns_bypass_signal` (counts every `source='nftables' AND event_type='bypass_attempt'`); `gateway/nftables.conf:126` (the `quic-blocked` log/reject rule)
- **What is wrong:** UDP/443 is QUIC to any website. It is not DNS evasion. With the default threshold of 3 events in 300 s, every Chrome or YouTube device fires repeatedly.
- **Why it matters:**
  - The incident is tagged ATT&CK Defense Evasion. Combined with any other tactic, it can form a campaign.
  - If `auto_quarantine_enabled` is on, it counts toward the minimum-tactics threshold for automatic quarantine.
  - It is also notification noise.
- **Recommended fix:**
  - Exclude `block_reason='quic-blocked'` from `dns_bypass_signal`. Only count UDP/443 to `@doh_resolvers` (DoH3) and 853.
  - Keep QUIC rejects as a plain metric.
- **Tests to add:** QUIC-only events do not fire `dns_bypass`. QUIC to a DoH resolver IP does.

### M4. The nftables `log` rules have no rate limit, so any LAN client can flood the journal and the events table

- **Confidence:** High confidence.
- **Location:** `gateway/nftables.conf:91, 124-126`; `app/ingest.py:970-1048` `read_nft_log`
- **What is wrong:** Each rejected packet to 853, to a DoH resolver on 443, or to UDP/443 is logged with no `limit rate`. Each log line becomes an `events` row.
- **Failure scenario:** A LAN device sends a UDP/443 flood. This produces kernel log lines, journald load, and a large `journalctl -o json` batch every 10 s, all of which are inserted and then scanned by `dns_bypass_signal`. The result is disk and CPU pressure on a 3.6 GiB box.
- **Recommended fix:** Use `log prefix "…" limit rate 10/second burst 20 packets`, or limit per source (`meter`). Log only `ct state new`.
- **Tests to add:** A config test asserting `limit rate` on every `log` rule.

### M5. Campaigns can never be closed, so new incidents attach to ancient campaigns and auto-response is one-shot per device

- **Confidence:** Confirmed. No code path anywhere updates `campaigns.status`.
- **Location:** `app/correlation.py:1145-1232` (`existing` lookup at `:1189` has no time bound); `app/orchestrator.py:1036-1075` (`auto_response`, "never twice" per campaign); `app/webapp.py:1361` (read-only list)
- **What is wrong:** A device's first campaign stays `new` forever. Every later ATT&CK-tagged incident on that device, even weeks later, is attached to it and its `tactics` string is overwritten. `auto_response` skips campaigns it has already acted on, so a device is auto-quarantined at most once in its lifetime.
- **Why it matters:**
  - A genuine second attack is never auto-contained.
  - The campaign bonus in `risk.device_risk` keeps a stale campaign alive.
  - The kill-chain history is rewritten.
- **Recommended fix:**
  - Add campaign status transitions: a PATCH endpoint, plus auto-close when there are no live incidents within `campaign_window_seconds`.
  - Bound the `existing` lookup by `last_seen > since`.
- **Tests to add:**
  - A second, separated attack creates a new campaign.
  - `auto_response` acts on it.

### M6. Hostname-based identity merging still hands one device's identity to another through "unknown" devices

- **Confidence:** High confidence.
- **Location:** `app/registry.py:125-173` `resolve_device` (merge allowed when `trust != 'approved'`, `:152`)
- **What is wrong:**
  - The fix for the earlier H2 only blocks merging into *approved* devices.
  - Every new device is `unknown` by default (`restrict_unknown_devices` is off by default). So an attacker who announces a victim's DHCP hostname has their MAC attached to the victim's device record.
  - When the operator later approves "the device", the attacker's MAC is approved as well.
  - An operator or auto-response quarantine of the victim record also blocks the attacker, and the attacker's malicious traffic is attributed to the victim.
- **Failure scenario:** The attacker sets hostname `Galaxy-S23`. Their scans raise incidents on the victim's record. Auto-quarantine then cuts off the victim's real MAC (collateral denial of service), or approval admits the attacker.
- **Recommended fix:** Never merge on hostname automatically. Create a new device and surface a "probably the same as #N" suggestion for the operator to confirm.
- **Tests to add:** A new MAC with the hostname of an unknown device creates a new device. Approving device X does not approve MACs added by hostname.

### M7. The unauthenticated `/login` reads a request body of any size before rate limiting

- **Confidence:** Confirmed from code (uvicorn has no body-size limit by default).
- **Location:** `app/webapp.py:191-261` (`await request.body()` at `:208`, rate-limit check at `:218`)
- **What is wrong:** Any LAN client can POST a multi-gigabyte body. It is buffered in full and `parse_qs`'d. The rate limit only applies afterwards, and each accepted attempt costs a 600,000-iteration PBKDF2.
- **Failure scenario:** A LAN client streams a large body, or many parallel requests. The console process runs out of memory, and the OOM killer may also hit ingest or AdGuard on the 3.6 GiB host.
- **Recommended fix:**
  - Reject when `Content-Length` is over about 4 KiB, or read with a size cap.
  - Check the rate limit before reading or hashing.
  - Cap the password length (for example 1 KiB).
- **Tests to add:** An oversized body returns 413. A rate-limited IP receives 429 without its body being read.

### M8. Synchronous SQLite writes inside the async auth middleware block the event loop on every request

- **Confidence:** High confidence.
- **Location:** `app/webapp.py:147-165` (`db()`, `get_session`, `touch_session` → `commit()`); `app/session_auth.py:200-205`
- **What is wrong:** The middleware is `async`, but it opens a connection and commits a write on every request, including 5-second polls. With the default 5 s busy timeout, a writer lock held by ingest, retention or the engine stalls *all* console requests. Connections are never explicitly closed; the test run shows `ResourceWarning`s.
- **Recommended fix:**
  - Run the session lookup and touch in `run_in_threadpool`.
  - Throttle `touch_session`, for example once per 60 s per session.
  - Close connections in `finally`, or use a request-scoped dependency.
- **Tests to add:** A middleware unit test with a locked database, asserting a bounded latency or a 503.

### M9. The session idle timeout is ineffective because background polling refreshes every session every 5 s

- **Confidence:** Confirmed. This was reported in `Audit.md` and is not fixed.
- **Location:** `app/static/app.js:117-124` (`tick()` runs every 5 s regardless of `document.hidden`); `app/webapp.py:164`
- **What is wrong:** Any open tab, including a background one, keeps the session active until its 12-hour absolute expiry. The 30-minute idle timeout never fires.
- **Recommended fix:**
  - Mark polling requests with a header such as `X-SP-Background: 1` and do not `touch_session` for them.
  - Pause `tick()` when `document.hidden`.
- **Tests to add:** A background-flagged request does not advance `last_active`.

### M10. The health staleness check raises recurring false "DNS filter stale" incidents on a quiet network

- **Confidence:** High confidence. The docstring in `read_agh_api` gives the measured rate of about 950 DNS queries a day, roughly one per 90 s.
- **Location:** `app/health.py:159-197` (`:183-187`); `app/settings.py` `health_stale_after_seconds` default 60
- **What is wrong:** "No LAN DNS query in 60 s" is treated as a hung sensor. The IDS check has the same problem at night.
- **Why it matters:** A new medium-severity `platform_stale` incident after every quiet gap longer than the 10-minute dedup window, each one notified. Real hangs get lost in this noise.
- **Recommended fix:** Use sensor-intrinsic heartbeats: the IDS `stats` record time in `sensor_stats`, and the DNS filter's own `/control/status` or a successful `read_agh_api` call. Do not use traffic volume.
- **Tests to add:** No events for 10 minutes plus a fresh `sensor_stats` row means not stale.

### M11. Threat-intel correlation matches every indicator ever seen, forever

- **Confidence:** Confirmed.
- **Location:** `app/correlation.py:728-748` `_threat_intel_matches` (joins `ioc` with no `last_seen` filter); `app/intel.py` `_upsert_indicators` (never expires)
- **What is wrong:** The fix for the earlier Audit finding applied the 30-day freshness rule only to the *blocklist file*. Correlation still raises **high** severity "known-malicious" incidents for domains and IPs that abuse.ch delisted long ago, typically hacked sites that were cleaned up or reassigned IPs.
- **Recommended fix:** Apply the same freshness predicate used in `_write_domain_blocklist_file`. Prune or archive `ioc` rows older than N days.
- **Tests to add:** An IOC last seen more than 30 days before its feed's latest refresh does not match.

### M12. The engine loop is not protected against exceptions outside the correlation and orchestrator calls

- **Confidence:** High confidence. The unit's `Restart=` policy is not in the repository.
- **Location:** `app/engine.py:19-54` (`rollup.rollup_closed_hours`, `retention.run_retention_if_due` and `health.record_engine_heartbeat` are not wrapped)
- **What is wrong:** A `sqlite3.OperationalError: database is locked` is plausible given the 5 s busy timeout, ingest's writes, and retention's single large daily `DELETE`. It kills the engine process, which stops detection, enforcement expiry and notifications.
- **Recommended fix:**
  - Wrap each stage like `ingest.run_step`.
  - Set `sqlite3.connect(..., timeout=30)` everywhere.
  - Run retention in chunks, for example `DELETE … WHERE id IN (SELECT id … LIMIT 5000)`, committing between chunks.
  - Commit the unit files with `Restart=always`.
- **Tests to add:** An engine-step test where `rollup` raises. The loop continues and the heartbeat still advances.

### M13. Ingest readers load all new log lines into memory in one batch and one transaction

- **Confidence:** Confirmed.
- **Location:** `app/ingest.py:512-567` `read_eve`; the same pattern in `read_agh_querylog` (`:617-660`) and `read_dpi_events` (`:870-912`)
- **What is wrong:** After a restart, a rotation to a large file, or an ingest outage, the whole backlog is read into `rows` and inserted in one transaction. That means unbounded memory, a long writer lock (feeding M8 and M12), and a delayed DNS fail-open check, which runs later in the same loop.
- **Recommended fix:** Cap each pass to N lines or bytes, for example 20,000 lines. Save the offset after each chunk and let the next 2 s cycle continue.
- **Tests to add:** A 100k-line file is ingested over several passes with a correct final offset.

### M14. The DNS-filter API watermark assumes entries arrive in timestamp order

- **Confidence:** Possible concern. It depends on whether AdGuard Home stamps `time` at query start; verify on the live API.
- **Location:** `app/ingest.py:763-829` (`if ts <= watermark: continue`)
- **What is wrong:** If a slow upstream query that started at t0 is logged after a faster query that started at t1 > t0, and a poll happens in between, the watermark moves to t1 and the slow entry is skipped permanently. Slow queries are disproportionately NXDOMAIN or timeouts, which are exactly the inputs to the DGA and tunnelling signals. A backlog larger than 10,000 entries (`AGH_API_MAX_PAGES`) is also dropped silently.
- **Recommended fix:**
  - Keep an overlap window (watermark minus 30 s) with a dedup key that includes `elapsedMs` and `upstream`.
  - Log when the page cap is hit.
- **Tests to add:** An out-of-order entry arriving after the watermark advanced is still imported.

### M15. Dashboard and devices polling scan whole time windows every 5 seconds

- **Confidence:** Confirmed.
- **Location:**
  - `app/webapp.py:573-630` `bucket_series` (three full-window scans done in Python)
  - `:743-892` `api_overview` (includes `count(*) FROM events` over the whole table)
  - `:1313-1324` `api_heatmap` (every event from the last 7 days, bucketed in Python)
  - `:996-1047` `api_devices` (N+1: five queries per device, including an all-history aggregation, plus `risk.device_risk` per device)
  - `:1136-1166` `_hunt_aggregates` (`SELECT *` with no limit, up to 7 days)
  - Callers: `app/static/app.js:588-592, 836`
- **Why it matters:** At the measured rate of about 16k events a day, with 30-day retention, each open tab triggers hundreds of thousands of row visits every 5 s on a low-power box, competing with ingest for the database.
- **Recommended fix:**
  - Use `device_hourly` rollups for 24h and 7d ranges.
  - Compute the heatmap with SQL `GROUP BY strftime(...)` or from rollups, and cache it for 60 s.
  - Replace the per-device loops in `/api/devices` with grouped queries.
  - Add a limit to hunt aggregates.
- **Tests to add:** Query-count tests, for example `/api/devices` runs a constant number of queries regardless of device count.

### M16. Root daemons write into directories that non-root principals can modify

- **Confidence:** Possible concern (live permissions need checking).
- **Location:**
  - `dpi/deploy-dpi.sh:120` (`chown maheshwari:maheshwari /var/log/securepi`)
  - `dpi/securepi_adfilter.py:296-315` (fixed `RULE_STATS_PATH + ".tmp"`, `open(..., "w")` as root)
  - `gateway/setup-privilege-separation.sh` (`/var/lib/securepi` and `/var/lib/securepi-dpi` at mode 2770 without the sticky bit)
- **What is wrong:**
  - The root mitmproxy truncates a fixed-name temp file in a directory owned by the login user.
  - Root ingest and engine open `securepi.db`, its `-wal`/`-shm` files, and `orchestrator.lock` (`O_CREAT`, following symlinks) in a directory where the `securepi` group, and so the console process, can delete and replace files.
- **Failure scenario:** A compromised console process, or the login account, replaces `dpi-rule-stats.json.tmp` or a WAL-adjacent file with a symlink. A root process then truncates or writes an arbitrary file. This is a residual of the earlier C1 finding at the data layer.
- **Recommended fix:**
  - Make `/var/log/securepi` root-owned.
  - Use `tempfile.mkstemp` in the add-on.
  - Set the sticky bit (mode 3770) on shared data directories, or better, run ingest and engine as a dedicated non-root user.
  - Open lock files with `O_NOFOLLOW`.
- **Tests to add:** Config tests asserting ownership and modes in the setup scripts, with no personal usernames.

### M17. The console TLS CA is an unconstrained root CA whose key stays on the gateway and is trusted by the admin Mac

- **Confidence:** Confirmed from the script.
- **Location:** `gateway/generate-console-tls.sh` (CA key at `/opt/securepi-tls/ca.key`; instructions to add it as `trustRoot` to the macOS System keychain)
- **What is wrong:** Anyone who gets root on the gateway can mint a certificate for any domain that the admin's Mac trusts system-wide.
- **Recommended fix:**
  - Either add `nameConstraints=critical,permitted;IP:10.10.0.1/255.255.255.255,permitted;DNS:localhost` to the CA,
  - or trust only the leaf certificate,
  - and delete or move `ca.key` offline after issuing.
- **Tests to add:** A config test that checks for the name-constraints extension.

### M18. Daemons that parse untrusted input run as full root

- **Confidence:** High confidence. The units for ingest, engine and canary are not in the repository.
- **Location:** `dpi/deploy-dpi.sh` (the `securepi-dpi` and `securepi-ca-server` units have no `User=`); `Makefile` comment ("every securepi-* service unit has no User=")
- **What is wrong:** mitmproxy (TLS and HTTP parsing of LAN traffic), `python -m http.server` (LAN-facing), and the JSON and DNS-name parsing in ingest and engine all run as root. The console dropped root, but the larger attack surface still has it.
- **Recommended fix:**
  - Run `securepi-ca-server` as `nobody` with `ProtectSystem=strict`.
  - Run mitmproxy as a dedicated user with `CAP_NET_ADMIN` only if it needs it; transparent mode needs `SO_ORIGINAL_DST`, which usually doesn't require root.
  - Run ingest and engine as a `securepi-engine` user that reaches nftables through the helper.
  - Add systemd sandboxing directives.

### M19. The DPI add-on decodes and buffers every decrypted response, including video segments

- **Confidence:** High confidence. This was reported in the earlier audit and is not fixed.
- **Location:** `dpi/securepi_adfilter.py:510-525` `response()` (`flow.response.get_text()` on every response); `decrypt_suffixes` includes `googlevideo.com`
- **Why it matters:** Media segments are buffered in full and decoded as text before they reach the phone. That adds latency and memory spikes in the root proxy, and wastes CPU.
- **Recommended fix:**
  - Return early unless the content type is JSON or HTML and the host is in an "inspect bodies" allowlist.
  - Set `stream_large_bodies` and use a `responseheaders` hook to mark `googlevideo.com` flows as streamed.
- **Tests to add:** A `video/mp4` response is not touched and `get_text` is never called.

### M20. The repository cannot rebuild the gateway: unit files, dependency manifest and CI are missing

- **Confidence:** Confirmed.
- **Location:** The repository root. There is no `requirements.txt`/`pyproject.toml`, no `.github/`, and no units for `securepi-ingest`, `securepi-engine`, `securepi-privacy-canary`, `securepi-static`, `securepi-intel-refresh.timer`, `securepi-doh-refresh.timer` or `securepi-test-harness`.
- **Why it matters:**
  - Restart policies, users and ordering can't be reviewed.
  - A rebuild after disk loss depends on runbook prose.
  - Tests run on Python 3.14 on the Mac while the gateway runs 3.12.
  - `README.md` says 362 tests; there are 465.
- **Recommended fix:**
  - Commit every unit file under `gateway/systemd/`.
  - Pin `fastapi`, `uvicorn`, `jinja2`, `pydantic` and `mitmproxy`.
  - Add a CI workflow that runs `make test` on 3.12.

---

## 6. Low-Severity Findings

| ID | Title | Confidence | Location | Problem, impact and scenario | Recommended fix | Test to add |
|---|---|---|---|---|---|---|
| L1 | NaN passes numeric setting validation | Confirmed (reproduced) | `app/settings.py:376-393` `validate`; `webapp.py:2487` | `json.loads('NaN')` passes the `<min` and `>max` checks. For example, `baseline_z_threshold=NaN` makes `z > NaN` always false, which silently disables volume-anomaly detection (the same applies to beacon and entropy thresholds). | Reject `not math.isfinite(value)` | `set_value(..., float('nan'))` raises |
| L2 | The settings reset route ignores the `dedicated` flag | Confirmed | `app/webapp.py:2506-2516` | `POST /api/settings/restrict_unknown_devices/reset` changes a setting that is meant to be changed only through `/api/trust/restrict`, and does not reconcile | Apply the same `dedicated` check as `api_settings_set` | The reset of a dedicated key returns 400 |
| L3 | The suppression API accepts any `device_id` and contradicts its own contract | Confirmed | `app/webapp.py:1386-1416` vs the model comment `:347-353` | `None` becomes the incident's device, so network-wide suppression is impossible for device incidents. Any other device id is accepted, so one false-positive incident can silence a signal on an unrelated device. | Allow only `None` (the incident's device) or an explicit `"network"` flag | An unrelated `device_id` returns 400 |
| L4 | An incident merge can move `last_seen` backwards | High confidence | `app/correlation.py:128-135` | `UPDATE incidents SET last_seen=?` uses the newest firing's value even if it is older, for example two destinations in one cycle. This affects dedup and risk decay. | `last_seen = max(last_seen, ?)` | Merge an older firing and check `last_seen` is unchanged |
| L5 | `quote_client` passes newlines and control characters into DNS-filter rule text | Confirmed (reproduced); exploitability is a possible concern | `app/adguard.py` `quote_client` / `domain_rule` | A device label containing `\n` produces an extra rule line. Labels come from `friendly_name` (operator) or DHCP hostname; AdGuard likely sanitises the latter (not verified). | Reject or strip `\r\n\t` and control characters in labels and client names | Control characters raise or are stripped |
| L6 | Threat-intel indicators are written into the blocklist unvalidated and non-atomically | High confidence | `app/intel.py:165-191` | Feed values are written as `\|\|%s^` with no domain validation. A malformed or modifier-bearing value becomes a rule. `open("w")` means the DNS filter may fetch a truncated list. | Validate with `orchestrator.normalize_domain`; write to a temp file and `os.replace` | A malformed indicator is skipped |
| L7 | Webhook URLs are shown unmasked; email allows cleartext credentials | Confirmed | `app/notify.py` `FIELDS`, `masked_config`, `validate_channel` | Slack- and Discord-style webhook URLs *are* credentials but are returned in full by `/api/notifications/channels`. `security: none` with a password sends it in cleartext. | Mask the webhook URL path; refuse `none` when a password is set | A masked URL in `channel_dict` |
| L8 | Dead and legacy code | Confirmed | `app/quarantine.py` (only `docs/demo/serve.py` uses it); `inet filter quarantine` IP set; `registry.attribute_events(limit=50000)` (unused parameter; returns *total* attributed, logged as "attributed N"); `app/services.list` lists `securepi-test-harness` as always-on | Misleading logs and a larger maintenance surface. The test harness counts as production health. | Remove, or mark legacy; return `rowcount` of new attributions; move the harness out of `services.list` | — |
| L9 | "Current IP" logic is duplicated and inconsistent | Confirmed | `webapp.py:1002-1004, 1949-1951, 2026-2028, 3379-3381`; `orchestrator.py:1178, 1115` | These use "latest `device_ips` row" rather than `orchestrator.device_ip`, which is the reassignment-aware rule from the Audit H3 fix. They can show or adopt the wrong device for a reassigned IP. | Use one helper everywhere | Reassigned IP maps to the new owner in `/api/filtering/dpi/enrolled` |
| L10 | No CSP or HSTS on the console | High confidence | `app/webapp.py:177-183` | 130 `innerHTML` sinks render attacker-influenced DNS, SNI and hostname strings. The spot check found consistent `esc()`, but one future slip becomes stored XSS in the admin console. | Add `Content-Security-Policy: default-src 'self'; script-src 'self'` (move the inline `onclick` in `device_detail.html:155`) and HSTS | A header test |
| L11 | LIKE wildcards are not escaped in search | Confirmed | `webapp.py:1125, 1569` | `%` and `_` in the user's term act as wildcards. This is a correctness issue, not injection. | Escape and add `ESCAPE '\'` | Search for a literal `_` |
| L12 | Unbounded list endpoints | Confirmed | `api_incidents` (`:1050`), incident evidence (`:3385-3388`), `api_list_campaigns` | These grow with retention (365 days of incidents). | Pagination and limits | A limit test |
| L13 | Tables with no retention | Confirmed | `login_attempts`, `campaigns`, `ioc`, `devices`/`device_ips`/`device_macs`, digest `notifications` (`incident_id IS NULL`) | Slow, unbounded growth | Add them to `retention.py` | Retention tests |
| L14 | SQLite settings only partially applied | Confirmed | `app/schema.sql:12-13`; every `sqlite3.connect` | `synchronous=NORMAL` applies only to the connection that ran the schema. `PRAGMA foreign_keys` is never enabled, so the declared foreign keys are decorative. `busy_timeout` stays at the 5 s default. | One `connect()` helper that sets the pragmas | — |
| L15 | Documentation drift | Confirmed | `README.md:14,79,652` (362 tests); `session-start.sh` prints `http://localhost:8000` although the console is HTTPS-only | Misleading | Update | — |
| L16 | Retention runs as one huge daily transaction | Possible concern | `app/retention.py:73-99` | The first run or a backlog makes one long writer lock, which causes M8 and M12 symptoms. The database is never `VACUUM`ed. | Chunked deletes; periodic `PRAGMA incremental_vacuum` | Chunked delete test |
| L17 | The password rehash on login can overwrite a concurrent password change | Possible concern (legacy hash only) | `webapp.py:237-239` vs `:2477-2478` | A login using the old legacy password rehashes and writes *after* a concurrent change, restoring the old password | Compare-and-swap: re-read the stored value before writing | — |
| L18 | Timestamp parse failures silently become "now" | Confirmed | `app/ingest.py` `parse_rfc3339` (`except Exception: return time.time()`) | Mis-timestamped events are not counted as parse errors | Return `None`, count an error, and skip | Malformed timestamp increments `parse_errors` |
| L19 | The DGA and tunnelling base domain is still "last two labels" | Confirmed | `app/correlation.py:856-864` | `*.co.uk` and `*.com.au` group unrelated sites. This is the residual of the earlier H11. | Bundle a small public-suffix list | `a.example.co.uk` gives base `example.co.uk` |
| L20 | `decrypt_suffixes` has no breadth guard; the canary checks one host | Confirmed | `dpi/adfilter_rules.py:validate_rules`; `dpi/privacy_canary.py` | With confirmation, an operator (or a stolen session) can add `googleapis.com`, `apple.com` and so on. Only `example.com` is canary-tested. | Refuse single-label and public-suffix entries; keep an allowlist of permitted suffixes | Validation tests |
| L21 | `managed_rules` is checked outside the lock | High confidence | `webapp.py:1542-1547` | A time-of-check/time-of-use gap: a rule can become managed between the check and the removal | Check inside `orchestrator.lock()` | — |
| L22 | The evaluation battery writes synthetic devices and incidents into the production database and uses fixed `/tmp` paths as root | Confirmed | `gateway/battery.py:76, 575-586` | Pollutes production history (NEXT-SESSION notes 167 incidents had to be cleaned). Predictable `/tmp/battery-sshd` as root. | Separate database or tag-and-purge; `tempfile.mkdtemp` | — |
| L23 | Wi-Fi has no management-frame protection | High confidence | `gateway/hostapd.conf` | WPA2-PSK without `ieee80211w` allows trivial deauthentication | `ieee80211w=1`, or WPA3-SAE transition mode | Config test |
| L24 | `backup.sh` runs `git add -A && git push` to a public repository | High confidence | `backup.sh` | `.gitignore` does not exclude `*.db` or `*.bak` outside `docs/demo/`. A copied database or backup would be pushed with its browsing history. | Add `*.db*` and `*.bak` to `.gitignore`; stage paths explicitly | — |

---

## 7. Security Review

**Strong points, verified:**
- **SQL:** Every dynamic fragment is a constant or a placeholder list: `_hunt_where`, `retention`, `registry.touch_interval` table names. No injection path was found.
- **Privileged helper** (`gateway/securepi-web-helper`): argv lists only; strict IP, MAC, hour and second validation; hardcoded table and set names; `sudoers` scoped to one binary; installed `root:root` with mode 700.
- **Authentication:** PBKDF2-SHA256 with 600k iterations; empty-password rejection; atomic `write_password_file`; server-side sessions; `HttpOnly`, `SameSite=Strict` and `Secure` cookies; other sessions revoked on password change; per-IP failed-login limit.
- **CSRF:** `SameSite=Strict` plus the Origin check. FastAPI parses JSON bodies only for JSON content types.
- **Open redirect:** the `next` check plus Starlette's `RedirectResponse` percent-encoding blocks `/\evil.com` (see §14).
- **Front end:** consistent `esc()`; `toast()` uses `textContent`.
- **Secrets:** channel secrets masked (except webhook URLs, L7); `_host()` and `_redact()` keep tokens out of stored errors.

**Weak points, by trust boundary:**

| Boundary | Findings |
|---|---|
| WAN or LAN → gateway services | H2 (no input filtering), M7 (`/login` body denial of service), L23 |
| LAN device → identity and trust | M6 (hostname merge) |
| Console → privacy-sensitive enforcement | H1 (inspection re-enabled), L20 (suffix breadth) |
| Unprivileged → root | M16 (shared writable directories and symlinks), M18 (root parsers) |
| Admin workstation trust | M17 (unconstrained CA) |
| Availability safety nets | M1, M2 (fail-open) |
| Session management | M9 (idle timeout ineffective), L10 (no CSP or HSTS), L17 |
| Third-party data | L6, M11 (threat-intel feeds) |

---

## 8. Correctness and Reliability Review

- **Orchestrator:** The apply → verify → roll back design is solid and well tested (43 tests). The gap is that the invariants live in `reconcile()` only, while the console path uses `_apply_and_verify` (H1). Also, `create_policy` commits the policy as `active` before applying it. A non-backend exception (a bug or a locked database) leaves an active policy and "replaced" predecessors with no rollback, and the next reconcile enforces it. Catch `Exception` around the apply and revert the rows.
- **Detection:** M3 (QUIC counted as bypass), M5 (campaigns never close), M10 (staleness), M11 (stale IOCs), L4 (`last_seen` backwards), L19 (base domain). `raise_incident` dedup and evidence counting are correct.
- **Ingest:** H4 from the earlier audit is fixed with binary `readline` and per-step `run_step` with rollback. Remaining: M13 (unbounded batch), M14 (ordering assumption), L18, and a stat-then-open rotation race in `read_eve` (`os.stat` then `open` by path).
- **Health:** M1, M2, M10. `check_dpi_proxy` fails open correctly.
- **Engine:** M12.
- **Error swallowing:** `registry.read_leases` returns `[]` on any exception, silently. `adguard.service_catalog` failures are hidden by `_catalog_or_empty`. Both are acceptable, but they should log.

---

## 9. Performance Review

| Hot path | Cost | Finding |
|---|---|---|
| Dashboard tick (5 s per tab) | 3 full-window scans + 7-day heatmap in Python + full `count(*)` | M15 |
| Devices page (5 s) | N+1 queries: 5 per device + all-history aggregation + risk | M15 |
| Hunt | Unbounded `SELECT *` aggregation | M15 |
| Every request | Session write and commit in async middleware | M8 |
| `registry.attribute_events` (every 2 s) | Scans all unattributed LAN events; pass 3 scans every `device_id IS NULL` row for `fe80%`; correlated subqueries per row. Events from LAN IPs that never match (e.g. `10.10.0.1`) are rescanned forever | Low–Medium: add a partial index `ON events(src_ip) WHERE device_id IS NULL` and cap by id watermark |
| DPI `response()` | Decodes every decrypted body, including media | M19 |
| `intel._write_domain_blocklist_file` | Correlated `max()` subquery per row, with no index on `ioc.source` | Low: precompute per-source max |
| `audit.for_target` | No index on `audit_log(target)` | Low |
| Retention | One giant `DELETE`; no vacuum | L16 |

---

## 10. Dead Code, Duplication, and Unused Dependencies

- **Dead or legacy:**
  - `app/quarantine.py` (demo-only).
  - The IP-keyed `inet filter quarantine` set and its helper verbs (kept for the CLI).
  - The `limit` parameter of `registry.attribute_events`.
  - `adguard.add_nxdomain_rule` / `add_user_rule` have callers, but the old per-device helpers are gone. That's good.
  - `app/status.py` is a top-level script (the `securepi-db` CLI), not dead, but it has no `__main__` guard.
- **Duplication:**
  - Three near-identical `_helper_argv` / `_run` wrappers (`quarantine.py`, `dpi_enroll.py`, `firewall_sets.py`).
  - Five copies of "device label" logic (`webapp.device_label`, `orchestrator.device_label`, `notify._device_name`, `correlation.campaign_signal`, `new_device_signal`).
  - "Current IP" logic (L9).
  - The schema declared twice: `schema.sql` and `ingest.SCHEMA_MIGRATIONS`, with no version ledger.
  - Reader boilerplate repeated across the three file tailers.
- **Brittle patching:** `docs/demo/serve.py` rewrites `webapp.py` with `str.replace` and runs `exec`. If a constant is renamed, the demo silently points at real paths.
- **Dependencies:** No manifest (M20). Chart.js is vendored (fine).

---

## 11. Testing Gaps

- **`app/webapp.py` (3,410 lines) has no route tests.** `test_audit_coverage.py` only checks source strings. There are no tests of the middleware, login, rate limit, Origin check, `next` validation, or any API. Add `httpx` so `TestClient` can be used.
- **No tests at all for:** `profiles.py`, `fingerprint.py`, `dpi_enroll.py`, `firewall_sets.py`, `engine.py`, `tracker_entities.py`, `native_trackers.py`.
- **Missing regression tests for this audit's findings:**
  - Enrollment re-add after a flush (H1)
  - Fail-open orphan and SERVFAIL cases (M1, M2)
  - QUIC exclusion (M3)
  - Campaign closure and second auto-response (M5)
  - Hostname merge into an unknown device (M6)
  - Oversized `/login` body (M7)
  - NaN settings (L1)
  - Dedicated-key reset (L2)
- **Security tests are string-based:** `test_privilege_separation.py` and `test_console_tls_config.py` grep files. They do not check effective permissions, `input` chain policy, or `log` rate limits.
- **Test environment:** runs on Python 3.14 locally against a 3.12 target, with no CI. `tools/replay.py:262` leaks SQLite connections (the `ResourceWarning` flood in the test output).

---

## 12. Architectural and Maintainability Debt

1. **Invariants split across entry points.** The "only toward less inspection" rule and the adopt/end logic live in `reconcile()` only (H1). Put invariants inside the converge primitives that every path shares.
2. **One shared SQLite file written by three processes with mixed privilege.** This drives M8, M12, M13, M16 and L16. Consider a single-writer design (for example, ingest owns writes and the console sends commands through a queue table) or at least a consistent connection helper with timeouts and chunked writes.
3. **Everything that matters runs as root** (M18). The console's privilege separation is a good template to extend.
4. **Very large modules:** `webapp.py` (3,410 lines), `app.js` (4,091), `correlation.py` (1,649), `orchestrator.py` (1,367), `ingest.py` (1,154). Natural seams:
   - `webapp.py`: routers per area (auth, filtering, policies, reports).
   - `correlation.py`: one signal per module.
   - `ingest.py`: a reader base class.
5. **Deployment knowledge lives in prose** (runbooks, Makefile comments) rather than in versioned units and manifests (M20).
6. **Evaluation tooling shares the production database** (L22).
7. **Very long explanatory docstrings.** They help auditability, but some have drifted from the code (for example the `_converge_enrolled` docstring claims a guard that isn't implemented, and the README test count is stale). Keep the key invariants as short docstrings next to asserting tests.

---

## 13. Potential Production Failure Modes

| Trigger | Consequence | Related |
|---|---|---|
| Canary flush or reboot, then an operator toggles inspection on any device | Previously flushed devices are decrypted again | H1 |
| Upstream DoT or WAN hiccup lasting longer than the grace period | Filtering silently off for the whole LAN | M2 |
| Database lock during fail-open activation, then the DNS filter recovers | Permanent unfiltered DNS; the console says it's inactive | M1 |
| Busy database (retention, ingest backlog) | Engine crash; console stalls for up to 5 s per request | M8, M12, M13, L16 |
| Ingest restart after a long outage or a large `eve.json` | Memory spike; fail-open check delayed | M13 |
| LAN client sends a huge `/login` body or a UDP/443 flood | Console out of memory; journal and events flood | M7, M4 |
| Quiet night | Repeated "DNS filter stale" incidents and notifications | M10 |
| Chrome or YouTube users | Constant `dns_bypass` incidents; can contribute to auto-quarantine | M3 |
| Weeks of operation | Stale IOC false positives; campaigns never close; tables grow; dashboard slows | M5, M11, L13, M15 |
| Gateway root compromise | Admin Mac MITM-able for any domain | M17 |
| Disk loss or rebuild | Services can't be recreated from the repository | M20 |

---

## 14. Findings Rejected or Downgraded During Second Pass

| Candidate | Outcome | Reason |
|---|---|---|
| Open redirect via `next=/\evil.com` on `/login` | **Rejected** | Starlette's `RedirectResponse` percent-encodes `\` (not in its safe set), giving `/%5Cevil.com`, which is a same-origin path |
| Auth bypass via `/static/../api/...` | **Rejected** | The router dispatches `/static/*` only to `StaticFiles`, which refuses traversal. `/api` routes never see that path |
| Stored XSS through hostnames, SNI or DNS names | **Downgraded to L10 (hardening)** | Every non-escaped interpolation in `app.js` was reviewed. Dialog `description` values are literals or escaped; `toast` uses `textContent`; Jinja autoescape is on |
| SQL injection in dynamic query building | **Rejected** | Every `%s` composition uses constant fragments or placeholder lists |
| Command injection via the privileged helper | **Rejected** | argv lists; strict validators; fixed set names |
| Earlier C1 (writable code directories) | **Fixed**; residual narrowed to M16 | Code directories are now `root:root 755`; data moved to `/var/lib` |
| Earlier C2 (empty-password window) | **Fixed** | `verify_password` rejects empty values; atomic replace; other sessions revoked |
| Earlier H4, H6, H7, H8, H9, H10 | **Fixed** | Verified in code. H10's residual is L21 |
| Earlier H5 (API overflow) | **Mostly fixed**; residual M14 is a *possible* concern | Pagination added; ordering assumption unverified |
| Rule injection through the console domain fields | **Rejected** | `normalize_domain` regex is applied before any rule is written |
| Newline rule injection via device names | **Downgraded to L5** | Confirmed in `quote_client`, but the sources are the operator's own name or a DHCP hostname that AdGuard likely sanitises |
| Negative `LIMIT` bypass | **Fixed** | `Query(ge=1)` on every limit |
| `api_policy_extend` leaving duplicate active policies | **Rejected** | `_superseded` marks the old policy `replaced` |
| No Critical severity for H1 | **Downgraded from Critical** | Needs an operator action within a short window (or the engine down), and only affects devices that had previously opted in |

---

## 15. Recommended Fix Order

1. **H1** — enforce the enrollment invariant in `_converge_enrolled`. Small change, closes a privacy guarantee gap.
2. **M1 + M2** — make fail-open recovery check nftables, and probe liveness instead of resolution.
3. **H2 + M4** — `input` default-drop with explicit allows; rate-limited `log` rules. Apply with the existing lockout-insurance runbook.
4. **M7, M8, M9** — body cap and early rate limit on `/login`; move session writes off the event loop and throttle them; skip session touches for background polls.
5. **M12, M13, L16, L14** — resilient engine loop, a shared connection helper (timeout, pragmas), chunked ingest and retention.
6. **M3, M5, M10, M11** — detection-quality fixes (QUIC exclusion, campaign lifecycle, sensor heartbeats, IOC freshness).
7. **M6** — stop automatic hostname merges.
8. **M16, M17, M18** — privilege and filesystem hardening; constrained console CA.
9. **M15, M19** — dashboard, devices and DPI performance.
10. **M20** plus testing — commit the unit files, pin dependencies, add CI, add `webapp` route tests and the regression tests above.
11. **Low findings (L1–L24)** — quick wins first: L1, L2, L3, L4, L7, L15, L21, L24.

---

### Prioritized Summary Table

| Priority | Severity | Confidence | Finding | File / Location | Recommended Action | Estimated Difficulty |
|---|---|---|---|---|---|---|
| 1 | High | Confirmed (repro) | Console enroll/unenroll re-enables flushed or rebooted inspection | `app/orchestrator.py:891` `_converge_enrolled`; `:949`, `:419`, `:466` | Move the "applied before and now missing → end, don't re-add" guard into converge | Low |
| 2 | Medium | High | Fail-open orphaned DNAT rule never removed | `app/health.py:374-381` | Deactivate whenever nft shows the rules, regardless of the DB flag | Low |
| 3 | Medium | High | SERVFAIL treated as "filter down" → network-wide bypass | `app/health.py:332-345` | Liveness probe via a locally answered name; accept SERVFAIL as alive | Low |
| 4 | High | High (config) | `input`/`output` chains accept all, including WAN | `gateway/nftables.conf:69-93` | Default-drop `input` with explicit allows | Medium |
| 5 | Medium | High | Unlimited nft `log` on reject rules | `gateway/nftables.conf:91,124-126` | `limit rate` per rule, or a meter | Low |
| 6 | Medium | Confirmed | `/login` reads a body of any size before rate limiting | `app/webapp.py:208-218` | Cap `Content-Length`; rate limit first; cap password length | Low |
| 7 | Medium | High | Sync SQLite writes in async auth middleware | `app/webapp.py:147-165` | Threadpool + throttled touch + close connections | Low |
| 8 | Medium | Confirmed | Idle timeout defeated by 5 s polling | `app/static/app.js:117-124`; `webapp.py:164` | Background header; pause when hidden | Low |
| 9 | Medium | High | Engine loop not exception-isolated | `app/engine.py:19-54` | Wrap each stage; raise busy timeout; commit units with `Restart=always` | Low |
| 10 | Medium | Confirmed | Unbounded ingest batches | `app/ingest.py:512-567` and siblings | Chunk and checkpoint per N lines | Medium |
| 11 | Medium | Confirmed | QUIC counted as DNS bypass | `app/correlation.py:523-600` | Exclude `quic-blocked` except to DoH IPs | Low |
| 12 | Medium | Confirmed | Campaigns never close; auto-response once per device | `app/correlation.py:1189`; `orchestrator.py:1050-1057` | Status transitions, auto-close, time-bounded lookup | Medium |
| 13 | Medium | High | False "DNS filter stale" on quiet networks | `app/health.py:183-187` | Sensor heartbeats instead of traffic volume | Low |
| 14 | Medium | Confirmed | Stale IOCs matched forever | `app/correlation.py:728-748` | Apply the feed-freshness predicate; prune `ioc` | Low |
| 15 | Medium | High | Hostname merge transfers identity into unknown devices | `app/registry.py:125-160` | New device plus an operator-confirmed merge suggestion | Medium |
| 16 | Medium | Possible | Root writes in non-root-writable directories (symlink risk) | `dpi/deploy-dpi.sh:120`; add-on `_write_rule_stats`; data dirs 2770 | Root-owned log dir, `mkstemp`, sticky bit or separate users | Medium |
| 17 | Medium | Confirmed | Unconstrained console root CA trusted by the Mac | `gateway/generate-console-tls.sh` | Name constraints or leaf-only trust; take the key offline | Low |
| 18 | Medium | High | Parsers and daemons run as root | `dpi/deploy-dpi.sh` units; ingest and engine units | Dedicated users plus systemd sandboxing | Medium–High |
| 19 | Medium | Possible | API watermark assumes time-ordered log entries | `app/ingest.py:763-829` | Overlap window with a richer dedup key | Medium |
| 20 | Medium | Confirmed | Full-window scans on 5 s polls; N+1 device queries | `app/webapp.py:573-630, 743, 996-1047, 1136-1166, 1313-1324` | Rollups, SQL grouping, caching, limits | Medium |
| 21 | Medium | High | DPI decodes and buffers all decrypted bodies, including video | `dpi/securepi_adfilter.py:510-525` | Content-type and host gating; stream large bodies | Low–Medium |
| 22 | Medium | Confirmed | No unit files, dependency manifest or CI | Repository root | Commit units, pin dependencies, add CI on Python 3.12 | Medium |
| 23 | Low | Confirmed (repro) | NaN accepted for float settings | `app/settings.py:376-393` | `math.isfinite` check | Low |
| 24 | Low | Confirmed | Reset route ignores `dedicated` | `app/webapp.py:2506` | Same guard as set | Low |
| 25 | Low | Confirmed | Suppression `device_id` contract broken | `app/webapp.py:1386-1416` | Restrict to the incident device or explicit network-wide | Low |
| 26 | Low | High | Merge can move `last_seen` backwards | `app/correlation.py:128-135` | `max()` on update | Low |
| 27 | Low | Confirmed | Control characters pass into DNS-filter client quoting | `app/adguard.py` `quote_client` | Strip or reject control characters | Low |
| 28 | Low | High | IOC blocklist written unvalidated and non-atomically | `app/intel.py:165-191` | Validate domains; atomic replace | Low |
| 29 | Low | Confirmed | Webhook URLs unmasked; cleartext SMTP credentials allowed | `app/notify.py` | Mask the URL path; refuse `none` with a password | Low |
| 30 | Low | Confirmed | Inconsistent "current IP" logic | `webapp.py:1002, 1949, 2026, 3379`; `orchestrator.py:1115, 1178` | One helper everywhere | Low |
| 31 | Low | High | No CSP or HSTS on the console | `app/webapp.py:177-183` | Add headers; remove the inline handler | Low |
| 32 | Low | Confirmed | Unbounded lists, unpruned tables, SQLite pragmas | `webapp.py:1050, 3385`; `retention.py`; `schema.sql:12-13` | Pagination, retention additions, connection helper | Low–Medium |
| 33 | Low | Confirmed | Dead code, stale docs, harness in `services.list`, battery uses the production DB | `app/quarantine.py`, `README.md`, `app/services.list`, `gateway/battery.py` | Remove or relocate; update docs; isolate evaluation data | Low |
| 34 | Low | High | Wi-Fi without PMF; `backup.sh` blanket `git add -A` | `gateway/hostapd.conf`; `backup.sh`, `.gitignore` | `ieee80211w=1`; ignore `*.db*`/`*.bak`; explicit staging | Low |

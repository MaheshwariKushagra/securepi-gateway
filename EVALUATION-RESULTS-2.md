# SecurePi Gateway — Evaluation Results 2 (Stage 1 onward)

This is the results file `ENHANCEMENT-PLAN.md` §2 ("any results are appended to
`EVALUATION-RESULTS-2.md`") points every later stage at. `EVALUATION-RESULTS.md`
stays as-is: the closed record of the Day 14 evaluation, run before this plan
existed.

---

## 0.3 — Baseline snapshot ("Before" column)

Measured 14 September 2026, ~17:15, against the live gateway, a few minutes
after a full reboot (`uptime` ~3 minutes at capture) and right after `make
deploy` (step 0.2) restarted `securepi-ingest`, `securepi-engine` and
`securepi-web` cleanly. **Zero devices were connected to `SecurePi-Test`** at
capture time — this is an idle-system baseline, not a baseline under real
household use. That matters for reading several numbers below honestly.

### Database

| | |
|---|---|
| Live DB file (`securepi.db`) | 9,089,024 bytes (8.67 MiB) |
| `securepi.db-wal` / `-shm` | 255,472 / 32,768 bytes |
| Pre-migration `.bak-*` copies still on disk | 8 files, 8.56–9.06 MiB each (~68 MiB total) — the manual safety-net copies taken before steps 1.3, 1.4, 6.1–6.5 and the ad-block deploy. Not yet cleaned up; still useful, not counted against the "live" DB size above |
| Disk free (`/`) | 86 GiB free of 98 GiB (9% used) |
| Event history span | 2026-09-12 00:31 → 2026-09-14 11:42 UTC (2.5 days — the project's whole life so far, not a mature steady state) |
| Events, all-time | 26,322 |

### Events by type, all-time

| Type | Count |
|---|---:|
| `dns_query` | 11,087 |
| `flow` | 6,229 |
| `dns` | 4,748 |
| `tls` | 1,892 |
| `quic` | 1,838 |
| `anomaly` | 138 |
| `alert` | 134 |
| `http` | 94 |
| `fileinfo` | 57 |
| `ssh` | 49 |
| `ike` | 41 |
| `dhcp` | 15 |

### Events by type, last 24h *(caveat below)*

| Type | Count |
|---|---:|
| `flow` | 114 |
| `dns_query` | 20 |
| **Total** | **134** |

> **Why this looks low compared to the Day 14 evaluation's 15,884-events/24h
> figure:** that figure was captured while real devices were active on the
> network. At this capture, no device had been connected for hours (the last
> event in the DB is from 11:42; the gateway had also just been rebooted) —
> the 24-hour window here is almost entirely gateway-generated background
> traffic (blocklist syncs, NTP-adjacent, health checks), not household
> browsing. Take this as "system floor," not "typical day." A more
> representative events/day figure should be recaptured once real devices are
> back on the network for a full day — the 7-day continuous run in step 7.0
> will do this properly regardless.

### Incidents

| | |
|---|---:|
| Total, all-time | 26 |
| Last 24h (by `first_seen`) | 0 |

| Signal | Status | Count |
|---|---|---:|
| `new_device` | new | 12 |
| `malicious_domain` | new | 4 |
| `port_scan` | new | 4 |
| `brute_force` | new | 3 |
| `adblock_ineffective` | resolved | 1 |
| `privacy_scope_failure` | resolved | 1 |
| `volume_anomaly` | resolved | 1 |

12 devices known to the registry in total.

### DNS blocked % over 24h *(same low-traffic caveat as above)*

| | |
|---|---:|
| Total DNS queries | 20 |
| Blocked | 18 |
| Blocked % | 90.0% |

Per-device breakdown wasn't meaningful at capture time — all 20 queries in
the window were unattributed gateway-origin traffic (`device_id IS NULL`),
not traffic from a registered device. Re-run this query once real devices
are generating DNS traffic; the query itself (`app/status.py`-style,
grouping `events` by `device_id` where `event_type='dns_query'`) is already
correct and ready to use.

### Memory per service (idle, ~3 minutes after reboot + deploy)

Read from each unit's cgroup (`systemctl show <unit> -p MemoryCurrent`).

| Service | Memory |
|---|---:|
| Suricata | 583.3 MB |
| AdGuard Home | 269.0 MB |
| securepi-web | 44.3 MB |
| **securepi-dpi (mitmproxy addon)** | **70.1 MB — idle, unenrolled** ¹ |
| securepi-ca-server | 15.8 MB |
| securepi-ingest | 15.1 MB |
| securepi-engine | 5.9 MB |
| hostapd | 2.6 MB |
| **System total used** | **1,349 / 3,683 MB** |

<sup>¹ The plan asks for mitmproxy's memory "while enrolled." `securepi-dpi`
runs continuously regardless of enrollment (enrollment only adds an nftables
redirect rule per device), so this figure is real, but it's mitmproxy sitting
idle with no TLS connections to inspect — not the working-set figure while
actively decrypting a device's traffic. No device had a DHCP lease at capture
time, so `securepi enroll all` had nothing to enroll (by design — see A2 /
`gateway/securepi`, which refuses a no-op enrollment). Recapture this
specific number once a real device is connected and enrolled; the Day 14
evaluation's own equivalent figure has the same shape (measured "separately
while enrolled" — see `EVALUATION-RESULTS.md` §5), and it isn't yet in this
file for the same reason.</sup>

`securepi-ap0`, `nftables` and `securepi-test-harness` report no cgroup
memory figure (`MemoryAccounting` isn't enabled for those units — `nftables`
in particular is a oneshot ruleset load, not a long-running process, so
"memory" doesn't apply to it the way it does to a daemon).

**Sanity check against Day 14:** Day 14's evaluation measured 1,457 MB used
under active attack-harness load. This baseline, idle and freshly rebooted,
measures 1,349 MB. Suricata (583 vs 683 MB) and AdGuard (269 vs 235 MB)
account for most of the difference — consistent with "idle vs. under load,"
not a regression.

### What this baseline is for

Stage 2 adds the most compute-heavier signals in the whole plan — DNS
tunnelling/DGA (subdomain entropy over every DNS event) and C2 beaconing
(timing/size regularity scoring across flows). Comparing `securepi-engine`'s
memory and the correlation-engine cycle time before and after Stage 2 lands
is the honest way to check those signals stay inside the 3.6 GiB budget,
per §7's "budget check after every stage."

---

## Stage 2

### 2.1 — Scan family: network sweep + slow-scan variants

Three new signals, all following `correlation.py`'s existing trailing-window
pattern: `network_sweep_signal` (horizontal — one port, many distinct hosts,
300 s window, mirrors `port_scan_signal`'s vertical shape) and
`slow_scan_signal` (re-runs both the vertical and horizontal check over a
7200 s window, so a scan paced slower than a fast window's
window/threshold ratio — the deliberate pacing nmap's `-T0`/`-T1` timing
templates use — still gets caught, just later). 8 new unit tests (positive,
negative, dedup, and the two "fast signal must NOT fire, slow one must"
cases), plus 2 harness scenarios added to `gateway/evaluate.py`. Full
reasoning and the ATT&CK mapping decision (`network_sweep` → T1018 Remote
System Discovery, distinct from `port_scan`'s T1046) are in
`app/correlation.py` and `app/playbooks.py`.

The harness (`gateway/setup-test-harness.sh`) needed extending first: a
sweep test needs real distinct hosts to find, and scanning an address with
no host behind it produces no Suricata flow event at all (no ARP
resolution, so no IP packet is ever sent). Added nine more IP aliases
(`10.10.0.222`–`230`) to `ns_victim`'s single interface — still fully
isolated from `ap0`/hostapd and the two real devices. Applying this live
required tearing down and recreating `br-test`/`ns_attacker`/`ns_victim`
(the running harness was created at this boot, before the script changed)
and restarting Suricata afterward, since its AF_PACKET capture socket binds
to `veth-atk`'s interface index at startup and would otherwise keep
listening on the now-deleted old interface. Both confirmed clean
(`securepi status` all-active immediately after).

**Live verification, 14 September 2026, against the real gateway (not just
unit tests):**

| Test | Result |
|---|---|
| `nmap -sT -Pn -p 443 --min-rate 500` against 10 distinct hosts (`test_network_sweep`) | **Detected in 74.1 s.** Incident: "Network sweep detected on port 443", evidence_count 10, all 10 host IPs named in the description |
| Fast `port_scan_signal` while the sweep ran | Correctly did **not** fire (the traffic was one port across many hosts, not many ports on one host — the two signals' shapes are genuinely distinct, not just relabeled) |
| `nmap -sT -Pn -p <8 ports> --scan-delay 45000ms --max-parallelism 1` against one host (`test_slow_scan`), ~6 minutes wall-clock | **Fast `port_scan_signal` correctly did NOT fire** (`fast_fired=False`) — paced at 45s/port, no single 300s slice ever contained more than ~6 of the 8 ports. **`slow_scan_signal` detected it 22.0 s** after the scan finished (well inside its 7200s window). Incident: "Slow port scan detected against 10.10.0.221", evidence_count 8 |

The slow-scan incident's evidence actually lists 9 port values in the raw
query result but 8 distinct ports counted (`443,20006,20004,20007,20002,
20000,20001,20005`) — port 443 is real evidence too, left over from the
`test_network_sweep` run minutes earlier in the same session, which also
touched `10.10.0.221:443`. Both events are genuinely inside the slow-scan
signal's 7200s window, so this isn't a bug: it's the honest trade-off a
long window makes; two unrelated test runs against the same host, close
enough together, can legitimately merge into one incident's evidence. In
production this would read as "worth a second look, not two separate
incidents" rather than as noise.

`make deploy` used for this step (see §0.2): all three services restarted
clean, journal clear, both new settings keys (`network_sweep_threshold`,
`network_sweep_window_seconds`, `slow_scan_threshold`,
`slow_scan_window_seconds`) confirmed resolving their real hardcoded
defaults via `settings.get()` on the live database before either live test
ran.

### 2.2 — DNS-bypass hardening + detection

**Hardening**, all applied live and verified, not just written:

| Change | Verification |
|---|---|
| Two AdGuard `$dnsrewrite=NXDOMAIN` rules: Firefox's DoH canary (`use-application-dns.net`) and Apple's iCloud Private Relay opt-out (`mask.icloud.com`, `mask-h2.icloud.com`) | `dig` against each returned genuine `status: NXDOMAIN` (confirmed this gateway's global `blocking_mode` is `"default"`, which would otherwise answer a plain block with `0.0.0.0` - a real, resolvable-looking answer that would NOT trip either mechanism's own "did this fail to resolve" check) |
| HaGeZi's DoH-only blocklist (`doh.txt`, 3,313 rules) added and enabled network-wide | `dig` against `dns.google`, `cloudflare-dns.com`, `dns.quad9.net` each returned `0.0.0.0` (previously resolved normally) |
| HaGeZi's combined DoH/VPN/Proxy-bypass list added but **disabled** network-wide - the plan's "VPN/proxy part available as a profile option in 4.3" isn't buildable yet (no profile system exists), so this stays a togglable-but-off list until then, rather than either skipping it or force-enabling VPN/proxy blocking network-wide without that control | `filtering_status()` confirms `enabled: false`, `rules_count: 0` |
| `doh_resolvers` nftables set now refreshed daily from HaGeZi's maintained `doh-ips.txt` (`gateway/refresh-doh-set.sh` + `securepi-doh-refresh.timer`) instead of 14 hand-picked IPs | Ran the script live: **1,445 addresses loaded** in one atomic `nft` transaction (flush+fill, no empty-set window). Script fails safe on a bad/short download (`MIN_PLAUSIBLE_COUNT` guard) rather than ever wiping the set to empty |
| `log prefix` added to all three reject rules (`dot-bypass`, `doh-bypass`, `quic-blocked`) in the forward chain | See the live firewall-reload section below |

**Firewall change process (lockout insurance, since this touches the live forward chain):**
1. Backed up `nft list ruleset` and `/etc/nftables.conf` before touching anything (`~/nft-backups/`, `/etc/nftables.conf.bak-2.2-*`).
2. `sudo nft -c -f` (check-only, no apply) against the new config first - passed clean.
3. Confirmed both `quarantine` and `enrolled` sets were empty before reload (a full `nft -f` re-application flushes every set with no static elements - documented, expected behaviour, same as the ad-block deploy session's own note on this).
4. Applied with `sudo nft -f`, then immediately re-ran an independent `ssh` connection to confirm the management link survived, followed by a full `securepi status`.

**Detection - the harder verification problem:** the test harness's isolated `ns_attacker`/`ns_victim` pair sits on `br-test`, which has no path to `ap0` (the interface these reject rules match on) - the same limitation the plan's own step 5.7 documents for the DPI redirect rule. A real DoT/DoH/QUIC bypass attempt from a genuine LAN client couldn't be exercised this session (0 devices were connected to `SecurePi-Test`). Rather than skip verification or fake it, each layer was checked with what's actually available, honestly scoped:

| Layer | How verified |
|---|---|
| `log prefix` → kernel ring buffer → `journalctl -k` (the actual OS/nftables plumbing, not project-specific code) | **Proven with real, live traffic**: a temporary, non-persisted `chain output` rule (`log prefix "dot-bypass: "` on `tcp dport 853` outbound) was added, a fresh `dig` query forced a real DoT handshake from AdGuard to its upstream (`1.0.0.1:853`), the resulting kernel log lines were confirmed in `journalctl -k`, and the temporary rule was removed immediately after (never persisted to `/etc/nftables.conf`) |
| `app/ingest.py`'s `read_nft_log` | Run live against those real journal lines (not synthetic ones): correctly parsed and inserted 10 real `bypass_attempt` events with the right `src_ip`/`dest_ip`/`dest_port`/`proto`/`block_reason` |
| `app/correlation.py`'s `dns_bypass_signal` | Run live against the real database: executed with no error; correctly did **not** fire, since the test traffic (the gateway's own outbound DoT) has no `device_id` (it's WAN-side gateway traffic, not an attributable LAN device) - exactly the intended behaviour |
| The `iifname "ap0"` match condition specifically (a real LAN client's traffic actually reaching these rules) | **Not exercised this session** - no real device attempted a bypass, and the harness genuinely cannot reach `ap0`. This is standard, well-established nftables interface matching, not bespoke project logic, so the residual risk here is low - but it's not "observed," and is recorded as such rather than implied |
| Cleanup | The 20 test rows this verification created (unattributed, `device_id IS NULL`) were deleted from the live database afterward - they were also technically mislabeled `bypass_attempt` despite never having actually been rejected, since the temporary test rule only logged, never blocked, to avoid disrupting AdGuard's real upstream DNS during the test |

8 new unit tests for `dns_bypass_signal` (nftables-only, canary-only, SNI-only, and all three combined toward one threshold), 10 new unit tests for `flatten_nft_log`/`read_nft_log`/the watermark helpers (subprocess mocked, the same pattern `ReadAghApiTests` already uses for AdGuard's API). 2 new settings (`dns_bypass_threshold`, `dns_bypass_window_seconds`). ATT&CK: tagged at the tactic level only (Defense Evasion, TA0005) - full reasoning in `app/playbooks.py`, the same caution `malicious_domain`'s own docstring already applies to a signal with a real benign-majority risk.

`make deploy` (app code) and manual `rsync` (the firewall config and refresh script, deliberately kept out of the automated `make deploy` target - see the Makefile's own comment) both used. All three app services restarted clean; journal clear throughout every step above.

### 2.3 — IDS alerts → taxonomy → incidents

Closes the exact gap `ENHANCEMENT-PLAN.md` §1.1 names: "Suricata metadata only. Alerts ingested but never used." New `app/signature_taxonomy.py` maps Suricata's own `alert_category` text - confirmed against this gateway's real `/etc/suricata/classification.config`, not guessed - to a plain name, our severity, and (for 7 curated, genuinely specific categories) an ATT&CK tag. Everything else falls to a generic `ids_other` bucket, severity taken from Suricata's own numeric priority.

**A real finding from the live data, before writing any code:** the gateway's own accumulated alert history (2.5 days) is almost entirely `Misc activity` (86 events) and `Generic Protocol Command Decode` (43) - both ET's own lowest-priority ("INFO") classification, mostly STUN/WebRTC observations and one recurring "ET INFO Observed Cloudflare DNS over HTTPS Domain" signature (interesting: an existing ET rule already does some of what step 2.2's `dns_bypass_signal` does independently, via TLS SNI). This is the same shape of problem `malicious_domain`'s own G3 finding describes for blocklist-hit volume - which is why `ids_alert_signal` groups by **(device, alert_category)**, not just device: a burst of low-value `Misc activity` alerts must never let a genuinely severe, unrelated trojan alert get silently merged into that same incident thread by `raise_incident`'s dedup (keyed on device + signal_type). Each curated category gets its own `signal_type` for exactly this reason - the same pattern `slow_scan_signal` (step 2.1) already established with two variants, extended here to a larger but still bounded, fully known set.

**A second real finding, also from the live data:** 5 real alerts in category `Potential Corporate Privacy Violation` (priority 1) turned out, on inspection, to be `ET INFO DNS Query for TOR Hidden Domain .onion Accessible Via TOR` - a genuinely interesting, specific, actionable finding despite ET's own "INFO" naming, and priority 1 (→ our "high" severity) is the right call for it. This wasn't added as its own curated category (the `policy-violation` classtype covers many unrelated signatures, not just this one), but it's exactly the kind of case the generic fallback's "use Suricata's own priority, don't invent a name" design is meant to get right without needing to be anticipated in advance - confirmed here against a real example, not just reasoned about.

**Live verification:**

| Check | Result |
|---|---|
| `make deploy` | Clean; journal clear across all three services |
| `ids_alert_signal` run against the real database | No crash. Correctly did **not** fire on the real historical alert data (73/10/5 alerts across three categories for a real past device) - all of it is 36+ hours old, far outside the signal's window (300s default, 3600s max) |
| Settings validation | Attempting to widen the window past its own schema max (3600s) to force-test against that old data correctly raised `SettingsError` - the validator did its job; no override was left behind (confirmed unchanged afterward) |
| Fresh live-fire attempt | A port scan and a `.onion` DNS query were run through the isolated `ns_attacker` harness (the same safe mechanism used all session) to try to trigger a **new** real alert. Neither did, given this gateway's currently-enabled Suricata ruleset and the harness's limited reachability - recorded honestly as not achieved this session, rather than claimed |
| Unit tests | 8 curated-category tests, fallback tests, dedup-by-category test, `classify()` tests, and a regression test confirming every `signature_taxonomy.ALL_SIGNAL_TYPES` entry has a `playbooks.py` entry |

The signal is correctly wired, deployed, and will pick up any qualifying activity going forward - the specific gap is a fresh, real, *security-relevant* trigger within this session's environment, the same class of limitation already recorded for steps 2.1's live namespace constraints and 2.2's `ap0` reachability gap.

11 new unit tests (`tests/test_signature_taxonomy.py` + additions to `tests/test_correlation.py`). 2 new settings (`ids_alert_threshold`, `ids_alert_window_seconds`). 8 new signal_types (7 curated + `ids_other`), each with a `playbooks.py` entry.

### 2.4 — Offline threat intelligence

New `app/intel.py` fetches three real abuse.ch feeds daily - Feodo Tracker (botnet C2 IPs), URLhaus (malware-hosting hostnames), ThreatFox (mixed IOCs, filtered to `ip:port` and `domain` types only) - into a new `ioc` table, matched against events by `app/correlation.py`'s new `threat_intel_signal`. Domain-type indicators are also pushed to AdGuard as a real Tier 1 blocklist, so a match is both blocked and turned into an incident, per this step's own wording.

**Every feed's real format was confirmed against a live download before writing any parser** - none of the three matched a naive first guess:

| Feed | What was assumed | What's actually true (confirmed live) |
|---|---|---|
| Feodo Tracker | - | Correct on the first try: bare IPs, `#`-comments |
| URLhaus | - | Correct on the first try: hosts-file format, `127.0.0.1<TAB>hostname` |
| ThreatFox | A `csv/recent/` path would exist, standard `"a","b","c"` CSV quoting | Real path is `export/csv/recent/`; real quoting has a **space** after each comma (`"a", "b", "c"`) - a naive `split('","')` silently parsed zero rows until this was caught and fixed before deploying |

**A real bug found and fixed before touching the gateway:** `add_blocklist()` was first pointed at a `file:///opt/securepi/ioc-domains.txt` URL, on the assumption AdGuard could read a local blocklist file directly. Running it live returned `HTTP 400: bad enum value: "file"; want "http" or "https"` - AdGuard's `add_url` endpoint validates the scheme server-side and rejects anything but http/https outright. Fixed by adding `securepi-static.service`, a loopback-only (`127.0.0.1:8082`) static file server - the same `python3 -m http.server` pattern `dpi/deploy-dpi.sh` already uses for the CA download server - and registering `http://127.0.0.1:8082/ioc-domains.txt` instead. Re-run afterward, clean.

**Live verification, 14 September 2026:**

| Check | Result |
|---|---|
| `make deploy` (new `ioc`/`intel_feed_state` tables via `SCHEMA_MIGRATIONS`) | Clean; journal clear; both tables confirmed present |
| `intel.py` run live | **5 Feodo IPs, 354 URLhaus hostnames, 5,292 ThreatFox IOCs (3,849 IP, 1,443 domain)** fetched and loaded |
| AdGuard blocklist registration | `http://127.0.0.1:8082/ioc-domains.txt` registered, **1,794 rules**, enabled |
| A real fetched domain (`0following.com`) | `dig` confirms `0.0.0.0` - genuinely blocked |
| `intel_feed_state` ("feed age visible", this step's own exit criterion) | All three sources show `last_error: NULL`, a real `last_fetched` timestamp, and a computed age in seconds |
| `threat_intel_signal`, live | A synthetic `flow` event was inserted against a **real** Feodo-listed IP (`162.243.103.246`) - never actually contacted; the same safe "insert the row, don't touch the destination" approach the unit tests already use - attributed to the isolated test-attacker device (id 4). Fired correctly: "Contact with known-malicious IP: 162.243.103.246", severity high, evidence_count 1, description naming the source feed and malware label. The synthetic event and incident were deleted afterward |
| Daily timers | `securepi-doh-refresh.timer` and `securepi-intel-refresh.timer` both enabled, next runs scheduled, added to `services.list` / `gateway/securepi`'s health check |

13 new unit tests (`tests/test_intel.py`, using real feed-shaped sample text captured from live downloads, plus additions to `tests/test_correlation.py`). 2 new settings (`threat_intel_threshold` defaulting to 1 - unlike a hit-volume signal, one confirmed match is significant - and `threat_intel_window_seconds`). ATT&CK: tagged tactic-level only (Command and Control, TA0011) - a curated indicator confirms the destination is malicious, not which specific technique this device's traffic to it represents.

### 2.5 — DNS tunnelling + DGA

New `dns_tunneling_signal` in `app/correlation.py` groups DNS queries by (device, base domain) - a simplified last-two-labels heuristic, documented as a real, stated limitation rather than pulling in a maintained Public Suffix List this project's own traffic volume doesn't need - and computes Shannon entropy, distinct-subdomain count, and TXT-query ratio per group, splitting into two incident types on the same one-function-two-signal_types pattern `slow_scan_signal` (step 2.1) established:

- **`dns_tunneling`**: many distinct high-entropy subdomains, or an unusual TXT-query ratio, under one domain - a common way malware carries data out through DNS. ATT&CK: **T1071.004** Application Layer Protocol: DNS - an exact, textbook match, not an inference.
- **`dga`**: a burst of *genuine* NXDOMAIN lookups (the domain doesn't exist anywhere - not just blocked) with high-entropy labels - malware searching for its C2 server via algorithmically generated names. ATT&CK: **T1568.002** Dynamic Resolution: Domain Generation Algorithms - also an exact match.

**A real gap found and fixed before writing the signal:** `app/ingest.py`'s `flatten_agh_api` never captured AdGuard's own `status` field (the real DNS response code), so `dns_rcode` was always `NULL` for AdGuard-sourced queries - there was no way to tell a genuine NXDOMAIN from anything else. Confirmed live (14 September 2026) against this gateway's real API that `status` is exactly this field, and - importantly - that **a query THIS gateway blocks still reports `NOERROR`** (the "default" blocking_mode's `0.0.0.0` answer is a real, if bogus, successful response, the same fact `app/adguard.py`'s `add_nxdomain_rule` already established for a different reason in step 2.2). This distinction is exactly what DGA detection needs: a genuine NXDOMAIN means the domain doesn't exist anywhere, not that AdGuard chose to block it. 2 new ingest tests confirm both cases.

**The exit criterion's two halves, both verified live against the real gateway, not just unit tests:**

| Check | Result |
|---|---|
| "No firing on 24h of phone traffic" | Ran the exact grouping/entropy/threshold logic against **all 4,732 real DNS queries** from a real device's full 2.5-day history (201 distinct base domains) - **zero false positives** on either `dns_tunneling` or `dga`. The highest average entropy seen on any real domain was 4.07 bits/char on `fastly-edge.com`, comfortably explained by a single real Google Safe Browsing OHTTP-relay hostname appearing repeatedly (1 distinct subdomain, nowhere near the 20-subdomain gate) - not an actual DGA/tunnelling pattern, and correctly not flagged |
| "Harness generators detected" | Synthetic tunnelling (25 distinct high-entropy subdomains) and DGA (12 genuine-NXDOMAIN high-entropy lookups) rows were inserted for the isolated test-attacker device (id 4, real DNS traffic never generated) and the signal run live: **both fired correctly**, with accurate titles, severities and descriptions. Cleaned up afterward |

7 new unit tests for the signal (`DnsTunnelingSignalTests`), `ShannonEntropyTests` and `BaseDomainTests` for the two new helper functions, and 2 new `flatten_agh_api` tests for the `dns_rcode`/`status` fix. 6 new settings (window, plus one min-distinct/min-entropy/min-txt-ratio for tunnelling and one min-nxdomain-count/min-entropy for DGA).

### 2.6 — C2 beaconing

New `beacon_signal` in `app/correlation.py`: a RITA-style regularity score, not a literal port of RITA's own scoring code (which wasn't available to verify against in this environment - this project's own standard favors a formula simple enough to state and check by hand over one copied without being able to confirm it matches). Scores every (device, destination IP, destination port) pair on the **coefficient of variation** (stdev/mean) of both the *intervals between connections* and the *connection sizes* - CV near 0 means "every gap and every payload was nearly identical", the beacon signature; CV near or above 1 means ordinary, irregular traffic. Combined as `0.7 × timing_score + 0.3 × size_score`, weighted toward timing since a C2 channel's payload can legitimately vary a little more than its check-in timer.

**The formula was calibrated against the exit criterion's own numeric target before writing the signal**, not tuned after the fact: a synthetic 60-second-interval, 10%-jitter beacon (Python's own `random`, seeded) scores **0.955** under this formula; a synthetic irregular, human-like browsing pattern (exponential inter-arrival times, wildly varying page sizes) scores **0.15**. Both checked in an interactive scratch run before either the settings default (`beacon_score_threshold: 0.8`) or the signal itself were written.

`ALLOWLIST_BEACON_PORTS` covers NTP (123/udp) specifically - confirmed **39 real NTP flow events already exist on this gateway's own history**, so the allowlist has real, not just hypothetical, relevance. A broader push-notification allowlist (Apple APNs, Google FCM) is deliberately **not** included: those need vendor-specific IP ranges this project has no way to confirm live without an enrolled device actively using them, and the honest position is to name that gap rather than guess at ranges.

**Live verification, 14 September 2026 - both halves of the exit criterion run against the real gateway:**

| Check | Result |
|---|---|
| "No real-phone incidents" | Ran the signal's exact scoring logic against **all 5,551 real flow events** from a real device's full 2.5-day history (405 distinct destination pairs) - **zero false positives**. The highest score seen on any real destination was **0.30**, comfortably below the 0.8 threshold |
| "Harness beacon (60s, 10% jitter) ≥ 0.8" | A synthetic 60-second/10%-jitter beacon (30 connections) was inserted for the isolated test-attacker device (id 4, no real traffic) and the signal run live: fired with **regularity score 0.95** - "Possible C2 beacon to 203.0.113.199:8443", evidence_count 30. Cleaned up afterward |

8 new unit tests (`BeaconSignalTests`, `CoefficientOfVariationTests`) - including a direct check that the exit criterion's own 60s/10%-jitter shape scores ≥ 0.8 under the real formula, not just an assertion that *some* incident was raised. 3 new settings (`beacon_window_seconds`, `beacon_min_connections`, `beacon_score_threshold`). ATT&CK: `beacon` → Command and Control / T1071 Application Layer Protocol (base technique - the score doesn't identify which protocol carries the beacon, only that the channel behaves like one).

### 2.7 — Suppression rules

New `app/suppression.py` + a `suppressions` table: an operator's false-positive verdict on a real incident is the *only* way a rule comes into being here - `POST /api/incidents/{id}/suppress` refuses unless the incident's own status is already `false_positive`, so there's no way to pre-emptively suppress a signal that hasn't fired yet. Scoped to **(signal_type, device_id)** - `device_id=None` means network-wide for that signal_type. This is coarser than per-destination suppression (e.g. "stop `threat_intel` for this one IP on this one device"): each of this project's 13 signals varies its own "what's the specific recurring thing" differently (a destination for `port_scan`/`beacon`, a domain for `malicious_domain`, a category for `ids_alert`, ...), and a genuinely generic per-signal match key would need its own small schema per signal type. Documented as a real, stated scope boundary rather than an oversight - an operator who wants one destination allowed through already has the Filtering page's "unbreak" tools (step 5.2) for DNS-level cases; this is for "this signal doesn't apply to this device (or network) at all."

`correlation.py`'s `raise_incident()` - the single function all 13 signals funnel through - checks `suppression.is_suppressed()` first and writes nothing at all while a rule is active, not even a merged-and-ignored incident. Rules can expire (`expires_at`, checked live on every call) or never expire; `app/retention.py`'s daily run physically removes already-expired rows as pure housekeeping (an expired rule is already inert either way).

**Live verification, 14 September 2026, against the real gateway and the real HTTP API (not just unit tests or direct function calls):**

1. Inserted a synthetic `false_positive` incident (device 4, `port_scan`).
2. `POST /api/incidents/35/suppress` over real HTTP (Basic Auth, the real console credentials) - **succeeded**, created suppression id 1, 1-day expiry.
3. Ran a **real** `nmap` scan through the isolated test-attacker harness against `ns_victim` (21 new ports, comfortably over the port-scan threshold) - **zero new incidents** were created for device 4 after the suppression rule's timestamp, confirmed by querying the real database directly.
4. `DELETE /api/suppressions/1` over real HTTP - succeeded, `GET /api/suppressions` confirmed empty.
5. Ran a **second** real scan (a different port range) - **fired normally this time**: incident id 36, "Port scan detected against 10.10.0.221", evidence_count 21, confirming the signal genuinely resumes once the rule is gone rather than staying stuck off.

All synthetic incidents, suppression rows and test flow events were deleted afterward.

12 new unit tests (`tests/test_suppression.py`'s `IsSuppressedTests`/`ListSuppressionsTests`, plus `RaiseIncidentSuppressionTests` in `tests/test_correlation.py` - including one that goes through a real signal function end-to-end, not just `raise_incident()` directly - and one retention test for the expired-rule cleanup). No new settings (suppression rules are created through the API with an explicit reason and optional expiry, not tuned via thresholds).

### 2.8 — Campaign correlation + MITRE ATT&CK kill chain

The closing piece of Stage 2 - the plan's own "never cut" detection core is now complete. New `campaign_signal` in `app/correlation.py` is different in kind from the twelve signals above it: it reads **incidents**, not raw events, and doesn't go through `raise_incident()` - a campaign is a different sort of object, with its own table and its own status lifecycle (mirroring incidents' `new`/`investigating`/`resolved`/`false_positive` so it triages the same way).

A device's open incidents (within a much longer 24-hour window than any individual signal's own) are filtered to just the ones with a **recognized ATT&CK tactic** (`app/playbooks.py`'s existing mapping - `malicious_domain`, `new_device`, `ids_other` and `adblock_ineffective` have none, on purpose, and can't be a kill-chain stage). If they span at least 2 **distinct** tactics - two incidents of the *same* tactic (two scan variants, say) are one stage, not a multi-stage pattern - they're linked into one campaign. `tactics` records the kill chain itself: the distinct tactics in the order their first incident actually started. Re-evaluated every cycle: an existing open campaign is extended (not duplicated) as later incidents add new tactics.

**"Weighted into risk"** (the plan's own wording): `app/risk.py` adds one new named term, `CAMPAIGN_BONUS = 25`, for a device with an open campaign - decaying on the same 24-hour half-life as every other term, and deliberately smaller than a single high-severity incident's peak contribution (40): real extra evidence the correlation itself matters, not enough to dominate the score.

**Live verification, 14 September 2026, of the exit criterion's own literal example** ("scan → brute force → beacon → one campaign linking three incidents"), on a fresh, isolated temporary device to get an unambiguous result (the real test-attacker device, having generated genuine detections across every step of this session's live testing, already had a legitimately messy real incident history that a clean demo would have obscured - see the note below):

| Check | Result |
|---|---|
| Three incidents raised (`port_scan` → Discovery, `brute_force` → Credential Access, `beacon` → Command and Control) | `campaign_signal` linked all three into **one** campaign: `tactics = "Discovery -> Credential Access -> Command and Control"` - the exit criterion's exact wording, produced by the real code, not written by hand |
| `GET /api/campaigns` over real HTTP | Returned the campaign with its 3 linked `incident_ids` |
| `risk.device_risk()` for that device | **Score 100** (capped): 40 + 40 + 40 from the three incidents, **+ 25 from the campaign bonus** - each term visible and named in the breakdown, nothing opaque |
| Schema migration on the live database | `campaigns` table and `incidents.campaign_id` column both confirmed present after `make deploy`; journal clean throughout |

All synthetic incidents, the campaign row, and the temporary device were deleted afterward.

**A real, useful observation, not a bug:** running `campaign_signal` against the actual test-attacker device (id 4) - which has genuinely triggered `network_sweep`, `slow_port_scan`, `port_scan`, `brute_force` and `beacon` incidents across this session's real, harness-driven verification for steps 2.1, 2.2 and 2.7 - correctly produced a campaign linking *all* of them, with a longer, messier tactic sequence than the clean three-stage example. That's the mechanism working as designed on real (if session-generated) accumulated history, not a defect - it's the reason the clean demonstration above deliberately used an isolated device instead of reusing that noisier one.

9 new unit tests (`CampaignSignalTests` in `tests/test_correlation.py`, `tests/test_risk.py`'s `CampaignRiskBonusTests` - the first test coverage `app/risk.py` has had at all, scoped honestly to just the campaign-bonus addition step 2.8 made, not a full backfill of its pre-existing severity-weighting logic). 2 new settings (`campaign_window_seconds`, `campaign_min_distinct_tactics`). New `GET /api/campaigns` endpoint. `app/templates/device_detail.html`'s risk breakdown updated to degrade gracefully for a campaign row (no `incident_id` to link to).

---

**Stage 2 is now complete** (2.1–2.8, all eight steps) - the project's original signal set is fully restored and exceeded, every new signal has an ATT&CK tag where one genuinely applies, and incidents now correlate into campaigns. `make test`: 206/206 passing.

---

## Stage 3

### 3.1 — Session authentication

Replaces the HTTP Basic Auth the console used through Stage 2 with a real login: a hashed password, a per-login session token in an HttpOnly `SameSite=Strict` cookie, a login rate limit, an Origin check on every state-changing request, and both an idle and an absolute session timeout. New `app/session_auth.py` holds all of it as small, independently testable functions; `app/webapp.py` wires them into one auth middleware plus `/login` (GET+POST) and `/logout` routes.

**Two real environment gaps found before writing any deploy-bound code, not guessed:**

- The plan called for a scrypt hash. Checked live on the Mac first: `/usr/bin/python3` (Apple's system build, linked against LibreSSL 2.8.3, not OpenSSL 1.1+) has no `hashlib.scrypt` at all - `AttributeError`, caught by this step's own first test run. The `cryptography` package isn't installed on the Mac either. Since "tests pass on the Mac" is this project's own definition of done, **PBKDF2-HMAC-SHA256 (600,000 iterations, OWASP's 2023 recommendation for that specific KDF) was used instead** - built into `hashlib` on every Python, measured at ~0.18s per hash on the Mac, fast enough for an interactive login. A legacy plaintext password (what every gateway had before this step) still verifies once, then is transparently rehashed on that same successful login - `session_auth.needs_rehash()` - so deploying this step never locks anyone out.
- Starlette's own `request.form()` needs the separate `python-multipart` package installed even for a plain `application/x-www-form-urlencoded` body, not just real multipart uploads - this project doesn't depend on that package anywhere, on the Mac or the gateway, and adding it just for one password field would be a new dependency for no real gain. `/login`'s POST body is parsed with `urllib.parse.parse_qs` instead - no new dependency, and it was this exact `AssertionError` surfacing during local testing (a local demo-server smoke test, before any gateway deploy) that caught it.
- A third, smaller gap in the project's own tooling: `tests/test_audit_coverage.py`'s regression-guard regex only matched `def name(` right after a `@app.post/patch/put(...)` decorator, not `async def name(`. `/login` is this project's first `async def` write endpoint, and the scanner silently skipped it entirely rather than checking it - the opposite of what a "future endpoint added without an audit call fails this test immediately" guard is for. Caught by running the scanner against the real new endpoint and noticing it wasn't in the results, not assumed; the regex now matches an optional `async `.

**Local verification (the Mac):** 25 new unit tests in `tests/test_session_auth.py` - password hashing/verification/rehash-detection (including a legacy-plaintext case and a malformed-hash-fails-closed case), session create/get/touch/delete/cleanup against a real temp SQLite DB (idle and absolute timeout tested by writing an already-expired timestamp directly, the same pattern `test_suppression.py` already uses, not by sleeping), rate-limit accumulation/scoping/reset/window-expiry, and the Origin check's same-origin/cross-origin/missing-header/different-port cases. `make test`: **231/231 passing** (was 206). Idle/absolute timeouts and the rate-limit thresholds are console-tunable settings (`session_idle_timeout_seconds`, `session_absolute_timeout_seconds`, `login_rate_limit_max_attempts`, `login_rate_limit_window_seconds`), not hardcoded, following the same central-config pattern step 1.2 established.

Also verified locally, end to end, against the real FastAPI app (not a mock) using `docs/demo/serve.py` restarted with the new code: unauthenticated GET of a page redirects (303) to `/login`; unauthenticated GET of an API route returns a 401 JSON body; a cross-origin POST (`Origin: http://evil.example`) is rejected with 403 before it ever reaches the login handler; a wrong password returns 401 with an error banner rendered in the console's own visual language; the 11th failed attempt from one address in the window returns 429; a correct login sets the `sp_session` cookie (`HttpOnly`, `SameSite=strict`, no `Secure` yet - see below) and redirects to `next`; the cookie authenticates subsequent requests; logout deletes the session and the same cookie is then rejected. Confirmed visually in a real Chrome tab, including the error-banner's intended red tint (`--high-bg`/`--high-line`/`--high-text` tokens), which one screenshot briefly rendered as a desaturated grey for a reason never pinned down (possibly a mid-paint capture) but did not reproduce on a second, clean navigation - recorded honestly as an unreproduced one-off rather than silently ignored or claimed fixed. `docs/demo/serve.py` needed one matching update: it already monkeypatches `_console_password()` for the demo password, but the real password FILE PATH (`/root/...`, which this step now writes to on every successful login for the rehash) wasn't patched, and the Mac has no permission to write there - fixed by pointing `CONSOLE_PASSWORD_FILE` at a local demo path too, the same source-rewrite pattern the rest of that file already uses for `DB_PATH` etc.

**Deployed to the live gateway and verified there the same day.** `.bak-3.1-<timestamp>` copies of `webapp.py`, `schema.sql`, `ingest.py` and `settings.py` taken first; `make deploy`'s dry run (`-n -i`) previewed exactly the expected file set (two new files - `session_auth.py`, `templates/login.html` - plus the four edited ones) with nothing unexpected, then the real deploy ran clean and `securepi-ingest`/`securepi-engine`/`securepi-web` all restarted with no errors in the journal. The new `sessions`/`login_attempts` tables were confirmed created by `ingest.py`'s migration path (the same "`ALTER`/`CREATE TABLE IF NOT EXISTS` list, applied every startup" mechanism steps 1.2 onward already use), not schema.sql's fresh-install path, since the live database already existed.

**Live-verified over the real management tunnel (`http://localhost:8000`), against the real console:**

| Check | Result |
|---|---|
| Unauthenticated `GET /` | 303 → `/login` |
| Unauthenticated `GET /api/devices` | 401 JSON |
| Cross-origin `POST /login` | 403, rejected before the password was even checked |
| Real login, with the gateway's actual (still-plaintext, pre-migration) console password | 303, `sp_session` cookie set - and the password file was rewritten to `pbkdf2_sha256$600000$...` immediately, confirmed by reading the file's first 20 bytes after login |
| Authenticated `GET /api/devices` with the new cookie | 200 |
| `POST /logout`, then the same cookie again | 303, then 401 - the session row was actually deleted, not just the cookie cleared client-side |
| `audit_log` after login/logout | `auth.login` (`ip=10.10.0.1`, the loopback-side address the SSH tunnel presents) and `auth.logout` rows present, password value never logged |
| Three real wrong-password attempts | recorded in `login_attempts`, confirmed by direct query, then cleared as a courtesy so the operator isn't left three attempts into the real rate limit |
| Journal, all three restarted services | clean throughout |

**Not yet done, named rather than implied:** the cookie is not yet `Secure` (would stop it being sent at all until TLS exists - step 3.2 will flip this), and there is still no CSRF token distinct from the Origin check - the plan's own reasoning for why the Origin check plus `SameSite=Strict` is enough for now is in `session_auth.origin_is_allowed()`'s docstring. `README.md`'s console-access instructions and the architecture table were updated for the new login flow; the emergency SSH-based password reset still works exactly as before (writing plaintext to the file is still accepted once, then rehashed).

### 3.2 — TLS on the console

Replaces the console's plain HTTP with HTTPS, using a certificate from a CA generated only to vouch for this console - deliberately **separate** from the CA `dpi/deploy-dpi.sh` generates for HTTPS ad inspection (step 5.6), since that one is trusted to re-sign OTHER sites' traffic, a much bigger thing to hand out trust for. New `gateway/generate-console-tls.sh` (EC P-256, 10-year CA / 825-day leaf - the longest Apple's ATS will trust even once the CA is trusted, the Mac being this console's primary browser) and a now-repo-tracked `gateway/securepi-web.service` adding `--ssl-keyfile`/`--ssl-certfile` to uvicorn's `ExecStart`. `app/webapp.py`'s session cookie now sets `Secure` dynamically from the request's own scheme (`request.url.scheme == "https"`), not hardcoded - the real gateway is HTTPS-only so it's always `True` there, while `docs/demo/serve.py`'s local, plain-HTTP screenshot tool keeps working unmodified.

**Three real bugs found, in three different verification passes, none guessed:**

- **Local, before touching the gateway:** the exact CA/leaf-generation `openssl` commands were prototyped in a scratch directory on the Mac first (real OpenSSL 3.6.4, confirmed compatible with the gateway's OpenSSL 3.0.13 - both modern enough for `-addext`/`-extfile` SAN handling) and the resulting certificate's SANs, EKU, `CA:FALSE` constraint and CA-chain validity were checked with `openssl x509 -text` / `openssl verify` before the script was ever run for real. A temporary uvicorn instance loaded the same key/cert pair directly to confirm Python's `ssl` module accepted them, then served the real webapp app over `https://127.0.0.1:8766` to confirm: a plain HTTP request to that port gets no response at all (curl error 52, not a redirect - this is what "HTTPS only" means for a bare uvicorn listener with no reverse proxy in front of it), an HTTPS request without trusting the CA fails certificate verification (curl error 60), and one with `--cacert` succeeds (200). All three checked, not assumed, before any of this touched the gateway.
- **Live, on the gateway's first real run:** `generate-console-tls.sh`'s final `chown root:root "$TLS_DIR"/*.key "$TLS_DIR"/*.crt` step failed with "No such file or directory" - the glob is expanded by the *invoking, non-root* shell before `sudo` ever runs, and since `$TLS_DIR` was `chmod 700`, that shell couldn't even list the directory to expand the glob, leaving the literal unexpanded pattern passed to `chown`. Checked before assuming a security gap: `sudo ls -la` showed every file already had the correct owner/permissions anyway (`openssl`'s own defaults - 600 on keys, 644 on certs, root:root since a sudo'd process wrote them), so this failure was cosmetic, not a real exposure - but the script was still broken for a future `--force` regenerate, so it was rewritten to use the four explicit filenames instead of a glob (also just simpler to read).
- **Live, immediately after, while working through the README's own documented "trust the CA on the Mac" step rather than just writing it down:** `scp maheshwari@192.168.2.5:/opt/securepi-tls/ca.crt ...` failed with "Permission denied" - `chmod 700` on `$TLS_DIR` blocks the non-root `maheshwari` user from even traversing into the directory to read the world-readable `ca.crt` inside it, the exact way an operator needs to fetch it to trust it. Fixed by checking `dpi/deploy-dpi.sh`'s own CA directory first rather than guessing a number: `/opt/securepi-dpi/ca` is `755`, with its public cert at `644` and its private key file at `600` - the same split this step now uses. `$TLS_DIR` was changed to `755`, live, and the fix was verified twice: `scp` of `ca.crt` now succeeds, and `scp` of `ca.key` still fails with the same "Permission denied" (the file's own `600` mode, unaffected by the directory change, still protects it).

**Local verification (the Mac):** 5 new structural regression-guard tests in `tests/test_console_tls_config.py` - the same "not a functional test, a structural guard" honesty `test_hostapd_config.py` already uses, since the actual generation script needs root and paths that only exist on the gateway. These confirm the script's required SANs, its `CA:FALSE` leaf constraint, its 825-day leaf validity, and that the systemd unit's `--ssl-keyfile`/`--ssl-certfile` paths actually match the `TLS_DIR` variable the script itself writes to (read from the script's own source, not hardcoded, so a future rename of that variable fails this test rather than silently drifting). `make test`: **236/236 passing** (was 231).

**Deployed to the live gateway and verified there.** `.bak-3.2-<timestamp>` copies of the live `/etc/systemd/system/securepi-web.service` and `/opt/securepi/webapp.py` were taken before either was touched. `gateway/generate-console-tls.sh` and `gateway/securepi-web.service` were copied and installed manually (`gateway/` is deliberately excluded from `make deploy` - see the Makefile's own comment on why), then `app/webapp.py`'s `Secure`-cookie fix was deployed normally via `make deploy` afterward, once the certificate existed for it to apply to.

| Check | Result |
|---|---|
| `sudo systemctl restart securepi-web`, journal | `Uvicorn running on **https**://10.10.0.1:8000` - confirmed the server actually switched protocols, not just that the flags were accepted |
| Plain `http://localhost:8000/` over the real management tunnel | No response (curl error 52) |
| `https://localhost:8000/` without trusting the CA | Certificate verification failure (curl error 60) |
| `https://localhost:8000/login` with `--cacert` pointed at the real, fetched `ca.crt` | 200 |
| `scp` the real `ca.crt` as the non-root operator user | Succeeds, after the 755 fix |
| `scp` the real `ca.key` as the same user | Still fails - the private key stayed protected throughout |
| Journal, `securepi-ingest`/`securepi-engine`/`securepi-web` | Clean throughout both restarts |

**Recorded honestly rather than glossed over:** a final attempt to also confirm the `Secure` cookie attribute on a REAL login against the live gateway (as opposed to the identical code path already proven on the local demo server) hit a self-inflicted dead end - the console's password file now correctly holds only a one-way PBKDF2 hash since step 3.1, so `sudo cat`-ing it for a "real" login attempt just fed the hash string back in as if it were the password, which correctly failed with 401. That failure is the hashing working as designed, not a bug, and it was not worth chasing further by guessing at real credentials against the live console - the `Secure`-flag logic itself is identical code already verified end to end against a local HTTPS uvicorn instance in the pre-deploy pass above, and the live deployment was separately confirmed to be running that exact code via `grep`.

**Not done, named rather than implied:** the CA was not trusted into the Mac's own System keychain as part of this session - `sudo security add-trusted-cert` modifies the Mac's system trust store, which this project's own standing safety rules reserve for the user to run themselves. The exact command is documented in `README.md` and in the script's own printed output; until it's run, the Mac's browser will show a certificate warning on the console (expected, and the underlying TLS is still genuine - `--cacert`-based verification above proves the chain is valid, this is purely "no browser has been told to trust it yet"). No HSTS header was added either, a deliberate choice: the console's own tunnel/browsing pattern reuses the generic hostname `localhost`, and HSTS is scoped per-hostname, not per-port - setting it here could make a real Chrome/Safari refuse plain HTTP for every *other* local dev tool on the Mac that happens to also use `localhost`, a real collateral-damage risk for a header the plan's own "HTTPS only" exit criterion doesn't actually ask for (a plain HTTP request already gets no response at all, with or without HSTS).

### 3.3 — Privilege separation

The console (`securepi-web`) no longer runs as root (finding G9 - "web app runs `nft` itself"). It now runs as a new unprivileged system user, `securepi-web`, member of a new `securepi` group. Firewall control (device quarantine, Tier 2 HTTPS-inspection enrollment) goes through a new privileged helper, `gateway/securepi-web-helper`, reachable only via a sudoers rule (`gateway/securepi-web-sudoers`) that allows running that ONE program and nothing else - `sudo /usr/sbin/nft ...` directly is refused, checked live. `app/quarantine.py` and `app/dpi_enroll.py` keep their existing idempotency/error-handling logic unchanged; only their `_run()` internals changed, from calling `nft` to calling the helper via `sudo`, which passes `nft`'s real stdout/stderr/exit code straight back through.

The helper hardcodes the family/table/set for each of its 7 verbs (never taken from the caller) and validates every argument before nftables is ever touched - real IP parsing via `ipaddress.ip_address()`, an hour count bounded to 1-720 - so a malformed value is rejected before it can reach `nft` at all, whether it's a typo, a bug elsewhere in the app, or a deliberate injection attempt.

Two root-only files the console reads on almost every request (`/root/.securepi-console-password`, `/root/.securepi-dns-password`) were moved to `/etc/securepi/` (`root:securepi`, `750`/`660`) - `/root` itself is `700`, so no permission change on a file *inside* it would ever have let a non-root process reach it. The console's own SQLite database and the Tier 2 rule-set JSON file got a **sticky bit** on their containing directories (`/opt/securepi`, `/opt/securepi-dpi`, both `1775`) rather than a plain `775`: group write lets `securepi-web` create or edit its own data, but the sticky bit means only root or a file's own owner can rename/delete an *existing* entry - proven live, not just declared, by trying (and failing) to `rm`/overwrite `webapp.py` as the unprivileged user.

**Four real bugs found, three of them live on the gateway, before this step's own definition of done was satisfied:**

- **`setup-privilege-separation.sh`'s own file-existence checks were wrong on their first real run.** `[ -f "$old" ]`/`[ -f "$new" ]` are evaluated by the script's own (non-root) invoking shell, and both `/root` (700) and the new `/etc/securepi` (750, no "other" access) block that shell from even `stat`-ing a file inside them - the script reported both real, already-existing password files as missing. The exact same class of bug already found once this session in `generate-console-tls.sh`'s glob-under-sudo issue, recurring because the underlying cause (a non-root shell probing a root-restricted path) is easy to reintroduce in a new script without thinking about it fresh each time. Fixed with `sudo test -f` in place of the bare test, verified by rerunning the corrected script and watching it correctly detect and move both files this time.
- **The console's own TLS private key (`/opt/securepi-tls/console.key`, generated root-only in step 3.2, when the console still ran as root) blocked the console from starting at all** the moment `securepi-web.service` actually switched to the unprivileged user - `PermissionError: [Errno 13] Permission denied` in uvicorn's own `create_ssl_context`, live in the journal within seconds of the restart. This is exactly the kind of cross-step interaction a step-by-step plan can miss: step 3.2's own definition of done never needed to consider a caller without root, because at the time it was written, nothing else was going to read that key. Fixed by making `console.key` (never `ca.key`, which nothing at runtime needs) `root:securepi 640`, and `generate-console-tls.sh` itself was updated to do this automatically on any future fresh run, guarded by `getent group securepi` so it stays a no-op if 3.3 hasn't happened yet on a box.
- **The Tier 2 rule-set file's atomic write (`os.tmp` + `os.replace()`, the pattern that guarantees the DPI addon never reads a half-written file) failed with `PermissionError: Operation not permitted`** the first time it was tested as the unprivileged user - not because of a missing permission, but because of the STICKY BIT working exactly as designed: a `rename()` onto an *existing* file only succeeds for that file's own owner (or root), and `adfilter-rules.json` was still `root:securepi`. The fix was ownership, not the sticky bit: this file is genuinely the console's own editable data (step 5.9 built exactly that feature), so it now belongs to `securepi-web:securepi` directly - `setup-privilege-separation.sh` was corrected to do this on future runs, with the reasoning recorded in its own comment so a future reader doesn't "fix" it back to `root:securepi` by analogy with the database file, which has no such rename step and was correctly left root-owned.
- **A pre-existing, harmless assumption caught mid-verification, not a bug this step introduced:** trying to reuse the real console password for a "real" HTTP login test failed, because `sudo cat`-ing the password file (a habit from before step 3.1) now returns a one-way PBKDF2 hash, not the plaintext - fed back in as a password, it correctly failed authentication. Recorded as a reminder for future sessions, not chased further as a defect.

**Local verification (the Mac):** 24 new tests across `tests/test_securepi_web_helper.py` (the helper's `build_nft_argv()` - every verb's happy path, wrong-argument-count, non-IP, out-of-range-hours, and three explicit injection-shaped strings, none of which reach `nft`) and `tests/test_privilege_separation.py` (structural regression guards: `quarantine.py`/`dpi_enroll.py` never call `"nft"` directly any more; the systemd unit actually sets `User=`/`Group=`; `NoNewPrivileges` is deliberately absent, checked as a real directive line rather than a substring search after that same naive check first matched this file's own explanatory comment about why it's absent; the sudoers rule allowlists exactly one program). `make test`: **262/262 passing** (was 236).

**Deployed to the live gateway with a staged, verifiable rollout, not a single all-at-once cutover:**

1. Full backups first: the live `securepi-web.service`, both password files, `webapp.py`/`quarantine.py`/`dpi_enroll.py`/`adguard.py`, and a full `securepi.db` copy.
2. `setup-privilege-separation.sh` run (creates the user/group, moves the password files, re-permissions the DB/rules-file directories, installs the helper and sudoers rule) - **while the console was still running as root**, so nothing was live-affected yet.
3. The helper tested directly as `securepi-web` via `sudo -u securepi-web sudo securepi-web-helper ...`, *before* touching the running service - confirmed it can list/quarantine/enroll, confirmed a malformed IP is rejected, and confirmed `sudo /usr/sbin/nft` directly is refused (a password prompt, not silent success) - proving the sudoers allowlist is real, not just declared.
4. New `app/` code deployed via `make deploy` **before** the service's own privilege drop, as a separate, independently-verified checkpoint: the console kept running correctly, still as root, on the new code (new `/etc/securepi` paths, helper-routed quarantine/enroll modules) - confirmed via a clean journal and a live HTTPS request.
5. Only then was the updated `securepi-web.service` (`User=securepi-web`, `Group=securepi`) installed and the service restarted - the actual privilege-drop moment, where the TLS-key bug above surfaced and was fixed within the same minute.

| Check | Result |
|---|---|
| `systemctl show securepi-web -p User -p Group` | `User=securepi-web`, `Group=securepi` |
| `ps -o user,cmd -C python3` | The real running uvicorn process is owned by `securepi-web`, not root |
| `sudo -u securepi-web sudo /usr/local/sbin/securepi-web-helper quarantine-list` | Real nftables JSON returned |
| `sudo -u securepi-web sudo /usr/sbin/nft list ruleset` | Refused - sudo asks for a password, since only the helper is allowlisted |
| `quarantine.quarantine()`/`.release()` and `dpi_enroll.enroll()`/`.unenroll()`, called directly as `securepi-web` against a throwaway test IP | Each added then correctly removed itself, confirmed via the helper's own list verbs |
| `rm`/overwrite attempt on `webapp.py` as `securepi-web` | Both refused (`Operation not permitted`) - the sticky bit protecting application code, proven, not assumed |
| **Full real HTTP round trip**: logged in over HTTPS with the actual (temporarily reset) console password, `POST /api/devices/5/quarantine` (the `[TEST HARNESS] test-victim` device, never a real one) `{"quarantined": true}`, confirmed via the helper's own `quarantine-list` that `10.10.0.221` was really in the set, then released the same way | 200 both ways; ground truth matched at every step |
| `GET /api/audit` after the HTTP test | Two `device.quarantine_set` rows, correct actor/target/detail |
| `journalctl -t securepi-web-helper` | Every single call above present - the helper's own independent audit trail, separate from and in addition to the app's `audit_log` table |
| Journal, all three restarted services, across the whole rollout | Clean once the TLS-key fix landed; the brief crash-loop before that fix is present and was not hidden |

**A real, if minor, operational note:** verifying a full authenticated HTTP round trip required a real session, and the live console password was already a one-way hash (step 3.1) with no way to recover the original value - it was reset once, via the same documented emergency SSH procedure `README.md` already describes, to a freshly generated random value, used for this verification, then reset again to a second fresh random value before finishing. The user was given that final password directly and advised to change it via the console's own Settings page.

### 3.4 — Security self-review

Full findings and reasoning are in `docs/SECURITY-REVIEW.md` - this entry is the summary the plan's own step 2 checklist asks for.

CSRF, XSS, SQL injection, command injection and secrets-in-logs were each checked directly against the real source (not assumed from earlier steps) and found already clean - several because steps 3.1-3.3 had already closed the gap a fresh review would otherwise have raised (Basic Auth, plaintext HTTP, a root web process). The XSS check was the most labor-intensive: a script-assisted sweep of all 91 `innerHTML` sites in `app/static/app.js` flagged ~107 "suspicious" template-literal expressions, the large majority of which turned out to be false positives from the sweep script's own inability to parse nested template literals - each was read individually to confirm, rather than trusted at face value. `X-Content-Type-Options`, `X-Frame-Options` and `Referrer-Policy` were added as defense-in-depth even though no XSS/clickjacking gap was found, at essentially zero functional cost for a console that never needs to be framed or serve untrusted uploads.

`pip-audit` had never been run in this project before. Installing it revealed the gateway has **no `pip` at all** - every Python package (`fastapi`, `starlette`, `pydantic`, etc.) is `apt`/`dpkg`-installed, confirmed by `python3 -m pip --version` failing outright. The gateway's exact installed versions were read via `dpkg -l` and Python's own `__version__` attributes, then audited from the Mac one package at a time (auditing them together as a single requirements file hit real pip dependency-resolution conflicts). Real CVEs exist in `fastapi`/`starlette`/`h11`/`anyio`/`jinja2`/`cryptography` at the exact versions Ubuntu 24.04 ships - checked with `apt-cache policy` that no newer version is available yet even from `noble-security`, meaning Ubuntu's own security team hasn't backported fixes for these specific advisories. `python-multipart` and `requests`/`urllib3` also showed CVEs but are confirmed **unused** by this project's own code (installed only as transitive `apt` dependencies of unrelated system tooling); `click`'s one CVE is in CLI-argument parsing this project's own systemd unit supplies with a fixed argv, never attacker input. The framework-level CVEs are recorded as a genuine, standing gap this step's own scope couldn't close (an `apt`-only upgrade path with nothing newer offered, and a `pip`-based override would mean introducing a second package manager to a gateway that deliberately has none) - not silently accepted, written down.

`shellcheck` had also never been run in this project - installed via Homebrew (not previously on the Mac) and run against every `.sh` file plus the three extensionless scripts (`gateway/securepi` and friends). Two trivial, non-security findings fixed (an unquoted loop-counter variable in `setup-test-harness.sh`, a missing `|| exit` after a `cd` in `session-start.sh`); this session's own new scripts (`generate-console-tls.sh`, `setup-privilege-separation.sh`) had zero findings.

**Two real WAN-exposure findings, both found via `sudo ss -tlnp` and fixed live:**

- `mitmdump` (Tier 2 HTTPS inspection) listened on `0.0.0.0:8080` - every interface, including the WAN Wi-Fi uplink - when the nftables redirect rule that feeds it only ever needs `10.10.0.1` (the address `redirect` implicitly targets for `ap0`-sourced traffic). Fixed in both the live unit and `dpi/deploy-dpi.sh`'s tracked copy; verified live via `ss -tlnp` showing the narrowed bind and the nftables rule unchanged. **Not fully verified**: a real redirected connection reaching the relocated listener - the same `ap0`-isolation gap already documented for step 5.7, since the test harness can't reach `ap0` and no device was actively enrolled this session.
- `sshd` listened on `0.0.0.0:22` with `PasswordAuthentication yes`. Checked `authorized_keys` first (one key present) and confirmed this entire session's SSH access had already worked via key auth throughout with zero password prompts, before disabling password auth via a new `10-securepi-harden.conf` (named to sort and win ahead of the existing `50-cloud-init.conf`, which still sets it to `yes` - OpenSSH keeps the first value it sees for a keyword). `sudo sshd -t` validated before reloading; verified live immediately after with two connections - one forced to `PreferredAuthentications=password` (refused: "Permission denied (publickey)"), one ordinary key-based connection (succeeded). `sshd`'s WAN-facing `ListenAddress` was deliberately left unchanged - a lockout-risk system-access change this project's own standing rules reserve for the user, even though the more exploitable half (password guessing) is now closed.

Every other listener (the console, the DPI CA download server, AdGuard DNS) was already correctly scoped to `10.10.0.1` or loopback - checked, not assumed, before writing "no other findings."

`make test`: **265/265 passing** (was 262) - 3 new structural tests for the security headers.

### 3.5 — Platform health supervisor

Every existing signal in `app/correlation.py` answers "is a device doing something suspicious"; nothing answered "is the gateway itself healthy enough to trust what those signals are telling you". A stopped Suricata process is a silent blind spot, not a quiet network, and the operator had no way to know the difference short of SSHing in and checking manually. New `app/health.py` runs five checks - `check_services` (every unit in the new `app/services.list`, via `systemctl is-active`/`systemctl show`), `check_staleness` (ingest/engine/Suricata/AdGuard all still producing fresh output, not just "still running"), `check_disk` (free space on the DB's volume), `check_db_size` (retention keeping up), `check_wan` (a single ping to `1.1.1.1`) - and raises ordinary rows in the `incidents` table for whatever's wrong, with `device_id=NULL` and a `signal_type` deliberately left out of `app/playbooks.py`'s `ATTACK_MAPPING`, the same "no tactic, on purpose" treatment `malicious_domain`/`new_device`/`ids_other` already get. They show up in the same Incidents queue, get the same audit treatment, and clear the same way - an operator resolves one once the real problem is fixed; this module never auto-resolves anything, matching every other signal's behavior.

**Architectural decision, made explicit rather than left implicit:** these checks run from `app/ingest.py`'s loop, not `app/engine.py`'s, even though `app/engine.py` (the correlation engine) is itself one of the things being watched. A process cannot reliably detect its own death. `app/ingest.py` is a genuinely separate systemd unit, so it keeps running (and can correctly report "the engine hasn't run recently" via `check_staleness`'s read of `signal_state`) even if the engine itself has crashed outright. Throttled via `run_if_due()` - the same "gate on a stored timestamp" pattern `app/retention.py` already uses for its own once-a-day job - to `health_check_interval_seconds` (default 30s, comfortably under the plan's own 60s exit criterion), since ingest's own loop runs every 2s and several of these checks (systemctl calls, a WAN ping) are too costly to repeat that often.

Several down services are combined into **one** `platform_service_down` incident naming all of them, rather than one incident per service - matching the exit criterion's own singular "a platform incident" wording, and avoiding a dedup collision, since `raise_incident()`'s dedup key is `(device_id, signal_type)` and a device_id of `NULL` is shared by every platform check.

**One real, latent bug found and fixed - not in the new code, in code steps 1.1-2.x had shipped without ever exercising this path:** `correlation.raise_incident()`'s own dedup query read `WHERE device_id = ?`. In SQLite, `=` never matches `NULL`, not even `NULL` against another `NULL` - confirmed directly in a live interpreter (`SELECT count(*) FROM t WHERE device_id = ?` with a bound value of `None` returns 0 against a row whose `device_id` actually is `NULL`, while the same query with `IS ?` returns 1). Every existing signal type always has a real `device_id`, so this had never surfaced in two prior stages of testing - a device-less platform incident is the first thing in this project to ever call `raise_incident()` with `device_id=None`. Left unfixed, every single health-check cycle would have raised a brand-new `platform_service_down` incident instead of extending the one still open, flooding the Incidents queue every 30 seconds for as long as a service stayed down. Fixed by changing the dedup query to `IS ?`, which behaves identically for every real `device_id` and correctly matches `NULL` to `NULL` for platform incidents. A regression test (`test_a_device_less_platform_incident_dedups_against_itself` in `tests/test_correlation.py`) was written and confirmed to **fail against the reverted (`=`) code first**, before confirming the fix passes it - the same "prove the test would have caught it" discipline used for every fix this stage.

Two new tables support this: `sensor_stats` (Suricata's own `eve.json` `stats` event type - `kernel_packets`/`kernel_drops`/`errors` - previously silently discarded by `SKIP_TYPES`, now parsed by a new `save_sensor_stats()` in `app/ingest.py` and upserted as a single row) and `service_health` (one row per service, refreshed every check cycle with `is_active`/`memory_bytes`/`cpu_seconds` - the latter two read from systemd's own cgroup accounting via `systemctl show -p MemoryCurrent -p CPUUsageNSec`, not `psutil`/`/proc` parsing, matching the plan's own §1.6 decision against adding a system-monitor dependency for this). Both added to `app/schema.sql` for fresh installs and to `app/ingest.py`'s `SCHEMA_MIGRATIONS` list for the live, already-existing database.

**A repo-tracking gap found while building this, not a functional bug:** the live gateway's `/opt/securepi/services.list` had existed on disk for stages 1-2 but was never checked into the repo - `app/health.py` needed to read it, and there was nothing in git to deploy. Added as `app/services.list`, copied exactly from the live file's real service list, with a comment noting the new reader.

**Local verification (the Mac):** 16 new tests in `tests/test_health.py`, each against a real temp SQLite DB with only the actual system calls (`systemctl`, `ping`, `shutil.disk_usage`, `retention.db_size_bytes`) monkeypatched - the same "test the real decision logic, not the OS" approach `quarantine.py`/`dpi_enroll.py`'s own tests already use, since this project has no systemd or network access to test against on the Mac. Covers: no incident when everything's active; one and multiple down services (the latter proving the "combine, don't cascade" design); **repeated downtime extending rather than duplicating an incident - the direct regression proof that the `raise_incident` NULL-dedup fix actually works, not just that its own isolated unit test passes**; an unknown (`None`) active state correctly not treated as "confirmed down"; staleness for ingest/engine/Suricata/AdGuard, including the "never seen a single event from this source yet" startup case correctly NOT flagged as stale (`MAX(ts)` returns `NULL` on an empty table, which must not be misread as "very stale"); low/healthy disk; oversized/normal database size; failed/successful WAN ping; and `run_if_due`'s own throttle window. `make test`: **282/282 passing** (was 265).

**Deployed to the live gateway with the same staged, verify-before-flip methodology as every other step this stage:**

1. `.bak-3.5-<timestamp>` copies taken of the live `webapp.py`... no state-changing config flip exists for this step (unlike 3.2's TLS or 3.3's privilege drop), so the main risk was purely the schema migration and the new `ingest.py` loop body, both covered by backups of `securepi.db` and `ingest.py` themselves.
2. `make deploy`'s dry run (`-n -i`) previewed the exact expected file set - `health.py`, `services.list` (new), plus the five edited files - with nothing unexpected.
3. Real deploy ran clean; `securepi-ingest`/`securepi-engine`/`securepi-web` all restarted with no errors in the journal.
4. The `sensor_stats`/`service_health` migrations were confirmed applied against the live, already-existing database via `sqlite3 .schema`, the same migration-path verification used in every prior stage-3 step.

**Live-verified against the real exit criterion ("a stopped service surfaces as a platform incident within 60 seconds"), not just assumed from the passing unit tests:**

| Check | Result |
|---|---|
| `sudo systemctl stop securepi-dpi` (chosen deliberately - Tier 2 was already unenrolled this session, so this carried zero real-user impact) | Stopped cleanly |
| Database polled every 10s after the stop | `platform_service_down` incident (naming `securepi-dpi`) appeared at **~14 seconds** - well under the 60s requirement |
| `service_health` row for `securepi-dpi` during the outage | `is_active=0`, `memory_bytes`/`cpu_seconds` both `NULL` (a stopped unit has no cgroup accounting left to read) |
| `sudo systemctl start securepi-dpi`, then polled again | `service_health` updated to `is_active=1` on the next check cycle - but the incident stayed open, **not** auto-resolved |
| Manual resolve of the test incident (id 185) via the console | Succeeded, confirmed removed from the open-incidents view - cleanup, not part of the feature under test |
| Journal, all three restarted services | Clean throughout |

The "recovery updates `service_health` but does not auto-resolve the incident" behavior was verified deliberately, not assumed - it's the same "an operator must manually resolve, the system never closes one out from underneath them" design already established for every other signal type, and this step's own module docstring says so explicitly; the live test above is what actually proves it holds for this signal too.

**Not done this step, named rather than implied:** step 3.6 (fail-open DNS behavior) was deliberately left for a future session due to the session's own resource budget, not for a technical reason - it has no dependency on anything built in 3.5.

### 3.6 — Fail-open DNS

F§8.4's own failure table draws a sharp line for AdGuard specifically, different from every other service: "AdGuard Home dies → DNS fails LAN-wide". Every device on the network resolves names through the gateway (`gateway/nftables.conf` forces plaintext DNS there), so unlike Suricata or the DPI proxy going down - a detection or ad-blocking gap, not an outage - AdGuard going down and staying down means every device loses the internet by name, not just loses filtering. Step 3.5's `platform_service_down` incident would have caught and reported this, but reporting isn't the same as keeping the network usable while the underlying problem gets fixed.

New `app/dns_failopen.py` adds (and later removes) two nftables rules - `iifname "ap0" ip daddr 10.10.0.1 udp/tcp dport 53 ... dnat to 1.1.1.1:53`, tagged with `comment "dns-failopen"` - that redirect plaintext DNS bound for the gateway's own address to a public upstream resolver. This is a genuinely different rule from the two DNS-forcing rules `gateway/nftables.conf` already has: those only match `ip daddr != 10.10.0.1` (a device hardcoded to some other resolver, forced back to filtering), so a client correctly pointed at 10.10.0.1 - what DHCP actually hands out - never touches them at all, and gets nothing back the moment nothing is listening there. The two match conditions (`daddr != 10.10.0.1` vs `daddr 10.10.0.1`) are mutually exclusive by construction, so there's no ordering dependency between the existing rules and the new one.

A new `check_dns_failopen()` in `app/health.py` decides when to flip this on: it probes AdGuard with a real `dig` query (not `systemctl is-active`, which a hung-but-running AdGuard would still pass - the same "active isn't the same as working" distinction `check_staleness` already draws), and after a configurable grace period (`dns_failopen_after_seconds`, default 10s - long enough that AdGuard's own `Restart=always`/`RestartSec=10` usually fixes a simple crash by itself first) calls `dns_failopen.activate()` and raises a `platform_dns_failopen` incident (`device_id=NULL`, no `ATTACK_MAPPING` entry - infrastructure health, not an adversary technique, the same treatment every other `platform_*` signal gets). It runs on its own dedicated, faster throttle (`run_dns_failopen_if_due`, default every 5s) separate from the general `health_check_interval_seconds` (30s) - the ~30s "clients still resolve" exit criterion has no room to wait out a slower shared cycle on top of the grace period.

**Recovery is automatic for the network, deliberately not for the incident.** The moment AdGuard answers a real query again, `check_dns_failopen()` calls `dns_failopen.deactivate()` and clears the redirect - no operator action needed for DNS itself to come back, matching F§8.4's "protection returns on recovery" wording. The `platform_dns_failopen` incident it raised, however, still needs a manual resolve, exactly like every other platform incident (`app/health.py`'s own module docstring already establishes this for 3.5, and changing it just for this one signal would have meant special-casing the one piece of `raise_incident()` behavior 3.5 explicitly tested and relied on). The plan's "automatic recovery" describes the network, not the audit trail - a real DNS outage is worth an operator's eventual look even after it's already fixed itself.

A `dns_failopen_state` table (one row, `active`/`down_since`/`changed_at`) is the bridge between the two: `down_since` starts counting the moment a probe fails and is cleared the instant one succeeds again, `active` only ever gets set to 1 once the redirect is actually in effect. The two are deliberately not the same thing - a blip that self-heals inside the grace period sets `down_since` without ever setting `active`, so it raises no incident and calls neither `activate()` nor `deactivate()`, confirmed by a dedicated test. The unprivileged web console (step 3.3) reads this table directly through a new `GET /api/dns-status` route - it cannot ask `nftables` itself - and a new banner in `base.html` (visible on every page, not buried in a widget) shows "DNS protection degraded" while `active` is true, polled every 5s alongside the console's other live widgets.

**One real bug found and fixed, caught only by an actual browser, not by any unit test:** the banner stayed visible even after the API correctly reported `active: false` and the DOM's own `hidden` attribute was confirmed `true` via `javascript_tool` - a genuine CSS cascade surprise. `.degraded-banner { display: flex; ... }` is an *author* stylesheet rule; the browser's own default `[hidden] { display: none }` lives in the *user-agent* stylesheet, and author rules always outrank user-agent rules in the CSS cascade regardless of selector specificity. The class rule won, and the element stayed visible with `hidden` correctly set. Fixed with an explicit `.degraded-banner[hidden] { display: none; }` override. Found by watching the actual dashboard in a real Chrome tab through two full outage/recovery cycles (via `mcp__claude-in-chrome`) rather than trusting the API response and DOM state in isolation - a case where "the data is correct and the JS ran" was not enough to conclude the feature worked.

**Local verification (the Mac):** 303/303 tests passing (was 282) - `tests/test_dns_failopen.py` (17 new tests: `_add_rule_argv`/`_delete_rule_argv`/`_extract_handles` tested directly as pure functions against a real `nft -a list` output sample captured from the gateway, the same "pure argv builder, no subprocess" split `securepi-web-helper`'s own `build_nft_argv()` uses; `is_active`/`activate`/`deactivate` tested by monkeypatching `dns_failopen._run`) plus a new `CheckDnsFailopenTests`/`RunDnsFailopenIfDueTests` in `tests/test_health.py` (4 new tests: no action while resolving; a sub-grace-period blip touches neither the firewall nor the incidents table; an outage past the grace period fails open and raises exactly one incident even across repeated cycles; recovery deactivates and clears `down_since`/`active`).

**Deployed to the live gateway with the same staged methodology as every step this stage:** `.bak-3.6-<timestamp>` copies of every file this touched (`health.py`, `ingest.py`, `playbooks.py`, `schema.sql`, `settings.py`, `webapp.py`, `static/app.css`, `static/app.js`, `templates/base.html`) plus a full `securepi.db` copy, taken before deploying; `make deploy`'s dry run previewed exactly the expected file set (the new `dns_failopen.py` plus the nine edited files); the `dns_failopen_state` migration confirmed applied via a direct Python/sqlite3 query against the live database (no `sqlite3` CLI on the gateway - checked via the same `python3 -c "import sqlite3; ..."` approach used throughout this session).

**Live-verified against the real exit criterion, end to end, twice:**

| Check | Result |
|---|---|
| `sudo systemctl stop AdGuardHome`, then `dig @10.10.0.1 example.com` from the gateway itself | Immediately fails ("connection refused") - confirms the outage is real before anything else is checked |
| `dns_failopen_state` polled every 3s after the stop | `active` flipped to 1 at **~19 seconds** (first run) and **~19 seconds** (second run) - well under the 30s exit criterion, with the 10s grace period plus one ~5-9s detection cycle accounting for it |
| `sudo nft -a list chain ip nat prerouting` while active | The two `dns-failopen`-commented rules present with exactly the intended match/target (`iifname "ap0" ip daddr 10.10.0.1 udp/tcp dport 53 ... dnat to 1.1.1.1:53`) |
| Real Chrome tab, dashboard, while active | "DNS protection degraded - AdGuard isn't answering (since HH:MM:SS)..." banner visible, screenshotted |
| `sudo systemctl start AdGuardHome`, then polled again | `active` reverted to 0 within **~7-8 seconds** of AdGuard answering again; the two nft rules confirmed gone via `nft -a list` |
| Same Chrome tab, after recovery | Banner correctly hidden (after the CSS fix above - confirmed still visible, incorrectly, before it) |
| `incidents` table across both outage/recovery cycles | Exactly **one** `platform_dns_failopen` incident (id 189, first_seen 00:31:27, last_seen 00:40:10) spanning both test outages - extended, not duplicated, the same dedup behavior 3.5 already proved; manually resolved as cleanup afterward |
| Journal, `securepi-ingest`/`securepi-web`/`AdGuardHome`, across the whole test | Clean - only expected `AdGuard API unreachable ... falling back to file tailing` messages from `app/adguard.py`'s own pre-existing graceful-degradation path while AdGuard was deliberately down, no tracebacks |

**Not fully verified, named rather than implied:** the redirect rule's effect on an actual `ap0`-connected client's DNS query was not tested with a real Wi-Fi device - `securepi status` showed 0 clients connected this session, and the project's own test harness (`ns_attacker`/`ns_victim`) is deliberately built on a separate `br-test` bridge, "entirely separate from the production ap0/hostapd network" (its own setup script's words), so it cannot generate `ap0`-sourced traffic to test this specific path. Rather than risk attaching a virtual interface to the live, production Wi-Fi AP interface to simulate one - a state-changing experiment on the one interface actual devices depend on, for a rule whose match criteria were independently confirmed correct by direct inspection - this was left as a real gap: the detection, activation, deactivation, incident, and console-banner machinery are all live-verified end to end; the very last hop (a real phone's DNS query actually being answered by 1.1.1.1 instead of timing out) is not. Confirmed instead, as strong indirect evidence: the rule's match/target syntax is byte-for-byte what a manual read of `nft`'s own documentation and the existing, already-proven `dpi-redirect` rule's shape would predict, and the two conditions (`daddr != 10.10.0.1` for the existing rules, `daddr 10.10.0.1` for this one) cannot both match the same packet.

---

## Stage 4

Response and policy orchestration, built and verified 25–26 September 2026. Every check below ran on the live gateway against the test harness's `[TEST HARNESS] test-victim` device (id 5, MAC `02:00:00:00:00:12`, IP `10.10.0.221`), never a real person's device. The console's password is a one-way hash since step 3.1, so instead of signing in over HTTP these checks ran the real orchestrator code on the gateway **as the unprivileged `securepi-web` user** - the console's own privileges and code path, minus only the HTTP layer. That layer, and every new console page, was exercised end to end in a headless browser against the demo console (`docs/demo/serve.py`) instead: quarantine through the dialog, adding a webhook channel and sending a signed test, the profile editor, the Response page, dark and light themes, and phone width. No page errors.

`make test`: **362** passing (was 303) - `tests/test_orchestrator.py` (39), `tests/test_notify.py` (14), six new helper-verb tests, plus the flaky-test fix below.

### Four real bugs found, none guessed

1. **AdGuard does not ignore a trailing `# comment` on a rule line.** Steps 5.2 and 5.5 stored a temporary allow's expiry and a vendor list's tag as `  # securepi-expires:…` / `  # securepi-tag:…` after the rule, on the assumption that AdGuard ignores it. Checked live with `check_host` on four rule shapes: every rule with the comment matched **nothing**, the same rules without it matched. So every temporary "unbreak" and every vendor-telemetry block applied since those steps was stored but never enforced. There were none live at the time. The orchestrator now writes plain rules and remembers which are its own in `orchestrator_state`. `migrate_legacy_rules()` converts any old commented line into a real policy and removes the broken line. The quoted form `$client='[TEST HARNESS] test-victim'` was confirmed to match (victim blocked, another client not).
2. **Step 2.2's firewall change was never made permanent.** The live forward chain had no `log prefix` on the three DNS-bypass reject rules, and `/etc/nftables.conf` (what `nftables.service` loads at boot) was dated 13 September - the pre-2.2 file. Step 2.2 had copied the new file to `/opt/securepi/nftables.conf` and loaded it with `nft -f`, but never installed it at `/etc`, so the reboots on 20, 21 and 25 September each put the old rules back. From then on the nftables half of `dns_bypass` detection was silently off (the DoH-set refresh kept working - 709 entries). Fixed in the same install as step 4.2's new sets: the repo file is now both `/etc/nftables.conf` and `/opt/securepi/nftables.conf`, and they're identical.
3. **A per-device pause didn't pause everything.** AdGuard's per-client `filtering_enabled=false` switches off blocklist matching only: with it off, a Kids device still had TikTok blocked (`FilteredBlockedService`) and Google rewritten (`FilteredSafeSearch`), while `doubleclick.net` resolved. A pause now clears the device's blocked services and safe search as well, and restores the whole profile when it ends.
4. **Journal flooding from read-back.** The orchestrator reads three nftables sets every 15-second cycle through the helper, and each read went through `sudo` (a PAM session opened and closed) and wrote a helper log line - about 24 journal lines every 30 seconds. The engine already runs as root, so it now calls the helper directly, and the helper no longer logs the read-only `*-list` verbs (changes and rejected input are still logged). Measured after: 2 lines in 30 seconds.

A pre-existing test flake was also fixed: four behavioural-baseline tests put their flow 60 s past the top of the hour, which is in the future during the first minute of every hour. The suite happened to run at 19:00:56 UTC, where the positive test failed and the three negative ones passed only because they saw nothing.

### Deploy

Backups first in `/opt/securepi-backups/`: the live ruleset (`nft list ruleset`), `/etc/nftables.conf`, the helper and a full `securepi.db` copy (SQLite online backup). Then `nft -c -f` on the new file, and a **dead-man switch** (`systemd-run --on-active=180` restoring the saved ruleset) before `nft -f /etc/nftables.conf`. The DoH set was refreshed straight after (the reload resets it to its seed). SSH, the console (HTTP 200) and DNS were re-checked from the Mac, then the switch was cancelled. Nothing was enrolled, quarantined or failed-open at the time, so the reload lost no runtime state. Then the helper, then `make deploy` of the expected 21 files, with `.bak-4-<timestamp>` copies of every changed one. Migrations ran on the ingest restart. Every existing device came through as `approved` (13 devices). The engine created `orchestrator.lock` on its first cycle, and that cycle read back all six enforcement points with no errors.

### 4.1 — Policy orchestrator

| Check | Result |
|---|---|
| Injected failure: AdGuard accepts a client update but doesn't keep it (Kids profile on the victim) | `PolicyApplyError: read-back did not match what was applied (Device filtering settings (AdGuard)) - rolled back, nothing was changed`. The client object was identical before and after. Policy recorded as `failed` |
| Injected failure: the firewall accepts a quarantine add but doesn't keep it | Same shape of error for `Quarantine (firewall)`. `quarantine_mac` unchanged, no active quarantine policy left behind |
| Real apply: block `sp-drift-test.example` for the victim only | Rule `\|\|sp-drift-test.example^$client='[TEST HARNESS] test-victim'` in AdGuard; `check_host` from the victim → `FilteredBlackList`, from another client → `NotFilteredNotFound` |
| Out-of-band change: that rule deleted directly through AdGuard's own API | Restored within 1 s (the engine's next cycle happened to land right away). Audit row `policy.drift_corrected` - "1 rule(s) removed or edited in AdGuard: …". Platform incident #201 "A response policy was changed outside the console" |

### 4.2 — Response actions

| Check | Result |
|---|---|
| The new rules loaded | `iifname "ap0" ether saddr @quarantine_mac … drop` and `iifname "ap0" ip daddr @blocked_ip … drop` accepted by the kernel in the `inet` forward chain |
| New helper verbs as `securepi-web` | Add/list/delete round trips for both sets. `quarantine-mac-add "…; flush ruleset"` → `REJECTED`, logged. Old verbs unaffected |
| Timed quarantine (120 s) + block IP (120 s) | Kernel held both with 178 s left (policy + the 60 s backstop margin). Both policies `expired` by the orchestrator **11 s** after their time, both sets empty |
| Auto-response on a synthetic scan → brute force → beacon chain on the victim | The real engine built campaign #3 "Discovery -> Credential Access -> Command and Control"; the orchestrator created `auto:campaign:3` (5 min, by `auto-response`) and raised incident "…test-victim was quarantined automatically". The kernel entry was extended to the longer of the two overlapping quarantines. The synthetic incidents and campaign were deleted afterwards, as in 2.8 |

**Not verified live, named rather than implied:** "survives a DHCP renewal" needs a real device whose traffic arrives on `ap0` - the harness namespaces sit on `br-test`, which never touches the `iifname "ap0"` rules (the same limitation 3.6 and 5.7 record). No device was connected to SecurePi-Test this session. What *is* established: quarantine is keyed on MAC, the orchestrator follows a device's new MACs (unit-tested), and a new IP changes nothing about the set (unit-tested). Still to run: connect a phone, quarantine it for 15 min, force a renewal (toggle Wi-Fi), and confirm the `quarantined-mac` rule's counter rises and the phone stays offline until expiry. **Since done** - see "Real-device checks (26 September 2026)" below.

### 4.3 — Filtering profiles

Kids on the victim, with its schedule edited for the test to block `group:gaming` from 00:38 (two minutes ahead):

| Check | Result |
|---|---|
| Read back after apply | `filtering_enabled` true, safe search on, 13 blocked services, `steam` not yet among them |
| `check_host` from the victim before the window | `amemv.com` (TikTok, always) → `FilteredBlockedService`; `www.google.com` → `FilteredSafeSearch`; `dota2.wmsj.cn` (a Steam service domain) → `NotFilteredNotFound` |
| Window opens at 00:38:00 | `dota2.wmsj.cn` → `FilteredBlockedService` at **00:38:01**. Recorded as a planned change, not drift |
| Pause for 60 s (after bug 3's fix) | During: all three domains `NotFilteredNotFound`. After: back to `FilteredBlackList` / `FilteredBlockedService` / `FilteredSafeSearch`, policy `expired` 13 s after its time |
| Clean-up | Kids reset to its defaults; the victim's client back to standard (filtering on, no services, no safe search); AdGuard's custom rules back to the original three `$dnsrewrite` lines |

### 4.4 — Device trust

| Check | Result |
|---|---|
| Restrict unknown devices on; the registry creates a new device (synthetic harness MAC `02:00:00:00:4e:01`) | Created as `unknown` at 00:43:40 |
| Restricted | MAC in `quarantine_mac` at 00:43:44 - within one engine cycle - by policy `source=trust`, "unknown device - restricted until approved" |
| Approved | Out of the set on the same call; policy `removed`, "trust is now approved" |

The device was kept, renamed `[TEST HARNESS] live 4.4 new device`, the same way step 6's evaluation devices were. "Restrict unknown devices" was switched back off.

### 4.5 — Notifications

A webhook channel on the gateway pointed at a small listener on the Mac (`192.168.2.1`, over the management cable - nothing sent to a third-party service).

| Check | Result |
|---|---|
| Send test | Received, `X-SecurePi-Signature` HMAC-SHA256 verified against the body. The API showed the secret only as `••••-key` |
| Three harness port scans 20 s apart | Incident #206 (port scan) grew to 80 events over several cycles and #207 (slow port scan) was raised. The Mac received **exactly two** webhooks, one per incident. `notifications` held one `sent` row each |
| Clean-up | Channel removed (the listener was temporary); #201, #206, #207 resolved with a note |

Telegram and SMTP were not sent live (no accounts were set up for this). Their exact requests are unit-tested (`RequestShapeTests`), and they share the same dispatch path the webhook check proved.

## Real-device checks (26 September 2026)

The rules that match `iifname "ap0"` had never seen a real device's
traffic: the test harness sits on `br-test` (see 2.2, 3.6, 4.2, 5.7). This
session closed that gap with a Samsung Galaxy A33 (Android 16) on
SecurePi-Test, driven from the Mac over USB with `adb`, on the code
deployed the same morning (the `Audit.md` fixes, commits `44c8c6c` to
`5d616fa`). Policies were created and ended through `orchestrator.py` as
`securepi-web`, the same path the console uses. The phone is registry
device 2, MAC `ca:25:f0:57:6d:87` (Android's persistent per-network random
MAC; the same address came back on every reconnect).

| Check | Result |
|---|---|
| **Deploy** (`migrate-data-dirs.sh`, `make deploy`, DPI + canary scripts, 4 new input rules added live without a flush) | All services active. Database, lock and rule set in `/var/lib/securepi*`; code directories `root:root 755`. Engine heartbeat live; privacy canary "passthrough and decrypt decisions both correct"; addon loaded rules from `/var/lib/securepi-dpi/`. Pre-deploy backup: `securepi.db.pre-audit-fixes-20260926-075723.bak` (600) |
| **5.7 inspection redirect** (enrolled, Chrome) | `youtube.com` / `m.youtube.com` **decrypted**; `/pagead/adview` and `/youtubei/v1/log_event` blocked by the addon. `en.wikipedia.org`, `google.com`, `graph.facebook.com` and others **passed through** undecrypted |
| **4.2 quarantine** (5 min, while enrolled) | MAC in `quarantine_mac`; internet ping 100% lost, gateway still reachable |
| **4.2 survives a reconnect** | The phone left SecurePi-Test and came back (new association and DHCP) still quarantined: ping 100% lost, `quarantined-mac` counter 6 → 151 |
| **Audit H1: proxied HTTPS while quarantined** | New `quarantined-mac-proxied` input rule dropped **175** packets of the phone's redirected HTTPS (64 of them from loading YouTube in Chrome, which stayed blank). Before the fix these reached the internet through the proxy |
| **4.2 expiry** | Policy `expired` by the orchestrator **6.3 s** after its time; set empty; phone back online |
| **2.2 DoT bypass, layer 1** | Private DNS `dns.google`: AdGuard blocked the hostname (`\|\|dns.google^`), so the phone never attempted port 853. 9 of 10 common DoT hostnames are blocked this way (`dot.sb` is not) |
| **2.2 DoT bypass, layer 2** | Private DNS `dot.sb`: `10.10.0.50 → 185.222.222.222:853` **rejected** by the `dot-bypass` rule, logged, ingested, and added as evidence to `dns_bypass` incident #447 |
| **2.2 QUIC** | Chrome's QUIC attempts (51) were rejected by `quic-blocked` and raised the same incident #447 |
| **3.6 fail-open DNS** | AdGuard stopped → both `dns-failopen` rules in place after **16 s**, incident #451 raised; removed again once AdGuard was back |

**Not proven, named rather than implied:**

- **3.6:** the phone's lookups during the fail-open ran just after AdGuard
  was restarted (a timing mistake in the test), so they don't prove the
  phone resolved *through* the fail-open rules. The rules going in and
  coming out, and the incident, are verified. A stricter rerun (lookups
  while AdGuard is held down) is still to do.
- **Quarantine and Android roaming:** turning Wi-Fi off and on made the
  phone join a different saved network with working internet (Babu_Home)
  instead of the quarantined one. Quarantine removes a device from this
  network; it can't stop the device leaving for another network it knows.
  The reconnect check above was done with Babu_Home's auto-reconnect off.
- **Device 2's open `slow_network_sweep` incidents** belong to this phone,
  so they come from ordinary phone traffic - most likely a false-positive
  pattern, to look at in 7.3.

## Stage 7

In progress: 7.1 and 7.2 are done, 7.0 and 7.3-7.9 are still to run.

### 7.2 — Detection battery, five runs per signal

`gateway/battery.py` drives every signal with real traffic through the
test harness (the DNS signals through the gateway's own resolver). Each run
uses its own source host, and it only counts as detected when an incident
links an event *from that run*. Final battery: 26 September 2026, 05:43-06:12,
`eval/results/battery-20260926-054306.json`.

| Signal | Detected | Median TTD | p95 TTD |
|---|---|---|---|
| threat_intel | 5/5 | 11.6 s | 11.6 s |
| malicious_domain | 5/5 | 12.2 s | 12.2 s |
| dns_tunneling | 5/5 | 9.5 s | 11.6 s |
| dga | 5/5 | 8.5 s | 10.5 s |
| dns_bypass | 5/5 | 11.6 s | 11.7 s |
| ids_alert (rule 2100498) | 5/5 | 14.1 s | 15.1 s |
| new_device | 5/5 | 43.2 s | 45.1 s |
| brute_force | 5/5 | 75.6 s | 76.6 s |
| port_scan | 5/5 | 91.2 s | 91.2 s |
| network_sweep | 5/5 | 91.1 s | 91.2 s |
| volume_anomaly | 5/5 | 105.5 s | 105.5 s |
| beacon (10 s ±10%) | 5/5 | 152.0 s | 154.8 s |
| campaign (scan → brute force → beacon) | 5/5 | 151.2 s * | 154.1 s * |
| slow_port_scan (9 probes, 50 s apart) | 5/5 | 486.2 s | 486.2 s |
| slow_network_sweep (50 s apart) | 5/5 | 580.5 s | 580.6 s |
| **benign host** (irregular web fetches, 4 min) | **nothing fired** (correct) | | |

\* The engine's own `campaigns.created_at` (137-154 s). The battery's check
only starts once the beacon thread finishes, so it logged 261-274 s; it now
uses `created_at` (fixed in `battery.py` after this run).

Most of the scan and brute-force TTD is Suricata's TCP flow timeout (a flow
is only logged ~60 s after its last packet), then one 15 s engine cycle.
The slow signals' TTD is dominated by the attack itself: nine probes, 50 s
apart, take 400 s.

**What the battery found, in order (four real problems, none guessed):**

1. **dns_bypass - fixed.** AdGuard never logs the Firefox canary
   `use-application-dns.net`, so the signal never had evidence (smoke test).
   It is now also counted from Suricata's DNS records. 0/1 → 5/5.
2. **beacon - fixed (engine bug).** Found through the replay's determinism
   check (see 7.1 below). Live evidence from the smoke test: logged gaps of
   5.0-14.9 s for a 10 s beacon, score 0.73 against 0.8. It now times from
   `flow_start`. 0/1 in the smoke test → 5/5 in both five-run batteries.
3. **volume_anomaly - harness problem, not an engine bug.** First five-run
   battery (04:53, `eval/results/battery-20260926-045314.json`): 0/5. Each
   150 MB transfer was logged as ~0.98 MB. The namespaces' `eth0` had
   segmentation offload on, so the veth carried 64 KB packets and Suricata
   kept only part of each (54 reassembly gaps, no kernel drops).
   `setup-test-harness.sh` now turns TSO/GSO/GRO off inside both namespaces,
   on every boot. With offloads off, an unthrottled transfer (~420 Mbit/s)
   then outran the single veth capture thread: of 50 MB, 10.3 MB was counted,
   with 29,856 kernel drops. At 40 Mbit/s all of it was counted, with no drops.
   The AP is 2.4 GHz, so real clients never approach 420 Mbit/s. The battery
   now caps the transfer at 40 Mbit/s, and line-rate capture belongs to step
   7.8's throughput sweep. 0/5 → 5/5.
4. **new_device run 1 in the first battery was invalid (battery bug).** Its
   hostname `battery-new-device-1` was reused from the smoke test, so the
   registry rightly treated it as a known device with a re-randomized MAC.
   The check accepted the smoke test's old incident: "detected in 0.1 s".
   Hostnames are now unique per battery, and only incidents created after
   the run started count. All five runs in the final battery are genuine.

**Also seen, not yet acted on:**
- Every battery campaign's tactic chain reads "Exfiltration → Command and
  Control → Discovery → …", though the volume transfer came last:
  volume_anomaly sets `first_seen` to the start of the hour, so it sorts
  first. The console shows a kill chain in the wrong order. Small fix, for later.
- Device 2 (not a battery device) has 116 open slow_network_sweep incidents.
  It looks like a false-positive pattern; look at it in 7.0/7.3.
- On `make deploy` the engine ran one cycle before ingest had added the
  new column: one `beacon_signal failed: no such column: flow_start`, then
  normal. This only happens on a deploy that adds a column.

### 7.1 — PCAP replay pipeline

`tools/replay.py` runs a capture through Suricata on the Mac with the
gateway's own rules, then through `app/ingest.py`'s real parser into a fresh
database, then runs `app/correlation.py`'s real engine every 15 s on a
simulated clock stepping through capture time. Nothing in `app/` is changed
for it. Inputs, and how to set them up, are in `eval/README.md`; 15 tests in
`tests/test_replay.py`.

**Determinism check - the first attempt failed, and it found a real bug.**
Two replays of the same capture gave different results: one raised a beacon
incident, the other didn't, and the detection time moved from 214 s to 259 s.
Suricata's output was the same flow for flow. Only each flow record's
`timestamp` differed, by a median 44 s and up to 6 minutes. That field is
when Suricata *logged* the flow, which happens after the flow times out, in
batches, whenever its flow-manager thread wakes up.

- **In the replay:** a flow's timestamp is now set to when the flow times out
  (its last packet plus the timeout in `tools/replay-suricata.yaml`), and ties
  sort without Suricata's random `flow_id`. The live gateway adds a few seconds
  of flow-manager delay on top, which a replay can't reproduce, so replay
  detection times are slightly optimistic. The timezone is pinned to UTC.
  After this, repeated runs give an identical result sha256.
- **In the engine (live bug):** `beacon_signal` measured the gaps between
  connections from that same logging time. So the gaps it saw were the flow
  manager's rhythm, not the beacon's. **Confirmed on the live data:** the
  smoke test's beacon sent a connection every 10 s ±10% (score 0.96 on those
  times), but the ten logged times on the gateway had gaps of 5.0-14.9 s, and
  the engine's own `_beacon_score()` gives them 0.73, under the 0.8
  threshold. That is why the smoke test's beacon was never detected. Ingest now
  also stores when each flow *started* (`events.flow_start`, a new column
  added by migration), and the beacon signal times from it. The window still
  uses the logging time, so a late-logged flow isn't lost. There is a
  regression test (fails before the fix, passes after). **To be confirmed
  live** by the battery's beacon runs after `make deploy`.

**Signals a replay can't judge**, because their inputs aren't in a capture:
threat_intel (feed table), malicious_domain and adblock_ineffective (AdGuard's
block decisions), new_device (the device registry) and volume_anomaly (7 days
of hourly rollups). Runs labelled with these are reported as "not replayable",
not scored as misses; the live battery measures them.

**Public captures (CTU-13, CC BY 2.0 - citation in `eval/README.md`).**
Suricata 8.0.7, the gateway's rule set as copied on 26 September 2026. Each
capture was replayed three times, with the same result sha256 each time.

| Capture | Events | Capture length | Infected host detected | First incident after | Incidents raised | Result sha256 (first 12) |
|---|---|---|---|---|---|---|
| Scenario 6, DonBot | 4,896 | 2 h 0 min | yes | 64 s | beacon, brute_force, network_sweep, slow_network_sweep, ids_other | `4c2f512f1691` |
| Scenario 7, Sogou | 249 | 14.5 min | yes | 20 s | network_sweep, slow_network_sweep, ids_other | `b0de6dfc0b76` |

Full results: `eval/results/replay-ctu13-donbot.json` and `replay-ctu13-sogou.json`.
These captures are labelled only at the host level ("this host is
infected"), so they show detection, not per-signal precision.

**The battery's own capture** (final battery, 16 harness hosts, 46 labelled
runs; the DNS and new_device runs don't cross this link) was replayed twice,
with an identical result sha256 (`286d068a34d1`):

| Label | Runs | Detected | Correct | Replay median TTD | Live median TTD |
|---|---|---|---|---|---|
| ids_alert | 5 | 5 | 5 | 6.7 s | 14.1 s |
| brute_force | 5 | 5 | 5 | 69.4 s | 75.6 s |
| network_sweep | 5 | 5 | 5 | 79.2 s | 91.1 s |
| port_scan | 5 | 5 | 5 | 80.9 s | 91.2 s |
| beacon | 5 | 5 | 5 | 140.9 s | 152.0 s |
| campaign | 5 | 5 | 5 | 140.9 s | 151.2 s |
| slow_port_scan | 5 | 5 | 5 | 485.8 s | 486.2 s |
| slow_network_sweep | 5 | 5 | 5 | 515.8 s | 580.5 s |
| benign | 1 | 0 | 1 | - | - |
| volume_anomaly | 5 | not replayable (bulk data left out of the capture, needs hourly rollups) | | | |

The replay agrees with the live battery on every run (45/45 correct). Its
detection times are 0-12 s earlier. That's expected: the replay logs each
flow exactly at its timeout, while the live flow manager and the 2 s ingest
poll add a little on top. The one larger gap, slow_network_sweep (65 s),
hasn't been looked into yet.
`eval/results/replay-battery-20260926-054306.json`.

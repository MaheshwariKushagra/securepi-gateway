# SecurePi Gateway — Project Report

*Report material, brought up to date in ENHANCEMENT-PLAN.md step 8.1 on
10 October 2026 (repository commit `8a5343f` plus this stage). It
assembles the chapters the 15-day plan (§9) laid out, around the sources
that hold the detail. Every figure below links to where it was measured and
how to reproduce it (§10).*

| Chapter | Where the full material is |
|---|---|
| 1. Problem and objectives | §1 here; `docs/feasibility-study.md` §1-4 |
| 2. Survey and technology choices | §2 here; `docs/feasibility-study.md` §7 |
| 3. Topology | §3 here; `docs/feasibility-study.md` §5 |
| 4. Architecture and contribution boundary | §4 here; `README.md` "Architecture" |
| 5. Implementation | §5 here; `ENHANCEMENT-PLAN.md` progress notes, `ADBLOCK-ENHANCEMENT-PLAN.md`, `AUDIT-10OCT-PLAN.md` |
| 6. Evaluation | §6 here; `EVALUATION-RESULTS-2.md` (Stage 1 onward), `EVALUATION-RESULTS.md` (Day 14) |
| Ad-blocking chapter | `REPORT-adblocking.md`, `FIRST-PARTY-ADS-ANALYSIS.md` |
| 7. Deviations from the plan | §7 here |
| 8. Limitations | §8 here |
| 9. Future scope | §9 here |
| Appendix: reproducing every figure | §10 here |

---

## 1. Problem and objectives

Small networks (a home, a small office, a lab) face the same threats as
enterprises: scanning, credential brute force, malware calling home,
DNS-based evasion, tracking. They have none of the tooling: no SOC, no
analyst, no budget. SecurePi Gateway is a single-host network security
platform that sits as the routed gateway of a dedicated small LAN and
provides:

1. **DNS-level content filtering** for every device, with bypass prevention.
2. **Full traffic monitoring** (an IDS plus DNS and firewall telemetry).
3. **An automated SOC with no analyst:** events from several sensors are
   normalised, attributed to devices, correlated into a small number of
   explainable incidents, and acted on through reversible, audited policies.
4. **Opt-in, narrowly scoped HTTPS inspection** for first-party ads, which
   DNS filtering cannot reach (added beyond the original plan; §7).

The design constraint throughout: incident volume must stay low enough for
a non-expert to act on, and every detection must be explainable from the
events that caused it.

## 2. Survey and technology choices (final)

The feasibility study (§7) compared the open-source options. What was
finally integrated, with the version running on the gateway on
10 October 2026:

| Function | Integrated component | Version | Why this one |
|---|---|---|---|
| Packet capture, protocol parsing, signature matching | Suricata, ET Open rules | 7.0.3 (`1:7.0.3-1build3`), 52,688 rules | Ubuntu archive, EVE JSON output, AF_PACKET capture on two interfaces |
| DNS filtering and DHCP | AdGuard Home | v0.107.79 | Headless and API-driven; one process for DNS and DHCP; MAC-keyed persistent clients |
| Access point | hostapd | 2.10 | In-tree, `ap_isolate` support |
| Forwarding, NAT, firewall, timed sets | Linux 6.8 + nftables | 1.0.9 | Kernel-native; sets with element timeouts drive quarantine, blocks and enrolment |
| TLS interception engine | mitmproxy (transparent mode) | 12.2.3 | Scriptable `tls_clienthello` hook decides decrypt-or-relay before any certificate is shown |
| Storage | SQLite (WAL) | system `libsqlite3` | Measured volume (about 16k events/day at the start, 8k per device-day) does not justify PostgreSQL's ~1 GB on a 3.6 GiB host |
| Console | FastAPI 0.101.0, Starlette 0.31.1, uvicorn 0.27.1, Jinja2 3.1.2, Chart.js 4.4.4 (vendored) | Ubuntu archive | Server-rendered pages plus a vanilla-JS front end; no build step |
| OS | Ubuntu Server 24.04.1 LTS | kernel 6.8.0 | Hardware support on the Dell Vostro 3501 |
| Threat intelligence | abuse.ch Feodo Tracker, URLhaus, ThreatFox | daily | Free, offline-usable, no account |
| Blocklists | AdGuard DNS filter, HaGeZi Pro, Peter Lowe, HaGeZi DoH bypass, offline threat intel | 392,229 rules | Chosen by measured unique contribution (§6.4) |

Rejected and still excluded, with the measured or stated reason:
Zeek, ELK/OpenSearch, Wazuh, PostgreSQL/TimescaleDB and Docker (each 1-4 GB
of RAM on a 3.6 GiB host); Suricata IPS mode as default (latency and
false-positive outage risk); ML detection (cannot be validated at this
volume); cloud LLM summaries (telemetry would leave the box); HTTPS
inspection for all traffic or on by default (privacy, pinning, breakage).
Full table: `ENHANCEMENT-PLAN.md` §1.5.

## 3. Topology (as built)

Feasibility "Model D", a routed gateway on a dedicated project LAN, in a
one-radio variant:

```
   Mac (development) 192.168.2.1 ══ Cat7 ══ enp1s0 192.168.2.5   (management only)
                                               │
   home router ~~ Wi-Fi ~~ wlp2s0 (station, DHCP) ── WAN
                                               │  same radio
                         ap0 10.10.0.1/24 "SecurePi-Test" (hostapd, ap_isolate=1)
                              │ DHCP 10.10.0.50-150 from AdGuard Home
                         phones, tablet, laptops (the project LAN)
   test harness: br-test + netns ns_attacker 10.10.0.220, ns_victim 10.10.0.221-230
```

- The AP follows the uplink's channel (one radio cannot use two), through
  `securepi-ap-follow-uplink` on every Wi-Fi (re)connect.
- Client isolation forces phone-to-phone traffic through the gateway, where
  the sensors see it (feasibility risk R9, step 1.7).
- Management is out of band: losing the project LAN never loses SSH.
- The isolated test harness lets real attack tools run against the real
  pipeline without touching any real device.

Exact configuration: `STAGE8-RECORD.md` §1 and `docs/INSTALL.md`.

## 4. Architecture and the contribution boundary

```
 Suricata eve.json ─┐
 AdGuard query API ─┤                        ┌─ correlation.py: 15 windowed signals → incidents
 DPI telemetry ─────┼─ ingest.py ─ events ───┤   (dedup, campaigns + ATT&CK, suppression)
 nftables kernel log┘   (2 s)     (SQLite)   ├─ risk.py: decaying, explained device risk
 DHCP leases + ARP + Wi-Fi association ─ registry.py (device identity)
                                             └─ orchestrator.py: policies → nftables sets +
                                                AdGuard rules/clients, read back, rolled back,
                                                drift repaired (via a root-only helper)
 webapp.py (HTTPS console, sessions, audit) · health.py (supervisor, DNS fail-open)
 engine.py (15 s loop) · notify.py · retention.py/rollup.py
 dpi/: mitmproxy addon (selective decrypt + structural ad removal) · privacy canary
```

### 4.1 The contribution boundary (feasibility §17.2, updated to what was built)

| Integrated (third-party) | Built in this project |
|---|---|
| Packet capture, protocol parsing, signature matching (Suricata, ET Open) | **Unified event schema and ingest** across four heterogeneous sources (IDS EVE, the DNS filter's API with a file fallback, the DPI addon's telemetry, the firewall's kernel log), with bounded, resumable, rotation-safe readers |
| DNS resolution, blocklist matching, DHCP (AdGuard Home) | **Device identity** across lease churn and MAC randomisation: lease intervals, ARP, Wi-Fi association for presence, IPv6 link-local MAC recovery, and a hostname merge that never carries approval, inspection consent or exceptions to another device |
| Storage engine (SQLite) | **Stateful windowed correlation**: 15 signal functions as plain SQL over a time window, re-run every 15 s, deduplicated into incidents, grouped into campaigns with MITRE ATT&CK tactics, with operator suppression |
| Forwarding, NAT, firewall primitives, set timeouts (Linux, nftables) | **Explainable, time-decayed device risk** |
| Access point (hostapd) | **Policy orchestration**: one desired-state model rendered to two engines (nftables sets, the DNS filter's rules and clients), applied, read back, rolled back on mismatch (and the rollback itself read back), drift repaired every cycle, through a privilege-separated root helper |
| TLS interception engine (mitmproxy) | **Reversible response framework**: MAC-keyed timed quarantine, IP and domain blocks, per-device filtering profiles with schedules, pause, per-device and per-site HTTPS inspection, auto-response, device trust, all audited |
| Web framework (FastAPI/Starlette/uvicorn/Jinja2), Chart.js | **The device-centric SOC console**: dashboard, devices, incident workbench, hunt, filtering analytics, weekly report, settings, audit, with session auth, TLS and Origin checks |
| Threat intelligence (abuse.ch), blocklists, ET Open signatures | **Platform health supervision and fail-open behaviour**: service, staleness, disk, WAN and capture-drop checks; DNS fail-open; HTTPS inspection fail-open gate |
| Base OS (Ubuntu 24.04) | **The selective-inspection addon**: SNI-level decrypt-or-relay per device and per site, a structural JSON sweep for first-party ads, per-site rule modules, pinned-client auto-bypass, deny-by-default site scope |
| | **The privacy-scope canary**: an automated, recurring check of the addon's real decision code, with fail-safe unenrolment |
| | **The evaluation**: detection battery, PCAP replay, threshold sweeps, held-out replay, ad-blocking benchmark, chaos tests, performance and identity measurements (§6) |

The honesty of the left column is what makes the right column credible:
the project wrote no packet parser, no DNS resolver, no TLS stack and no
signature engine.

## 5. Implementation, stage by stage

| Stage | What it delivered | Key outcome | Record |
|---|---|---|---|
| Days 1-14 | The 15-day build: AP + NAT + DNS filter + IDS + ingest + 4 signals + console | Detection working end to end on 13 Sep | `SECUREPI-15-DAY-PLAN.md`, `EVALUATION-RESULTS.md` |
| 0 | Housekeeping, `make deploy`, baseline snapshot | Safe deploy loop (no `--delete`, no ownership change) | `ENHANCEMENT-PLAN.md` §8 |
| 1 | Test suite, retention, real-time DNS ingest (API instead of a file flushed every 1,000 queries), audit log, accuracy fixes, AP client isolation, Tier 2 fixes | Hours of DNS detection lag removed | `EVALUATION-RESULTS-2.md` |
| 2 | Network sweep, slow scans, DNS-bypass hardening and detection, IDS alerts with a taxonomy, threat intel, DNS tunnelling and DGA, C2 beaconing, suppression, campaigns + ATT&CK | 4 signals → 15 | same, Stage 2 |
| 3 | Session auth (PBKDF2, rate limit, Origin check), TLS console, privilege separation, security self-review, health supervisor, DNS fail-open | The web process lost root | same, Stage 3 |
| 4 | Policy orchestrator with read-back and drift repair, MAC-keyed timed quarantine, blocks, auto-response, profiles and schedules, trust, notifications | Four real bugs found by testing, none guessed | same, Stage 4 |
| 5 | Ad-blocking telemetry, unbreak workflow, analytics, list health, Tier 2 lifecycle (console enrolment, CA page, auto-expiry), privacy canary, pinning bypass, hot-reloadable rules, effectiveness watchdog, cosmetic CSS | Tier 2 became a managed product, not a script | same |
| 6 | Behavioural baselines, fingerprinting, settings, incident workbench, hunt, weekly report, responsive layout | The console reached its polish bar | same, Stage 6 |
| 7 | Evaluation 2.0 (§6); boot faults found and fixed before the freeze | Tag `stage7-final` (`33c4b0d`), 541 tests | same, Stage 7 |
| 7A | Per-site inspection modules (Instagram; Facebook partly), per-device site switches, switching that applies at once, per-client pin bypass, VPN visibility, list trim | First-party ads removed on a second site | `ADBLOCK-ENHANCEMENT-PLAN.md` |
| 7B | Remediation of an external static audit (`Audit10Oct.md`): 47 verdicts, 20 steps | Two consent and verification bugs fixed; 641 → 751 tests | `AUDIT-10OCT-PLAN.md` |
| 8 | This report, the one-command installer, the demo script, the close-out runbook | Reproducible from the docs | `STAGE8-RECORD.md` |

### 5.1 What Stage 7B changed, because it changes claims made elsewhere

An independent static audit (OpenAI Codex, 10 Oct 2026) was triaged
finding by finding against the code. 27 recommendations were accepted, 13
accepted with a different fix, 7 rejected with reasons. The fixes that
change what the rest of this report can claim:

- **Inspection scope is deny-by-default.** Before 7B, a device with no
  entry in the per-device site map fell back to YouTube. Once a device could
  be enrolled for Instagram only, a lost map meant decrypting YouTube for a
  device that never agreed to it. Now any doubt means no inspection, a site
  switched off is never rewritten even on an already-open connection, and a
  failed map write rolls the change back. Verified on the A33 through the
  real redirect.
- **Removal verification checked the wrong record.** The orchestrator
  verified removals against the ownership record that no longer listed the
  removed item, so "removed" passed even when the element stayed. Fixed, and
  rollbacks are now read back too.
- **Decrypted request URLs were in the system journal.** mitmdump's default
  `flow_detail=1` printed every decrypted request line: 5,163 lines over
  14 days. Fixed with `--set flow_detail=0`; the old lines are removed only by
  the close-out journal purge (8.4). This corrects statements in
  `REPORT-adblocking.md` §6 and §11.
- **DNS-over-QUIC (UDP 853) was not blocked.** Now rejected and logged.
- Also: firewall enforcement no longer depends on the DNS filter being up;
  DNS fail-open installs atomically and recovery removes leftovers; login
  admission is counted before the password check; the console's session
  check is off the event loop and background polls no longer keep a session
  alive; a DNS backlog beyond the page cap is caught up; one bad record can
  no longer stall a source; only current threat indicators raise incidents.

## 6. Evaluation

All figures are from the live gateway or replays of its data, on the
project's own devices, between 13 September and 10 October 2026. Attacks
ran from the isolated test harness or the project's own red-team laptop,
never against a real device.

### 6.1 Detection (7.2, 7.3, 7.4)

- **Detection battery, final code** (`gateway/battery.py`, 5 runs per signal
  type, 26 Sep 10:13): **all 15 signal types detected in 5 of 5 runs**; the
  benign host raised nothing. Median time to detect, measured from the start
  of each run: DNS-based signals 10.5-15.1 s, `new_device` 31.2 s,
  `brute_force` 77.6 s, `port_scan`/`network_sweep` 92.2 s,
  `volume_anomaly` 106.5 s, `beacon` 139.2 s, `campaign` 138.8 s,
  `slow_port_scan` 494.2 s, `slow_network_sweep` 580.5 s.
- **Offline replay agrees with live:** the battery's capture replayed on the
  Mac through Suricata and the real pipeline (`tools/replay.py`): 45 of 45
  scored runs detected and attributed correctly.
- **Precision and recall** (`tools/sweep.py`, the live database of 2 Oct
  replayed; 154 labelled positive runs; real devices as negatives): recall
  **1.00** for every signal; overall precision **0.64 → 0.91** after the 7.3
  fixes (false positives 86 → 15). The remaining weak signal,
  `malicious_domain` (precision 0.42), was retired by default.
- **Held-out false positives** (`tools/heldout_replay.py`, the Mac's 7.5
  benchmark traffic, which postdates the tuning data; 306,390 events,
  3.05 device-hours): **126 → 22 → 14** false-positive incidents (original →
  7.3 → frozen engine), 0.46 per 10,000 events (95% CI 0.25-0.77). The 22
  match what the live engine raised that evening exactly.
- **Behavioural signals vs signatures** (`tools/headline.py`): of 53 scan,
  sweep and brute-force runs from inside the LAN, **the IDS's own signatures
  alerted on 0; the behavioural signals detected 53.** ET Open's 274 scan
  rules are written for outside attackers.
- **Beacon jitter:** detected up to 45% timing jitter with constant-size
  check-ins and 35% when size varies too; common C2 defaults (0-30%) are
  caught either way.
- **Reduction (ablation, live database replayed at the live 15 s cycle):**
  attack devices 32,044 signal firings → 160 incidents (**200 : 1**) → 70
  after campaign grouping; real devices 1,082 → 23 (**47 : 1**). Day 14's
  differently defined ratio (raw events ÷ incidents over a clean 24 h) was
  1,588 : 1 (`EVALUATION-RESULTS.md` §2).

### 6.2 Response and orchestration

- Quarantine applies and is read back; ending it removes the element; timed
  policies get a kernel timeout as a backstop (unit tests and live checks,
  Stage 4 and 7B).
- **With the DNS filter down for 60 s (7B, live):** a quarantine still
  applied and verified; only the DNS-side domains reported errors, and an
  enforcement incident was raised.
- Drift (an element removed by hand) is put back and recorded as an
  incident (Stage 4, live).

### 6.3 Resilience (7.7, 7B)

| Fault | Back after | What a device saw |
|---|---|---|
| IDS killed | <1 s (events 25 s, rule reload) | nothing |
| Ingest killed | 5.1 s | nothing |
| Engine killed | 5.1 s | nothing |
| DNS filter killed | 10.2 s | 2 failed lookups |
| DNS filter stopped 60 s | fail-open on at +15.5 s, off at +62.4 s; repeated in 7B: on at +18 s, off at +61 s, 0 leftover rules | lookups failed ~13 s, then resolved (unfiltered) for the rest |
| Inspection proxy killed | 6.1 s; gate closed within 1 s | 0 HTTPS failures (traffic went out undecrypted) |
| Disk at 8% free | incident at 6.9 s | nothing |
| Uplink cut 120 s | incident at 16.4 s | no internet (expected), back at once |
| Upstream DNS only (DoT) blocked 75 s (7.0) | fail-open correctly did **not** engage | filtering stayed on |

Reliability over 12 Sep - 3 Oct: 17 boots, all clean shutdowns; every unit
failure explained (deliberate chaos, development, a fixed boot race, and the
"database is locked" family fixed before the freeze); privacy canary 265
checks, 0 failures. On 10 Oct the gateway ran its battery flat and powered
off cleanly (`systemd-shutdown`); after power returned every service, the
database (`PRAGMA quick_check: ok`) and the canary came back without help.

### 6.4 Ad blocking (7.5, 7A, 7B; full chapter in `REPORT-adblocking.md`)

- **Third-party (Tier 1, DNS), 240 page loads of 20 ad-heavy sites:**
  requests **−83%**, third-party requests −93%, bytes −58%, tracker
  companies **971 → 9 (−99%)**, median onLoad 3.9 s → 1.5 s; pages that
  never finished loading 19/60 → 0/60. It matched uBlock Origin Lite on
  requests and beat it on bytes and tracker companies (9 vs 41).
- **Breakage:** 0 of 48 real top-50 sites (95% Wilson interval 0-7.4%).
- **List utility:** HaGeZi Pro carries almost all unique blocking (21-25%
  of blocked household queries are caught by it alone); OISD Big and AdAway
  together added 0.6% and were dropped, cutting the DNS filter's memory from
  271 to 187 MB. The tool agrees with the filter's own decisions on 97.9% of
  blocks and 99.7% of allows.
- **DNS latency:** cold lookups p50 47 ms / p95 281 ms with the 5.5 tuning
  (vs the ISP resolver's 61 / 894 ms); 91% of answers come from cache.
- **First-party (Tier 2, HTTPS inspection):** YouTube pre-rolls in mobile
  Chrome **30/30 → 0/29** (7.5) and **10/10 → 0/30** (7A, A33), **0/10** again
  on the final 7B code; Instagram web feed ads 10/10 → 0/10 runs (Dell test
  browser) and **4/6 → 0/6** on the A33, 3/3 → 0/3 on the 7B code; Facebook
  partial (scroll-loaded ads 5 → 0; two page-embedded ad units stay).
- **In-app ad networks (Tier 1):** an AdMob banner shown 6/6 runs off,
  0/5 on (one app).
- **Bypass matrix:** DoH to known and lesser-known resolvers, Firefox's DoH
  roll-out, Chrome Secure DNS, Android Private DNS (strict) and iCloud
  Private Relay are all blocked and, except a provider name that simply
  doesn't resolve, detected. DNS-over-QUIC is blocked and logged since 7B.
  **VPNs** are not blocked; since 7A a WireGuard/OpenVPN-shaped flow raises
  an informational `vpn_tunnel` flag.
- **Privacy scope:** 0 unexpected decryptions in every scope check (tablet
  9 Oct, A33 10 Oct); 0 non-allowlisted hosts decrypted after the
  `ignore_conn` fix (it was 95 before; `REPORT-adblocking.md` §6).
- **Cost of Tier 2:** the browser's TLS handshake to a decrypted host is
  shorter (it ends at the gateway, −37 ms p50), with a +109 ms p95 tail in
  time to first byte; passthrough adds about 40 ms p50; proxy memory 72 MB
  idle, 116-221 MB while decrypting video.

### 6.5 Performance and storage (7.0, 7.8)

- **Capture:** no kernel drops up to 400 Mbit/s on one capture thread at a
  third of a core, far above what the 2.4 GHz AP carries; one thread
  saturates at 6.0 Gbit/s on the virtual link (85% drops).
- **Ingest lag p95:** about 4 s per source in normal and heavy use; 15.7 s
  for the IDS during a 245,000-alert flood.
- **Memory, peak per service under heavy real browsing (2 Oct):** IDS
  871 MB, DNS filter 365 MB, console 294 MB, ingest 216 MB; in normal
  running 629 / 306 / 311 / 74 MB. System total on 10 Oct 13:15: 1,475 of
  3,683 MiB used.
- **Storage:** about 414 bytes per event all-in; one device at 8,000
  events/day levels off at about 80 MB under retention (flow/TLS 14 days,
  the rest 30).
- **Console latency:** most API calls 40-400 ms; the 24 h and 7 d dashboard
  aggregates reach about 1 s on a day with 337,000 events (they scan the
  window; precomputing from rollups is future work).

### 6.6 Identity (7.6)

5 of 5 physical devices are exactly one registry record each; every event
from their addresses went to the right device; OS fingerprint 5/5, category
3/5 and vendor 2/5 (the rest "unknown", none wrong). Presence was wrong for
devices that had left until it was tied to Wi-Fi association (fixed 3 Oct).

### 6.7 Usability (7.9, replaced)

An expert review (heuristic evaluation, cognitive walkthrough, scripted
expert paths with KLM times, an axe-core WCAG audit): all six study tasks
reachable in 1-5 clicks (4.0-20.7 s KLM); top findings: risk not shown on
the Devices list, device rows not keyboard-reachable, dark-theme contrast.
**Not established:** a System Usability Scale score or real success rates;
the participant kit is ready (`docs/usability-study/`).

### 6.8 What the evaluation does not establish

- No multi-day unattended run of the final code (the seven-day run was
  replaced by a one-session evaluation; a planned soak was dropped).
- The false-positive rate rests on one device's scripted browsing for
  3 hours; household projections assume 8,000 events per device-day.
- Tier 2 results are from two Android phones' Chrome and one Linux
  browser; iOS was never tested.

## 7. Deviations from the plan (final)

`ENHANCEMENT-PLAN.md` §1 recorded each cut of the 15-day plan and the
decision taken on 13 September. Final outcome, 10 October 2026:

### 7.1 Technology

| Area | Feasibility (38 weeks) | 15-day plan | As built (final) | Why |
|---|---|---|---|---|
| Storage | PostgreSQL + TimescaleDB | SQLite | SQLite WAL + own retention job and hourly rollups | RAM; measured volume |
| Frontend | React + TS + ECharts, WebSocket | Jinja2 + HTMX | Jinja2 + vanilla JS + Chart.js, polling | Met the UI bar without a build step |
| Deployment | Docker Compose | systemd | systemd + `gateway/install.sh` (8.2) | RAM; containers gave no isolation with host networking |
| OS | Debian | Debian → Ubuntu | Ubuntu Server 24.04 | Dell hardware support |
| Topology | Wired WAN, switch + dumb AP with isolation | same | One radio: Wi-Fi station uplink + hostapd AP, `ap_isolate=1` | No spare AP or switch; isolation restored in 1.7 |
| Event sources | IDS, DNS filter, nftables log | IDS, DNS filter | IDS, DNS filter **API**, DPI telemetry, nftables log | Restored in 1.4, 2.2, 5.1 |

### 7.2 Features cut by the 15-day plan

| Feature | Final status |
|---|---|
| Policy orchestration with rollback and drift detection | Built (4.1), verification hardened in 7B |
| TLS console | Built (3.2) |
| C2 beaconing | Built (2.6) |
| DoH bypass detection and blocking | Built (1.8, 2.2), DoQ added in 7B |
| Behavioural baselines | Built (6.1) |
| MAC-randomisation identity heuristics | Built (6.2), merge narrowed in 7B |
| Notifications | Built (4.5) |
| PCAP replay | Built (7.1) |
| Three-week evaluation campaign | Stage 7, one-session form (7.0 replaced) |
| Chaos testing | Built (7.7) |
| Retention and rollups | Built (1.3, 6.1) |
| Usability study (5-8 people) | **Replaced** by an expert review (7.9); kit ready |
| Seven-day continuous run | **Replaced** by a one-session evaluation (7.0) |
| Raspberry Pi second sensor | Not built (stretch S.1) |

### 7.3 Beyond the original plan

| Addition | Note |
|---|---|
| Selective HTTPS inspection (Tier 2) | Feasibility listed TLS interception as "will not do". Built with strict limits: per-device opt-in, per-site allowlist, off after every reboot, deny-by-default scope, fail-open, a recurring privacy canary. The deviation is explained in `REPORT-adblocking.md` |
| Per-site inspection modules (7A) | Instagram and Facebook, each after its own written privacy review |
| Structural JSON sweep | Beat uBlock Origin's endpoint rules on mobile YouTube (`REPORT-adblocking.md` §5) |
| An external audit and its remediation (7B) | 47 verdicts, 20 steps, all verified live |
| IPv6 link-local MAC recovery for identity | Reported in 6.6 |

### 7.4 Stage 8 itself

- **8.1:** this report. The six 7.9 usability recommendations were queued
  for Stage 8 in `NEXT-SESSION.md`, but the plan's Stage 8 table has no such
  step and the user decided (10 Oct) to leave 7.9 as it is; they are future
  scope (§9).
- **8.2:** the installer and pinned requirements; `docs/INSTALL.md`.
- **8.3:** `docs/DEMO.md`.
- **8.4:** the close-out runbook (`docs/CLOSE-OUT.md`), executed only on the
  user's confirmation.

## 8. Limitations

**Detection**
- The final code has not run unattended for days; slow leaks or faults past
  one day are untested.
- Residual false positives on ordinary traffic: `beacon` on periodic app
  traffic (Google push 5228, STUN 3478, port-80 checks), `dga` on short ad
  domains and reverse lookups, `network_sweep` on unanswered ad servers.
- A beacon with ≥40% jitter and varying size escapes `beacon`.
- IDS rules were downloaded once (12 Sep) and are not updated on a schedule.

**Filtering and inspection**
- VPNs bypass filtering; they are flagged, not blocked.
- Tier 2 reaches browsers only: apps pin their certificates, and Android 7+
  apps don't trust user CAs. Pinned apps are passed through after failed
  handshakes and keep their ads.
- Server-side ad insertion would end first-party removal entirely; the
  effectiveness watchdog reports it rather than hiding it.
- A device with Instagram or Facebook switched on has that site's own host
  decrypted, inbox list and login included, in the proxy's memory.
- QUIC is rejected network-wide to keep traffic observable.
- Decrypted request URLs were written to the journal until 10 Oct (§5.1);
  removed only by the close-out purge.

**Platform**
- IPv4 only: IPv6 is not forwarded (and so not filtered or monitored
  beyond link-local identity).
- One radio: the AP must share the uplink's channel; a 5 GHz-only uplink
  cannot work.
- Single host, no high availability; the gateway is a laptop on battery
  when unplugged.
- Console aggregates slow to about 1 s on very busy days.

**Evaluation**
- One evaluator for usability; no SUS.
- Small device population (two phones, a tablet, laptops).

## 9. Future scope

| Item | Why it matters | Starting point |
|---|---|---|
| Multi-day unattended run of the final code | The one claim Stage 7 could not make | `gateway/collect_run.sh mark|collect`, the run monitor |
| Participant usability study (5-8 people) | SUS and real success rates | `docs/usability-study/` |
| The six 7.9 recommendations | Contrast, Devices-list risk column, keyboard reachability, persistent domain-test result, console dialog instead of `prompt()` | `docs/usability-study/heuristic-evaluation.md` |
| Scheduled IDS rule updates | Rules are a month old | a `suricata-update` timer |
| Detection precision on ordinary traffic | The held-out residuals above | `tools/heldout_replay.py`, a popular-domain allowlist for `dga` |
| VPN policy (block or require per device) | VPNs are the remaining bypass | `vpn_tunnel` already detects |
| Dashboard aggregates from hourly rollups | 1 s refreshes on busy days | `device_hourly` |
| IPv6 forwarding with parity rules | Feasibility listed it as a v1 limitation | `nftables.conf` already uses an `inet` table |
| Raspberry Pi as a second sensor (S.1) | Proves the ingest layer is sensor-agnostic | ingest's per-source readers |
| Network map, offline GeoIP/ASN (S.2) | Context for incidents | — |
| WireGuard remote access to the console (S.4) | Off-site administration | — |
| Further inspection modules (S.5) | Each only after its own written privacy review | `dpi/adfilter-rules.json` modules |
| Scriptlet injection (5.11 Path 2) | Narrow gain, real breakage risk | deferred, recorded in `ENHANCEMENT-PLAN.md` |
| Encrypted Client Hello | Will hide SNI from both the IDS and the inspection decision | track |

## 10. Appendix: reproducing every figure

Results files are committed under `eval/results/`. Inputs that contain
real household traffic (database copies, captures) are **not** committed
(`.gitignore`): to re-run a replay, take a fresh copy of the live database
first, for example

```
ssh maheshwari@192.168.2.5 'sudo python3 -c "import sqlite3; s=sqlite3.connect(\"/var/lib/securepi/securepi.db\"); d=sqlite3.connect(\"/tmp/live.db\"); s.backup(d)"'
scp maheshwari@192.168.2.5:/tmp/live.db eval/bench-data/live.db
ssh maheshwari@192.168.2.5 'sudo rm -f /tmp/live.db'
```

The original copies (`live-20261002.db`, `securepi-start.db`) were not
kept, so re-runs on a new copy reproduce the method, not the identical
numbers.

| Figure | Command (from the repository root unless it says "on the gateway") | Result file |
|---|---|---|
| Detection battery, TTD (6.1) | on the gateway: `sudo systemd-run --unit securepi-battery --collect /usr/bin/python3 -u /opt/securepi-eval/battery.py --runs 5` | `eval/results/battery-20260926-101333.json` |
| Battery replay on the Mac | `python3 tools/replay.py <battery pcap> <labels json>` (needs a local Suricata 7 and `eval/rules/`) | `eval/results/replay-battery-20260926-101333.json` |
| Precision / recall (6.1) | `python3 tools/sweep.py eval/bench-data/live.db --battery eval/results/battery-20260926-054306.json --battery eval/results/battery-20260926-101333.json --negative-device 1 --negative-device 2 --negative-device 13 --exclude 2:2026-09-26T07:00:00:2026-09-26T10:00:00 --exclude 2:2026-10-02T16:30:00:2026-10-02T18:00:00 --attack 13:port_scan,slow_port_scan,brute_force,beacon:2026-09-15T14:20:00:2026-09-15T15:45:00` | `eval/results/sweep-20261002-final.json` |
| Signatures vs signals, jitter, ablation (6.1) | `python3 tools/headline.py eval/bench-data/live.db` with the same `--battery/--attack/--exclude/--negative-device` and `--sweep-result eval/results/sweep-20261002-final.json` | `eval/results/headline-20261002.json` |
| Held-out false positives (6.1) | `python3 tools/heldout_replay.py eval/bench-data/live.db --device 99 --start 2026-10-02T18:20:00 --end 2026-10-02T21:35:00 --reference-events-per-day 8000 --live-incidents` | `eval/results/heldout-replay-20261003-final-engine.json` |
| Chaos (6.3) | on the gateway: `sudo python3 /opt/securepi-eval/chaos.py <kill-ids|kill-dns|kill-ingest|kill-engine|kill-proxy|stop-dns|fill-disk|drop-wan>`; device side `tools/chaos_phone_probe.sh` | `eval/results/chaos/` |
| Ad-blocking benchmark (6.4) | `tools/bench_run.sh <device id> <client ip> eval/results/bench` (Mac on SecurePi-Test, `.venv-bench`) | `eval/results/bench/summary.json` |
| Breakage top 50 | `tools/breakage_run.sh` | `eval/results/bench/top50_*.jsonl` |
| List utility | `python3 tools/blocklist_utility.py --workdir eval/bench-data/listutil --days 7 --exclude-device 99` | `eval/results/blocklist-utility-20261002-210900.json` |
| DNS latency A/B | `scp gateway/dns_ab.py eval/dns-latency-domains.txt maheshwari@192.168.2.5:/tmp/`, then on the gateway: `sudo -u securepi-web python3 /tmp/dns_ab.py /tmp/dns-latency-domains.txt /tmp/dns-ab.json`. It temporarily applies and then restores the resolver configuration through the DNS filter's API; its ISP resolver is hard-coded as the home router `192.168.29.1` (change `ISP` on another network). Since 3 Oct the tuned configuration is the live one, so its "current" and "tuned" passes now measure the same thing | `eval/results/dns-latency-ab-20261002.json` |
| YouTube Tier 2 | `tools/youtube_tier2.sh` (A33 over adb) | `eval/results/youtube*/` |
| Instagram / Facebook | `tools/site_ads_measure.py <instagram|facebook> <out> --runs N` (Dell test browser) | `eval/results/sites/` |
| Scope check | `python3 tools/scope_check_device.py <out> --device-id <id> --serial <adb serial>` | `eval/results/scope-check/` |
| Bypass matrix | `tools/bypass_doh.sh`, `tools/bypass_private_dns.sh`, `python3 tools/bypass_vpn.py` | `eval/results/bypass-*` |
| Throughput | on the gateway: `sudo python3 /opt/securepi-eval/throughput_sweep.py --seconds 20` | `eval/results/throughput-sweep-20261002.json` |
| Console latency | `scp gateway/dash_latency.py maheshwari@192.168.2.5:/tmp/`, then on the gateway: `sudo python3 /tmp/dash_latency.py /tmp/dash-latency.json`. It creates a session with the app's own code for the run (15 requests per endpoint) | `eval/results/dash-latency-idle-20261002.json` |
| Expert paths, axe audit | `python3 tools/usability_expert.py paths <out>`; `python3 tools/usability_expert.py axe <out> --axe <axe.min.js>` (demo console) | `eval/results/usability/` |
| 7B live checks | the commands are recorded step by step in `AUDIT-10OCT-PLAN.md`, Progress | — |

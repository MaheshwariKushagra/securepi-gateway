# SecurePi Gateway — Master Enhancement Plan

**Status:** active plan, replaces the forward schedule of both earlier plans
**Written:** 13 September 2026, after Day 14 (Day 15 is paused)
**Revision 2:** adds a dedicated ad-blocking and privacy-filtering stage (Stage 5) and early ad-blocking fixes (steps 1.8, 2.2). Later stages are renumbered.

**Lineage:**

| Document | Role now |
|---|---|
| Feasibility study & 38-week roadmap (`~/.claude/plans/project-securepi-gateway-crispy-lerdorf.md`, to be archived into `docs/` in step 0.1) | The original full scope. Still the reference for architecture reasoning and the report |
| `SECUREPI-15-DAY-PLAN.md` | The compressed build. Finished through Day 14 |
| `REPORT-adblocking.md`, `FIRST-PARTY-ADS-ANALYSIS.md` | Ad-blocking design, results and the first-party boundary analysis |
| **This document** | What we build next, and in what order |

---

## How to follow this plan

1. **Work through the stages in order, and the steps inside each stage in order.** Later steps assume earlier ones are done.
2. **A step is finished only when all of these are true:**
   - its exit criteria pass,
   - tests pass on the Mac,
   - it's deployed and verified on the gateway,
   - there's a short plain-language write-up of what went in and why,
   - any results are appended to `EVALUATION-RESULTS-2.md`,
   - the tracker in §8 is updated and the work is committed.
3. **Cut lines** mark where stopping still leaves a coherent, stronger project than today.
4. **Standing constraints (unchanged):**
   - The gateway has 3.6 GiB RAM.
   - Code stays plain, readable Python: sync, hand-written SQL, lots of comments.
   - Development happens on the Mac. The Dell is only a deployment target.
   - Everything runs locally, metadata only. No cloud dependency.
   - HTTPS inspection stays opt-in, narrowly scoped and verified.

---

## 1. What the 15-day plan cut, and where each cut stands now

The 15-day plan was about 1/25th of the 38-week schedule. It kept the concept and
architecture and cut breadth. This section lists each reduction, checks it against
the code as built, and decides whether it comes back.

### 1.1 Technology substitutions

| Area | Feasibility (38 wk) | 15-day plan | Actually built | **Decision now** | Why |
|---|---|---|---|---|---|
| Storage | PostgreSQL + TimescaleDB (compression, retention, continuous aggregates) | SQLite WAL | SQLite WAL | **Keep SQLite.** Restore the missing *functions* ourselves: a retention job and an hourly rollup table (1.3) | PostgreSQL would cost about 1 GB of RAM on a 3.6 GiB host. Measured volume is about 16k events/day |
| Frontend | React + TS + Vite + ECharts, WebSocket push | FastAPI + Jinja2 + HTMX + Chart.js | Jinja2 + vanilla JS + Chart.js, polling | **Keep** | Already meets the polish bar. A rewrite adds risk and no capability |
| Deployment | Docker Compose + provisioned host | Native systemd | Native systemd, reboot-verified | **Keep.** Add a one-command installer (8.2) | RAM, and containers gave no isolation with host networking |
| OS | Debian stable | Debian 13 → Ubuntu 24.04 | Ubuntu Server 24.04 | **Keep** | Hardware support on the Dell |
| Detection source | Suricata + ET Open + our correlation | Suricata metadata + curated rules | Metadata only. **Alerts ingested but never used** | **Partly restore:** alerts become incidents (2.3) | Promised in feasibility §9.6 |
| Topology | Wired WAN, switch + dumb AP **with client isolation** | Same | One radio: station uplink + hostapd AP. **No `ap_isolate`** | **Keep the topology. Enable client isolation** (1.7) | Otherwise phone-to-phone traffic is invisible (feasibility R9) |
| Event sources | Suricata, AdGuard DNS + DHCP, **nftables log** | Suricata, AdGuard | Suricata, AdGuard query log **file**, DHCP leases | **Restore the nftables log source** (2.2). **Replace file tailing with the AdGuard API** (1.4). **Add HTTPS-proxy telemetry** (5.1) | The file flush caused hours of DNS detection lag (EVAL §1) |

### 1.2 Explicit cuts (15-day plan §4 "OUT" list)

| Cut feature | Status in current code | **Decision** | Step |
|---|---|---|---|
| Policy orchestration with validation, rollback, drift detection | Missing | **Restore (lite version)** | 4.1 |
| TLS on the console | Missing | **Restore** | 3.2 |
| C2 beaconing detection | Missing | **Restore** | 2.6 |
| DoH bypass detection and blocking | Blocking partly built (port-53 DNAT, DoH/DoT to 14 known IPs, QUIC reject). Detection missing | **Restore detection and harden blocking** | 1.8, 2.2 |
| Behavioural baselines | Missing | **Restore** | 6.1 |
| MAC-randomization identity heuristics | Partly built (hostname anchor, randomized-bit flag, IPv6 link-local MAC recovery) | **Restore the rest** | 6.2 |
| Notifications | Missing | **Restore** | 4.5 |
| PCAP-replay test infrastructure | Missing (namespace harness used instead) | **Restore** | 1.1, 7.1 |
| Usability study | Missing | **Restore** | 7.9 |
| Three-week evaluation campaign | One afternoon | **Restore as Stage 7** | 7.x |
| Chaos / failure testing | Reboot test only | **Restore** | 7.7 |
| Tiered retention, continuous aggregates | Missing | **Restore** (retention job + rollup table) | 1.3 |
| Raspberry Pi as second sensor | Missing | **Stretch only** | S.1 |

### 1.3 Smaller reductions that weren't on the OUT list

| Original intent (feasibility section) | What shipped | **Decision** | Step |
|---|---|---|---|
| 6–8 signals incl. network sweep, slow scan, DNS tunnelling, DGA, beaconing, bypass, volume anomaly (§12.3) | 4 signals | **Restore all** + IDS alerts + threat intel | 2.1–2.6, 6.1 |
| Incidents grouped by **kill-chain phase** (§12.3) | Device + signal only | **Restore as campaigns + ATT&CK** | 2.8 |
| Five console views incl. **Settings** (§9.5) | Four views | **Restore** | 6.3 |
| Audit log (§11.1) | Missing | **Restore** | 1.5 |
| Hashed passwords, sessions, rate-limited login (§11.1) | Basic Auth | **Restore** | 3.1 |
| Privilege-separated nftables helper (§11.1) | Web app calls `nft` directly | **Restore** | 3.3 |
| Fail-open DNS (§8.4) | Missing | **Restore** | 3.6 |
| Sensor-silence alerts, drop counters, disk watchdog (§5.5, §8.4) | Pipeline panel only | **Restore** | 3.5 |
| **Filtering §9.3:** per-group profiles, temporary bypass, allow/deny **with rationale** | Per-device on/off, global custom rules | **Restore** | 4.3, 5.2 |
| **Filtering §9.3:** block statistics & **bandwidth-saved estimate** | None | **Restore** | 5.3 |
| **Filtering §9.3:** DoH/DoT bypass detection | None | **Restore** | 2.2 |
| **Filtering §9.3:** encrypted upstream (DoT) | **Done** (DoT to 1.1.1.1) | Extend with resilient upstreams | 5.5 |
| **Filtering §9.3:** scheduled blocklist updates | AdGuard 24 h interval, no failure visibility | **Add list health monitoring** | 5.4 |
| Block domain/IP response (§9.4) | Quarantine only, keyed on IP | **Restore** | 4.2 |
| Top talkers, protocol breakdown, uplink health (§9.2) | Partial | **Restore** | 6.5, 3.5 |
| Signature taxonomy, OSS attributions page (§9.6) | Missing | **Restore** | 2.3, 6.3 |
| Identity-accuracy measurement (§14 Ph4) | Never measured | **Restore** | 7.6 |
| Precision/recall, slow-scan advantage, TTD p95 (§17.3) | Detection rate + mean TTD | **Restore** | 7.2–7.4 |
| **Filtering metrics (§17.3):** request reduction, page-load delta, DNS latency, DoH bypass attempts | Only 10-domain block test | **Restore + expand** | 7.5 |
| Demo scenarios 4, 5, 7, 11, 12 (§15.3) | Not possible yet | **Enabled by Stages 2–3** | 8.3 |
| One-command deployment (§14 Ph11) | Runbooks only | **Restore** | 8.2 |

### 1.4 Where the build went *beyond* the original plan

| Addition | Note for the plan |
|---|---|
| **Selective HTTPS inspection** for YouTube first-party ad removal (`dpi/`) | Feasibility listed TLS interception as **WILL NOT DO**. We built it with strict limits (SNI allowlist, per-device opt-in, off after reboot), and it works in the browser. **Keep it and harden it in Stage 5** (console enrollment, short-lived CA, automatic scope verification, graceful handling of pinned apps, testable rules). **Don't widen it by default.** The report must explain the deviation |
| Structural JSON sweep beat uBO's endpoint rules (the `/get_watch` finding) | A real engineering result. Stage 5 turns it into a tested, hot-reloadable rule set |
| Reboot-safe namespace attack harness | Reused in Stage 7 |
| Console polish (command palette, notifications, heatmap) | Sets the UI bar for new pages |
| Identity through IPv6 link-local MAC recovery | Worth describing in the report |

### 1.5 Still excluded (reconfirmed)

| Excluded | Reason |
|---|---|
| Zeek, ELK/OpenSearch, Wazuh manager, PostgreSQL, Docker | Each costs roughly 1–4 GB RAM on a 3.6 GiB host |
| Suricata IPS mode as default | Latency and false-positive outage risk |
| ML / deep-learning detection | Can't be validated at this data volume |
| Cloud LLM incident summaries | Sends telemetry off-box |
| **HTTPS inspection for all traffic, or on by default** | Privacy, pinning, and it breaks apps. Stays per-device opt-in and per-host allowlisted |
| **Removing YouTube server-side-inserted (SSAI) ads** | When SSAI is active the ad is stitched into the video stream, so there's no JSON left to prune. Documented as the expected end-state boundary. We detect it (5.10) and don't try to defeat it |
| **In-video sponsor skipping (SponsorBlock-style)** | Needs client-side playback control. Not reachable from the network |
| **Porting a full uBO/adblock-rust URL engine to the gateway** | Only useful on decrypted traffic, which we deliberately limit. DNS lists already cover third-party ads |
| **DNS "block page" for HTTPS sites** | Causes certificate errors on every blocked HTTPS domain |
| Host agents, HA, multi-site, compliance, mobile app, React rewrite | Feasibility §13.4 reasoning |
| Full IPv6 policy, Encrypted Client Hello handling, captive portal, WireGuard | Future scope (1.8 still adds an IPv6 bypass guard) |

---

## 2. Market analysis

### 2.1 Security and monitoring platforms

| Category | Platforms | Relevant strengths |
|---|---|---|
| Prosumer security firewalls | Firewalla, UniFi + CyberSecure | Device-centric UI, IDS/IPS, ~7-day behaviour learning, new-device quarantine, per-device schedules, push alerts |
| Open-source NGFW | OPNsense/pfSense + Suricata + Zenarmor | Signature IPS, app control, trusted/untrusted device access control, reporting |
| NSM / SOC | Security Onion, Malcolm, Wazuh | Alert queue, cases, detection tuning, playbooks, hunting |
| Traffic analytics | ntopng | Flow risks, explainable host score, behavioural checks, periodicity, alert endpoints |
| C2 hunting | Zeek + RITA | Beacon scoring from timing/size distributions, DNS subdomain analysis |

| Capability | Firewalla | UniFi+CS | OPNsense+Zen | SecOnion | ntopng | RITA | **SecurePi now** | Step |
|---|---|---|---|---|---|---|---|---|
| IDS alerts surfaced | ✓ | ✓ | ✓ | ✓ | ◐ | ✗ | **◐** | 2.3 |
| Behavioural / anomaly detection | ✓ | ◐ | ◐ | ◐ | ✓ | ✓ | **◐** | 2.x, 6.1 |
| C2 beaconing | ◐ | ✗ | ✗ | ◐ | ◐ | ✓ | **✗** | 2.6 |
| DNS tunnelling / DGA | ◐ | ✗ | ✗ | ◐ | ✓ | ✓ | **✗** | 2.5 |
| Threat-intel IOC matching | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | **◐** | 2.4 |
| Device type fingerprinting | ✓ | ✓ | ✓ | ✗ | ◐ | ✗ | **◐** | 6.2 |
| New-device approval | ✓ | ◐ | ✓ | ✗ | ✗ | ✗ | **◐** | 4.4 |
| Incident correlation + evidence | ◐ | ✗ | ✗ | ✓ | ◐ | ✗ | **✓ ahead** | 2.8 |
| Explainable risk score | ✗ | ✗ | ✗ | ◐ | ✓ | ✓ | **✓ ahead** | — |
| Timed / automated response | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | **◐** | 4.2 |
| Notifications | ✓ | ✓ | ◐ | ◐ | ✓ | ✗ | **✗** | 4.5 |
| Hunt / search | ◐ | ✗ | ◐ | ✓ | ✓ | ◐ | **◐** | 6.5 |
| Platform + WAN health | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | **◐** | 3.5 |
| Hardened admin (TLS, sessions, audit) | ✓ | ✓ | ✓ | ✓ | ✓ | n/a | **◐** | 1.5, 3.1–3.3 |
| Data retention | ◐ | ◐ | ✓ | ✓ | ✓ | ✓ | **✗** | 1.3 |
| Identity across MAC randomization | ◐ | ◐ | ✗ | ✗ | ✗ | ✗ | **✓ ahead** | 6.2 |

### 2.2 Ad-blocking and privacy filtering

| Product | Layer | Relevant strengths |
|---|---|---|
| **AdGuard Home** (our engine) | Network DNS | Blocklists, persistent clients by IP/MAC/ClientID, blocked services with schedules, CNAME/response inspection, check-host API, safe search, DoT/DoH upstreams |
| **Pi-hole v6** | Network DNS | Groups, regex, CNAME deep inspection, strong per-client analytics |
| **NextDNS** | Cloud DNS | Profiles, "block bypass methods", native tracking protection per vendor (Apple, Samsung, Xiaomi, Windows…), recreation-time schedules, company/destination analytics |
| **Firewalla** | Network box | Per-device ad block, schedules, pause, app blocking, unbreak workflow in app |
| **HaGeZi lists** | Blocklists | Tiered ad/tracker lists, native device tracker lists, DoH/VPN/TOR/proxy bypass list, threat-intel (TIF) list |
| **uBlock Origin** | In browser | URL filtering, cosmetic filtering, scriptlets (e.g. `json-prune`). The reference for first-party ads |
| **AdGuard apps (desktop/Android)** | On-device HTTPS filtering | Decrypts locally and injects cosmetic CSS + scriptlets into HTML, excludes pinned apps automatically |

| Capability | AdGuard Home | Pi-hole v6 | NextDNS | Firewalla | uBO (browser) | AdGuard apps | **SecurePi now** | Step |
|---|---|---|---|---|---|---|---|---|
| Third-party ad/tracker DNS blocking | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | **✓** 655,974 rules, 100% on test set | — |
| Per-device profiles, schedules, pause | ✓ | ◐ | ✓ | ✓ | ◐ | ◐ | **◐** on/off per device | 4.3 |
| Blocked services (TikTok, gaming…) | ✓ | ◐ | ✓ | ✓ | ✗ | ◐ | **✗** | 4.3 |
| Policy follows device across IP change | ✓ (MAC ids) | ◐ | n/a | ✓ | n/a | n/a | **✗** keyed on IP | 1.8 |
| Bypass prevention (DoT/DoH/Private Relay/canary/VPN) | ◐ | ◐ | ✓ | ✓ | n/a | n/a | **◐** 14 static IPs, port 53 DNAT | 1.8, 2.2 |
| CNAME-cloaked tracker visibility | ✓ | ✓ | ✓ | ◐ | ✓ | ✓ | **◐** engine does it, never surfaced | 5.5 |
| Native device telemetry blocking | ◐ | ◐ | ✓ | ◐ | ✗ | ◐ | **✗** | 5.5 |
| "Why was this blocked?" / test a domain | ✓ | ✓ | ✓ | ◐ | ✓ | ✓ | **✗** | 5.2 |
| Unbreak: one-click per-device allow | ◐ | ◐ | ✓ | ✓ | ✓ | ✓ | **◐** global rules only | 5.2 |
| Analytics: trends, per device, by company, savings | ◐ | ✓ | ✓ | ✓ | ◐ | ✓ | **◐** query-log search only | 5.3 |
| Blocklist health & contribution | ◐ | ◐ | n/a | n/a | ◐ | ◐ | **✗** | 5.4 |
| First-party ad removal (in-stream JSON) | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ | **✓ ahead** YouTube, enrolled browser | 5.6–5.10 |
| Cosmetic filtering / scriptlets | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ | **✗** | 5.11 |
| Graceful handling of pinned apps | n/a | n/a | n/a | n/a | n/a | ✓ | **✗** app breaks | 5.8 |
| Interception scope verified automatically | n/a | n/a | n/a | n/a | n/a | ✗ | **◐** manual only | 5.7 **unique** |

**What this shows:** no network product in this group removes first-party ads at all. We do, for opt-in browser devices, and the report documents that the privacy scope was measured. Where we're behind is the *everyday product experience*: profiles, unbreak, "why blocked", analytics, native tracker lists and bypass hardening. Tier 2 also still depends on CLI steps and manual verification.

---

## 3. Review findings folded into the plan

### 3.1 Code review — security core
| # | Finding | Step |
|---|---|---|
| G1 | Signal 1 is called "horizontal" but detects many ports on **one** host, which is a *vertical* scan by standard terms | 1.6 |
| G2 | `raise_incident()` only merges into `status='new'`, so an "investigating" incident gets duplicated | 1.6 |
| G3 | Malicious-domain false positive from Android ad-SDK chatter | 1.6 |
| G4 | DNS ingest tails `querylog.json`, which AdGuard flushes only when its buffer fills (hours) | 1.4 |
| G5 | Quarantine keyed on IP, so a DHCP renewal escapes it | 4.2 |
| G6 | No tie-break for overlapping `device_ips` intervals | 1.6 |
| G7 | No automated tests | 1.1 |
| G8 | `hostapd.conf` has no `ap_isolate=1` | 1.7 |
| G9 | Web app runs `nft` itself, so it has root-level reach | 3.3 |
| G10 | Nothing deletes rows, so the DB grows without bound | 1.3 |

### 3.2 Code review — ad blocking
| # | Finding | Where | Step |
|---|---|---|---|
| A1 | `deploy-dpi.sh` creates `enrolled` in `inet filter`, but the redirect rule lives in `ip nat`, and the script prints enroll commands for the wrong table. `nftables.conf` already notes sets are per-table. Re-running the script could leave a broken or duplicate setup | `dpi/deploy-dpi.sh` step 4 | 1.8 |
| A2 | `securepi enroll` with no argument enrolls **every lease**. Any device without the CA then loses YouTube over HTTPS | `gateway/securepi` | 1.8 |
| A3 | Per-device AdGuard clients are keyed on **IP**, so policy is lost on lease change. AdGuard (which is also our DHCP server) supports MAC identifiers | `app/adguard.py` `set_client_filtering` | 1.8 |
| A4 | DoT (tcp/853) is rejected only toward the 14 listed resolver IPs. Android Private DNS pointed at any other provider bypasses filtering | `gateway/nftables.conf` | 1.8 |
| A5 | DoH blocking is a static IP list. No hostname-level DoH blocking, no Firefox canary domain, no iCloud Private Relay opt-out, no IPv6 equivalents | `nftables.conf` | 2.2 |
| A6 | Tier 2 statistics exist only as journal lines. The console shows nothing about decrypted vs. passed-through connections or removed ads | `dpi/securepi_adfilter.py` | 5.1 |
| A7 | The privacy scope (no non-allowlisted decryption) was verified **once, by hand**. That's the exact failure mode described in `REPORT-adblocking.md` §6 | — | 5.7 |
| A8 | Enrolling a device breaks the pinned YouTube app instead of degrading gracefully | report §8 | 5.8 |
| A9 | Tier 2 rules (`AD_FIELDS`, `AD_RENDERERS`, `BLOCKED_PATHS`) are hard-coded with no tests. A YouTube format change or SSAI rollout would break it silently | addon | 5.9, 5.10 |
| A10 | The CA uses mitmproxy's long default validity (verify on gateway) and is served over plain HTTP. A forgotten CA stays trusted for years | `deploy-dpi.sh` step 5 | 5.6 |
| A11 | Filtering page has no statistics, no "why blocked", no per-device unbreak, no list health | `app/templates/filtering.html` | 5.2–5.4 |
| A12 | `FIRST-PARTY-ADS-ANALYSIS.md` §5.1 says cosmetic filtering is impossible after interception. On-device AdGuard shows CSS/scriptlet injection into decrypted HTML is possible. Only the DOM-after-JavaScript part is out of reach | doc | 5.11, 8.1 |

---

## 4. The ordered plan

Effort is in build days. **Origin:** F§ = feasibility section, 15d = 15-day cut, Mkt = market analysis, CR/A = review finding.

### Stage 0 — Housekeeping (½ day)

| Step | Work | Origin | Exit criteria |
|---|---|---|---|
| 0.1 | Copy the feasibility study and day-1 status notes into `docs/`. Link from README | — | Committed |
| 0.2 | `Makefile` with `test`, `deploy` (rsync + restart) and `status` targets | 15d §2.5 | `make deploy` works from the Mac |
| 0.3 | **Baseline snapshot:** DB size, events/day by type, incidents/day, memory per service **including mitmproxy while enrolled**, blocked-query % per device over 24 h | F§17.3 | "Before" column in `EVALUATION-RESULTS-2.md` |

### Stage 1 — Foundation and correctness (~7 days)

| Step | Work | Origin | Exit criteria | Days |
|---|---|---|---|---|
| 1.1 | **Test suite.** `tests/` with pytest. A generator script creates synthetic eve/querylog/lease fixtures (no personal data). Temp-DB helper. Positive, negative and dedup tests for every signal, plus regression tests for the two past bugs | F§15.2, G7 | `make test` green. Reintroducing either old bug fails a test | 1.5 |
| 1.2 | **Central config.** `settings` table with validated defaults for thresholds, windows, retention, channels. The engine re-reads it each cycle | Mkt | Threshold change takes effect without a restart | 1 |
| 1.3 | **Retention + hourly rollups.** `app/retention.py` nightly: flow/TLS 14 days, DNS 30 days, incidents 365 days, audit kept forever. `device_hourly` rollup (bytes, flows, queries, **blocked queries**) kept 180 days. **Deploy early: 6.1 needs ≥7 days of rollups** | F§10.4, G10 | Old rows gone. Rollups fill. DB size logged daily | 1 |
| 1.4 | **AdGuard API ingest.** Poll `/control/querylog` with a time watermark and duplicate guard. **Also capture the block reason, matched rule, filter-list id, upstream time and cached flag** (needed by Stage 5). File reader kept as fallback | EVAL §1, G4 | Blocked-domain latency ≤ 30 s with no flush-forcing traffic. New columns populated | 1 |
| 1.5 | **Audit log.** `audit_log` table and an `audit()` helper on every write endpoint (filtering changes included) | F§11.1 | Every console action → one audit row | 0.5 |
| 1.6 | **Detection fixes G1, G2, G3, G6**, each with a test | CR | Tests pass. The Day 14 false positive no longer fires on its fixture | 1 |
| 1.7 | **AP client isolation** (`ap_isolate=1`). Document the casting/mDNS trade-off | F§4.4, G8 | Client-to-client test flow appears in `events` | 0.5 |
| 1.8 | **Ad-blocking correctness fixes.** (a) Fix `deploy-dpi.sh` to use the `ip nat` `enrolled` set and correct instructions (A1). (b) `securepi enroll` requires an explicit device, no silent "all" (A2). (c) AdGuard per-device clients use **MAC identifiers** (plus new MACs synced from the registry on rotation) instead of IP (A3). (d) Reject **all** tcp/853 from `ap0`, not just listed IPs (A4). (e) IPv6 guard: confirm no v6 egress, and add `ip6` drop/DNAT parity so a future v6 uplink can't bypass filtering | A1–A4 | Clean re-deploy works. Per-device filtering survives a DHCP renewal. Android Private DNS with an unlisted provider falls back to our resolver | 0.5 |

### Stage 2 — Detection breadth: restore the original signal set (~11 days)

New signals follow the `correlation.py` pattern (trailing-window SQL → `raise_incident()` → evidence ids), with an ATT&CK tag, config entries, fixture tests and a harness scenario.

| Step | Work | Origin | Exit criteria | Days |
|---|---|---|---|---|
| 2.1 | **Scan family:** network sweep (one port across many hosts) + slow-scan variants | F§12.3 | `nmap -T0` from `ns_attacker` detected | 1 |
| 2.2 | **DNS-bypass hardening + detection.** *Hardening:* (a) DNS-level blocking of DoH hostnames (HaGeZi DoH/VPN/proxy bypass list, DoH part on by default; VPN/proxy part available as a profile option in 4.3). (b) Firefox canary `use-application-dns.net` → NXDOMAIN, which disables Firefox's automatic DoH. (c) iCloud Private Relay opt-out: `mask.icloud.com` / `mask-h2.icloud.com` → NXDOMAIN, Apple's documented network signal. (d) The `doh_resolvers` nft set refreshes daily from resolved DoH hostnames instead of 14 static IPs. *Detection:* `log prefix` on the dot/doh/quic reject rules, those log lines ingested as events (the restored nftables source), plus Suricata TLS SNI matches on DoH hostnames. Incident: "Device X tried to bypass DNS filtering N times via DoH/DoT/Private Relay" | F§11.3, 15d cut, A5, Mkt (NextDNS) | Firefox with DoH on, Chrome Secure DNS with a custom provider, and Android Private DNS each end up resolving through AdGuard (or failing closed). One incident per device with evidence | 2 |
| 2.3 | **IDS alerts → taxonomy → incidents** (mapping table: ET category/SID → plain name, severity, ATT&CK) | F§9.6 | Test signature → plain-language incident | 1 |
| 2.4 | **Offline threat intel.** Daily abuse.ch Feodo/URLhaus/ThreatFox into an `ioc` table, matched on IP/domain/SNI. The same domains are pushed to AdGuard as a **security blocklist**, so they're both blocked and turned into incidents | F§19, Mkt | Seeded test IOC is blocked **and** raises an incident. Feed age visible | 1 |
| 2.5 | **DNS tunnelling + DGA** (subdomain entropy, label length, unique subdomains, TXT ratio; NXDOMAIN burst + entropy) | F§12.3 | Harness generators detected. No firing on 24 h of phone traffic | 1.5 |
| 2.6 | **C2 beaconing** (RITA-style timing and size regularity score, allowlist for NTP/push) | F§12.3, 15d cut | Harness beacon (60 s, 10% jitter) ≥ 0.8. No real-phone incidents | 2 |
| 2.7 | **Suppression rules** (from false-positive verdicts, audited, expiring) | F§11.2 | Suppressed pattern stops raising incidents | 1 |
| 2.8 | **Campaign correlation + MITRE ATT&CK kill chain**, weighted into risk | F§12.3 | Scan → brute force → beacon → one campaign linking three incidents | 1.5 |

> **Cut line A** (~3¾ weeks). Original signal set restored, campaigns built, and DNS filtering can no longer be quietly bypassed.

### Stage 3 — Hardening and platform reliability (~5 days)

| Step | Work | Origin | Exit criteria | Days |
|---|---|---|---|---|
| 3.1 | **Session authentication** (scrypt hash, HttpOnly SameSite=Strict cookie, rate limit, Origin check, timeout, password change) | F§11.1 | Unauthenticated → login. Cross-origin POST rejected | 1 |
| 3.2 | **TLS on the console** (console CA, separate from the DPI CA) | F§11.1 | HTTPS only | 0.5 |
| 3.3 | **Privilege separation:** unprivileged web app + allowlisted root helper for quarantine, block, **enroll/unenroll** | F§11.1, G9 | Web process has no root. Helper rejects malformed input. Calls audited | 1 |
| 3.4 | **Security self-review** (CSRF/XSS/injection, secrets in logs, `pip-audit`, WAN exposure) → `docs/SECURITY-REVIEW.md` | F§14 Ph9 | No unmitigated high findings | 0.5 |
| 3.5 | **Health supervisor:** Suricata `stats` (drops), staleness alerts for Suricata / AdGuard / ingest / engine / **HTTPS proxy**, disk, DB growth, WAN probe → platform incidents | F§5.5, F§8.4 | Stopping any service raises a platform incident within 60 s | 1 |
| 3.6 | **Fail-open DNS** with a "protection degraded" banner and automatic recovery | F§8.4 | Kill AdGuard → clients still resolve within ~30 s. Filtering returns on recovery | 1 |

### Stage 4 — Response and policy orchestration (~7½ days)

| Step | Work | Origin | Exit criteria | Days |
|---|---|---|---|---|
| 4.1 | **Policy orchestrator (lite).** Desired state for quarantine, blocks, filtering profiles, **allow/deny rules and enrollment**. Apply → read back to verify → roll back on mismatch. Drift loop catches out-of-band changes | F§8.3, 15d cut | Injected failure rolls back. A change made directly in AdGuard is detected | 2 |
| 4.2 | **Response actions:** MAC-keyed and timed quarantine, block domain/IP from an incident, opt-in auto-quarantine for high-confidence campaigns | F§9.4, G5 | Quarantine survives DHCP renewal and expires on its own | 1.5 |
| 4.3 | **Filtering profiles.** Standard / Kids / IoT-restricted / Strict-privacy / Unrestricted → AdGuard persistent clients: list sets, **blocked services** (TikTok, gaming, social…), safe search, **blocked-services schedules** (e.g. no gaming 22:00–07:00), optional VPN/proxy bypass blocking. **Pause filtering 5/15/60 min** per device or network-wide, with auto-resume | F§9.3, Mkt | Profile assignment verified by read-back. A scheduled service block activates on time. Pause auto-expires | 2 |
| 4.4 | **Device trust states** (approved / unknown / blocked; opt-in restriction for unknown devices with a lockout-safe fallback) | Mkt | New device restricted until approved | 1 |
| 4.5 | **Notifications** (ntfy / Telegram / SMTP / webhook, severity threshold, rate limit, quiet hours, digest). Includes "ad-blocking degraded" alerts from Stage 5 once they exist | F§9.4, 15d cut | One notification per incident, not one per cycle | 1 |

> **Cut line B** (~6¼ weeks). Detect → respond loop closed, orchestrated, audited and hardened. Per-device filtering profiles and schedules exist.

### Stage 5 — Ad blocking and privacy filtering (~10½ days + 1½ optional)

The goal is to take ad blocking from a working prototype to a full product, in two tiers:
- **Tier 1 (DNS, every device):** reach parity with NextDNS/Firewalla on everyday experience.
- **Tier 2 (HTTPS inspection, opt-in):** make it safe, self-verifying, testable and resilient to YouTube changes.

Order: telemetry first, because every later step displays or measures it. Then Tier 1 product features. Then Tier 2 hardening.

#### 5A — Telemetry foundation
| Step | Work | Origin | Exit criteria | Days |
|---|---|---|---|---|
| 5.1 | **Filtering telemetry model.** *Tier 1:* use the reason, rule, list id, upstream time, cached flag and CNAME-match info captured in 1.4, and aggregate into `device_hourly` (1.3) plus a `filter_hourly` table (hits per list, per blocked domain). *Tier 2:* the addon writes one compact JSON line per connection decision (device IP → device id, SNI, decision = decrypt/passthrough/auto-passthrough, TLS failure, ads stripped, paths blocked). **No URLs or bodies for passthrough hosts, and only path prefixes for decrypted ones.** Ingest into a `dpi_events` table covered by retention | A6, F§9.3 | A browsing session produces matching counts in the DB and in the proxy log. No passthrough hostname has path data stored | 1.5 |

#### 5B — Tier 1: everyday product experience
| Step | Work | Origin | Exit criteria | Days |
|---|---|---|---|---|
| 5.2 | **"Why blocked?", domain tester and unbreak workflow.** (a) Test a domain for a device: AdGuard `check_host` → verdict, matching rule, source list, and whether a CNAME matched. (b) Per-device **"Recently blocked"** panel on the device page and the Filtering page. (c) One-click **Allow for this device** (AdGuard `$client` modifier on the persistent client name) or **for everyone**, optionally **temporary** (auto-removed after 1 h / 1 day), with a required reason. Everything goes through the orchestrator (4.1) and the audit log. (d) Allowlist churn is tracked as a false-positive / breakage metric | F§9.3, Mkt, A11 | Breaking a site by blocking its CDN, then fixing it from the device page, takes under 30 s. The temporary allow expires. Audit shows who, what and why | 1.5 |
| 5.3 | **Ad-blocking analytics.** (a) Block % over time, network and per device (from rollups). (b) Top blocked domains and top clients. (c) **Tracker company attribution** from an offline entity map (DuckDuckGo Tracker Radar or Disconnect entity data, licence checked and cited): "Device X contacted 14 tracking companies; 11 blocked". (d) Per-device **privacy report** card. (e) **Estimated bandwidth and requests saved**, with the method stated on the page (median blocked-request size taken from the 7.5 benchmark, not invented). (f) Tier 2 panel: connections decrypted vs. passed through, ads stripped, endpoints blocked | F§9.3, Mkt (NextDNS/Firewalla), A11 | All panels render from real data. The savings estimate names its method and source figure | 2 |
| 5.4 | **Blocklist health and contribution.** (a) List last-updated age, update failures, rule counts, plus a platform incident if a list is stale for more than 48 h. (b) **Per-list contribution:** hits attributed to each list. An offline script on the Mac replays 7 days of queried domains against all lists to compute unique blocks per list and an overlap matrix. (c) AdGuard memory vs. total rules measured with lists toggled. (d) Recommendations shown in the console ("OISD Big uniquely blocks 0.4% — consider removing") | Mkt, F§10.2 | Contribution and overlap table produced and shown. A broken list URL raises an alert | 1.5 |
| 5.5 | **Tracker coverage and resolver quality.** (a) Surface CNAME-cloaked tracker blocks separately in analytics, and add the AdGuard CNAME-trackers list. (b) **Native device telemetry lists** (HaGeZi native Apple / Samsung / Xiaomi / Windows / TikTok…) selectable per device or profile. Picked manually now, auto-suggested by fingerprinting once 6.2 lands. (c) Resolver quality: optimistic caching and cache size, DNSSEC on, two DoT upstreams (Cloudflare + Quad9) in parallel with fallback. DNS latency measured before and after | Mkt (NextDNS native tracking, Pi-hole CNAME), F§17.3 | CNAME blocks visible. A Samsung/Xiaomi-profile device blocks vendor telemetry without breaking updates (checked). p50/p95 DNS latency recorded | 1 |

#### 5C — Tier 2: selective HTTPS inspection, hardened
| Step | Work | Origin | Exit criteria | Days |
|---|---|---|---|---|
| 5.6 | **Enrollment and CA lifecycle in the console.** (a) Per-device "HTTPS ad removal" toggle through the orchestrator and root helper (replaces the CLI). Enrolled set keyed on MAC. (b) **Onboarding page:** CA download, QR code, per-OS install steps, and a live "is the CA trusted on this device?" check (successful handshakes to allowlisted hosts vs. TLS failures from 5.1). (c) **Auto-unenroll timer** (default 24 h), plus the existing off-after-reboot behaviour. (d) **Short-lived CA** (e.g. 90 days) with expiry on the page and a documented rotation. Old CA material destroyed on rotation. (e) Reminder banner to remove the CA from devices that are no longer enrolled | A2, A10, report §11 | Enroll → install CA → trust check green → auto-unenroll after timer. CA validity verified with `openssl x509 -enddate` | 1.5 |
| 5.7 | **Automatic privacy-scope verification** (turns the report §6 lesson into a control). Every 15 minutes a canary client in a test namespace, placed in the enrolled set, opens TLS through the real redirect to (a) a **non-allowlisted** host and asserts the presented certificate is **not** issued by the SecurePi CA, and (b) an **allowlisted** host and asserts it **is** (proving inspection works). This checks what the *enforcing* component actually does, not the addon's log. On failure: **fail safe** (flush the enrolled set, inspection off), raise a platform incident, notify. Console badge: "Privacy scope verified 4 min ago" | Report §6, A7 | Deliberately reintroducing the `ignore_conn` typo in a test deploy triggers fail-safe within one cycle. Normal operation shows the badge green | 1.5 |
| 5.8 | **Pinning-aware auto-passthrough.** The mitmproxy TLS-failure hook records (device, SNI) handshake failures. After N failures that pair is passed through undecrypted for 24 h, so pinned apps (e.g. the YouTube app) **keep working, with ads,** instead of breaking. Shown in the console as "App pins its certificate — bypassed" | A8, Mkt (AdGuard apps) | With the device enrolled, the YouTube app plays after at most N failed attempts. Browser YouTube on the same device stays ad-free | 1 |
| 5.9 | **Rule-set refactor and tests.** Move `AD_FIELDS`, `AD_RENDERERS`, `BLOCKED_PATHS`, `DECRYPT_SUFFIXES` into a versioned `dpi/adfilter-rules.json` that the addon hot-reloads. Edited from the console with validation and audit. Decrypt-suffix changes need an explicit privacy confirmation. **Fixture tests** for `strip_ads` on synthetic YouTube-shaped JSON: nested fields removed, ad renderers dropped, content preserved, output still valid JSON. **Per-rule hit counters** to spot dead rules | A9 | `make test` covers the addon. A rule edit takes effect without restarting the proxy. Dead rules visible | 1 |
| 5.10 | **Effectiveness watchdog and SSAI readiness.** Track ads stripped per YouTube watch session. If YouTube traffic continues but stripping stays at zero for a configured period, raise "YouTube ad removal may no longer be effective (format change or server-side ad insertion)" and notify. Document SSAI as the expected end state | A9, Mkt research | Removing a rule in a test deploy makes the watchdog fire. Report section drafted | 0.5 |
| 5.11 | *(Optional)* **Cosmetic and scriptlet injection** for allowlisted hosts only: inject a stylesheet hiding leftover ad containers, and optionally vetted scriptlets (`json-prune`, `set-constant` equivalents, licences checked) into decrypted HTML. Handle CSP nonces carefully. Measure breakage. Also correct `FIRST-PARTY-ADS-ANALYSIS.md` §5.1 (A12) | Mkt (uBO, AdGuard apps), A12 | Leftover ad placeholders gone on the test pages with no functional breakage in a 10-video check | 1.5 |

> **Open follow-up on 5.7 - revisit after 5.11:** 5.7 as built does NOT
> exercise the real nftables redirect rule or mitmproxy's transparent-mode
> handling, only the addon's own decision method. Closing that gap needs
> the `ap0` network-topology work described just below. Full detail is in
> §8's tracker note for step 5.7; the short version:
>
> - **What the plan asked for:** a canary client in a test namespace,
>   enrolled, opening a real TLS connection **through the actual
>   nftables `dpi-redirect` rule** to prove the *enforcing* component -
>   not the addon's log - makes the right call.
> - **Why that was ruled out, checked live, in this order:**
>   1. `ns_victim` (the existing safe test namespace, `gateway/
>      setup-test-harness.sh`) sits on `br-test`, which `evaluate.py`'s
>      own comments already establish has no path to `ap0` - the
>      interface the redirect rule matches on (`iifname "ap0" ip saddr
>      @enrolled tcp dport 443 ... redirect to :8080`). Traffic from it
>      never reaches that rule.
>   2. Connecting straight to `127.0.0.1:8080` (mitmproxy's own port)
>      with `openssl s_client -servername <host>` was tried live for
>      both an allowlisted and non-allowlisted host - both failed the
>      handshake identically. mitmproxy's transparent mode needs the
>      kernel's original-destination info that only a genuine nftables
>      REDIRECT carries; a direct connection can't supply that, so it
>      can't even reach the point of making the decision this check
>      needs to observe.
>   3. The only way left to genuinely exercise the rule is a client
>      whose traffic actually arrives on `ap0` - which means either
>      bridging a new synthetic namespace onto the same interface the
>      live AP and the two real phones depend on (network-topology
>      surgery on production, not something to improvise mid-session),
>      or using a real enrolled device as an unwitting scheduled target
>      (rejected outright - it would mean inspecting real traffic on a
>      timer its owner never chose, against this project's own opt-in
>      stance).
> - **What was built instead:** `dpi/privacy_canary.py` imports the real
>   addon file fresh every cycle and calls its actual `tls_clienthello()`
>   method directly with a synthetic ClientHello, reading the same
>   `ignore_connection` attribute the report's own historical typo broke.
>   Proven (by a smoke test that reintroduces that exact typo) to catch
>   that whole class of regression. It cannot catch a bug in the redirect
>   rule itself, or in mitmproxy's original-destination handling.
> - **What closing the gap for real would take, next time this is
>   picked up:** a dedicated network namespace bridged onto `ap0` itself
>   (not `br-test`), added carefully enough not to disturb the live AP or
>   the two real phones - likely its own veth pair on a small VLAN or a
>   second SSID reserved for gateway self-tests, checked first against a
>   spare AP/router before touching this one. Until that exists, the
>   redirect rule and traffic path should keep getting a deliberate,
>   manual check from time to time (as this session did once, by hand,
>   during 5.7's deploy verification), not be treated as continuously
>   covered.

> **Open follow-up on 5.11 - revisit after Stage 5 is complete:** the
> plan's own description of 5.11 names two things - cosmetic injection
> AND "optionally vetted scriptlets." Only the first (**Path 1**) was
> built. **Path 2** (JS scriptlet injection - `json-prune`/`set-constant`
> equivalents) was deliberately NOT attempted, decided together with the
> user rather than assumed unilaterally. Recorded here in full, the same
> way 5.7's real-enforcement-path gap was, so it isn't lost.
>
> - **What Path 2 would have been:** injecting a `<script>` into
>   decrypted HTML that overrides a specific JS property or function
>   YouTube's player reads before it decides whether/how to show an ad -
>   the same category of technique uBO's `set-constant`/`json-prune`
>   scriptlets use, but as an original implementation, not ported code
>   (uBO is GPLv3; this project's own licensing position on embedding
>   third-party scriptlet source was never resolved, and didn't need to
>   be once the risk case below was decided on its own).
> - **Why it was ruled out - a risk decision, not a technical one,**
>   confirmed explicitly with the user before proceeding: a MITM proxy
>   CAN rewrite a response body's JavaScript the same way this project
>   already rewrites JSON and HTML - FIRST-PARTY-ADS-ANALYSIS.md's
>   original claim that this was impossible was itself overstated and
>   has been corrected (§5, §5.1) as part of this same step. The real
>   barrier is that an injected script which gets something wrong
>   against YouTube's actively-changing, heavily-obfuscated frontend can
>   break the page outright - not just fail to remove an ad, but leave
>   an enrolled device's YouTube unusable - and this project has no way
>   to verify that didn't happen without a real device actively browsing
>   through the gateway, which wasn't available this session. Compare to
>   Path 1 (CSS): a wrong CSS selector is a silent no-op; a wrong
>   `set-constant` override can be a blank player.
> - **What Path 1 (cosmetic CSS injection) delivers on its own, so the
>   gap is smaller than it sounds:** hides leftover ad-shaped containers
>   left behind after `strip_ads()` already removed the underlying ad
>   instruction from the JSON - the empty box, not a functioning ad.
>   What Path 2 would additionally catch is ad-adjacent JS *behaviour*
>   that never went through a JSON field this addon inspects at all -
>   narrower than it may sound, and the DECISIVE gap (SSAI) is one
>   neither path can close - see REPORT-adblocking.md's SSAI section
>   (step 5.10).
> - **What picking this up later would need:** the same thing 5.7's
>   follow-up needs - a real device (or the user's own phone,
>   deliberately, never as the first test) actively enrolled and
>   browsing YouTube through the gateway, so an injected scriptlet's
>   effect can be watched and reverted immediately if the page breaks.
>   Until that's available, Path 2 should stay deferred rather than
>   shipped unverified.

> **Cut line C** (~8½ weeks, excluding 5.11). Ad blocking becomes a full product: profiles, schedules, unbreak, analytics, list health, hardened bypass prevention. Tier 2 verifies its own privacy scope, degrades gracefully, and notices when YouTube changes.

### Stage 6 — Intelligence and console (~10 days)

| Step | Work | Origin | Exit criteria | Days |
|---|---|---|---|---|
| 6.1 | **Behavioural baselines:** EWMA per device per hour of day on `device_hourly`, z-score volume anomaly / exfiltration signal, "learning" badge until 7 days of data | F§12.3, 15d cut | Harness bulk upload fires. Normal days don't | 1.5 |
| 6.2 | **Device fingerprinting** (DHCP option 55, OUI, hostname, connectivity-check domains, JA3/JA4) → type, OS, confidence. Second identity anchor. **Auto-suggests native tracker lists (5.5) and a filtering profile (4.3)** | F§9.2, 15d cut | Both phones classified with evidence. Correct list suggestion shown | 1.5 |
| 6.3 | **Settings view + attributions** (thresholds, retention, channels, password, audit viewer, OSS licences including blocklist and entity-map licences) | F§9.5, F§9.6 | All settings editable, validated, audited | 1.5 |
| 6.4 | **Incident workbench** (timeline, notes, ATT&CK, playbooks, campaign view, one-click responses) | F§9.5, Mkt | Triage and response without leaving the page | 1.5 |
| 6.5 | **Hunt / explorer** (flow/DNS/TLS search, pivots, top talkers, protocol breakdown, saved searches) | F§9.2, Mkt | "Everything device X talked to in the last hour" in two clicks | 2 |
| 6.6 | **Weekly report** (print-to-PDF): incidents by tactic, riskiest devices, **ad-blocking summary** (block %, top trackers, companies, savings, Tier 2 effectiveness), platform health | F§9.3, F§9.4 | Report renders for any past week | 1 |
| 6.7 | **Responsive layout** | F§13.3 | All pages usable at ~400 px | 1 |

> **Feature freeze** after Stage 6. Start the 7-day continuous run (7.0) right away.

### Stage 7 — Evaluation campaign 2.0 (~8 days of effort, spread over the 7-day run)

This restores feasibility Phase 10. ⚡ = run a first time **as soon as the feature lands**, repeat here for final numbers.

| Step | Experiment | Metrics |
|---|---|---|
| 7.0 | **7-day continuous run** on real devices | FP incidents/24 h, uptime, storage growth/day, ingest lag p95, reduction ratio, **block % per device** |
| 7.1 | **PCAP replay pipeline** (`suricata -r` → ingest → engine; runnable on the Mac via Homebrew Suricata; own captures + a small labelled public subset, licence cited) | Deterministic ground truth |
| 7.2 | ⚡ Detection battery for all signals, 5 runs each | Detection rate, TTD median + p95 |
| 7.3 | Precision / recall / F1 per signal. Threshold sensitivity sweeps | Justifies every threshold |
| 7.4 | ⚡ Slow-scan advantage vs. signatures. ⚡ Beacon jitter curve. Ablation (raw / dedup / dedup + campaigns) | Headline figures |
| 7.5 | **Ad-blocking benchmark (expanded).** Headless Chromium (Playwright) on the Mac, temporarily joined to `SecurePi-Test`, loads a fixed set of 20 ad-heavy sites × 3 runs under four conditions: **no filtering / Tier 1 / Tier 1 + profile lists (5.5) / reference: uBlock Origin in the browser with gateway filtering off**. Measure total and third-party requests, bytes, tracker companies contacted (entity map), onLoad/LCP. Also: ⚡ **breakage rate** on the top-50 sites (checklist + allowlist churn from 5.2), ⚡ **per-list marginal utility and overlap** (5.4), ⚡ **DNS latency** p50/p95 before/after 5.5 vs. ISP resolver, ⚡ **bypass matrix**: Firefox DoH, Chrome Secure DNS, Android Private DNS, iCloud Private Relay (if an Apple device is available), VPN app → blocked / detected / leaked. **Tier 2:** 30 YouTube videos in mobile Chrome, pre-roll shown yes/no under DNS only vs. Tier 2, ⚡ scope-canary results over 7 days, pinned-app behaviour before/after 5.8, mitmproxy RSS and added TLS setup latency | Request/byte/tracker reduction vs. uBO reference, load-time delta, breakage %, list utility, latency, bypass matrix, first-party ad block rate with confidence interval, privacy-scope uptime |
| 7.6 | Identity accuracy over the 7-day run | Accuracy vs. ground truth |
| 7.7 | ⚡ **Chaos tests:** kill Suricata / AdGuard / ingest / engine / **mitmproxy** (inspection must fail open to plain passthrough, not break browsing), fill disk (scratch), drop WAN | MTTR, detection gap, fail-open verified |
| 7.8 | Performance: throughput + drops sweep, dashboard query latency, memory/CPU with everything on, ⚡ storage before/after retention | System table |
| 7.9 | **Usability study** (5–8 people): tasks include "find the riskiest device and explain why" **and "a site is broken — fix it for one device only"** + SUS | Task success, time, SUS |

### Stage 8 — Documentation and demonstration (~5 days, restores Day 15 / feasibility Phase 11)

| Step | Work | Exit criteria |
|---|---|---|
| 8.1 | Update the report: contribution boundary (F§17.2), deviations table (§1 here), ad-blocking chapter (new benchmark, list utility, bypass matrix, privacy-scope canary as a verification method, SSAI boundary, A12 correction), limitations, future scope | Chapters current |
| 8.2 | **One-command installer** (`gateway/install.sh`, idempotent, includes the DPI components in an off state) | Fresh-machine install from docs alone |
| 8.3 | 15-minute demo script: F§17.4 plus slow scan, beaconing, DoH bypass blocked and detected, campaign, kill-Suricata, fail-open DNS, timed quarantine, **per-device unbreak in 30 s, schedule-based service block, and the privacy-scope canary going red→safe when sabotaged** | Rehearsed 3×, backup video |
| 8.4 | Close-out: purge journal, remove demo CA from the phone, rotate/destroy the DPI CA if the project is paused | Done |

### Stretch (only after Stage 8)

| ID | Work | Origin |
|---|---|---|
| S.1 | Raspberry Pi as a second independent sensor | F§5.4, F§19 |
| S.2 | Network map + offline GeoIP/ASN | Mkt |
| S.3 | Suricata IPS-mode latency experiment (measure only) | F§10.5 |
| S.4 | WireGuard remote access to the console | Mkt |
| S.5 | Additional first-party ad modules (e.g. web promoted posts on another site), each a separate opt-in rule file, **only after a written privacy review**, because each adds a decrypted hostname that may carry messages or logins | Mkt, §1.4 |

---

## 5. Schedule summary

| Stage | Effort (days) | Cumulative (5-day weeks) |
|---|---|---|
| 0 Housekeeping | 0.5 | — |
| 1 Foundation & correctness | 7 | ~1.5 wk |
| 2 Detection breadth | 11 | ~3.7 wk — **cut line A** |
| 3 Hardening & reliability | 5 | ~4.7 wk |
| 4 Response & orchestration | 7.5 | ~6.2 wk — **cut line B** |
| 5 Ad blocking & privacy filtering | 10.5 (+1.5 optional) | ~8.3 wk — **cut line C** |
| 6 Intelligence & console | 10 | ~10.3 wk — feature freeze |
| 7 Evaluation 2.0 | 8 (+7-day run in parallel) | ~11.9 wk |
| 8 Documentation & demo | 5 | ~12.9 wk |

**If time runs short, cut in this order:** 5.11 → 6.7 → 6.6 → 6.5 → 5.10 → 5.4 → 4.4.
Never cut Stage 2, steps 5.2, 5.3, 5.7, or evaluation items 7.2–7.5.

**Minimum path (~5 weeks):** 0 → 1 (all) → 2.1, 2.2, 2.6, 2.8 → 3.1, 3.2 → 4.3, 4.5 → 5.1, 5.2, 5.3, 5.7 → 7.2, 7.4, 7.5 → 8.

---

## 6. Files these stages touch (orientation)

- `app/correlation.py` — new signals, ATT&CK tags, campaigns, suppression, config thresholds
- `app/schema.sql` — `settings`, `audit_log`, `device_hourly`, `filter_hourly`, `dpi_events`, `ioc`, `suppressions`, `campaigns`, `incident_notes`, `sensor_stats`, `policies`, `signal_taxonomy`, `tracker_entities`, `notifications`
- `app/ingest.py` — AdGuard API source (with reason/rule/list/upstream fields), nftables log lines, Suricata `stats`, DHCP fingerprints, DPI decision lines
- `app/adguard.py` — MAC-keyed persistent clients, blocked services + schedules, `check_host`, `$client` allow rules, pause, upstream/cache/DNSSEC settings, list health
- `dpi/securepi_adfilter.py` + new `dpi/adfilter-rules.json` — hot-reloaded rules, decision telemetry, TLS-failure auto-passthrough, per-rule counters, optional cosmetic injection
- `dpi/deploy-dpi.sh`, `gateway/securepi` — table fix, explicit enroll, short-lived CA, MAC-keyed enrolled set
- `gateway/nftables.conf` — tcp/853 reject all, log prefixes, ip6 parity, refreshed DoH set, timed quarantine
- `app/risk.py`, `app/quarantine.py`, `app/registry.py` — as in earlier stages
- `app/webapp.py`, `app/templates/` (`filtering.html` rebuilt, new onboarding / settings / hunt / reports / campaign pages), `app/static/app.js`, `app/static/app.css`
- `gateway/evaluate.py`, `gateway/setup-test-harness.sh` — beacon, tunnel, bypass and scope-canary scenarios
- New: `tests/` (including `tests/test_adfilter.py`), `Makefile`, `app/retention.py`, `app/intel.py`, `app/notify.py`, `app/baseline.py`, `app/fingerprint.py`, `app/orchestrator.py`, `app/health.py`, `app/filter_analytics.py`, `app/dpi_canary.py`, `tools/blocklist_utility.py` (Mac-side), `bench/adblock_bench.py` (Playwright), `gateway/securepi-helper`, `gateway/install.sh`, `docs/`

## 7. Verification approach

- **On the Mac:** `make test` covers signals, retention, orchestrator, the `strip_ads` fixtures and analytics queries. The console runs against a fixture DB. The blocklist utility and ad-block benchmark run from the Mac (the benchmark with the Mac temporarily joined to `SecurePi-Test`).
- **On the gateway:** `make deploy` → `sudo securepi status` → the matching `evaluate.py` scenario in the isolated namespaces. Real devices are never attacked. The scope canary runs continuously once 5.7 lands.
- **Console:** `./mac-tunnel.sh start`. Confirm each page, action, audit row, undo path, expiry (temporary allow, pause, auto-unenroll, timed quarantine) and alert live.
- **Budget check** after every stage. Day 14 baseline: 1,457 MB used. mitmproxy measured separately while enrolled.

## 8. Progress tracker

| Stage | Steps | Status |
|---|---|---|
| 0 | 0.1 · 0.2 · 0.3 | Not started |
| 1 | 1.1 · 1.2 · 1.3 · 1.4 · 1.5 · 1.6 · 1.7 · **1.8 done** (out of order - see note below) | 1.8 done, rest not started |
| 2 | 2.1 · 2.2 · 2.3 · 2.4 · 2.5 · 2.6 · 2.7 · 2.8 | Not started |
| 3 | 3.1 · 3.2 · 3.3 · 3.4 · 3.5 · 3.6 | Not started |
| 4 | 4.1 · 4.2 · 4.3 · 4.4 · 4.5 | Not started |
| 5 | **5.1 done, 5.2 done, 5.3 done, 5.4 done, 5.5 done, 5.6 done, 5.7 done, 5.8 done, 5.9 done, 5.10 done, 5.11 done (Path 1 only)** (out of order) | 5.1–5.11 done - 5.11 scoped to Path 1 (cosmetic CSS), Path 2 (scriptlets) deferred and recorded |
| 6 | **6.1 done** · 6.2 · 6.3 · 6.4 · 6.5 · 6.6 · 6.7 | 6.1 done, rest not started |
| 7 | 7.0 – 7.9 | Not started |
| 8 | 8.1 · 8.2 · 8.3 · 8.4 | Not started |

**Note on 13 September:** at the user's request, 1.8 and Stage 5's telemetry
foundation (5.1) and "why blocked / unbreak" tools (5.2) were implemented
ahead of Stages 1–4, since they're self-contained ad-blocking fixes and
features that don't depend on the settings table, test suite, or session
auth those stages would otherwise add first.

**Deployed to the live gateway and verified the same day.** Before/after
`.bak-preadblock` copies of every replaced file were kept in place
(`/opt/securepi/*.bak-preadblock`, `/opt/securepi-dpi/*.bak-preadblock`,
`/etc/nftables.conf.bak-preadblock`, `/usr/local/bin/securepi.bak-preadblock`),
plus an online SQLite backup taken before the schema migration
(`/opt/securepi/securepi.db.pre-adblock-deploy-*.bak`). All three affected
services (`securepi-ingest`, `securepi-web`, `securepi-dpi`) restarted
cleanly with no errors in the journal. The nftables reload wipes the
`enrolled` set (it has no static elements in the config file) - this was
anticipated, the live membership (`10.10.0.50`, `10.10.0.51`) was captured
before the reload and restored immediately after, and re-checked at the
end of the session.

What was actually exercised against the live gateway, not just tested in
isolation:
- `/api/filtering/check` against real AdGuard data (`doubleclick.net` →
  correctly blocked with rule and filter_list_id; `wikipedia.org` →
  correctly allowed).
- `sudo securepi enroll` with no argument now refuses instead of silently
  enrolling every device (fix A2) - confirmed it does not touch the
  enrolled set at all.
- The new port-853 firewall rule is unconditional, confirmed via
  `nft list chain inet filter forward` (fix A4).
- `/api/devices/{id}/blocked` against a real device with real traffic
  (id 2, `kushagra-s-a33`) - correctly folded 19 `firebaselogging-pa
  .googleapis.com` hits into one row, the same Android-telemetry pattern
  `EVALUATION-RESULTS.md` §3 already flagged as background noise.
- The MAC-keyed identity fix (A3), proven against the test-harness's
  `test-victim` device (never against a real device): enabling filtering
  created an AdGuard client keyed on **MAC + IP**; simulating a MAC
  rotation by adding a second MAC row and re-applying the policy grew the
  client's `ids` to include both MACs and the IP, rather than losing the
  old one - the exact failure this fix targets.
- The per-device `$client`-scoped allow rule (5.2): added, listed correctly
  scoped to one device, confirmed harmless on the network-wide rules list,
  then removed. All test artifacts (the test rule, the synthetic MAC) were
  cleaned up afterward; device 5's filtering was restored to enabled.

**One real bug found and fixed during this same live pass:** `describe_check()`
assumed AdGuard's `check_host` response echoed back the domain it was asked
about (`result.get("host")` / `result.get("name")`). Live testing showed
neither key exists in AdGuard's actual response - every result rendered
`"domain": null`. Fixed by passing the domain through from the caller
instead of reading it back from AdGuard; redeployed and re-verified within
the same session.

**Not verified live, honestly:** the Tier 2 telemetry log
(`/var/log/securepi/dpi-events.jsonl`) exists with correct permissions but
is still empty - no device was connected to `SecurePi-Test` during this
deploy (`0 client(s)` throughout), so the decrypt/passthrough logging path
in the addon has only been exercised by the standalone tests on the Mac,
not by real HTTPS traffic through mitmproxy. Confirm this the next time
either phone is on the network and browsing.

**Note on step 5.3 (ad-blocking analytics), implemented locally, not yet
deployed:** built directly on top of the raw `events` table rather than
waiting for Stage 1's `device_hourly`/`filter_hourly` rollups, since those
don't exist yet and 5.3 was done out of order like 5.1/5.2 before it. Added:
- `app/tracker_entities.py` - a small, hand-curated domain -> company map
  (~50 ad/analytics/tracking companies actually likely to appear in this
  project's own traffic), explicitly NOT a copy of the Disconnect or
  DuckDuckGo Tracker Radar entity lists, with a docstring explaining why
  and what to do instead if the full dataset is ever needed.
- `GET /api/filtering/analytics` (network-wide: block % over time, top
  blocked domains, most-blocked-for devices, tracker company breakdown,
  an estimated bandwidth/requests-saved figure that names its own method
  instead of pretending to be measured, and a Tier 2 decrypt/passthrough/
  ads-stripped/paths-blocked panel) and `GET /api/devices/{id}/privacy`
  (the same, scoped to one device, all-time) in `app/webapp.py`.
- New "Ad-blocking Analytics" card on the Filtering page and "Privacy
  Report" card on the device detail page, in the existing Jinja + vanilla
  JS style (no new libraries).

Verified so far only with a standalone smoke test against a temporary
in-memory SQLite database seeded with synthetic events (tracker-domain
attribution, per-device vs. network-wide breakdown scoping, the savings
estimate's arithmetic, and the Tier 2 counts including the empty-window
case) - not yet against the live gateway's real data. `python3 -m
py_compile`, `node --check` and a standalone Jinja parse all pass on the
changed files. Deploying and verifying this against the real database is
the next step, the same way 1.8/5.1/5.2 were deployed and checked.

**Note on step 5.4 (blocklist health and contribution), also implemented
locally, not yet deployed:** added `GET /api/filtering/lists/health` to
`app/webapp.py`, surfaced as extra badges on each row of the existing
"Blocklist Sources" list (age since last sync, a "stale" chip past 48h, a
share-of-blocks percentage, and a "low contribution" chip) rather than as
a separate page - the list is already the natural place to see this.

One deliberate deviation from the plan's original method, made for
honesty rather than convenience: contribution is computed from this
project's own historical telemetry (the `dns_filter_list_id` captured on
every blocked DNS event since step 5.1 - which list's rule actually
matched a real block) instead of the offline multi-list replay script
the plan described. This is a *direct* measurement rather than a
synthetic reconstruction of one, and needed no new tooling - but it also
means two things the original method would have given us are explicitly
NOT provided here, and the API response says so under `deferred_note`
rather than pretending otherwise: the list-*overlap* matrix (which other
lists would also have matched the same domain), and AdGuard's memory use
with lists toggled on/off. Both need a controlled experiment against a
non-production AdGuard instance, which fits Stage 7's evaluation campaign
better than an always-on console feature - deferred there, not dropped.

Also unverified: whether AdGuard Home's real `/control/filtering/status`
response actually includes a `last_updated` field per filter in the
version running on the gateway. The code reads it defensively (`f.get(...)`,
try/except around the timestamp parse) and degrades to "sync age unknown"
if it's missing or a different shape than expected, rather than crashing -
but this needs a live curl to confirm either way, the same lesson
`describe_check` already taught this session once.

Smoke-tested locally with mocked `adguard.filtering_status()` and an
in-memory DB (staleness math, contribution/share arithmetic, the
disabled-list-not-flagged case, and the missing-timestamp case).

**Deployed to the live gateway and verified the same day.** `.bak-5.3-5.4-*`
copies of every replaced file were taken first (`webapp.py`, both
templates, `static/app.js`), plus the new `tracker_entities.py`; no
schema change this time, so no DB backup was needed. `securepi-web`
restarted cleanly (`sudo systemctl restart securepi-web`, journal clean,
`sudo python3 -m py_compile webapp.py tracker_entities.py` on the
gateway's own interpreter passed before the restart).

What was actually exercised against the live gateway:
- `/api/filtering/analytics?range=24h` - real tracker attribution across
  19 companies (Google Ads/Analytics, Meta, Firebase/Crashlytics, Branch,
  Yandex Metrica, Hotjar, AdColony and more), real top-blocked-domains
  and top-blocked-clients tables, a real savings figure. Tier 2 correctly
  reports `active: false` - consistent with the still-empty DPI telemetry
  log noted above.
- `/api/devices/{id}/privacy` against both real phones (ids 1 and 2) -
  distinct, plausible per-device tracker breakdowns (34% and 37% block
  rates respectively).
- `/api/filtering/lists/health` - **this is what resolved the one
  specific thing flagged as unverified above.** AdGuard's real
  `/control/filtering/status` (curled directly against port 3000, past
  this app's own layer) does return `last_updated` as a genuine
  RFC3339-with-offset string (`"2026-09-13T06:56:12+05:30"`), and
  `datetime.fromisoformat` parses it correctly - age_h and staleness
  came back sane for all 5 configured lists.
- The Filtering and device-detail pages were curled directly and checked
  for the new card markup (`analyticsRangeSel`, `blockPctChart`,
  `devicePrivacy`, etc.) actually present in the rendered HTML, and the
  deployed `static/app.js` was confirmed to contain the new
  `initFilteringAnalytics`/`initDevicePrivacy` functions.

**One real thing this surfaced, not a bug:** of 1,963 blocked DNS events
stored so far, only 6 carry a `dns_filter_list_id` at all, and all 6
point to list id 1 ("AdGuard DNS filter"), never to HaGeZi/OISD/Peter
Lowe/AdAway despite AdGuard's own on-disk `querylog.json` showing those
four lists matching plenty of queries. Tracing it: `read_agh_querylog`'s
byte-offset watermark means a querylog line already read (and inserted)
before this session's schema migration keeps whatever columns
`flatten_agh` produced *at read time* - it is never re-read and
backfilled just because the column exists now. So "6 attributed blocks,
all from list 1" is exactly what the plan's own caveat already predicted
("blocks recorded before 5.1 was deployed aren't attributed to any
list"), not a defect in this feature; the per-list contribution numbers
will become meaningful as more DNS traffic is ingested from here forward.
Confirmed live: a `doubleclick.net` block logged after the deploy carries
`dns_filter_list_id=1` correctly. Worth re-checking `/api/filtering/lists/health`
again after a few real days of traffic, specifically whether HaGeZi/OISD/
Peter Lowe/AdAway ever earn a non-zero share once given the chance -
list 1 alone may simply be catching most common ad domains first.

**Note on step 5.5 (tracker coverage and resolver quality), implemented
locally, not yet deployed.** Scoped down from the plan's original three
parts based on what a live investigation actually found possible or safe
to do in one pass, each documented rather than silently dropped:

- **(a) CNAME-cloaking.** `describe_check()` now returns AdGuard's `cname`
  field when a block happened via a CNAME match - confirmed to be a real
  field on the live check_host API during the 5.2 deploy already, so this
  is a small, safe addition, surfaced in both "why blocked?" tools (the
  Filtering page's and the device page's). What the plan also asked for -
  tagging *historical* blocked events in the analytics pages as
  CNAME-cloaked or not - turned out not to be available the way assumed:
  a live inspection of the gateway's real `querylog.json` (grepped for
  every key across a large sample) found no CNAME field on stored query
  log entries at all, only a base64-encoded raw DNS answer packet that
  would need a hand-written wire-format parser to read. Deferred rather
  than faked; adding the AdGuard "CNAME-trackers" blocklist itself needs
  no code at all, since it's just another URL through the existing
  blocklist-add flow - left for whoever runs the deploy to add through
  the console rather than silently pre-added by this session.
- **(b) Native telemetry profiles.** New `app/native_trackers.py` (small,
  explicitly-cautious per-vendor domain lists - apple/samsung/xiaomi/
  windows/tiktok, 2-3 domains each, picked for being consistently
  described as telemetry-only across multiple independent public
  sources) plus the machinery to apply one to a device: `adguard.py`'s
  `add_client_rule` gained an optional `tag` (alongside the existing
  `expires_at`, and confirmed via a smoke test that a rule carrying both
  at once still parses correctly - the old expiry parser used a plain
  substring split that would have broken on that combination, so it was
  rewritten with a regex while this was being touched anyway) and a new
  `remove_client_rule_group()` to remove a whole profile's rules at once.
  New endpoints and a device-page selector. Deliberately NOT
  claiming these lists are safe to trust yet: the plan's own exit
  criterion for this step is a profile "checked" against a real device
  without breaking updates, and that checking has to happen against an
  actual Apple/Samsung/Xiaomi/Windows device over time - nothing this
  session did substitutes for that. Live verification (below) applies a
  profile only to the test-harness device, never a real phone.
- **(c) Resolver quality.** `adguard.py` gained `dns_config()` (confirmed
  against the live gateway to be `GET /control/dns_info`, not guessed)
  and `set_dns_tuning()`. A new read-only `/api/filtering/resolver`
  shows the current config plus DNS latency actually measured from this
  network's own `dns_elapsed_ms` telemetry (p50/p95, cache hits
  excluded) - not a synthetic benchmark. A separate
  `/api/filtering/resolver/apply` can apply the recommended tuning
  (optimistic caching, DNSSEC, two independent DoT upstreams in
  parallel with fallback), but only with an explicit `confirm=true` and,
  in the console, a native `confirm()` dialog naming exactly what it's
  about to do - changing DNS resolution for every device on the network
  at once is a shared-infrastructure action this project's own operating
  rules say to confirm before doing, not just before deploying the code
  that could do it. **This apply endpoint has not been called against the
  live gateway** - only the read-only side has, see below.

Smoke-tested locally (mocked `adguard._request`/`adguard.dns_config`,
an in-memory DB): rule tagging and the tag+expiry combination case,
profile apply/list/remove including the unknown-vendor 400 case, latency
percentiles including the empty-sample and cached-answer-excluded cases,
and the resolver endpoints including the confirm-required 400 case and
that the applied config carries exactly the intended fields.

**Deployed to the live gateway and verified the same day**, with the one
deliberate exception noted below. `.bak-5.5-*` copies of every replaced
file were taken first; `securepi-web` restarted cleanly.

What was actually exercised against the live gateway:
- `/api/native-profiles` and the read-only side of `/api/filtering/resolver`
  - the latter showing real measured latency (p50 10.9ms / p95 33.4ms over
  18 uncached samples in the last 24h) and confirming the gateway's actual
  current config: DNSSEC already on, optimistic caching still off, a
  single upstream provider (Cloudflare only, no Quad9/fallback yet) -
  exactly the gap 5.5(c) was meant to close.
- The native-profile apply/remove cycle, on the test-harness device
  (`[TEST HARNESS] test-victim`, id 5) only, never a real phone, per the
  caution in this step's own docstrings: applied the Xiaomi profile (3
  domains, correctly `$client`-scoped and `securepi-tag:xiaomi` tagged),
  confirmed via `/api/devices/5/filtering/rules`, then removed it and
  confirmed zero residue both on the device and in the network-wide rules
  list.
- `/api/filtering/check?domain=doubleclick.net` confirmed the new `cname`
  field is present and correctly `null` for an ordinary (non-CNAME)
  block, alongside the existing fields.
- Both new UI cards (`resolverQuality` on the Filtering page,
  `deviceProfiles` on the device page) confirmed present in the actually
  served HTML.

**Deliberately NOT called live: `/api/filtering/resolver/apply`.** This
is the one endpoint from this whole step that changes shared
infrastructure - DNS resolution for every device on the network - rather
than just adding a console feature, and per this project's own operating
rules that kind of action gets confirmed explicitly rather than folded
into a routine "deploy and verify" pass. The gateway is currently running
with DNSSEC on but optimistic caching off and only one upstream provider
configured; applying the recommended tuning (or doing it by hand through
AdGuard's own settings) is left as a deliberate next decision rather than
something this session did on its own judgment. Asked explicitly after
this step landed: left as-is for now, to move on to Stage 5C first.

**Note on step 5.6 (enrollment and CA lifecycle in the console),
implemented locally, not yet deployed.** Investigated live before writing
any code, which changed the shape of all three parts below from what the
plan assumed:

- **(a) Per-device toggle.** The plan assumed this would need "the
  orchestrator and root helper" - but `systemctl show securepi-web -p
  User` showed the console already runs as root (no `User=` in its
  systemd unit), the same reason `quarantine.py` was already able to
  call `nft` directly with no helper process. New `app/dpi_enroll.py`
  mirrors `quarantine.py`'s exact shape for the `ip nat enrolled` set,
  replacing the `sudo securepi enroll/unenroll` CLI with
  `POST /api/devices/{id}/dpi`. **Kept keyed on IP, not MAC** as the plan
  asked: doing that for real means changing the dpi-redirect rule itself
  to match on `ether saddr`, a change to the rule deciding which
  connections reach the inspection proxy at all - judged too risky to
  bundle into the same pass as everything else here, so it keeps the
  same DHCP-renewal limitation `quarantine.py` already documents.
- **(c) Auto-unenroll timer.** Rather than a polling sweep (5.2's
  pattern, needed there because AdGuard rules have no native expiry),
  `gateway/nftables.conf`'s `enrolled` set now declares `flags timeout`,
  so an element can carry its own TTL and the kernel expires it with no
  scheduler at all. This flag addition was reload-tested live on a
  throwaway nftables table *before* any code was written against it,
  which surfaced a real, easy-to-miss behaviour: `nft add element` on an
  element that already exists is a silent no-op **even when the new
  command specifies a different timeout** - it does not refresh the
  expiry. `dpi_enroll.enroll()` therefore always deletes the element
  first, then re-adds it fresh; the smoke test for this specifically
  asserts both calls happen, since without the live test this bug would
  have shipped invisibly (re-enrolling an already-enrolled device would
  silently NOT reset its 24h clock).
- **(b)/(d)/(e) Onboarding, CA info, and the reminder.** Folded into a
  new "Tier 2: HTTPS Ad Removal" card on the Filtering page rather than a
  separate onboarding route, matching this project's existing
  one-page-per-area pattern. `adguard`-style: a new `_ca_info()` reads
  the real CA file with `openssl x509` (no new crypto dependency) for
  its fingerprint and validity window; the existing plain-HTTP download
  URL `deploy-dpi.sh` already serves it from (finding A10, unresolved -
  not this step's job to fix) is surfaced as-is. **Automated CA
  rotation was explicitly NOT built**: generating a new 90-day CA
  invalidates every enrolled device's stored trust at once, which is
  too consequential to automate without a reviewed runbook step - this
  only ever reads the existing certificate. The **QR code** the plan
  asked for was also dropped: no Python QR-encoding library is
  installed on the gateway and adding one is a real dependency decision,
  not appropriate to make silently mid-implementation; a plain download
  link plus the fingerprint is what's there instead. The reminder to
  remove the CA from a no-longer-enrolled device is a static note on the
  card, not a per-device detection - the gateway has no way to see a
  phone's own certificate store, so it can't actually tell which devices
  still have the CA installed.
- **A genuinely new signal, not previously planned for this step:**
  `dpi/securepi_adfilter.py` gained a `tls_failed_client` hook, logging a
  new `tls_failed` telemetry decision whenever the handshake to a client
  fails - the most likely real cause being a device that hasn't
  installed the CA. `_tier2_breakdown()` picks it up automatically (it
  already reads whatever `dpi_action` values exist, no allowlist). A new
  `/api/filtering/dpi/enrolled` uses it for a best-effort CA-trust badge
  per enrolled device ("trusted" / "check_ca" / "unverified"), inferred
  from OUR side of the handshake outcome, not confirmed from the device
  itself. **This hook has not been exercised against a real failed
  handshake** - mitmproxy's `tls_failed_client` hook signature is
  recalled with high but not certain confidence and was not curled or
  tested against a real untrusted-device connection attempt, unlike
  everything else in this step. Specifically worth checking the next
  time a device is enrolled without the CA installed first (deliberately,
  as a test, on the test-harness device or a spare device - never a real
  phone as the first check).

Smoke-tested locally (mocked `subprocess.run`/`nft`, an in-memory DB):
`dpi_enroll`'s enrolled-set parsing for both the timeout and no-timeout
element shapes, and specifically that `enroll()` issues a delete before
its add; CA info parsing for both the success and "certificate not
found" cases; the trust-check flipping from "trusted" to "check_ca" when
a later `tls_failed` event is added.

**Deployed to the live gateway and verified the same day - and this is
the step where live verification caught two real bugs neither the local
smoke tests nor the earlier live nftables probe had surfaced.**
`.bak-5.6-*` copies of `/etc/nftables.conf`, `webapp.py`, both templates,
`app.js` and the DPI addon were taken first; `nft -c -f` checked the new
nftables config in the actual target path (not just a throwaway table)
before reloading; both real runtime sets (`enrolled`, `quarantine`) were
confirmed empty immediately before the reload, so there was nothing to
capture/restore this time. `securepi-web` and `securepi-dpi` both
restarted cleanly (mitmproxy's own script auto-reload had in fact already
picked up the new addon file before the explicit restart even ran).

**Bug found live #1 - `_ca_info()`'s fingerprint was silently never
populated.** `curl`ing `/api/filtering/ca` came back with every other
field but no `fingerprint_sha256` at all. Running the same `openssl x509
-fingerprint -sha256` command directly on the gateway showed why: the
real output line is `sha256 Fingerprint=...` (lowercase "sha256"), not
`SHA256 Fingerprint=...` as assumed from the flag's own name. Fixed to a
case-insensitive match; redeployed just `webapp.py` and re-curled - the
fingerprint now renders. Also confirmed live: the real CA is valid for
10 years (2026-2036), not a short-lived one - consistent with 5.6d's
rotation being out of scope, not a new problem this uncovered.

**Bug found live #2 - `unenroll()`'s "does not exist" check never
matched.** The very first enroll attempt against the test-harness device
failed outright, because `enroll()` calls `unenroll()` first (see the
docstring on why) and that unconditionally raised. The real nft error for
deleting a non-existent element from THIS set is `"Error: Could not
process rule: No such file or directory"` - confirmed by deliberately
provoking the same case against `quarantine.py`'s own set for comparison,
which instead prints `"Error: element does not exist"`. **The two sets
give genuinely different error text for the identical situation**,
because `quarantine` has `flags interval` and `enrolled` has `flags
timeout` - copying quarantine.py's exact string was not safe to assume.
Fixed with a small tuple of known "not found" markers instead of one
hardcoded string, redeployed, and confirmed the full cycle end to end
against the test-harness device only (never a real phone): enroll at 24h
→ nft shows `timeout: 86400` → re-enroll at 1h → nft shows the timeout
actually replaced with `3600`, proving the delete-then-add fix genuinely
resets the clock rather than merely not-erroring → unenroll → nft set
empty again → a second unenroll on the same (already-unenrolled) device
succeeds as a no-op rather than raising.

Also verified: the onboarding card (`dpiCaInfo`/`dpiEnrolledList`) and
the device-page toggle (`deviceDpi`) both present in the actually served
HTML; no errors in either service's journal across the whole test.

**Still not verified live: the `tls_failed_client` hook and the CA-trust
badge it feeds.** Nothing in this test cycle produced a real failed TLS
handshake (the test-harness device was enrolled but never actually
initiated HTTPS traffic through the proxy). Worth checking deliberately -
enroll a device without installing the CA first and confirm a `tls_failed`
row appears and the badge on `/api/filtering/dpi/enrolled` turns
"check_ca" - on the test-harness device or a spare device, never a real
phone as the first check.

**Note on step 5.7 (automatic privacy-scope verification), implemented
locally, not yet deployed - and substantially rescoped after a live
investigation showed the plan's exact design isn't safely buildable in
one pass.** The plan calls for "a canary client in a test namespace...
through the real redirect", i.e. exercising the actual nftables
PREROUTING rule with a live TLS handshake against mitmproxy. Investigated
before writing any code:

- `ip netns exec ns_victim ...` was the obvious first choice - it's the
  exact mechanism `gateway/evaluate.py` already uses for safe synthetic
  traffic. But `evaluate.py`'s own comments already establish that
  `ns_victim` sits on `br-test`, which "has no path to AdGuard" - it is
  NOT bridged onto `ap0`, the interface the dpi-redirect rule matches on.
  Traffic from `ns_victim` never reaches that rule at all.
- Tried connecting directly to `127.0.0.1:8080` (mitmproxy's redirect
  target) instead, with `openssl s_client -servername <host>`, for both
  an allowlisted and a non-allowlisted hostname. **Live result: identical
  immediate handshake failure for both** - mitmproxy's transparent mode
  needs the kernel's original-destination info that only a genuine
  nftables REDIRECT carries, so a direct connection can't even reach the
  point where it would distinguish the two cases.
- Wiring a synthetic client onto the real `ap0` ingress path (the only
  way to genuinely exercise the redirect rule) means network-topology
  changes to the interface the live AP and two real phones depend on -
  judged not safe to improvise mid-session. Using one of the two real
  enrolled devices as an unwitting scheduled canary target was also
  rejected: it would mean inspecting real traffic on a timer the device's
  owner never chose, against this project's own opt-in stance.

**What was built instead, and why it's a substitute rather than a
downgrade:** `dpi/privacy_canary.py` imports the addon file straight off
disk - the exact same file mitmproxy loads, re-imported fresh every
15-minute cycle so a fix or a regression is picked up immediately - and
calls its real `tls_clienthello()` method directly with a synthetic
ClientHello for a non-allowlisted host (`example.com`, must stay
passed-through) and an allowlisted one (`youtube.com`, must be
decrypted), reading the `ignore_connection` attribute the method itself
sets. This is precisely the code path, and precisely the attribute, the
report's own `ignore_conn` typo broke - **proven by a smoke test that
reintroduces that exact typo into a throwaway copy of the addon and
confirms the canary correctly flags it as a failure** (both hosts read
as "will decrypt" once the real attribute is never set, exactly as the
live bug once did). What this substitute genuinely can NOT catch: a bug
in the nftables redirect rule itself, or in how mitmproxy's transparent
mode reads the original destination - both sit entirely outside it. That
gap is real and stays open, not resolved by this substitute; closing it
needs the `ap0`-topology work called out above. Until then, the redirect
rule and traffic path should get a deliberate, manual check against a
real enrolled device from time to time, rather than being treated as
fully covered by this automated canary.

On failure: every enrolled device is unenrolled at once
(`dpi_enroll.flush()`, confirmed to be a real, valid nftables operation)
and a high-severity platform incident (`device_id=NULL`,
`signal_type='privacy_scope_failure'`) is raised - or, since
`correlation.raise_incident`'s own 600s dedup window is shorter than this
canary's 15-minute cycle, a NEW helper (`_raise_or_touch_incident`)
touches any still-open incident of that signal type regardless of how
long ago it was last seen, so a sustained failure reads as one ongoing
incident rather than a fresh one every cycle forever. "Notify" (the
plan's own word) is, honestly, a clear `print()` into the journal -
Stage 6's real notification system (R3) doesn't exist yet, matching the
same stopgap `webapp.py`'s filtering endpoints already use for an audit
trail.

The console's "Privacy scope verified N min ago" badge reads
`signal_state` (reusing the exact table/row shape the correlation engine
already uses for its own signals - no new table) and whether an open
`privacy_scope_failure` incident exists, via a new
`/api/filtering/dpi/privacy-scope` endpoint, shown on the Tier 2 card.

Smoke-tested locally: the real addon file's actual decrypt/passthrough
decisions for `example.com`/`youtube.com`/`m.youtube.com`; the
reintroduced-typo failure case described above; the incident
touch-not-duplicate behaviour across a 40-minute gap; `run_check()`'s
full pass and fail paths including that `dpi_enroll.flush()` is actually
called on failure; and all four states of the console's status endpoint
(never run, healthy, stale, failing). mitmproxy itself had to be stubbed
out for this local test (it's only installed in the gateway's bundled
venv) - this stub is test-only, not part of what gets deployed.

**Deployed to the live gateway and verified the same day, and this
mitmproxy-venv detail is exactly what the deploy caught.** `dpi/deploy-
privacy-canary.sh` installs the script and a new
`securepi-privacy-canary.service`, independent of `securepi-dpi`'s own
lifecycle. The very first manual run on the gateway (deliberately run
by hand before trusting the systemd service, not just pushed live blind)
failed with `ModuleNotFoundError: No module named 'mitmproxy'` - the
addon file this canary imports does `from mitmproxy import http`, and
mitmproxy is only installed inside the DPI venv, not the system Python
the deploy script's systemd unit was pointed at
(`/usr/bin/python3`). **Confirmed live and fixed:** the venv's own
`/opt/securepi-dpi/bin/python3` is itself just a symlink to
`/usr/bin/python3` - but invoking Python via that path (rather than the
bare system path) is what makes it pick up the venv's `pyvenv.cfg` and
add its site-packages to `sys.path`. Fixed `ExecStart` to use that path;
redeployed; the service now starts and imports cleanly.

What was actually exercised against the live gateway and the real
production database (not a mock):
- The very first real 15-minute cycle passed cleanly against the real,
  correct, deployed `securepi_adfilter.py` - journal shows "ok -
  passthrough and decrypt decisions both correct" - and the console's
  badge read `healthy: true` with the real elapsed age.
- **The fail-safe path, end to end, against production:** a throwaway
  copy of the real addon with the exact `ignore_conn` typo reintroduced
  (never the deployed file itself) was pointed at by one manual
  `run_check()` invocation. It correctly failed, raised a real incident
  (`id=24`, `device_id=null`, `severity=high`, the exact description
  text naming report §6), and the console badge immediately flipped to
  `failing: true` / `healthy: false` with the right `incident_id`. The
  `enrolled` set was confirmed unaffected only because it was already
  empty - `dpi_enroll.flush()` running against a genuinely populated set
  was not tested live this session (nothing is currently enrolled to
  safely test that against without affecting a real device). The test
  incident was then marked resolved and the throwaway file removed -
  nothing was left behind in the real incident queue.

**Still not resolved, restated plainly:** the gap this whole step's
rescoping was honest about - the real nftables redirect path and
mitmproxy's original-destination handling - remains unverified by any
automated check. This deploy proved the *decision logic* and the
*fail-safe machinery* both work correctly against production; it did
not and could not prove the *enforcement path* does, for the reasons
explained above.

**Note on step 5.8 (pinning-aware auto-passthrough), implemented locally,
not yet deployed.** Builds directly on 5.6's `tls_failed_client` hook:
`dpi/securepi_adfilter.py` now keeps two small in-process dicts on the
addon instance - `_pin_fail_count` and `_pin_bypass_until`, both keyed on
`(src_ip, sni)` - rather than a database table, since this is consulted
on every single TLS handshake decision and only ever holds entries for
the tiny number of (enrolled device, DECRYPT_SUFFIXES host) pairs that
could ever reach this code at all. State resets on a `securepi-dpi`
restart; documented as an accepted, honest trade-off rather than
something worth persisting.

After `PIN_FAILURE_THRESHOLD` (3, a starting value - no Settings page
exists yet to tune it, see finding C5) consecutive handshake failures for
the exact same pair, `tls_clienthello` starts passing that pair through
undecrypted for `PIN_BYPASS_HOURS` (24, from the plan) instead of
attempting to decrypt it again. The failure counter resets to zero the
moment a bypass is set, so a fresh streak is needed after the bypass
naturally expires - this project doesn't try to detect whether the
underlying pinning is still happening versus attempt it again "just in
case"; 24 hours of ad-supported-but-working is the accepted trade-off.

Reuses the existing Tier 2 telemetry pipeline with no schema change: a
new `pin_bypass` `dpi_action` value, with `dpi_ads_removed` repurposed to
carry the bypass's own expiry epoch (documented in `_log_event`'s
docstring) rather than a count - the same reuse-a-nullable-column
reasoning `schema.sql`'s header already gives for `tls_sni`/
`block_reason`. New `GET /api/filtering/dpi/pinned` surfaces currently-
active bypasses (grouped by device+host, filtered to `expires_at > now`)
as the console's "App pins its certificate - bypassed" list on the Tier 2
card; `_tier2_breakdown()` picks up the new action value automatically
for the analytics and per-device privacy panels.

Smoke-tested locally against the real addon file (mitmproxy stubbed out
for the test only, as in 5.7's test): the first attempt on a pair still
tries to decrypt; staying one failure below the threshold keeps trying;
reaching the threshold bypasses the very next attempt and resets the
counter; **a different device hitting the same pinned host is
unaffected** (the state is genuinely per-pair, not per-host); a
non-allowlisted host is untouched by any of this; and an artificially
expired bypass correctly stops applying. Also smoke-tested the new
console endpoint's grouping and expiry filter, and that
`_tier2_breakdown` reports the new counts.

**Deployed to the live gateway and verified the same day.** `.bak-5.8-*`
copies were taken first; both `securepi-web` and `securepi-dpi`
restarted cleanly (compiled first with the DPI venv's own
`bin/python3 -m py_compile`, same lesson 5.7's deploy already taught).
Restarting `securepi-dpi` resets its in-process pinning dicts, which is
the accepted trade-off described above - nothing was enrolled at the
time, so nothing real was affected either way.

What was actually exercised against the live gateway:
- The real, just-deployed `/opt/securepi-dpi/securepi_adfilter.py` was
  imported fresh in-process (same technique 5.7 used) via the DPI venv's
  `bin/python3`, using the test-harness device's IP - never a real
  phone - and driven through the exact `PIN_FAILURE_THRESHOLD` failures:
  confirmed `ignore_connection` flips to `True` only after the threshold,
  not before, against the actual deployed bytes.
- `GET /api/filtering/dpi/pinned` and the analytics `tier2` block both
  read correctly against real (empty) production state.
- A single synthetic `pin_bypass` row was inserted directly into the
  live production database for the test-harness device (id 5), to prove
  the endpoint's live SQL - grouping, the device-name join, and the
  `expires_at > now` filter - all work against the real schema, not just
  the local copy: it correctly resolved to `"[TEST HARNESS]
  test-victim"` with the right `expires_in_s`. The row was deleted
  immediately afterward; a follow-up query confirmed zero residue.
- Both Tier 2 UI cards' new markup (`dpiPinnedList`) confirmed present
  in the served HTML; journal clean across both services throughout.

**Note on step 5.9 (rule-set refactor and tests), implemented locally,
not yet deployed - built to the plan's exact scope, no more and no
less.** The plan names four constants to move: `AD_FIELDS`,
`AD_RENDERERS`, `BLOCKED_PATHS`, `DECRYPT_SUFFIXES`. Reading the addon
file to do this turned up a fifth, `HTML_PLAYER_PAGES`, that was already
dead code - declared but never once read anywhere in the addon's logic,
predating this session entirely. Rather than migrate an unused field
into a new console-editable file (where an operator would reasonably
assume editing it does something), it was dropped rather than carried
forward - a small, justified cleanup, not scope creep, and not one of
the four things the plan actually asked to move.

- New `dpi/adfilter_rules.py`: the shared default rule set and
  `validate_rules()`, deliberately dependency-free (stdlib only) so it's
  safe to import from both `dpi/securepi_adfilter.py` (needs mitmproxy,
  runs in the DPI venv) and `app/webapp.py` (must NOT need mitmproxy).
  Since this project's deployment has no shared site-packages between
  those two environments, the one source file in git gets installed to
  BOTH `/opt/securepi-dpi/adfilter_rules.py` and
  `/opt/securepi/adfilter_rules.py` - documented explicitly in the
  module's own docstring as a deliberate choice, not an oversight.
- New `dpi/adfilter-rules.json`, seeded from the exact values that used
  to be hardcoded, so nothing changes in practice on a fresh deploy.
- `securepi_adfilter.py`: `strip_ads()` now takes `ad_fields`/
  `ad_renderers` as explicit parameters instead of reading module
  constants - purely testable, no hidden dependency - and an optional
  `hits` dict it increments per matched rule name. A new
  `_ensure_rules_fresh()` checks `RULES_PATH`'s mtime (cheap enough to do
  on every hook call, not worth a timer) and reloads only on a real
  change; a missing or invalid file logs a warning and keeps whatever
  was already loaded, falling back to the built-in defaults on a cold
  start - a bad edit degrades to "keep working with the last known-good
  rules," never to broken ad-blocking. `_write_rule_stats()` snapshots
  hit counts to `RULE_STATS_PATH` via a temp-file-plus-atomic-rename,
  written only when a count actually changes (ad-stripping and
  path-blocking are both naturally infrequent enough events that this
  adds no meaningful I/O).
- Console: `GET/POST /api/filtering/dpi/rules` in `app/webapp.py`, using
  the shared `adfilter_rules.validate_rules()` so a bad edit is refused
  with the identical logic the addon's own loader uses - not a
  hand-rolled second copy that could quietly drift out of sync. A
  `decrypt_suffixes` change needs `confirm_privacy_scope_change: true`
  (mirroring step 5.5's resolver-tuning confirm gate) since it changes
  what this gateway is even able to decrypt; every edit requires a
  `reason` string, printed to the journal as the same audit stopgap
  every other filtering endpoint already uses pending Stage 1.5's real
  `audit_log` table. New "Tier 2 Rule Set" card on the Filtering page:
  one textarea per rule category (one rule per line), a hit-count
  summary next to each, and a `confirm()` dialog (matching the resolver
  card's own pattern) when the decrypt scope actually changes.
- New `tests/test_adfilter.py` (17 cases) plus a root `Makefile` with a
  `test` target - the plan's own exit criterion, `make test` covers the
  addon, verified to actually run and pass. Covers exactly the four
  things the plan's exit criterion names for `strip_ads` (nested fields
  removed at varying depth, ad renderers dropped from lists with
  everything else preserved in order, real content preserved, output
  still valid JSON via an actual `json.dumps`/`json.loads` round trip)
  plus hit-counter accuracy and `validate_rules()`'s full rejection
  surface. mitmproxy is stubbed out for these tests, the same technique
  steps 5.7 and 5.8 already used locally, documented in the test file's
  own docstring as test-only.

Both `make test` (17/17) and every earlier smoke test in this session
were re-run after this change with no regressions - the new
`import adfilter_rules` in `webapp.py` meant every earlier smoke script
needed `dpi/` added to its own `sys.path`, which surfaced as an honest
`ModuleNotFoundError` (not a hidden failure) and was fixed before moving
on, not worked around.

**Deployed to the live gateway and verified the same day**, including
one verification step stronger than anything possible locally: `.bak-
5.9-*` copies were taken first; `adfilter_rules.py` was installed to
*both* `/opt/securepi-dpi/` and `/opt/securepi/` as designed; both
services compiled cleanly (webapp side with system `python3`, addon
side with the DPI venv's `bin/python3`) before either was restarted.

- **`make test`'s 17 cases were run a second time on the gateway
  itself, against the real, just-deployed addon file and the REAL
  installed mitmproxy package** - not the local stub. All 17 passed
  with no changes needed, the strongest confirmation yet that the
  local-stub testing technique this session has leaned on (5.7, 5.8,
  and this test file itself) hasn't been hiding a real divergence from
  actual mitmproxy behaviour.
- **Hot-reload was verified end-to-end against the real deployed addon
  file**, in-process via the DPI venv's `bin/python3` (the same
  technique 5.7/5.8 used): loaded with one rule set, the rules file was
  edited and re-checked - the new rule appeared without recreating the
  object; the file was then replaced with deliberately invalid JSON and
  re-checked again - the addon kept the last known-good rules rather
  than crashing or reverting to built-in defaults.
- **The real `POST /api/filtering/dpi/rules` endpoint was exercised
  against production**, not a temp path: the actual current rules were
  read first, one harmless test field (`zzzTestField`) was added via a
  real request with a `reason`, confirmed to land in
  `/opt/securepi-dpi/adfilter-rules.json` and in the journal's audit
  line (`filtering: DPI rules updated to version 2 - ...`), then
  reverted with a second real request back to exactly the shipped
  default field list. Restarting `securepi-dpi` was NOT needed for any
  of this - by design, and the point of the whole step.
- The `confirm_privacy_scope_change` gate was deliberately NOT
  re-exercised against production (it's already covered exhaustively in
  the local smoke test) - changing what this gateway can decrypt, even
  as a reverted test, was judged not worth the risk for a case the
  local test already proves thoroughly, the same caution 5.5's resolver
  tuning apply endpoint got.
- The new "Tier 2 Rule Set" card's markup confirmed present in the
  served HTML; journal clean across both services throughout.

**Note on step 5.10 (effectiveness watchdog and SSAI readiness),
implemented locally, not yet deployed.** Unlike 5.7's privacy-scope
canary, this needed no separate process or mitmproxy access: it's a
new fifth signal, `adblock_effectiveness_signal`, added to
`app/correlation.py`'s existing `SIGNALS` list and picked up
automatically by the already-running `engine.py` service on its normal
15-second cycle - the same reuse-what-already-exists reasoning that put
5.7's fail-safe incident through the same `incidents` table rather than
a bespoke one.

- **Logic:** a windowed query over `events` (`source='dpi'`) per device:
  count YouTube-family decrypt activity (`dpi_action IN ('decrypt',
  'ads_stripped')`) in the last `EFFECTIVENESS_WINDOW_SECONDS` (3600,
  "a configured period" per the plan); if that count is at least
  `EFFECTIVENESS_MIN_YOUTUBE_EVENTS` (5, enough real activity to judge
  by rather than one stray handshake) and **zero** of those events are
  `ads_stripped`, raise a medium-severity `adblock_ineffective` incident
  through the same `raise_incident()` every other signal uses -
  dedup, evidence chain and all, for free.
- Registered in `webapp.py`'s `SIGNALS` list too, so `/api/system`
  tracks its own staleness the same way it already does for the other
  four signals.
- New `GET /api/filtering/dpi/effectiveness` and an "Effectiveness"
  badge on the Filtering page's Tier 2 card (green when no open
  `adblock_ineffective` incident exists, red and linking to the
  incident when one does) - not named in the plan's own exit criteria
  for this step, but a small, proportionate addition matching the
  already-built privacy-scope badge's exact pattern, so the watchdog's
  own status is visible rather than only surfacing through the general
  incident queue.
- **SSAI documented as the expected end state**, per the plan's own
  wording - not in this plan document, but in `REPORT-adblocking.md`
  (§8, "Limitations, stated plainly"), the document this project's own
  report material actually lives in. Explains precisely why SSAI is a
  structural end state no rule update can fix (the ad is spliced into
  the same media segments as real content, so there is no longer a
  distinguishable scheduling instruction for a JSON-stripping proxy to
  remove) and points to this signal as the detection mechanism for when
  that day arrives. Also corrected the report's pre-existing "mobile
  apps unaffected" limitation row while touching that table, to reflect
  step 5.8's auto-passthrough (a pinned app now works, just without ad
  removal, instead of being left permanently broken) - a small, honest
  update prompted by work already completed this session, not scope
  creep.

**Exit criterion "removing a rule in a test deploy makes the watchdog
fire" is satisfied by composition, not a redundant end-to-end test:**
step 5.9's own fixture tests already prove `strip_ads()` returns 0 when
a field is absent from `ad_fields`/`ad_renderers`; `response()`'s
existing `if removed:` guard (unchanged by this step) is the one place
that decides whether an `ads_stripped` telemetry event is written at
all; and this step's own smoke test #1 below proves the watchdog fires
exactly when YouTube decrypt activity continues with zero `ads_stripped`
events. Chaining these three already-proven, unchanged-by-each-other
behaviours together end to end would exercise no code path not already
covered twice over - so it wasn't built as a fourth redundant test, and
that reasoning is recorded here rather than left implicit.

Smoke-tested locally (in-memory DB, no mocks needed - this is a pure SQL
signal like the other four): active decrypting with zero stripped fires
with the correct title/severity/device; the same activity WITH at least
one `ads_stripped` does not false-alarm; one stray handshake below the
minimum-activity floor does not false-alarm; activity outside the
window is ignored; a sustained failure across two cycles extends one
incident rather than duplicating; registration in both `SIGNALS` lists
confirmed. Also smoke-tested the new status endpoint's healthy/unhealthy
shapes.

**Deployed to the live gateway and verified the same day - end to end,
against real production data, exactly matching the plan's own exit
criterion.** `.bak-5.10-*` copies were taken first; `securepi-engine`
and `securepi-web` both restarted cleanly; `correlation.run_all()` was
run by hand against the real database immediately after (not just
waited for the next 15s cycle) and returned
`{'adblock_effectiveness_signal': 0, ...}` alongside the four existing
signals, all clean, no exceptions.

**Then the plan's exact scenario was reproduced live:** six synthetic
`decrypt`-only DPI events (device 5, `[TEST HARNESS] test-victim` - never
a real device) were inserted directly into the production database,
`run_all()` was re-run, and it fired:
`{'adblock_effectiveness_signal': 1, ...}`. The resulting incident
carried the exact right title ("YouTube ad removal may no longer be
effective"), the SSAI-aware description, `severity: medium`,
`evidence_count: 6`, and correctly resolved to
`"[TEST HARNESS] test-victim"`. `GET /api/filtering/dpi/effectiveness`
immediately reflected it (`healthy: false`, the right `incident_id`).
The incident was then marked resolved and the synthetic events deleted;
a follow-up query confirmed zero residue and the endpoint read
`healthy: true` again. This is a stronger, more literal proof of the
plan's own "removing a rule... makes the watchdog fire" criterion than
the by-composition reasoning above alone - both now stand together.

The new "Effectiveness" badge's markup confirmed present in the served
Filtering page HTML; journal clean across both services throughout.

**Note on step 5.11 (optional - cosmetic and scriptlet injection),
implemented locally, not yet deployed - explicitly scoped to Path 1
only, decided together with the user before any code was written.**
See the "Open follow-up on 5.11" callout right after the Stage 5C table
above for the full Path 1 vs. Path 2 record; this note covers what was
actually built.

- **`dpi/adfilter_rules.py`** gained two optional keys,
  `cosmetic_injection_enabled` (bool, default `False`) and
  `cosmetic_selectors` (a list of CSS selectors - custom-element tag
  names matching YouTube's kebab-case convention for its ad renderers,
  **not verified against a live youtube.com page this session**, since
  a wrong or stale selector is a silent no-op rather than a breakage
  risk - see the Path 1/Path 2 record for why that asymmetry mattered
  to the scoping decision itself). Deliberately NOT added to
  `REQUIRED_RULE_KEYS`: a rules file written before this step (the live
  gateway's real one, at the time of writing) has neither key at all,
  and must keep validating successfully with the feature off, not start
  failing. A new `apply_defaults()` backfills both keys only when
  they're absent, explicitly never overwriting an operator's own choice
  (including a deliberately empty selector list) - `load_rules()` now
  calls it after `validate_rules()`.
- **`dpi/securepi_adfilter.py`** gained two new pure functions:
  `inject_cosmetic_css(html_text, selectors)` (inserts one `<style>`
  block right before `</head>`, falling back to just after `<body>`,
  falling back to prepending the whole document - a wrong selector
  matches nothing and changes nothing) and
  `loosen_csp_for_inline_style(csp_header)` (adds `'unsafe-inline'` to
  a response's `style-src`, or `default-src` if there's no `style-src`
  directive, so the injected `<style>` tag isn't blocked by the page's
  own Content-Security-Policy - **and only ever touches the style
  policy**, never `script-src`, proven by its own dedicated test). Both
  wired into `response()`'s existing HTML branch, gated behind
  `cosmetic_injection_enabled`, logging a new `cosmetic_injected`
  telemetry decision (`dpi_ads_removed` repurposed once again, this
  time to carry the count of configured selectors - the addon does not
  parse the page to know which ones actually matched anything, by
  design, matching the no-DOM-parsing philosophy the existing
  `ad_fields` HTML-neutralisation branch already uses).
- **Console:** `DpiRulesUpdate` gained `cosmetic_injection_enabled`/
  `cosmetic_selectors` as `Optional` fields defaulting to `None`, NOT
  `False`/`[]` - a real, deliberately-avoided bug: a Pydantic default of
  `False`/`[]` would mean any edit that only means to touch, say,
  `blocked_paths` would silently wipe an operator's cosmetic settings
  back to disabled every time, since FastAPI has no way to distinguish
  "the field was omitted" from "the field was explicitly set to its
  default." `api_dpi_rules_set` merges `None` fields against what's
  already on disk instead. A dedicated smoke test proves exactly this
  scenario: enable cosmetic injection with custom selectors, make an
  unrelated `blocked_paths`-only edit, confirm the cosmetic settings
  survived untouched. The "Tier 2 Rule Set" card gained a toggle and a
  selectors textarea, saved together with everything else through the
  existing single "Save rules" button - no separate save path to keep
  in sync.
- **`REPORT-adblocking.md`'s and `FIRST-PARTY-ADS-ANALYSIS.md`'s**
  overstated claims were both corrected as part of this same step (the
  plan's own A12 finding): `FIRST-PARTY-ADS-ANALYSIS.md` §5 and §5.1
  originally stated cosmetic filtering "remains impossible" after MITM
  and that scriptlet-style JS rewriting is a capability "TLS
  interception does not confer" - both corrected in place (marked
  "Corrected 2026") to the accurate, more nuanced position: both are
  technically possible, cosmetic injection was built because it's
  low-risk, scriptlet injection was deliberately deferred because it
  isn't, and licensing was never actually the barrier either claim
  implied.

**Exit criterion "no functional breakage in a 10-video check" is
explicitly NOT met, and can't be from this session.** That check needs
a real device actively browsing real youtube.com pages through the
actual Tier 2 pipeline - the same infrastructure gap 5.7's follow-up
already identified (no namespace bridged onto the real `ap0` path), and
CSS injection makes the *consequence* of skipping this check low
(wrong selector = nothing visible happens) rather than the check being
unnecessary. This should be verified deliberately, on a real enrolled
device, before cosmetic injection is turned on for daily use - it ships
here disabled by default specifically so that verification can happen
on the user's own schedule rather than being implied as already done.

Smoke-tested locally (35 cases in `make test`, up from 17): every
`inject_cosmetic_css` anchor-selection path (head-close present, falls
back to post-`<body>`, falls back to prepend, multiple selectors, output
still contains every original fragment); every `loosen_csp_for_
inline_style` case including the one that matters most structurally
(`script-src` is provably never touched); `apply_defaults` both filling
in absence and refusing to overwrite an explicit empty list;
`validate_rules` accepting a file with neither optional key and
rejecting a non-bool `cosmetic_injection_enabled` or a non-string-list
`cosmetic_selectors`; and the console's None-preserves-existing-value
merge behaviour end to end.

**Deployed to the live gateway and verified the same day**, including
the graceful-upgrade path this step's design specifically exists for.
`.bak-5.11-*` copies were taken first; `adfilter_rules.py` reinstalled
to both `/opt/securepi/` and `/opt/securepi-dpi/`; **all 35 `make test`
cases re-run on the gateway itself against the real deployed files and
the real mitmproxy package** (same technique 5.9's deploy used) - all
35 passed with no changes needed.

- **The graceful-upgrade path was proven, not just asserted:** the live
  gateway's real `adfilter-rules.json` predates this step (written
  during 5.9's own deploy testing, no `cosmetic_*` keys at all). After
  restarting `securepi-dpi`, the journal read `rules reloaded from
  /opt/securepi-dpi/adfilter-rules.json (version 3)` with no error -
  `apply_defaults()` backfilled both new keys silently and correctly.
  `GET /api/filtering/dpi/rules` immediately confirmed it:
  `cosmetic_injection_enabled: False`, `cosmetic_selectors` populated
  with the full default list - exactly the "off by default, nothing
  breaks for an existing deployment" contract this step's design
  promised, now proven against production rather than only a fixture.
- **Both new pure functions verified against the real deployed addon
  file**, imported fresh in-process via the DPI venv's `bin/python3`
  (same technique 5.7/5.8/5.9 used): `inject_cosmetic_css()` correctly
  placed a `<style>` block before `</head>` in a realistic fragment
  containing a real `<ytd-display-ad-renderer>` element and real
  content, both preserved; `loosen_csp_for_inline_style()` correctly
  added `'unsafe-inline'` to `style-src` on a three-directive CSP header
  while leaving `script-src 'self' 'nonce-abc'` provably byte-for-byte
  untouched.
- **The real console endpoint was exercised end to end against
  production**, not a temp path: current rules were captured first, a
  real `POST` enabled cosmetic injection with the full default selector
  list, confirmed via `GET` (`cosmetic_injection_enabled: True`) and in
  the journal's audit line, then immediately reverted to `False` with a
  second real request - **left disabled**, deliberately, since the "no
  functional breakage in a 10-video check" exit criterion still hasn't
  been met and shouldn't be implied by leaving the feature live. A
  follow-up `GET` confirmed the revert.
- The new toggle + selectors textarea confirmed present in the served
  Filtering page HTML; journal clean across both services throughout.

This closes Stage 5 (steps 5.1 through 5.11, with 5.11 scoped to Path 1
as recorded above) - every step implemented, locally tested, deployed
to the live gateway, and verified against real production data or the
real deployed code, with every deliberate scope reduction (5.6's
IP-vs-MAC keying, 5.7's substitute canary, 5.9's dropped dead constant,
5.11's Path 2 deferral) recorded with its reasoning rather than left
implicit.

## Stage 6 progress notes

**Note on step 6.1 (behavioural baselines), implemented locally.** Stage
6 as written assumes pieces of Stages 1-4 that don't exist yet; 6.1
specifically needs `device_hourly` (Stage 1's F3, "Retention + hourly
rollups"), which hasn't been built. Rather than block on Stage 1 or fake
the dependency, the minimal necessary piece was built as part of this
step, clearly scoped as exactly that - not the full F3 feature:

- **`app/schema.sql`** gained the `device_hourly` table (one row per
  device per closed hour: bytes down/up, DNS queries/blocked, flows).
  Since `ingest.py`'s `open_db()` only re-runs the *entire* schema.sql
  on a genuinely fresh database - an existing one (the live gateway's)
  only ever gets `apply_migrations()`'s statement list - the `CREATE
  TABLE`/`CREATE INDEX IF NOT EXISTS` statements were also added to
  `SCHEMA_MIGRATIONS`, which until now only ever held `ALTER TABLE`
  statements for new columns. They need no try/except wrapping the
  existing entries do (a "duplicate column" error has no equivalent for
  `IF NOT EXISTS` DDL - it's already idempotent by construction),
  documented in that list's own updated comment. Verified with a smoke
  test that specifically simulates the live gateway's actual situation
  (an existing DB, `device_hourly` absent) rather than only a fresh one.
- **New `app/rollup.py`**: `rollup_closed_hours()` aggregates every
  fully-closed hour that doesn't have a `device_hourly` row yet, resuming
  from the table's own `MAX(hour_start)` - no separate watermark table,
  matching how `ingest_state`/`signal_state` already read their own
  progress back from the data. Naturally a no-op on any cycle where
  nothing new has closed, which is what let it ride `engine.py`'s
  existing 15-second loop (called right before `correlation.run_all()`,
  so a freshly-closed hour is visible to the baseline signal the same
  cycle it closes) instead of getting a fourth new systemd service this
  session. Explicitly does NOT prune raw events - that's F3's job,
  still to come; this table only ever grows.
- **`app/correlation.py`** gained a sixth signal,
  `behavioral_baseline_signal`: for each device with real activity in
  the current (still-open) hour, compares it against that device's own
  `device_hourly` history at the SAME hour-of-day (not a flat trailing
  window - a smart TV at 9pm and a sensor at 3am have different normal
  volumes for themselves), using a z-score against that history's mean
  and sample stdev. Two independent gates before anything is judged:
  `BASELINE_MIN_SAMPLES` (7 - "learning badge until 7 days of data
  exist," from the plan) same-hour-of-day historical rows, and
  `BASELINE_MIN_BYTES_FLOOR` (5 MB) so a tiny device's relatively-large
  but absolutely-trivial jump can't fire. "Learning" isn't a separate
  mode in the signal itself - a device below the sample-count gate is
  simply never judged, full stop, not judged against a thin baseline.
- **Console:** `GET /api/devices/{id}/baseline` and a "Baseline" badge
  next to the existing risk-score chip on the device page. Deliberately
  uses a SIMPLER approximation for display (days since `devices.
  first_seen` >= 7) rather than replicating the signal's own precise
  per-hour-of-day sample count - good enough to tell an operator "give
  it about a week," not meant to make the actual detection decision,
  which stays entirely in `correlation.py`.

**The real gateway's own history is honestly too short to test this
against live yet** - confirmed by checking directly: only ~35 hours of
real event history exist (`min(ts)` to `max(ts)` across `events`), a
project barely two days old, nowhere near
`BASELINE_MIN_SAMPLES`'s 7-day threshold. This isn't a gap in the
implementation - it's genuinely where the project's real deployment
timeline is, and it's exactly the case the plan's own "learning badge"
concept exists for. The signal logic itself was proven correct with
synthetic `device_hourly` history for the test-harness device (matching
this session's established precedent of using synthetic data on that
one device, never a real one, to prove logic no real history can yet
exercise), directly against the plan's own exit criterion wording:

Smoke-tested locally: the migration path on a simulated pre-6.1
database; `rollup.py`'s aggregation, idempotent resume, that the
in-progress hour is never rolled up early, and that a quiet hour
produces no row rather than a zero row; **"harness bulk upload fires"**
(10 days of ~2 MB/hour seeded history, then a 500 MB hour - fires) and
**"normal days don't"** (the same history, an ordinary ~2.1 MB hour -
does not fire) as two literal, named test cases; a device below the
7-sample threshold is never judged even against a huge spike; amounts
below the 5 MB floor never fire regardless of relative jump; and the
console endpoint's learning/normal/flagged states.

**Deployed to the live gateway and verified the same day**, including an
online SQLite backup taken first (`securepi.db.pre-6.1-migration-*.bak`,
this session's first genuine schema migration against production since
5.1's) and `.bak-6.1-*` copies of every replaced file. Migration order
mattered here and was followed deliberately: `securepi-ingest` (the only
process that calls `apply_migrations()`) was restarted and confirmed to
have created `device_hourly` and its index **before** `securepi-engine`
was restarted - `correlation.connect()` is a bare `sqlite3.connect()`
with no migration logic of its own, so starting the engine first would
have crashed `rollup.py`'s very first query against a table that didn't
exist yet.

- **The automatic engine-loop integration proved itself without being
  asked to:** a manual `rollup.rollup_closed_hours()` invocation run
  shortly after `securepi-engine`'s restart returned 0 new rows - not
  because rollup was broken, but because the live engine's own 15-second
  loop had already rolled up every closed hour on its own in the
  ~30-60 seconds since restart. Checking `device_hourly` directly
  confirmed **25 real rows for the two real devices**, with sensible
  real numbers (e.g. one phone's real hourly download reaching 862 MB) -
  a stronger proof than a manual one-off call would have been, since it
  demonstrates the actual production wiring works unattended.
- `correlation.run_all()` run by hand immediately after confirmed all
  six signals execute cleanly against production, `behavioral_baseline_
  signal` included, with zero exceptions and zero false positives on
  real data.
- `GET /api/devices/{id}/baseline` against both real phones correctly
  read `learning: true, days_seen: 1.1` - an honest reflection of how
  young this deployment actually is, not a synthetic success.
- **The plan's exact "harness bulk upload fires" scenario was then
  reproduced live against production**, on the test-harness device only:
  10 days of ~2 MB/hour `device_hourly` history seeded directly, plus a
  real 500 MB spike in the events table for the current hour.
  `behavioral_baseline_signal` fired correctly (`z=595626.7` given how
  extreme the seeded spike was), the resulting incident named the right
  device, a sensible description, and `severity: medium`; the console's
  `flagged` field flipped to `true` immediately. Notably, `learning`
  stayed `true` on the same device throughout - correctly demonstrating
  that the console badge's simpler days-since-first-seen check and the
  signal's own precise per-hour-of-day sample gate are genuinely
  independent, exactly as designed, rather than one silently standing in
  for the other. The incident was marked resolved and every synthetic
  row (`device_hourly` and the event) deleted; a follow-up query
  confirmed zero residue and the endpoint read `learning: true, flagged:
  false` again.
- Journal clean across `securepi-ingest`, `securepi-engine` and
  `securepi-web` throughout; the new baseline badge markup confirmed
  present in the served device page HTML.

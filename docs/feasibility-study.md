> **Archived here by `ENHANCEMENT-PLAN.md` step 0.1, 14 September 2026.** This
> is the original pre-implementation study — the 38-week full-scope roadmap.
> It's kept as the reference for architecture reasoning and the final report;
> the actual build followed the compressed `SECUREPI-15-DAY-PLAN.md` and is
> now steered by `ENHANCEMENT-PLAN.md`. Nothing below has been updated to
> match what was actually built — see those two documents for that.

# SecurePi Gateway — Feasibility Analysis, Architecture & Roadmap

**Document type:** Pre-implementation feasibility study and engineering blueprint
**Date:** 2026-09-12
**Scope:** Final-year engineering project, solo developer, ~15-device small-enterprise network
**Status:** No code. Research, architecture, technology selection, scope, roadmap.

---

## Context

You are planning a final-year project that unifies **network monitoring**, **network-level ad blocking**, and a **lightweight SOC** into one platform for a ~15-device small-enterprise network. You explicitly do not want to reinvent mature technology — you want to select the best open-source engines and build the integration, orchestration, correlation, and presentation layer on top, presented as one product.

Three constraints from your clarifications drive most of what follows:

1. **Router capability is unknown and must stay unknown.** The architecture must not depend on whether your router supports bridge mode, VLANs, port mirroring, or custom DNS.
2. **A laptop is the intended compute host**, with a Raspberry Pi as an optional participant whose role is to be determined, not assumed.
3. **This is a controlled demo/lab network, not production.** You can build a separate test network. Zero-downtime is not a hard requirement.

Point 3 is the most important thing you told me, and it changes the answer substantially. It is what makes point 1 solvable rather than merely tolerated.

---

## 1. Executive Summary

**Verdict: Feasible, and well-matched to a final-year project — but only after two significant scope corrections.**

The concept is sound. The three capabilities are not three separate systems; they share one substrate (traffic passing through a controlled point) and one data model (events attributable to a device). Combining them is not merely possible, it is the natural design. Ad blocking is not a bolt-on feature — the DNS resolver is one of the richest security telemetry sources on a small network, and treating it as a SOC sensor rather than a convenience feature is the insight that makes the platform coherent.

Two corrections are required:

**Correction 1 — Stop treating router control as a variable to solve for.** Rather than analysing "what can we do given an unknown router," build a dedicated project LAN *behind* SecurePi Gateway, with the existing router demoted to a plain upstream uplink. The gateway then owns DHCP, DNS, routing, and NAT for its own subnet. This requires zero configuration changes on the existing router, works identically whether the router is a locked ISP box or a fully-flashable OpenWrt unit, and confines every failure to the project network. The router-control question disappears rather than being answered.

**Correction 2 — The Raspberry Pi should not be in the data path in version 1.** Splitting the data plane (Pi) from the analysis plane (laptop) requires either traffic mirroring across an extra interface or running the sensor on the Pi anyway, and it forces the control plane to manage two hosts with partial-failure states. That is real distributed-systems work with no proportional academic payoff. The laptop has ample headroom for 15 devices. The Pi earns its place later as a *second independent sensor*, which proves the ingest layer is sensor-agnostic — a far better demonstration than using it as a bridge.

Beyond that, the scope needs a sharp line between what is integrated and what is built. The IDS, a DNS filtering resolver, PostgreSQL, and nftables are integrated. The **unified data model, device identity resolution, correlation engine, policy orchestration layer, risk scoring, response framework, and SOC console are the project.** That distinction is what makes this defensible as engineering work rather than a configuration exercise, and it should be stated explicitly in the thesis.

The single largest technical risk is not performance — it is **storage growth from the IDS's event stream**, which will produce roughly 0.5–2 GB/day of raw JSON if handled naively. This is solvable with normalization and tiered retention, but it must be designed in from day one, not discovered in month five.

---

## 2. Overall Feasibility Verdict

| Dimension | Verdict | Confidence | Notes |
|---|---|---|---|
| Technical feasibility | **Feasible** | High | All required capabilities exist as mature OSS; integration is the work |
| Deployment/topology | **Feasible** | High | Router-agnostic design removes the main unknown |
| Hardware adequacy | **Feasible, comfortable** | High | Modern laptop is over-provisioned for 15 devices |
| Performance at 15 devices | **Feasible** | Medium-High | IDS throughput ceiling must be measured, not assumed |
| Storage sustainability | **Feasible with design effort** | Medium | Naive approach fails within weeks; requires deliberate schema + retention |
| Solo delivery in an academic year | **Feasible with strict scope control** | Medium | Requires the MVP gate in §13 to be enforced |
| Academic depth | **Strong** | High | Genuine original contribution in correlation, identity, orchestration |
| Novelty/originality | **Adequate, needs framing** | Medium | Not novel research; novelty is in integration design and the correlation model. Must be argued explicitly (see §17) |

**Where the project would fail if unmanaged:** scope creep into an enterprise SIEM, attempting TLS interception, attempting ML-based detection as a core claim, or spending the year on infrastructure and having no correlation logic to show.

---

## 3. Assumptions

These are stated explicitly so they can be challenged and so the evaluation numbers are interpretable.

| # | Assumption | Basis | If wrong |
|---|---|---|---|
| A1 | ~15 devices: mix of laptops, phones, and IoT | Your brief | Scales to ~50 without redesign |
| A2 | Internet uplink 50–300 Mbps typical, ≤1 Gbps peak | Typical Indian broadband, 2026 | >1 Gbps requires throughput re-measurement |
| A3 | Sustained LAN↔WAN throughput averages 5–50 Mbps, bursts to line rate | Small-office traffic profile | Higher sustained load raises IDS drop risk |
| A4 | Laptop has ≥4 physical cores, ≥8 GB RAM, ≥128 GB free SSD | Stated as primary host | 4 GB RAM forces dropping IDS rule categories |
| A5 | A dedicated Linux install (bare metal or dual-boot) is acceptable on the host | Required for reliable packet capture | VM-based hosting adds latency and NIC passthrough complexity |
| A6 | You can add a cheap unmanaged switch, a USB-Ethernet adapter, and a dumb AP (~₹3,000 total) | You indicated budget flexibility | Without an AP, wireless devices can't join the project LAN; falls back to Model C (§5) |
| A7 | Devices on the project LAN are yours or consenting participants | Ethical/legal necessity | Monitoring non-consenting users is not acceptable; see §12.6 |
| A8 | Timeline is one academic year (~8 months of usable working time), solo | Your answer | One semester requires cutting to MVP-only (§13) |

---

## 4. Technical Feasibility of Combining the Three Capabilities

### 4.1 What each capability actually requires

| Capability | Requires | Natural observation point |
|---|---|---|
| Network monitoring | Per-device flow records, bandwidth accounting, protocol breakdown, device inventory | Any point all traffic traverses |
| Ad blocking | Authoritative DNS for the LAN + blocklist evaluation + per-client policy | The DNS resolver clients are configured to use |
| SOC | Security events, attribution to a device, correlation over time, storage, alerting, response | Same traffic point + the DNS resolver + the firewall |

The three capabilities converge on the same requirement: **a single point that all traffic passes through, where the platform is also the DNS authority.** Once you have that, all three fall out of the same data. This is why unification is genuinely the right design rather than a marketing framing.

### 4.2 How they reinforce each other

This is the part worth writing up in the thesis, because it is the argument for the platform existing at all:

- **DNS → SOC.** DNS query logs are the highest-value, lowest-cost security telemetry on a small network. Malicious-domain lookups, DGA patterns, NXDOMAIN bursts, and DNS-tunnelling exfiltration are all visible in DNS alone, with no packet inspection and no encryption problem. A device querying a known-bad domain is a stronger signal than most packet-level alerts.
- **SOC → DNS.** Correlation output feeds blocking policy. A device flagged as compromised can have its DNS policy tightened automatically, and a domain observed in an incident can be added to the blocklist network-wide.
- **Monitoring → both.** Flow records provide the baseline that turns "this device made 400 connections" into "this device made 400 connections, which is 8× its 14-day norm."
- **Ad blocking → monitoring.** Blocked-query volume is itself a monitoring metric, and per-device blocked ratios reveal ad-heavy or telemetry-heavy devices.

An ad blocker running standalone next to an IDS running standalone gets none of this. The integration is the value.

### 4.3 What must be built vs. delegated

| Function | Decision | Rationale |
|---|---|---|
| Packet capture, protocol parsing, signature matching | **Delegate** | The IDS. Reimplementing this is a multi-year effort and adds nothing |
| DNS resolution, caching, blocklist evaluation | **Delegate** | Solved comprehensively. Correctness bugs here break the network |
| DHCP service | **Delegate** | Solved; needed anyway |
| Packet forwarding, NAT, firewall | **Delegate** | Linux kernel + nftables |
| Time-series storage, indexing, retention | **Delegate** | PostgreSQL/TimescaleDB |
| Event normalization across sources | **Build** | No off-the-shelf tool knows our unified schema |
| Device identity resolution | **Build** | The genuinely hard, genuinely original problem |
| Stateful correlation → incidents | **Build** | Core academic contribution |
| Risk scoring | **Build** | Core academic contribution |
| Policy orchestration across engines | **Build** | This is what makes it one platform |
| Response actions with audit + rollback | **Build** | Core |
| Unified console | **Build** | The "unified platform" requirement |
| Health supervision / fail-safe behaviour | **Build** | Reliability engineering, and a good evaluation axis |

### 4.4 Hard limitations that must be accepted, not engineered around

These are physics and protocol design, not implementation gaps. State them in the thesis as design constraints, not as failures.

| Limitation | Consequence | Handling |
|---|---|---|
| TLS encrypts payloads (~95%+ of traffic) | No content inspection | Metadata-based detection: SNI, JA4 fingerprints, certificate data, flow size/timing patterns. This is the modern standard approach, not a compromise |
| Encrypted Client Hello (ECH) is increasingly deployed | SNI hidden on some connections | Falls back to IP + JA4 + flow shape. Note as a measured limitation |
| DoH/DoT bypasses the DNS filter | Ad blocking and DNS telemetry defeated | Detectable and blockable — see §11.3. Convert into a feature |
| Wi-Fi client↔client traffic never reaches the gateway | Lateral movement between wireless devices invisible | Enable AP client isolation on the project AP. Document the trade-off (breaks mDNS/casting) |
| No host agents | No process, user, or file-level visibility | Explicitly out of scope. Network-only SOC is a legitimate, defensible scope |
| MAC randomization on modern phones | Device identity churns | Handled by the identity resolution layer (§9.2) — this is an opportunity, not just a risk |

---

## 5. Network Topology and Deployment Analysis

### 5.1 Candidate models

I evaluated seven deployment models. Router-control dependency is called out because it is your stated unknown.

#### Model A — Passive tap / SPAN sensor (out-of-band)

```
Internet ──▶ Router ──▶ Managed Switch ──▶ Devices
                              │
                         (mirror port)
                              ▼
                        SecurePi (sensor only)
```

| Property | Assessment |
|---|---|
| Traffic flow | Unchanged; gateway sees a copy |
| Can see | Everything crossing the mirrored link |
| Cannot see | Wi-Fi client↔client; anything not traversing that switch port |
| Can filter | **No** |
| Can inspect | Yes |
| Acts as gateway | No |
| Passive operation | Yes — completely |
| Config changes | Managed switch required; **most consumer routers have no port mirroring** |
| Router dependency | Low, but requires added hardware |
| Host offline | Network entirely unaffected |

**Verdict:** Safest possible option, but delivers zero enforcement. No ad blocking, no response actions, no policy. Eliminates two of your three pillars. **Rejected as primary.**

#### Model B — DNS-only insertion

```
Internet ──▶ Router ──▶ Devices
                │  (DHCP hands out SecurePi as DNS)
                └──────────▶ SecurePi (DNS filter only)
```

| Property | Assessment |
|---|---|
| Can see | DNS queries only |
| Cannot see | All flows, all packets, all non-DNS activity |
| Can filter | DNS only; trivially bypassed by hardcoded resolvers or DoH |
| Acts as gateway | No |
| Config changes | Router DHCP option 6 — **requires router admin access (your unknown)** |
| Host offline | Total name-resolution outage across the whole network |

**Verdict:** Cheapest, but the SOC becomes impossible — no flows means no port-scan detection, no beaconing detection, no bandwidth anomalies. Also the *worst* failure mode of any model. **Rejected.**

#### Model C — Transparent L2 bridge (inline, invisible)

```
Internet ──▶ Router ══[SecurePi bridge]══▶ Switch/AP ──▶ Devices
                        (no IP on bridge)
```

| Property | Assessment |
|---|---|
| Traffic flow | Passes through; gateway is invisible at L3 |
| Can see | Everything crossing the bridge |
| Cannot see | Wi-Fi client↔client if placed upstream of the AP |
| Can filter | Yes (bridge netfilter, NFQUEUE) |
| Acts as gateway | Functionally yes; not as an L3 hop |
| Config changes | **None on the router** — genuinely router-agnostic |
| Host offline | Link goes down; downstream network isolated |

**Verdict:** Strong contender and fully router-agnostic. Its weakness for this project is that operating at L2 makes per-device L3 policy, quarantine, and DHCP-based identity harder — you'd have to bolt DHCP snooping on top rather than owning DHCP. **Recommended fallback**, not primary.

#### Model D — Routed gateway on a dedicated project LAN ✅

```
Internet ──▶ Existing Router  (untouched, treated as upstream uplink)
                    │  192.168.1.0/24
                    │
              [WAN interface]
         ┌──────────────────────────┐
         │   SecurePi Gateway       │  DHCP · DNS filter · NAT
         │   (laptop, Debian)       │  nftables · IDS
         │                          │  TimescaleDB · API · Console
         └──────────────────────────┘
              [LAN interface]
                    │  10.10.0.0/24  ◀── project subnet
                    │
              Unmanaged Switch
                 ┌──┴──┐
            Dumb AP    Wired test devices
          (client isolation ON)
                 │
        Phones · Laptops · IoT  (~15 devices)
```

| Property | Assessment |
|---|---|
| Traffic flow | All project-LAN traffic is routed by SecurePi Gateway |
| Can see | **Everything** north-south, plus all inter-device traffic that isn't same-AP wireless |
| Cannot see | Same-AP wireless client↔client — *mitigated by enabling AP client isolation* |
| Can filter | Yes — DNS, L3/L4 firewall, per-device policy, quarantine |
| Can inspect | Yes — full packet visibility at the LAN interface |
| Acts as gateway | Yes, authoritatively. Owns DHCP → owns device identity |
| Passive mode | Optional (can run IDS-only with no blocking) |
| Config changes | **Zero on the existing router.** Fully router-agnostic |
| Router limitations imposed | None — router is just an upstream hop |
| Host offline | Project LAN loses connectivity. **Main household network unaffected** |

**Verdict: Recommended.** It is the only model that simultaneously (a) requires nothing from the unknown router, (b) gives full visibility, (c) gives full enforcement, and (d) confines the blast radius to the project network. Double-NAT is the only cost, and it is irrelevant for this use case.

#### Model E — Full router replacement (router in bridge mode to modem)

Same capabilities as D without double-NAT, but **requires the router to support bridge mode — precisely your unknown** — and puts real users behind an experimental system. **Rejected** on both counts.

#### Model F — Router-on-a-stick with VLANs

Requires a VLAN-capable router and managed switch. Adds VLAN configuration complexity for no capability gain over D at this scale. **Rejected as over-engineering.**

#### Model G — Two-host split: Pi as inline gateway, laptop as analytics backend

```
Router ──▶ [Pi: routing/NAT/DHCP/DNS] ──▶ Devices
                    │ (mirror via 2nd NIC)
                    ▼
              [Laptop: IDS, DB, UI]
```

| Pros | Cons |
|---|---|
| Network stays up when the laptop sleeps | Pi has one NIC — mirroring needs a USB adapter, and USB-Ethernet on a Pi is a known throughput/reliability weak point |
| Clean plane separation, architecturally elegant | Pi carries routing *and* mirroring load simultaneously |
| Demonstrates distributed deployment | Control plane must push config to two hosts and reason about partial failure |
| | Clock skew between hosts corrupts correlation windows |
| | Roughly doubles the operational surface for a solo developer |

**Verdict:** Genuinely attractive on paper, but the cost lands entirely on the part of the project that is *not* your contribution (infrastructure plumbing) while adding failure modes to the part that is (correlation). **Rejected for v1; documented as a Phase-2 extension.**

### 5.2 Comparison summary

| Model | Full visibility | Enforcement | Router-independent | Failure blast radius | Solo complexity | Verdict |
|---|:--:|:--:|:--:|---|:--:|---|
| A — SPAN sensor | Partial | ✗ | Needs switch | None | Low | Rejected |
| B — DNS only | ✗ | DNS only | ✗ | Whole network | Very low | Rejected |
| C — L2 bridge | ✓ | ✓ | ✓ | Downstream | Medium | **Fallback** |
| **D — Routed gateway** | **✓** | **✓** | **✓** | **Project LAN only** | **Medium** | **✅ Recommended** |
| E — Router replacement | ✓ | ✓ | ✗ | Whole network | Medium | Rejected |
| F — VLAN | ✓ | ✓ | ✗ | Whole network | High | Rejected |
| G — Pi + laptop split | ✓ | ✓ | ✓ | Project LAN | High | Phase 2 |

### 5.3 Should the laptop connect directly to the router?

**Yes — the laptop is the gateway, connected directly to the router on its WAN side.** Two viable interface arrangements:

| Arrangement | WAN | LAN | Extra hardware | Notes |
|---|---|---|---|---|
| **Preferred** | Built-in Ethernet → router | USB 3.0 Gigabit adapter → switch | ~₹800 | Both interfaces wired; most stable and highest throughput |
| Zero-cost | Wi-Fi client → router | Built-in Ethernet → switch | None | Works immediately; WAN throughput capped by Wi-Fi, which is fine for a demo |

Start with the zero-cost arrangement during early development (it works today, with no purchases), then move to the wired arrangement before performance benchmarking so your throughput numbers aren't distorted by the Wi-Fi uplink.

### 5.4 What role should the Raspberry Pi play?

**None in the data path for v1.** The reasoning, stated plainly for the thesis:

1. There is no computational argument. The laptop is not resource-constrained at 15 devices (§10).
2. Every component that must *act* — DNS filtering, firewall blocking, quarantine — must sit on the data path. Splitting means the policy orchestration layer manages two hosts and must handle "applied to A, failed on B" states. That is genuine complexity added to your core contribution.
3. Mirroring traffic from a Pi to a laptop requires a USB NIC on the Pi and doubles its I/O load.

**Where the Pi is genuinely valuable — Phase 2:**

- **Secondary independent sensor** on a second segment. This proves the ingest layer is sensor-agnostic and multi-source, which is architecturally meaningful and demos well. This is the strongest use.
- **Failover DNS resolver** so name resolution survives gateway restarts — directly addresses the fail-open reliability requirement.
- **Dumb AP** via hostapd, if you don't want to buy an AP. Workable but the Pi's built-in radio is weak; a ₹1,500 AP is better.

### 5.5 What happens when the gateway host goes offline

| Component | Effect | Mitigation |
|---|---|---|
| Whole host down | Project LAN loses internet and DNS | Accepted by design in a lab context. Household network unaffected — this is a key benefit of Model D |
| DNS service crashes | Name resolution fails LAN-wide | Watchdog restart + optional Pi secondary resolver (Phase 2) |
| The IDS crashes | Detection stops silently; traffic still flows | **Detect and surface this in the console** — silent sensor failure is a classic SOC blind spot, and handling it is a good engineering detail |
| Database full/down | Ingest stalls, UI degrades | Disk watchdog + enforced retention + bounded in-memory buffer with explicit drop accounting |

The design principle: **fail open on the data path, fail loud on the control plane.** Traffic keeps flowing when analysis breaks, and the console says so.

---

## 6. Hosting and Hardware Feasibility

### 6.1 Class comparison

| Platform | CPU | RAM | Storage | The IDS @ 15 devices | Verdict |
|---|---|---|---|---|---|
| Raspberry Pi 4 (4 GB) | 4× A72 | 4 GB | microSD/USB | Tight; needs reduced ruleset | Marginal; SD wear is a real problem for a write-heavy DB |
| Raspberry Pi 5 (8 GB) | 4× A76 | 8 GB | NVMe via PCIe HAT | Handles a few hundred Mbps with a tuned ruleset | Viable for the IDS role alone; cramped once DB + UI are co-resident |
| **Laptop (4-core x86, 8–16 GB, SSD)** | 4–8 threads | 8–16 GB | SSD | Comfortable | **✅ Recommended** |
| Mini-PC (N100 class) | 4 cores | 8–16 GB | NVMe | Comfortable | Excellent if you want a dedicated always-on box |

### 6.2 Why the laptop wins

- **Storage endurance.** This is the underrated argument. The workload is continuous small writes to a time-series database. An SSD absorbs this indefinitely; a microSD card degrades in months. This alone rules out an SD-booted Pi as the primary host.
- **x86 rule compatibility.** The IDS and the ET Open ruleset are best-tested on x86-64. ARM works but is less-trodden ground — an unnecessary variable for a solo project.
- **RAM headroom.** The IDS's flow tables plus PostgreSQL's shared buffers plus the application layer want 4–6 GB. 8 GB is workable; 16 GB is comfortable.
- **Development convenience.** Being your dev machine and your target machine removes an entire class of deploy-and-test friction.

### 6.3 Practical caveats for laptop-as-gateway

- Install Debian **bare metal or dual-boot**, not in a VM on your daily OS. NIC passthrough for reliable AF_PACKET capture inside a VM is fiddly and will distort your performance measurements (assumption A5).
- Disable suspend-on-lid-close and all sleep states (`logind` configuration).
- Thermal: sustained IDS load will keep fans running. Ensure ventilation during long baseline runs.
- Reserve ~60 GB for the database under the retention policy in §10.4.

**Answer to "can it support ~15 devices?": comfortably, with substantial headroom.** The binding constraint is the IDS's per-core inspection throughput, not device count — see §10.

---

## 7. Open-Source Ecosystem Analysis

### 7.1 Packet analysis / IDS

| Candidate | Strengths | Weaknesses | Fit |
|---|---|---|---|
| **IDS** | Multi-threaded; AF_PACKET; unified **EVE JSON** output covering alerts *and* flow, dns, http, tls, ssh, anomaly records; JA3/JA4 fingerprinting; free ET Open ruleset; optional IPS via NFQUEUE; excellent docs | Ruleset tuning needed to avoid FP storms; memory grows with flow table | **✅ Selected** |
| Zeek | Unmatched protocol metadata depth; scriptable; rich conn/dns/ssl/x509 logs | Single-threaded per worker; memory-hungry; multi-file TSV/JSON log sprawl; no signature alerting without add-ons | Rejected — see below |
| Snort 3 | Mature; strong rule ecosystem | Weaker structured JSON output; less convenient for programmatic ingest | Rejected |
| ntopng | Good flow analytics, nDPI app classification, REST API | Community edition is feature-limited; brings its own UI we'd have to hide; overlaps the IDS's flow output | Rejected |
| CrowdSec | Behavioural detection, crowd-sourced blocklists, clean local API, YAML scenarios | Log-driven not packet-driven; **its scenario engine would replace the correlation engine you need to build** | Rejected on academic grounds — see §7.7 |

**Key decision — the IDS alone, no Zeek.** The common wisdom is "run both: the IDS for alerts, Zeek for metadata." That advice is written for enterprise SOCs. The IDS's EVE output already emits `flow`, `dns`, `tls`, `http`, and `anomaly` event types alongside `alert` — which covers the great majority of what you'd use Zeek's `conn.log`, `dns.log`, and `ssl.log` for. Running Zeek too would roughly double CPU and memory for marginal added metadata at 15 devices, and would add a second log format to normalize.

**Choosing one engine that produces both alerts and metadata is a deliberate, defensible simplification** — exactly the kind of judgement call worth documenting in the thesis. Zeek belongs in Future Scope.

### 7.2 DNS filtering / ad blocking

| Candidate | Strengths | Weaknesses | Fit |
|---|---|---|---|
| **DNS filter** | Single static Go binary; OpenAPI-documented REST API for both config *and* query data; **built-in DHCP**; native DoH/DoT/DoQ upstream and server; per-client rules and policies; runs fully headless with UI bound to localhost | Single-vendor project; query-log API pagination is awkward for continuous tailing | **✅ Selected** |
| Pi-hole v6 | Very mature; huge community; v6 rebuilt the API and web server into the `pihole-FTL` binary (no more lighttpd/PHP); good group/client policy; gravity blocklists; DHCP available | Session-based auth is more awkward to script; UI is baked into FTL and needs deliberate containment; strongest brand recognition makes the "unified platform" framing harder | Strong alternative |
| Blocky | Purpose-built as a component; YAML config; native Prometheus metrics; **can write query logs directly to PostgreSQL** — near-zero integration glue | No DHCP; smaller community; fewer built-in features; thinner documentation if you get stuck | Attractive but riskier |
| Technitium DNS | Extremely API-first; authoritative + recursive; DoH/DoT server; plugin system | .NET runtime; heavier; more surface than needed | Rejected — over-scoped |
| Unbound + RPZ | Rock solid resolver | No management API, no policy UI, all glue is yours | Rejected |

**Selected: the DNS filter.** The deciding factor is that **it provides DHCP and DNS in one process.** That is not a convenience — it means DHCP lease events and DNS query events originate from the same component with consistent client identity, which materially simplifies the identity resolution layer (§9.2), your hardest sub-problem. Add a documented REST API, static-binary deployment, native encrypted-upstream support, and clean headless operation with the UI bound to `127.0.0.1`, and it fits the "invisible engine behind our platform" requirement better than the alternatives.

Blocky's direct-to-Postgres logging is genuinely tempting and would eliminate an adapter. It loses on the DHCP point and on community depth — the wrong risk for a solo project with a deadline.

### 7.3 Storage

| Candidate | Strengths | Weaknesses | Fit |
|---|---|---|---|
| **PostgreSQL + TimescaleDB** | One engine for relational config *and* time-series events; hypertables; native compression (~10×) and declarative retention policies; continuous aggregates for dashboard rollups; SQL for correlation; `LISTEN/NOTIFY` for live push | Compression and continuous aggregates are under the TSL licence (free to self-host, not OSI-approved) | **✅ Selected** |
| ClickHouse | Outstanding columnar performance and compression | Poor at transactional config data → forces a second datastore; over-scaled for this volume | Rejected |
| OpenSearch / Elasticsearch | Excellent full-text search and dashboarding | JVM; 4–8 GB RAM baseline; would dominate the host's memory budget | Rejected on resources |
| SQLite | Zero-ops, embedded | Concurrent-writer limits; no native retention/compression tooling | Rejected as primary |
| InfluxDB | Purpose-built time series | Weak relational side; v2/v3 ecosystem churn | Rejected |

**Selected: a single PostgreSQL instance with TimescaleDB.** One database to operate, back up, and reason about. Hypertable compression plus declarative retention directly solves the storage-growth risk (§10.4) with configuration rather than custom cleanup code. SQL makes correlation queries expressible and reviewable.

*Licence note:* if strict OSI compliance is required by your institution, plain PostgreSQL with `pg_partman` partitioning and a scheduled aggregation job achieves ~80% of the benefit. Verify your department's stance early; it is a five-minute question with a schema-level consequence.

### 7.4 Backend language and framework

| Candidate | Assessment |
|---|---|
| **Python + FastAPI** | ✅ Fastest path to a working system for a solo developer. Async, auto-generated OpenAPI, WebSocket support, excellent data-handling ecosystem. Ingest throughput with `orjson` is well above what 15 devices generate |
| Go | Better raw throughput and single-binary deploys, but more code per feature and slower iteration for one person |
| Rust | Excellent runtime properties, wrong cost/benefit for this timeline |
| Node/TypeScript | Language sharing with the frontend is real, but a weaker ecosystem for the data/network side |

**Selected: Python 3.12+ with FastAPI.** Honest limitation to state in the thesis: if sustained event rates exceeded roughly 5–10k events/sec, the hot ingest path would need to move to Go. At 15 devices you should measure something in the range of tens to a few hundred events/sec (§10.3) — one to two orders of magnitude of headroom.

### 7.5 Frontend

| Candidate | Assessment |
|---|---|
| **React + TypeScript + Vite** | ✅ Right fit for a live-updating SOC console with WebSocket-driven panels and interactive investigation views. Industry-standard, strong for the report and for you |
| **Grafana** | ❌ **Explicitly rejected.** It would be fast, but it (a) exposes third-party branding, violating your unification requirement, (b) removes most of the UX engineering contribution, and (c) cannot express device-centric investigation workflows. *Do* use it privately during development as a debugging lens on the database |
| HTMX + server-side templates | Genuinely less work; weaker for real-time multi-panel dashboards. Reasonable de-scope option if you fall behind |

Charts: **Apache ECharts** — better than Recharts for dense timelines, heatmaps, and relationship graphs, all of which you need.

### 7.6 Deployment

**Docker Compose for the application tier; native host configuration for the network tier.**

The split exists for a concrete reason: the IDS needs `CAP_NET_RAW`/`CAP_NET_ADMIN` and host network access; the DNS filter needs port 53 plus DHCP broadcast handling; nftables NAT is inherently host-level. Containerising these with `network_mode: host` retains dependency management and reproducibility while discarding most isolation benefit — so be explicit about the trade-off rather than pretending containers provide security here.

| Tier | Components | Mechanism |
|---|---|---|
| Network tier | nftables rules, interface/routing config | Host systemd units, rendered from templates by the orchestration layer |
| Engine tier | IDS, DNS filter | Containers with `network_mode: host` + required capabilities (or native systemd units; decide during Phase 2 spikes) |
| Application tier | PostgreSQL/TimescaleDB, ingest, correlation, API, frontend | Standard Docker Compose with a private bridge network |

Provisioning of the host tier belongs in a single idempotent script (or a small Ansible playbook), which also becomes your deployment-testing artefact.

### 7.7 Explicitly rejected platforms — and why it matters academically

| Platform | Why rejected |
|---|---|
| **Security Onion** | It *is* this project, pre-built. Deploying it leaves nothing to engineer |
| **Wazuh** | Host-agent-centric (agents on 15 endpoints is unrealistic here), requires OpenSearch and ~8 GB RAM, and its rule/decoder engine would substitute for the correlation engine that constitutes your contribution |
| **CrowdSec** | Well-engineered and tempting, but its scenario engine occupies precisely the design space you need to own |
| **OPNsense / pfSense** | Excellent firewalls with IDS plugins, but they are the platform — you'd be writing plugins for someone else's product, not building SecurePi Gateway |

This table is worth including verbatim in the thesis. The strongest defence against "why didn't you just deploy Security Onion?" is having asked and answered it deliberately: those platforms would satisfy the *functional* requirements while eliminating the *engineering* contribution. The value of SecurePi Gateway lies in being purpose-built and coherent for a 15-device network, where enterprise platforms are simultaneously over-scoped and poorly integrated.

---

## 8. Recommended Architecture

### 8.1 Logical architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SecurePi Gateway (single host)                   │
│                                                                     │
│  ┌───────────────── PRESENTATION ──────────────────────────────┐    │
│  │  SOC Console (React + TS)                                   │    │
│  │  Overview · Devices · Incidents · DNS/Filtering · Policy    │    │
│  └────────────────────────┬────────────────────────────────────┘    │
│                REST + WebSocket                                     │
│  ┌────────────────────────┴────────────────────────────────────┐    │
│  │  API & Orchestration Layer (FastAPI)          ★ OUR WORK    │    │
│  │  AuthN/Z · Policy API · Query API · Live push · Actions     │    │
│  └───┬──────────────────┬──────────────────┬──────────────┬────┘    │
│      │                  │                  │              │         │
│  ┌───┴──────┐  ┌────────┴────────┐  ┌──────┴──────┐  ┌────┴─────┐  │
│  │ Device   │  │  Correlation    │  │  Policy     │  │ Response │  │
│  │ Registry │  │  Engine         │  │ Orchestrator│  │ Framework│  │
│  │ ★ OURS   │  │  ★ OURS         │  │  ★ OURS     │  │ ★ OURS   │  │
│  │ identity │  │ windowed rules  │  │ render+apply│  │quarantine│  │
│  │ MAC↔IP↔  │  │ alerts→incidents│  │ +validate   │  │ +audit   │  │
│  │ hostname │  │ risk scoring    │  │ +rollback   │  │ +rollback│  │
│  └───┬──────┘  └────────┬────────┘  └──────┬──────┘  └────┬─────┘  │
│      │                  │                  │              │         │
│  ┌───┴──────────────────┴──────────────────┴──────────────┴─────┐  │
│  │  Normalization / Ingest Pipeline          ★ OUR WORK         │  │
│  │  parse · unify schema · enrich · attribute to device · dedup │  │
│  └───┬───────────────┬───────────────┬───────────────┬──────────┘  │
│      │               │               │               │              │
│  ┌───┴────┐   ┌──────┴─────┐   ┌─────┴──────┐  ┌─────┴────────┐    │
│  │  IDS   │   │ DNS filter │   │  nftables  │  │ Health       │    │
│  │EVE JSON│   │            │   │  log target│  │ Supervisor   │    │
│  │        │   │ DNS + DHCP │   │            │  │  ★ OURS      │    │
│  │ 3rd-pty│   │  3rd-party │   │   kernel   │  │              │    │
│  └────────┘   └────────────┘   └────────────┘  └──────────────┘    │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  PostgreSQL + TimescaleDB                                    │  │
│  │  events (hypertable) · flows · dns_queries · incidents ·     │  │
│  │  devices · policies · audit_log · rollups (cont. aggregates) │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
        ▲ WAN (to existing router)          ▼ LAN (10.10.0.0/24)
```

★ = original engineering. Everything unmarked is integrated third-party software.

### 8.2 Data flow

```
Packets on LAN interface
   │
   ├──▶ IDS (AF_PACKET) ──▶ eve.json ───────┐
   │                                        │
   ├──▶ DNS filter (DNS/DHCP) ──▶ API/log ──┤
   │                                        ├──▶ Ingest & Normalization
   └──▶ nftables ──▶ kernel log ────────────┘         │
                                                      ▼
                                         Unified Event Schema
                                                      │
                                    ┌─────────────────┼─────────────────┐
                                    ▼                 ▼                 ▼
                            Device Registry   TimescaleDB      Correlation Engine
                            (attribution)     (persistence)    (windowed state)
                                                                        │
                                                                        ▼
                                                            Incidents + Risk Scores
                                                                        │
                                              ┌─────────────────────────┼──────────┐
                                              ▼                         ▼          ▼
                                        WebSocket push          Notifications  Response
                                        → SOC Console                          actions
```

### 8.3 Control flow (policy application)

This path is where the "unified platform" claim is actually earned:

```
Admin edits policy in SOC Console
   │
   ▼
Policy API — validate against schema, check invariants
   │
   ▼
Policy Orchestrator — compute desired state, diff against current
   │
   ├──▶ DNS filter REST API     (blocklists, per-client rules, upstreams)
   ├──▶ nftables ruleset render + atomic reload  (firewall, quarantine)
   └──▶ IDS config/rule file + signal reload       (rule categories)
   │
   ▼
Verify applied state ──▶ on failure: automatic rollback to last-good
   │
   ▼
Audit log entry + drift-detection baseline update
```

**Drift detection** — periodically reading back the actual state of each engine and comparing it to the intended state — is a small feature with disproportionate value. It is real configuration-management engineering and it demos well ("I changed the DNS filter manually behind the platform's back; watch it get detected and reconciled").

### 8.4 Failure behaviour

| Failure | Data path | Detection | Response |
|---|---|---|---|
| The IDS dies | Traffic unaffected | Supervisor heartbeat + EVE staleness check | Restart; raise a **platform health alert** (silent sensor loss is a critical SOC failure) |
| The DNS filter dies | **DNS fails LAN-wide** | Health probe | Restart; if repeated, nftables rule releases port 53 to an upstream resolver (fail-open) and the console shows "protection degraded" |
| Database full/down | Ingest stalls | Disk watchdog + write errors | Enforce retention aggressively; bounded ring buffer with explicit drop counters (never drop silently) |
| Correlation engine dies | Events still stored | Heartbeat | Restart, replay from the last processed watermark |
| Whole host down | Project LAN offline | External | Accepted in lab context; documented |

### 8.5 Why this architecture over the alternatives

| Alternative | Why not chosen |
|---|---|
| Multi-host (Pi + laptop) | Doubles operational surface, adds partial-failure states and clock-skew risk, no compute benefit at this scale (§5.4) |
| Microservices over a message bus | Kafka/RabbitMQ adds an operational component for throughput two orders of magnitude below the need. A single Python service with an internal async queue and Postgres `LISTEN/NOTIFY` is sufficient. **Documented upgrade trigger:** if measured ingest lag exceeds 5 s at p95, introduce Redis Streams |
| Elastic/OpenSearch-centric (ELK) | Memory cost dominates the host; would force dropping either the IDS's ruleset or the app tier |
| Deploy Security Onion / Wazuh | Eliminates the engineering contribution (§7.7) |

---

## 9. Feature Architecture

### 9.1 Tiering

| Tier | Definition |
|---|---|
| **Core** | Without it there is no product. MVP. |
| **Supporting** | Makes the core usable and credible. |
| **Advanced** | Differentiators. Attempt after core is stable. |
| **Excluded** | Deliberately not attempted, with reasons. |

### 9.2 Network monitoring

| Feature | Tier | Notes |
|---|---|---|
| Device discovery & inventory | Core | From DHCP leases + ARP + passive observation |
| **Device identity resolution** | Core | MAC↔IP↔hostname↔friendly-name stitched over time. Handles lease churn and **MAC randomization** via DHCP fingerprinting, hostname stability, and TLS/JA4 fingerprints, with manual pinning as the fallback. *This is the hardest and most original sub-problem — everything else keys off it* |
| Per-device bandwidth (up/down, over time) | Core | From IDS flow records |
| Active flows / connection list | Core | |
| Protocol & service breakdown | Supporting | |
| Top talkers, top destinations | Supporting | |
| New-device detection | Core | Also a security signal |
| Per-device behavioural baselines | Advanced | Rolling statistics; feeds anomaly detection |
| Latency/uplink health monitoring | Supporting | Simple, cheap, visibly useful |
| Application identification via JA4 | Advanced | The IDS provides fingerprints free; identifying apps inside TLS is a strong differentiator |

### 9.3 Ad blocking / filtering

| Feature | Tier | Notes |
|---|---|---|
| Network-wide DNS blocking | Core | |
| Blocklist management from our UI | Core | Add/remove/enable lists; scheduled updates |
| Per-device / per-group policy | Core | Distinct profiles: e.g. *IoT-restricted*, *standard*, *unrestricted* |
| Allow/deny overrides with rationale | Core | |
| Block statistics & bandwidth-saved estimate | Supporting | Good demo metric |
| Temporary bypass ("disable 5 minutes") | Supporting | Real-world necessity; shows product thinking |
| Encrypted upstream (DoT/DoH to resolver) | Supporting | Privacy story, one config setting |
| **DoH/DoT bypass detection and blocking** | Advanced | See §11.3 — turns your biggest risk into a headline feature |
| Per-device query log with search | Core | Also the SOC's DNS telemetry view |
| Full URL/content filtering | **Excluded** | Requires TLS interception |

### 9.4 Security / SOC

| Feature | Tier | Notes |
|---|---|---|
| Unified security event ingestion | Core | IDS alerts + flow/dns/tls metadata + DNS decisions + firewall drops |
| Severity classification & normalization | Core | Our own taxonomy, mapped from ET signature IDs |
| Alert deduplication & suppression | Core | Without it the console is unusable |
| **Alert → Incident correlation** | Core | The central contribution |
| Port scan detection | Core | Correlate flow records; detect horizontal and vertical scans, including slow scans that per-packet signatures miss |
| Brute-force detection | Core | Failed-auth patterns via flow characteristics + IDS alerts |
| DNS anomaly detection | Core | NXDOMAIN bursts, DGA-like entropy, query-volume spikes, long-label tunnelling indicators |
| Malicious-domain / IP hits | Core | Local threat-intel feeds; no cloud dependency |
| New-device / rogue-device alerting | Core | |
| **C2 beaconing detection** | Advanced | Periodicity analysis on flow inter-arrival times. Works on encrypted traffic. High-value, high-impact demo |
| Data exfiltration heuristics | Advanced | Outbound volume vs. per-device baseline |
| **Device risk scoring** | Core | Weighted, time-decayed, **explainable** — the UI must answer "why is this device 78/100?" |
| Incident timeline / investigation view | Core | Device-centric: all events for one device on one timeline |
| Automated response: quarantine device | Supporting | nftables rule, with audit + one-click undo |
| Automated response: block domain/IP | Supporting | |
| Notifications (email / Telegram / webhook) | Supporting | |
| Platform self-monitoring | Core | Sensor-liveness, ingest lag, drop counters, disk headroom |
| Weekly report export | Advanced | |

### 9.5 Unified console

Five top-level views. The unifying principle: **the device is the primary object**, not the alert. Enterprise SOCs are alert-centric because they have thousands of hosts; on a 15-device network the operator thinks "is my network OK, and which device is the problem?" Designing around that is a legitimate and articulable design contribution.

| View | Contents |
|---|---|
| **Overview** | Network health, live throughput, active incidents by severity, blocked-query rate, device count, platform health strip |
| **Devices** | Inventory table with risk score, live/last-seen, bandwidth, policy profile. Drill-down → per-device dashboard: timeline, flows, DNS history, incidents, policy, actions |
| **Incidents** | Ranked incident queue; each opens to evidence chain, contributing events, affected devices, suggested actions, status workflow (new → investigating → resolved/false-positive) |
| **Filtering** | Blocklists, policy profiles, query log with search, block statistics, allow/deny management |
| **Settings** | Network config, retention, notifications, users, platform health details, audit log, OSS attributions |

### 9.6 Branding and attribution

The requirement to present one unified platform is satisfiable and legitimate:

- Bind the DNS filter's own web UI to `127.0.0.1` and never expose or link to it. Drive it exclusively through its REST API. The IDS has no UI.
- Maintain a **signature-to-taxonomy mapping table** so the console says *"Port scan detected from 10.10.0.42"* rather than *"ET SCAN Nmap NULL Scan"*. This is genuine normalization work, not cosmetics — and it is why the correlation layer exists.
- Include an **Open-Source Attributions page** in Settings listing every upstream project and licence (IDS GPLv2, DNS filter GPLv3, PostgreSQL PostgreSQL Licence, etc.).

The distinction to hold: **hiding upstream branding in the product UI is normal integration practice; hiding it from your examiners is not.** The thesis must state precisely what is integrated versus built — which is also your strongest academic argument (§17).

---

## 10. Performance Analysis

All figures are engineering estimates under the assumptions in §3, to be replaced by measurements in Phase 10. State them as estimates in the thesis until measured.

### 10.1 Throughput and CPU

| Load | IDS CPU (4-core x86) | Expected behaviour |
|---|---|---|
| 50 Mbps sustained | ~10–20% of one core | Trivial |
| 200 Mbps | ~0.5–1.5 cores | Comfortable |
| 500 Mbps | ~1.5–3 cores | Workable with a tuned ruleset |
| 940 Mbps (line rate burst) | 3–4 cores | Drops likely with the full ET Open set |

Reported experience places a tuned Raspberry Pi 4 at roughly 500–700 Mbps and a Pi 5 near gigabit; a 4-core x86 laptop should exceed both. Rule count is the dominant variable — the full ET Open set (~40–50k rules) is far heavier than a curated subset.

**Deliberate action:** measure `capture.kernel_drops` from the IDS's own statistics across a throughput sweep and publish the curve. "Our platform inspects at line rate up to X Mbps and begins dropping beyond it" is an honest, quantitative, defensible result — considerably better than an unqualified claim.

### 10.2 Memory

| Component | Estimate |
|---|---|
| The IDS (flow tables + ruleset) | 1.0–2.0 GB |
| PostgreSQL + TimescaleDB | 1.0–2.0 GB |
| DNS filter | 100–300 MB |
| Application tier (API, ingest, correlation) | 400–800 MB |
| OS + containers | ~1 GB |
| **Total** | **~4–6 GB** |

8 GB is workable; 16 GB is comfortable and lets PostgreSQL cache more.

### 10.3 Event volume

For ~15 devices over 24 h (order-of-magnitude estimates):

| Event type | Est. events/day | Notes |
|---|---|---|
| Flow records | 200k–500k | Dominant contributor |
| DNS queries | 80k–200k | IoT chatter inflates this substantially |
| TLS handshakes | 60k–150k | |
| HTTP transactions | 5k–30k | Small and shrinking; most traffic is TLS |
| IDS alerts | 50–2,000 | Highly ruleset-dependent; expect FP-heavy before tuning |
| **Total** | **~350k–900k/day** | **≈ 4–10 events/sec average, peaks perhaps 100–300/sec** |

This is comfortably within FastAPI/Python range with `orjson` — roughly two orders of magnitude below where the language choice would become a constraint.

### 10.4 Storage — the critical constraint

| Approach | Per day | Per 6 months | Viable? |
|---|---|---|---|
| Raw `eve.json` retained | 0.5–2 GB | 90–360 GB | **No** |
| Normalized typed rows (~250 B/row) | 100–250 MB | 18–45 GB | Marginal |
| **Normalized + TimescaleDB compression (~10×)** | **15–40 MB** | **3–7 GB** | **✅ Yes** |
| Above + tiered retention | ~10–25 MB effective | ~2–4 GB | ✅ Comfortable |

**Recommended retention tiers:**

| Data | Retention | Rationale |
|---|---|---|
| Raw normalized events | 14 days | Investigation window |
| Hourly per-device rollups | 180 days | Baselines and trends |
| DNS query log | 30 days | Privacy-conscious and sufficient |
| Incidents + alerts | 365 days | Small volume, high value |
| Audit log | Indefinite | Tiny; integrity-relevant |
| PCAP | **Not retained** | Privacy and volume. Optional short-lived rolling buffer for demos only |

**This is the single most important design decision in the project.** Getting the schema and retention right in Phase 3 costs a week; getting it wrong means discovering a full disk and unusable dashboards in month five. Treat "storage growth is bounded and measured" as a Phase-3 exit criterion.

### 10.5 Latency

| Path | Added latency | Notes |
|---|---|---|
| Routing/NAT through the gateway | <1 ms | Kernel path |
| The IDS in IDS mode (AF_PACKET copy) | **0 ms** | Out-of-band copy; does not delay packets |
| The IDS in IPS mode (NFQUEUE) | 1–10 ms + jitter | A reason to keep IDS mode as default |
| DNS resolution (cache hit) | <1 ms | Often *faster* than the ISP resolver |
| DNS resolution (cache miss) | 20–80 ms | Upstream-dependent |

**Design consequence:** default to IDS mode. Enforcement happens at the DNS and firewall layers, which SecurePi Gateway controls directly and can reverse instantly. Offer IPS as an optional, clearly-labelled toggle — and measure its latency cost as an experiment rather than enabling it by default.

### 10.6 Bottleneck ranking

1. **Storage growth** — highest risk, fully mitigable by design (§10.4)
2. **The IDS drops at high throughput** — measurable, tunable, honestly reportable
3. **Correlation engine state memory** — bounded windows and eviction policies required
4. **Dashboard query latency over 30+ days** — solved by continuous aggregates
5. **Python ingest throughput** — ample headroom at this scale

---

## 11. Security and Reliability

### 11.1 The platform is a high-value target

SecurePi Gateway sees every DNS query and every flow on the network. Compromising it yields comprehensive surveillance. This must be treated seriously — and doing so is itself worth marks.

| Risk | Mitigation |
|---|---|
| Console exposed to the network | Bind to the LAN interface only; **never** to the WAN side. Explicit nftables rules |
| Weak/absent authentication | Argon2id password hashing, session management, rate-limited login, mandatory setup-time credential creation (no default password, ever) |
| Plaintext admin traffic | TLS on the console with a locally-generated CA; document the trust process |
| Credential sprawl | Single secrets store; DNS-filter API credentials never in the repo or in logs; env-file with restricted permissions |
| Privilege escalation via the app tier | App tier runs unprivileged. Privileged operations (nftables changes) go through a **narrow, allowlisted helper** with validated inputs — never shell interpolation of user input |
| Injection into rendered configs | Treat nftables/Suricata config rendering as a code-generation problem: strict schema validation, typed rendering, no string concatenation of user-supplied values |
| Log integrity | Append-only audit table; every policy change and response action recorded with actor, timestamp, before/after state |
| Sensitive data in the DB | Full network history is sensitive. Encrypted disk, restricted DB access, documented retention |

### 11.2 Reliability

| Risk | Mitigation |
|---|---|
| Single point of failure (one host = everything) | **Accepted by design** in a lab context; documented explicitly. Blast radius limited to the project LAN by Model D |
| DNS failure = total outage | Fail-open path: release port 53 to an upstream resolver after repeated health-check failures; console shows "protection degraded". Optional Pi secondary resolver in Phase 2 |
| Silent sensor failure | Heartbeat + EVE-freshness monitoring; a stale sensor raises a platform alert |
| False-positive storms | Ruleset tuning phase, suppression lists, correlation-layer dedup, and per-rule FP tracking in the UI |
| Incorrect filtering breaks a service | Fast allowlist path, temporary-bypass control, and a "recently blocked" view for diagnosis |
| Bad policy bricks the network | Atomic apply with automatic rollback on verification failure; a physical/console recovery path that resets to a known-good ruleset |

### 11.3 Turning the DoH risk into a feature

DNS-over-HTTPS is the most serious threat to the DNS-based half of the platform, and it deserves a first-class response rather than a caveat:

1. **Force plaintext DNS to the gateway** — nftables DNAT redirect of all outbound port 53 to the local resolver, so hardcoded resolvers (very common in IoT firmware) are transparently captured.
2. **Block known DoH endpoints** — maintain a list of public DoH resolver IPs and hostnames; block at the firewall and via SNI observation.
3. **Detect DoH usage** — IDS TLS events plus a known-resolver list identify devices attempting to bypass filtering.
4. **Surface it** — "Device X attempted to bypass DNS filtering 47 times" is an excellent, concrete, novel-feeling console feature.

This converts a limitation into a demonstrable capability and shows you understood the threat model rather than working around it.

### 11.4 Ethical and legal considerations

Worth a short thesis section; examiners respond well to it:

- Deploy on a **dedicated project network** with only your own or consenting participants' devices (assumption A7).
- **Do not retain PCAP** of others' traffic. Metadata-only is both sufficient and defensible.
- Document the retention policy and what is and is not stored.
- Frame it as privacy-by-design: DNS logs at 30 days rather than indefinitely, no payload capture, no TLS interception. These are deliberate choices, and saying so is stronger than staying silent.

---

## 12. Small-Enterprise SOC Design

### 12.1 What "SOC" should mean at this scale

An enterprise SOC assumes analysts, tiered escalation, threat hunting, and compliance reporting. None applies to a 15-device network with one part-time administrator. Reproducing that shape would be the wrong design.

**The correct framing: an autonomous SOC for a network with no analyst.** Design consequences:

| Enterprise SOC | SecurePi Gateway SOC |
|---|---|
| High alert volume, analysts triage | **Low incident volume; aggressive correlation and suppression.** Ten incidents a day is a failure, not a feature |
| Alert-centric | **Device-centric** — "which device is the problem?" |
| Analysts interpret raw signatures | **Plain-language incidents with evidence and a recommended action** |
| Threat hunting workflows | **Automatic baselining**; the platform does the hunting |
| Manual response runbooks | **One-click reversible response** |
| Compliance reporting | Out of scope |

### 12.2 Capability tiering

| Capability | Verdict | Reason |
|---|---|---|
| Event collection & normalization | **Essential** | Foundation |
| Device inventory & identity | **Essential** | Attribution is prerequisite to everything |
| Signature-based IDS alerts | **Essential** | Delegated to the IDS |
| Alert dedup / suppression | **Essential** | Usability collapses without it |
| Alert → incident correlation | **Essential** | The core contribution |
| Port scan / brute-force detection | **Essential** | Classic, demonstrable, safely testable |
| DNS anomaly & malicious-domain detection | **Essential** | Highest signal-to-noise on a small network |
| Severity classification | **Essential** | |
| Incident timeline | **Essential** | Investigation is impossible without it |
| Device risk scoring | **Valuable → promote to core** | Distinctive and directly demonstrable |
| Beaconing detection | **Valuable** | High impact; works on encrypted traffic |
| Basic automated response | **Valuable** | Completes the detect→respond loop |
| Threat-intel enrichment (local feeds) | **Valuable** | Cheap; keep it offline-capable |
| Behavioural baselines (statistical) | **Valuable** | Achievable with rolling z-scores |
| Notifications | **Valuable** | |
| Case management / ticketing | **Optional** | Simple status workflow is enough |
| SOAR-style playbooks | **Too complex** | Not for a solo project |
| ML-based anomaly detection | **Too complex as a core claim** | Honest statistical baselining beats a poorly-validated model. Future scope |
| Threat hunting query language | **Too complex** | |
| Compliance reporting | **Excluded** | No relevance at this scale |

### 12.3 The correlation model — the heart of the project

This is where you demonstrate engineering depth, so specify it carefully.

**Pipeline:** `Raw Events → Signals → Incidents → Risk`

| Stage | Definition |
|---|---|
| **Event** | A single normalized observation (one flow, one DNS query, one IDS alert) |
| **Signal** | A stateful, windowed detection over events — e.g. "20+ distinct destination ports to one host within 60 s" |
| **Incident** | One or more related signals grouped by device + time + kill-chain phase, with an evidence chain |
| **Risk** | A per-device time-decayed aggregate over incidents, with explainable contributions |

**Initial signal set (target ~6–8 implemented rules):**

| Signal | Detection method | Data source |
|---|---|---|
| Horizontal port scan | Distinct destination ports per source, windowed | Flow records |
| Vertical/network scan | Distinct destination hosts per source, windowed | Flow records |
| Slow scan | Same, with a long window and low threshold — *catches what per-packet signatures miss* | Flow records |
| Brute force | Repeated short connections to an auth port with failure characteristics | Flows + IDS alerts |
| DNS tunnelling indicator | Query-name entropy, label length, TXT ratio, query rate | DNS logs |
| DGA indicator | NXDOMAIN rate + name entropy per device | DNS logs |
| C2 beaconing | Inter-arrival-time periodicity to a single destination (coefficient of variation below a threshold over N connections) | Flow records |
| New device | First-seen MAC on the network | DHCP/ARP |
| Bypass attempt | DoH/DoT connection attempts to known resolvers | TLS events + firewall |
| Volume anomaly | Per-device outbound bytes vs. rolling baseline (z-score) | Flow rollups |

**Headline metric to target:** alert-to-incident reduction ratio. A result like *"14,200 raw events over 72 h reduced to 23 incidents, of which 19 were true positives"* is concrete, measurable, and communicates the value of the correlation layer better than any feature list.

**Risk scoring** must be **explainable**. The device detail page should show the score alongside its contributing factors and their weights and decay. An unexplainable number is not useful to an administrator and is not defensible to an examiner.

---

## 13. MVP and Scope Control

### 13.1 MUST HAVE (MVP — the demonstrable core)

| # | Capability | Why non-negotiable |
|---|---|---|
| 1 | Model D gateway operational; 15 devices routed, NATed, DHCP-served | Everything depends on it |
| 2 | IDS + DNS filter integrated, driven entirely through our layer | Proves the integration thesis |
| 3 | Unified event pipeline → TimescaleDB with working tiered retention | The data foundation; retention proves sustainability |
| 4 | Device registry with identity resolution across lease churn | Attribution underpins all analysis |
| 5 | 6+ correlation signals producing incidents with evidence chains | The core contribution |
| 6 | Explainable device risk scoring | Distinctive, demonstrable |
| 7 | Unified console: Overview, Devices, Incidents, Filtering, Settings | The unified-platform requirement |
| 8 | Policy control from our UI → applied to engines, verified, rollback on failure | Proves orchestration, not just display |
| 9 | Authentication + TLS on the console | Non-negotiable for a security product |
| 10 | Platform self-monitoring (sensor liveness, ingest lag, disk) | Prevents silent failure; shows maturity |

### 13.2 SHOULD HAVE (strong additions once MVP is stable)

Quarantine action with audit and undo · DoH/DoT bypass detection and blocking · Notifications · Per-device DNS policy profiles · Temporary bypass control · Behavioural baselines with volume-anomaly detection · Beaconing detection · Configuration drift detection

### 13.3 COULD HAVE (only if genuinely ahead of schedule)

Weekly PDF report · JA4-based application identification · Raspberry Pi as second sensor · Rolling PCAP buffer for demo captures · Bandwidth-saved estimation · Mobile-responsive console

### 13.4 WILL NOT DO (state these explicitly in the thesis)

| Excluded | Reason |
|---|---|
| TLS/HTTPS interception (MITM CA) | Invasive, breaks certificate pinning, serious privacy implications, disproportionate effort |
| Host agents / EDR on client devices | Different project; unrealistic to deploy across 15 heterogeneous devices |
| Deep-learning anomaly detection | Cannot be validated properly in the time available; statistical baselining is more honest and more defensible |
| IDS IPS mode as the default | Latency and false-positive outage risk. Available as a labelled, measured option |
| High availability / clustering | Meaningless at this scale |
| Multi-site / multi-tenant | Out of scope |
| Compliance reporting | No relevance |
| Custom DNS resolver, IDS engine, or packet-capture library | Contradicts the core philosophy |
| Mobile app | Responsive web is sufficient |

**Stating exclusions with reasons is a strength, not an admission.** It demonstrates scope judgement, which is exactly what final-year projects most often lack.

---

## 14. Development Roadmap

Sequenced by **technical risk first**, not by feature attractiveness. The riskiest and most foundational work goes early, so that a failure in month two is recoverable and a failure in month seven never happens.

### Phase 0 — Groundwork (2–3 weeks)

**Objective:** Establish the problem space and the working environment.
**Why:** Prevents rediscovering known problems in month four.
**Tasks:** Literature survey (small-network IDS, alert correlation, DNS security, device fingerprinting) · Requirements specification · Risk register · Debian install on the gateway host · Git repository, project structure, CI skeleton · Acquire hardware (USB NIC, switch, AP).
**Deliverables:** Requirements doc · Risk register · Working development environment.
**Exit criteria:** Host boots into Debian; repository and CI run; hardware in hand.
**Risks:** Hardware procurement delay → order in week 1.

### Phase 1 — Network foundation spike (2 weeks)

**Objective:** Get Model D working manually, end to end.
**Why:** This is the highest-risk infrastructure. If routed-gateway operation does not work reliably, everything downstream is void. Prove it before writing application code.
**Tasks:** Configure WAN/LAN interfaces · nftables NAT and forwarding · DHCP serving on the LAN · Attach switch and AP with client isolation · Join 8–15 real or virtual devices · Validate throughput and stability over 48 h.
**Dependencies:** Phase 0.
**Deliverables:** Documented, reproducible host network configuration · Baseline throughput and latency measurements.
**Exit criteria:** 15 devices online through the gateway; internet works; stable for 48 h; `iperf3` baseline recorded.
**Risks:** USB-NIC instability → test early, fall back to Wi-Fi-WAN arrangement.

### Phase 2 — Engine spikes and measurement (2–3 weeks)

**Objective:** Prove each third-party engine works in this environment and quantify its cost.
**Why:** Converts the estimates in §10 into measurements before they are depended upon.
**Tasks:** the IDS with AF_PACKET on the LAN interface; ET Open rules; EVE output configured and sized · DNS-filter headless, UI bound to localhost, DHCP moved to it, REST API exercised for every operation the platform will need · Measure CPU, RAM, event rate, and raw log volume over 72 h · Throughput sweep with `capture.kernel_drops` recorded.
**Dependencies:** Phase 1.
**Deliverables:** Measured resource profile · **Measured daily event volume and log size** (feeds the Phase-3 schema) · Verified API coverage for every planned operation.
**Exit criteria:** Both engines run stably for 72 h; event rate and storage growth measured; every required API call confirmed to work.
**Risks:** A DNS-filter API gap → discovered here, while switching to Pi-hole v6 is still cheap. This is precisely why this phase exists.

### Phase 3 — Data model and ingest pipeline (3–4 weeks)

**Objective:** A unified schema and a working, bounded ingest path.
**Why:** Every later phase reads from this. Schema mistakes are expensive later.
**Tasks:** Design the unified event schema across all sources · PostgreSQL/TimescaleDB with hypertables, compression, continuous aggregates, retention policies · EVE JSON tailer with watermark/resume · DNS-filter query and DHCP-lease ingestion · nftables log ingestion · Normalization and enrichment · Ingest-lag and drop-counter instrumentation.
**Dependencies:** Phase 2 measurements.
**Deliverables:** Schema documentation · Running ingest service · Retention verified working.
**Exit criteria:** All sources flowing into the database for 7 days continuously; **storage growth measured and shown to be bounded**; ingest lag p95 under 5 s; zero silent drops.
**Risks:** Under-designed schema → prototype correlation queries against it *before* declaring the phase complete.

### Phase 4 — Device registry and identity resolution (2–3 weeks)

**Objective:** Reliable, stable device identity.
**Why:** Attribution is a prerequisite for every SOC feature. Also the most original sub-problem.
**Tasks:** Device model and lifecycle · MAC↔IP↔hostname stitching across lease churn · MAC-randomization handling (DHCP fingerprint, hostname stability, JA4) · Manual naming and identity pinning · First-seen/last-seen tracking · Accuracy evaluation against known ground truth.
**Dependencies:** Phase 3.
**Deliverables:** Device registry service · **Measured identity-accuracy results**.
**Exit criteria:** Correct identity for 15 known devices across a 7-day run with DHCP renewals and at least one randomizing phone.
**Risks:** Randomization defeats heuristics → manual pinning is the documented fallback; measure and report accuracy honestly either way.

### Phase 5 — Correlation engine and incidents (4–5 weeks) ← *the core*

**Objective:** Turn events into a small number of meaningful incidents.
**Why:** The central academic contribution. Allocate time accordingly.
**Tasks:** Signal framework (windowed, stateful, with bounded memory and eviction) · Implement 6–8 signals (§12.3) · Signal→incident grouping · Deduplication and suppression · Severity model · Evidence-chain construction · Unit tests with synthetic event fixtures · Validation against replayed PCAPs.
**Dependencies:** Phases 3, 4.
**Deliverables:** Correlation engine · Rule documentation · Test suite · **Precision/recall against scripted ground truth**.
**Exit criteria:** All scripted attacks in the test set detected; measured false-positive rate over a 72 h clean baseline; alert-to-incident reduction ratio measured.
**Risks:** Time overrun — this phase is the one most likely to slip. **Protect it by cutting from Phases 7–8, never from here.**

### Phase 6 — Policy orchestration (2–3 weeks)

**Objective:** One policy model that drives every engine.
**Why:** This is what makes it a platform rather than a dashboard.
**Tasks:** Unified policy schema · Renderers for DNS-filter API, nftables, and IDS config · Validation and invariant checks · Atomic apply with verification and rollback · Drift detection · Audit logging.
**Dependencies:** Phase 2 (API knowledge).
**Deliverables:** Orchestration service · Audit log.
**Exit criteria:** A policy change made through the API is verifiably applied to all engines; an injected failure triggers automatic rollback; manual out-of-band changes are detected.

### Phase 7 — SOC console (4–5 weeks)

**Objective:** The unified user experience.
**Tasks:** React + TypeScript scaffold · Five main views (§9.5) · WebSocket live updates · ECharts visualizations · Device drill-down and incident investigation views · Policy management UI · Responsive layout.
**Dependencies:** Phases 4, 5, 6.
**Deliverables:** Complete console.
**Exit criteria:** Every MVP capability reachable through the UI with no CLI required; live updates working; a non-expert can navigate it unaided.
**Risks:** Frontend work expands to fill available time → timebox strictly; de-scope to HTMX if Phase 5 has slipped.

### Phase 8 — Risk scoring and response (2 weeks)

**Objective:** Close the detect→assess→respond loop.
**Tasks:** Risk scoring model with time decay and explainability · Explanation UI · Quarantine and domain/IP block actions · Audit and one-click undo · Notifications.
**Dependencies:** Phases 5, 6, 7.
**Exit criteria:** A quarantine action demonstrably isolates a device and is cleanly reversible; risk scores are explainable in the UI.

### Phase 9 — Hardening (2 weeks)

**Objective:** Make it safe to run and safe to show.
**Tasks:** Authentication and authorization · TLS on the console · Secrets management · Privilege separation for the nftables helper · Input validation across config rendering · Self-security review · Watchdog and fail-open behaviour · Dependency audit.
**Exit criteria:** Self-conducted security review passes with no unmitigated high findings; fail-open DNS verified by killing the resolver.

### Phase 10 — Evaluation campaign (3 weeks)

**Objective:** Generate the quantitative results the thesis needs.
**Why:** A separate phase because measurement done incidentally is measurement done badly.
**Tasks:** Execute every experiment in §16 · 7-day continuous baseline run · Scripted attack scenarios · Throughput and drop sweeps · Storage-growth measurement · Usability study with 5–8 peers · Compile datasets and figures.
**Dependencies:** Phases 1–9.
**Deliverables:** **Results dataset, graphs, and analysis** — the empirical core of the thesis.
**Exit criteria:** All planned metrics collected and reproducible.

### Phase 11 — Documentation and demonstration (2–3 weeks)

**Tasks:** Thesis writing · Architecture documentation · One-command deployment on a clean machine · 15-minute demo script with rehearsed fallbacks · Recorded backup demo video.
**Exit criteria:** Fresh-machine deployment succeeds from documentation alone; demo rehearsed end to end at least three times; backup video recorded.

### 14.1 Schedule summary

| Phase | Weeks | Cumulative |
|---|---|---|
| 0 — Groundwork | 2–3 | 3 |
| 1 — Network foundation | 2 | 5 |
| 2 — Engine spikes | 2–3 | 8 |
| 3 — Data pipeline | 3–4 | 12 |
| 4 — Device registry | 2–3 | 15 |
| **5 — Correlation engine** | **4–5** | **20** |
| 6 — Orchestration | 2–3 | 23 |
| 7 — Console | 4–5 | 28 |
| 8 — Risk & response | 2 | 30 |
| 9 — Hardening | 2 | 32 |
| 10 — Evaluation | 3 | 35 |
| 11 — Documentation | 2–3 | 38 |

≈ 38 weeks against roughly 8 months of usable working time. **The schedule is tight and has little slack.** Build the buffer in by treating §13.2 (SHOULD HAVE) as genuinely optional and by protecting Phase 5 at the expense of Phases 7 and 8.

If the timeline is one semester rather than two: deliver Phases 0–5 plus a minimal console, and present it as a detection-and-correlation platform with a basic UI. That is still a strong project.

---

## 15. Testing Strategy

### 15.1 PCAP replay as the testing backbone

The single most valuable testing decision available: build the test infrastructure around **replaying captured packet traces** through the IDS on an isolated interface.

Why it matters:
- **Deterministic and repeatable** — the same input produces the same events, making regression testing possible
- **Safe** — no live attacks, no risk to any network
- **Labelled ground truth** — public research datasets provide known attack labels, enabling genuine precision/recall figures
- **Fast** — a 24-hour capture replays in minutes, so correlation rules can be iterated quickly

Sources: your own captures of scripted attacks in an isolated lab; public malware-traffic captures; and academic IDS datasets (the CIC-IDS family and similar). Verify licensing and cite whatever you use.

### 15.2 Test layers

| Layer | Scope | Approach |
|---|---|---|
| **Unit** | Correlation rule logic, normalization, risk scoring, identity stitching | Synthetic event fixtures with golden-file expected outputs. Pure functions where possible — design the signal framework for testability |
| **Integration** | Ingest → DB → correlation → API | Docker Compose test environment; PCAP replay end to end; assert on resulting incidents |
| **Contract** | Adapters to the DNS filter and the IDS | Recorded API responses; detect upstream breaking changes on version bumps |
| **Network** | Routing, NAT, DHCP, DNS, isolation | Automated connectivity checks from a test client; verify quarantine actually isolates |
| **Performance** | Throughput, latency, drops, ingest rate | `iperf3` sweeps; IDS drop counters; synthetic event floods; DB query benchmarks |
| **Security** | The platform's own attack surface | Auth bypass attempts, injection into policy fields, CSRF/XSS on the console, secrets-in-logs scan, dependency CVE audit, unauthenticated-access checks from the WAN side |
| **Failure/chaos** | Resilience | Kill each service; fill the disk; saturate the link; disconnect WAN; corrupt a config. Measure detection and recovery time |
| **Usability** | Console effectiveness | Task-based study, 5–8 participants |
| **Deployment** | Reproducibility | Clean VM, deploy from documentation, verify full function |

### 15.3 Safe demonstration scenarios

All conducted on the isolated project LAN against your own targets:

| # | Demonstrates | Method | Expected result |
|---|---|---|---|
| 1 | Port scan detection | `nmap` at varying speeds (`-T0` through `-T5`) from a lab host | Incident raised; **the slow `-T0` scan is the impressive case** — it evades per-packet signatures but not windowed correlation |
| 2 | Brute-force detection | Repeated failed SSH auth against a lab VM | Incident with attempt count and source device |
| 3 | Malicious-domain detection | Resolve domains from a known-bad test list | Blocked, alerted, attributed to the device |
| 4 | DNS tunnelling | Scripted high-entropy long-label queries to a lab domain | Anomaly signal triggers |
| 5 | C2 beaconing | Script periodic callbacks at a fixed interval to a lab endpoint | Periodicity detected — works despite TLS |
| 6 | Ad blocking | Load a fixed set of ad-heavy pages with and without filtering | Measured block ratio, request reduction, load-time delta |
| 7 | DoH bypass | Configure a client for a public DoH resolver | Attempt detected, blocked, surfaced in the console |
| 8 | New-device detection | Join an unknown device | Alert within seconds |
| 9 | Correlation value | Replay a 72 h capture containing scripted attacks | Show the raw-events-to-incidents reduction ratio |
| 10 | Response action | Quarantine a device from the console | Device loses connectivity; audit entry created; one-click restore works |
| 11 | Resilience | Kill IDS mid-demo | Traffic continues; platform health alert appears; auto-restart succeeds |
| 12 | Fail-open DNS | Kill the DNS service | Name resolution recovers via fallback; console shows "protection degraded" |

Scenarios 1, 5, 9, and 11 are the strongest. Scenario 9 is the one that proves the thesis; scenario 11 is the one that convinces examiners you built something operationally real rather than a demo.

---

## 16. Risk Analysis

Probability and impact are assessed for this project in this environment.

| # | Risk | Prob | Impact | Why it matters | Mitigation | Fallback |
|---|---|:--:|:--:|---|---|---|
| R1 | **Storage growth exhausts the disk** | High | High | Would corrupt results and stall ingest late in the project | Normalized schema + compression + tiered retention designed in Phase 3; disk watchdog; measured in Phase 2 | Shorten retention to 3 days; drop flow-record storage, keep rollups only |
| R2 | **Scope creep** | High | High | The most common cause of final-year project failure | Hard MVP gate (§13); phase exit criteria; SHOULD-HAVEs treated as genuinely optional | Ship Phases 0–5 + minimal console; present as a detection platform |
| R3 | **Encrypted traffic limits inspection** | Certain | Medium | Constrains what detection is possible | Metadata-based detection (SNI, JA4, flow shape, timing); state as a design constraint | Lean harder on DNS telemetry, which is unaffected |
| R4 | **DoH/DoT bypasses DNS filtering** | High | High | Would undermine both ad blocking and DNS telemetry | Port-53 DNAT redirect; block known DoH endpoints; detect and surface attempts (§11.3) | Accept and measure the bypass rate; report honestly as a limitation |
| R5 | **Correlation engine phase overruns** | Medium | High | It is the core contribution; losing it hollows out the project | 5 weeks allocated; strictly protected; reduce to 4 well-tested signals rather than 8 rushed ones | Cut Phases 7–8 scope, never Phase 5 |
| R6 | **False-positive storms from ET Open** | High | Medium | Makes the console unusable and undermines the demo | Dedicated tuning window in Phase 5; suppression lists; correlation-layer dedup; per-rule FP tracking | Run a curated rule subset; document the selection criteria |
| R7 | **The IDS drops packets at high throughput** | Medium | Medium | Undermines completeness claims | Ruleset tuning, AF_PACKET fanout, CPU affinity; **measure and publish the ceiling** | Report the measured throughput limit as a finding, not a failure |
| R8 | **MAC randomization breaks device identity** | High | Medium | Attribution failure degrades every SOC feature | Multi-signal identity heuristics; manual pinning; measured accuracy | Manual device naming; report accuracy honestly |
| R9 | **Wi-Fi client↔client traffic invisible** | High | Medium | Lateral movement between wireless devices unseen | Enable AP client isolation, forcing traffic through the gateway | Document as a known limitation |
| R10 | **Laptop-as-gateway operational friction** (sleep, portability, thermals) | High | Medium | Interrupts long baseline runs | Dedicated Debian install; disable all sleep states; scheduled unattended runs | Migrate to a mini-PC if it becomes disruptive |
| R11 | **Single point of failure** | Certain | Low (lab) | Whole platform on one host | Accepted by design; Model D confines the blast radius to the project LAN | Documented as an architectural limitation with an HA discussion in Future Scope |
| R12 | **Upstream API/tool changes** | Low | Medium | Could break adapters mid-project | Pin versions; adapter pattern isolates changes; contract tests | Freeze versions for the remainder of the project |
| R13 | **DNS-filter API insufficient for a needed operation** | Low | Medium | Would force a mid-project engine swap | **Verified exhaustively in Phase 2, while switching is still cheap** | Switch to Pi-hole v6; the adapter pattern contains the change |
| R14 | **Integration complexity underestimated** | Medium | Medium | Three engines with different data models and time bases | Spike each engine independently in Phase 2 before integrating | Reduce to two engines: drop nftables logging as a source |
| R15 | **Hardware procurement delay** | Medium | Low | Blocks Phase 1 | Order in week 1; the Wi-Fi-WAN arrangement needs no purchases | Start with the zero-cost interface arrangement |
| R16 | **Insufficient realistic traffic for evaluation** | Medium | Medium | 15 lab devices may generate thin, unrepresentative traffic | Supplement with PCAP replay and scripted traffic generators | Use public datasets for volume-dependent results; label them clearly |
| R17 | **Ethical/consent issues** | Low | High | Monitoring non-consenting users is not acceptable | Dedicated project network; own/consenting devices only; no PCAP retention; documented policy | Purely synthetic environment |
| R18 | **TimescaleDB licensing objection** | Low | Low | TSL is not OSI-approved | Confirm your department's stance in Phase 0 | Plain PostgreSQL with `pg_partman` and scheduled aggregation |

---

## 17. Academic Value and Original Contribution

### 17.1 Answering "isn't this just gluing tools together?"

Expect this question. The answer has three parts:

**1. Integration at this scale is a genuine research-adjacent problem.** Enterprise SOC tooling assumes analysts, budget, and infrastructure. Small networks have none of these, yet face similar threats. The design question — *what does a SOC look like when there is no analyst?* — is real, under-addressed, and has non-obvious answers. The device-centric rather than alert-centric model, and the requirement that incident volume stay low enough for a non-expert to act on, are design contributions derived from that constraint.

**2. The correlation and identity layers are original engineering.** No off-the-shelf component performs event normalization across these specific sources, resolves device identity through DHCP churn and MAC randomization, correlates windowed signals into explainable incidents, or scores device risk with decaying evidence. These are designed, implemented, and evaluated by you.

**3. The evaluation is empirical.** Measured detection rates, time-to-detect, false-positive rates, correlation reduction ratios, throughput ceilings, and identity accuracy — on a real network with real traffic — constitute genuine experimental work.

### 17.2 The contribution boundary

| Integrated (third-party) | Built (your contribution) |
|---|---|
| Packet capture, protocol parsing, signature matching (IDS) | Unified event schema and normalization across four heterogeneous sources |
| DNS resolution and blocklist evaluation (DNS filter) | Device identity resolution across lease churn and MAC randomization |
| DHCP service (DNS filter) | Stateful windowed correlation: events → signals → incidents |
| Time-series storage engine (PostgreSQL/TimescaleDB) | Explainable, time-decayed device risk model |
| Packet forwarding, NAT, firewall primitives (Linux/nftables) | Policy orchestration: one model rendered to three engines, with validation, atomic apply, rollback, and drift detection |
| Threat signatures (ET Open) | Reversible response framework with full audit |
| Base OS, container runtime | Unified device-centric SOC console |
| | Platform health supervision and fail-open behaviour |
| | The empirical evaluation |

Include this table in the thesis. Its honesty is what makes the contribution column credible.

### 17.3 Evaluation metrics

Derived from the architecture rather than chosen in advance:

**Detection effectiveness**

| Metric | Method | Target |
|---|---|---|
| Detection rate per attack class | Scripted attacks + labelled PCAP replay | Report per class |
| Time-to-detect (TTD), median and p95 | Timestamp delta from attack start to incident creation | Report distribution |
| False-positive rate | Incidents per 24 h over a 7-day clean baseline | As low as achievable; report honestly |
| Precision / recall per signal | Against scripted ground truth | Per-signal table |
| **Alert-to-incident reduction ratio** | Raw events ÷ resulting incidents | **The headline metric** |
| Slow-scan detection advantage | Correlation-based vs. signature-only detection of `-T0` scans | Directly demonstrates the correlation layer's value |

**Filtering effectiveness**

| Metric | Method |
|---|---|
| Block ratio on a fixed site set | Controlled browsing script |
| Request reduction (%) | Compare with filtering on/off |
| Page-load-time delta | Measured, both directions |
| DNS resolution latency (cache hit/miss) | vs. ISP resolver baseline |
| DoH bypass attempts detected | Controlled bypass test |

**System performance**

| Metric | Method |
|---|---|
| Throughput ceiling before packet drops | `iperf3` sweep with `capture.kernel_drops` |
| Added latency (IDS mode, and IPS mode) | Ping RTT with gateway inline vs. bypassed |
| CPU/RAM under load | Sampled across the throughput sweep |
| Ingest rate sustained, and lag at p95 | Synthetic event flood |
| Storage growth per day, pre- and post-compression | 7-day measurement |
| Dashboard query latency at 7/30/90 days of data | Benchmarked |

**Attribution and reliability**

| Metric | Method |
|---|---|
| Device identity accuracy | vs. known ground truth over 7 days with lease churn |
| MTTR per component | Chaos tests |
| Detection gap during component failure | Measured |
| Uptime over a 7-day continuous run | Observed |

**Usability**

| Metric | Method |
|---|---|
| Task completion rate and time | 5–8 participants; tasks such as "identify the riskiest device and explain why" |
| SUS score | Standard questionnaire |

### 17.4 Demonstration strategy

A 15-minute demo, ordered for narrative impact:

1. **Overview dashboard, live** (1 min) — a real network, real traffic, right now
2. **Ad blocking** (2 min) — load an ad-heavy page with filtering off, then on. Immediate, visual, universally understood
3. **Device inventory and drill-down** (2 min) — 15 devices, identified, scored, explained
4. **Live attack: slow port scan** (3 min) — run `nmap -T0`; show the incident appear with its evidence chain. Emphasise that per-packet signatures miss this and windowed correlation does not
5. **Correlation value** (2 min) — the reduction-ratio figure from the 72 h replay
6. **Response** (2 min) — quarantine the offending device; show it lose connectivity; restore it
7. **Resilience** (2 min) — kill the IDS; traffic continues; the platform reports its own degradation and recovers
8. **Results summary** (1 min) — the metrics table

Steps 4 and 7 are the ones examiners remember. Record a backup video: live demos on live networks fail at exactly the wrong moment.

---

## 18. Recommended Final Blueprint

### What SecurePi Gateway should contain

A single-host network security platform that acts as the routed gateway for a dedicated ~15-device LAN, providing DNS-based content filtering, full traffic monitoring, and an automated SOC that correlates events from multiple sensors into a small number of explainable, device-attributed incidents — presented through one unified console with policy control and reversible response actions.

### What to build yourself

1. Unified event schema and normalization layer
2. Device identity resolution engine
3. Stateful windowed correlation engine (events → signals → incidents)
4. Explainable device risk scoring model
5. Policy orchestration layer with validation, atomic apply, rollback, and drift detection
6. Reversible response framework with audit
7. Unified device-centric SOC console
8. Platform health supervision and fail-open behaviour

### What to integrate

| Function | Choice |
|---|---|
| IDS / packet analysis | **IDS** with ET Open rules (no Zeek) |
| DNS filtering + DHCP | **DNS filter**, headless, API-driven (Pi-hole v6 as documented alternative) |
| Storage | **PostgreSQL + TimescaleDB** |
| Backend | **Python 3.12 + FastAPI** |
| Frontend | **React + TypeScript + Vite + ECharts** |
| Networking | **Linux kernel + nftables** |
| Deployment | **Docker Compose** (app tier) + provisioned host networking |
| OS | **Debian stable**, bare metal on the laptop |

### Deployment model

**Model D — routed gateway on a dedicated project LAN.** The laptop is the gateway: WAN interface to the existing router, LAN interface to a switch and a dumb AP with client isolation enabled. Zero configuration changes to the existing router; zero dependency on its capabilities; failures confined to the project network. **The Raspberry Pi stays out of the data path in v1** and returns in Phase 2 as a second independent sensor.

### What to demonstrate

Live ad blocking · Device inventory with explained risk scores · Slow-scan detection that signature-only systems miss · The alert-to-incident reduction ratio · Reversible device quarantine · Graceful degradation when a sensor dies.

### What to deliberately leave out of v1

TLS interception · Host agents · Deep-learning detection · IDS IPS mode as default · High availability · Multi-site support · Compliance reporting · Zeek · Any custom implementation of DNS resolution, packet capture, or signature matching.

---

## 19. Future Scope

| Item | Rationale |
|---|---|
| Raspberry Pi as a second sensor | Proves the ingest layer is sensor-agnostic; genuine multi-sensor architecture |
| Distributed multi-segment deployment | Natural extension of the above |
| Zeek as a supplementary metadata source | Richer protocol detail once resources permit |
| ML-based anomaly detection | Properly validated, with the statistical baseline as the comparison |
| Automated threat-intel feed integration | Currently local feeds only |
| High availability / failover | Meaningful only beyond lab scale |
| Mobile application | Responsive web suffices for now |
| IPv6 support | Deliberately deferred; note as a v1 limitation |
| Encrypted Client Hello handling | Emerging constraint on SNI-based detection; worth tracking |
| Guest-network isolation and captive portal | Natural small-enterprise extension |

---

## 20. Immediate Next Steps

Before any implementation begins:

1. **Confirm hardware** — laptop specification (cores, RAM, free disk), and whether you can dedicate a bare-metal Debian install.
2. **Confirm timeline** — one semester or two. This determines whether §14 runs in full or stops after Phase 5.
3. **Check the TimescaleDB licensing question** with your department (five minutes; schema-level consequence).
4. **Order hardware in week 1** — USB 3.0 Gigabit Ethernet adapter, unmanaged switch, cheap AP (~₹3,000 total). Procurement delay is the most avoidable early risk.
5. **Confirm the ethical framing** — devices on the project LAN are yours or consenting participants.

Then begin at **Phase 0**, and treat the Phase-1 and Phase-2 exit criteria as genuine gates: if Model D does not run stably for 48 hours, do not proceed to write application code.

---

## Verification

Since this document contains no code, verification means confirming the analysis holds before committing to it:

| Check | Method | Phase |
|---|---|---|
| Model D works on your actual hardware | Build it manually; 15 devices online for 48 h | 1 |
| The IDS runs within resource budget | 72 h run; measure CPU, RAM, drops | 2 |
| DNS-filter API covers every needed operation | Exercise every planned call before integrating | 2 |
| Event volume matches §10.3 estimates | Measure over 72 h | 2 |
| Storage projections hold | Measure growth over 7 days with compression enabled | 3 |
| Correlation rules detect scripted attacks | PCAP replay with labelled ground truth | 5 |

If any Phase-2 measurement diverges from §10 by more than roughly 3×, revisit the technology selection before proceeding — that is exactly what the spike phases are for.

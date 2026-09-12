# SecurePi Gateway — 15-Day Build Plan

**Supersedes the schedule in the feasibility document, not its analysis.**
Reference doc: `~/.claude/plans/project-securepi-gateway-crispy-lerdorf.md`

---

## 1. What changed, honestly

The feasibility plan was a ~38-week schedule. Fifteen days is roughly 1/25th of that.
This is not the same project delivered faster — it is a materially smaller project
that demonstrates the same core idea.

**What survives:** the concept, the architecture, the deployment model (Model D),
the integrate-vs-build boundary, and the correlation-engine-as-contribution argument.

**What does not:** breadth. Eight correlation signals become four. A React SPA becomes
one server-rendered page. Policy orchestration with rollback and drift detection is cut
entirely. The evaluation campaign shrinks from three weeks to one afternoon.

**Nothing already written is wasted.** The feasibility document is your *report*;
this is your *build plan*. The alternatives analysis, technology comparison, risk matrix,
and topology evaluation are exactly what a final-year report needs — and they are worth
more marks than three extra features would be. Chapters 1–4 of your report are already done.

---

## 2. Host machine: the spare Linux laptop

Your Mac is Apple Silicon (arm64, macOS 26). The gateway needs Linux — `nftables`,
Suricata AF_PACKET capture, `hostapd`, DHCP serving. None exist on macOS in a form
worth building against, and Asahi Linux is not a fifteen-day install.

**Decision: the spare Linux laptop is the gateway. The MacBook is the development machine.
Leave the Windows laptop alone.**

An x86 laptop is better than a Raspberry Pi for this: the ET Open ruleset and Suricata
are best-tested on x86-64, it has an SSD rather than an SD card, it has more RAM, and an
older laptop is *more* likely to have a built-in Ethernet port than a new one.

### Do this first: reinstall — Ubuntu Server 24.04 LTS

> **Superseded:** this section originally said Debian 13. Once the hardware was identified
> as a Dell Vostro 3501, the recommendation changed to **Ubuntu Server 24.04 LTS** for its
> broader hardware enablement on Dell laptops and Realtek wireless. See
> `GATEWAY-SETUP-RUNBOOK.md` §2. Install **Server, not Desktop**, and tick OpenSSH.

"Old Linux" is a real risk regardless of distribution. An aged install ships an old
Suricata whose EVE JSON field names may differ from current documentation — a subtle
problem that costs hours to diagnose. A clean install costs an hour and eliminates the
whole category.

**Detailed host setup, interface allocation, SSH access, and the day-1 sequence now live
in `GATEWAY-SETUP-RUNBOOK.md`.** That document is authoritative for days 1–2; the
day-by-day schedule in §6 below resumes from day 3.

### Zero-hardware network arrangement

You cannot wait for a delivery. Use the laptop's two built-in interfaces:

```
Internet ──▶ Existing Router ──[Ethernet]──▶ Linux Laptop ──[Wi-Fi AP via hostapd]──▶ Test devices
                (untouched)         WAN       SecurePi Gateway        LAN 10.10.0.0/24
```

### Day-1 checks, in this order — each one has a different fallback

| # | Check | Command | If it fails |
|---|---|---|---|
| 1 | Ethernet port present and working | `ip link` | Use Wi-Fi as WAN and Ethernet as LAN (reversed); needs a switch + AP |
| 2 | **Wi-Fi chipset supports AP mode** | `iw list \| grep -A10 "Supported interface modes"` — look for `AP` | See below |
| 3 | Suricata ≥ 7.x available | `apt-cache policy suricata` | Confirms the reinstall was worth it |

**If AP mode is unsupported** (a real possibility on older Intel and Realtek chipsets),
in order of preference: use an old spare router as a dumb AP if you have one lying around
— extremely common and completely solves it; otherwise run a wired-only demo with a cheap
unmanaged switch and containers as test devices. Decide this on day 1, not day 6.

**Device count:** do not chase 15 physical devices. Use 4–6 real ones plus containers as
synthetic devices. The architecture is identical; only the demo optics differ.

---

## 2.5 Development workflow: Mac for code, laptop for runtime

Develop on the MacBook. The split that makes this work:

| Runs anywhere (develop + test on the Mac) | Linux-only (deploy to the gateway) |
|---|---|
| Ingest and normalization logic | Suricata |
| Device registry | AdGuard Home (DNS + DHCP) |
| Correlation engine and signals | nftables / routing / NAT |
| Risk scoring | hostapd |
| FastAPI + templates + charts | Quarantine enforcement |
| SQLite schema and queries | |

Roughly 70% of the code you write — including the entire correlation engine, which is
your actual contribution — is pure Python plus SQLite and runs natively on macOS.

**Set this up on day 3, and it will pay for itself repeatedly:** once Suricata and
AdGuard Home are running on the gateway, capture a few hours of real `eve.json` and
AdGuard query-log output and copy it to the Mac as test fixtures. From then on, develop
the pipeline and correlation engine locally against those fixtures with a fast edit-run
loop, and deploy to the gateway only for integration checks.

Two further benefits worth noting in the report: replaying fixed fixtures makes your
detections **deterministically testable**, and it lets you iterate on correlation logic
without needing to re-run an attack every time.

**Deploy loop:** keep the git repo on the Mac; push with
`rsync -az --delete ./ user@gateway:~/securepi/ && ssh user@gateway 'systemctl --user restart securepi'`,
wrapped in a `make deploy` target. Read the console in your Mac browser over the LAN.
Do not edit files directly on the gateway — you will lose work.

---

## 2.6 CONFIRMED topology and hardware (day 1 resolved)

### Hardware, measured

| | | Consequence |
|---|---|---|
| CPU | Intel i3-1005G1, 2 cores / 4 threads @ 1.2 GHz | Modest. Suricata gets 1–2 threads; inspection ceiling likely 100–300 Mbps |
| RAM | **3.6 GiB** | **The binding constraint.** Drives the decisions below |
| Disk | 88 GB free | Ample — storage growth is a non-issue at 15 days |
| Wi-Fi | Qualcomm Atheros QCA9377, `ath10k_pci` | **AP mode CONFIRMED supported** |
| Interfaces | `enp1s0` built-in Ethernet, `wlp2s0` Wi-Fi, plus 2× USB Ethernet adapters | Enough for the design below |

### Final topology — TESTED AND ADOPTED (Option B)

The Dell takes its own internet directly from the home router over Wi-Fi, and serves the
project LAN from an access point on the **same radio and same channel**. The MacBook is
purely a development machine and a management link — it is **not** in the data path.

```
Internet ──▶ Home Router "Babu_Home"  2.4 GHz ch.6
                    ▲
                    │ station (wlp2s0)  −50 dBm, 72 Mbit/s
                    │
         ┌──────────┴─────────────────────────┐
         │  Dell Vostro 3501                  │
         │  SecurePi Gateway                  │
         │                                    │
         │  wlp2s0  = station (WAN uplink)    │  ── one radio, one channel ──
         │  ap0     = access point (LAN)      │     "SecurePi-Test" 10.10.0.1/24
         │  enp1s0  = management only         │  ── Cat7 to Mac, 192.168.2.5 ──
         └──────────┬─────────────────────────┘
                    │  10.10.0.0/24
              [AP: "SecurePi-Test"]
                    │
        Phones · Laptops · test devices
```

**Why the earlier Mac-as-upstream design was dropped.** Concurrent AP + station on one
`ath10k` radio was expected to be unstable and to halve throughput. Measurement disproved
both:

| Configuration | Throughput | Avg RTT | Jitter (mdev) |
|---|---|---|---|
| Via MacBook Internet Sharing | 31.2 Mbps | — | — |
| **Direct Wi-Fi, AP running concurrently** | **30.0 Mbps** | **8.4 ms** | **1.6 ms** |
| Station alone, AP stopped (baseline) | — | 11.6 ms | 5.6 ms |

Running the AP *improved* latency and cut jitter 3.5×, because `hostapd` keeps the radio
awake and the station stops paying power-save wake-up costs. Both paths reach ~30 Mbps,
which is the internet connection's own ceiling rather than a radio limit.

**Two implementation details that cost time and are worth recording:**

1. **The AP interface needs its own MAC.** A virtual AP inherits the station's MAC, and
   `mac80211` rejects it with the unhelpful `Name not unique on network`. The fix is to
   flip the locally-administered bit on the first octet.
2. **The card cannot run an AP on 5 GHz.** Its regulatory domain marks every 5 GHz band
   `PASSIVE-SCAN` (no-IR), so AP mode is restricted to 2.4 GHz channels 1–11. This forced
   the station onto the router's 2.4 GHz radio — which turned out to be a large win
   anyway: signal improved from **−77 dBm to −50 dBm**, since 2.4 GHz penetrates better
   over the distance to the router.

**Persistence:** `securepi-ap0.service` (creates the interface, sets the MAC and address)
ordered before `hostapd.service`; the station's BSSID is pinned to the 2.4 GHz radio in
netplan so it cannot drift back to 5 GHz.

### Known limitation, to state in the report

The gateway's uplink is wireless and shares one radio with the access point. Throughput
is bounded by the internet connection (~30 Mbps) rather than by the radio, so this does
not currently constrain the system — but it would on a faster connection, and the day-14
throughput benchmark should note that the measured ceiling is upstream-limited.

### Consequences of 3.6 GiB RAM

| Decision | Change |
|---|---|
| **Docker dropped entirely** | Everything runs natively under systemd. SQLite already removed the database container, leaving little for Compose to earn. Saves memory and a layer of complexity |
| Suricata ruleset | Curated subset, not full ET Open. Was already planned; now mandatory |
| Suricata memory | Explicit `flow.memcap` and `stream.memcap` limits rather than defaults |
| Expected footprint | Suricata ~0.7 GB · DNS filter ~0.2 GB · app ~0.3 GB · OS ~0.6 GB ≈ **1.8 GB of 3.6** |


### Possible later optimisation — do not bet the schedule on it

`iw list` reports interface combinations permitting one AP plus managed clients across up
to two channels, so concurrent AP + station on `wlp2s0` is theoretically possible — which
would let the Dell take its WAN from the home Wi-Fi directly and drop the Mac dependency.
Concurrent AP+STA on `ath10k` is unreliable in practice. Worth an experiment late if time
allows; not something to depend on.

---

## 3. Revised technology decisions

Three changes from the feasibility document, each justified by the compressed timeline.

| Component | 8-month choice | 15-day choice | Why it changed |
|---|---|---|---|
| Storage | PostgreSQL + TimescaleDB | **SQLite (WAL mode)** | Retention and compression solved a problem that no longer exists — you will collect days of data, not months. SQLite removes a container, a connection pool, and a whole class of setup failure. Defensible: "at this retention window and event rate, an embedded store is sufficient" |
| Frontend | React + TypeScript + Vite | **FastAPI + Jinja2 + HTMX + Chart.js** | Saves ~10 days. Server-rendered with HTMX polling gives live-updating panels at a fraction of the effort, and still looks like a product |
| Detection source | Suricata ET Open ruleset + own correlation | **Suricata as flow/DNS/TLS sensor + a small curated ruleset; detection logic almost entirely yours** | Eliminates the false-positive tuning phase, which was budgeted at days and could have consumed the whole schedule |

**Unchanged:** Suricata (metadata sensor), AdGuard Home (DNS + DHCP, headless, API-driven),
Python 3.12 + FastAPI, Linux + nftables, Debian/Raspberry Pi OS.

### The detection change is an academic upgrade, not a compromise

Leaning on Suricata for *metadata* rather than *alerts* means the port-scan, brute-force,
and DNS-anomaly detections are written by you against flow records, rather than being
Emerging Threats signatures firing. More of the detection logic sits in the contribution
column, and you skip the FP-tuning work entirely. State this as a deliberate design
choice in the report — because it is one.

---

## 4. Scope

### IN (must ship)

| # | Capability | Est. |
|---|---|---|
| 1 | Model D gateway on the Pi: WAN + Wi-Fi AP, DHCP, DNS, NAT, routing | 1.5 d |
| 2 | Suricata emitting EVE JSON; AdGuard Home headless with API access | 1 d |
| 3 | Ingest pipeline: EVE + AdGuard query log + DHCP leases → SQLite, unified schema | 2 d |
| 4 | Device registry: MAC ↔ IP ↔ hostname from DHCP leases, first/last seen | 1 d |
| 5 | Correlation engine with **3 core signals** (+ new-device) → incidents with evidence | 2.5 d |
| 6 | Simple device risk score (weighted, decaying, explainable) | 0.5 d |
| 7 | Web console: Overview, Devices, Incidents, Filtering | 3 d |
| 8 | Quarantine action via nftables, with undo | 0.5 d |
| 9 | Basic auth on the console | 0.25 d |

**The signals:** horizontal port scan · brute-force attempt · malicious/blocked-domain
repeat offender · (new device on network — near-free, trivially explainable). All four are trivially demonstrable with `nmap`,
`hydra`, `dig`, and joining a phone to the Wi-Fi.

### OUT (cut from the approved plan — state these as scope decisions in the report)

Policy orchestration with validation/rollback/drift detection · TLS on the console ·
C2 beaconing detection · DoH bypass detection and blocking · behavioural baselines ·
MAC-randomization identity heuristics · notifications · PCAP-replay test infrastructure ·
usability study · the three-week evaluation campaign · chaos/failure testing ·
tiered retention · continuous aggregates · Raspberry Pi as second sensor.

Beaconing detection and DoH blocking are the two most painful cuts — both are genuinely
distinctive. If you find yourself ahead on day 12, beaconing is the one to add back:
it is ~4 hours of work against flow inter-arrival times and it is the most impressive
detection in the set.

---

## 4.5 Working arrangement: Claude writes the code, you must be able to defend it

You have said you are not a Python programmer and that I will write the code. That is a
workable arrangement, but it shifts the main risk in this project from *schedule* to
**viva defensibility**. Raw code production actually gets faster. What gets harder is you
being able to stand in front of an examiner and explain how your own system works.

Examiners on final-year projects reliably probe the part that looks most impressive. Here
that is the correlation engine — days 8–10. Expect to be asked how port-scan detection
decides what counts as a scan, why a threshold is what it is, and what happens on a false
positive. "Claude wrote it" is the one answer that cannot be given.

### What this changes

| Area | Adjustment |
|---|---|
| **Signal count** | **Four signals → three.** Three detections you can explain in depth beat four you cannot. Port scan, brute force, malicious-domain repeat offender. New-device detection is nearly free and stays as a fourth only because it is trivially explainable |
| **Code style** | Synchronous over async wherever async buys nothing. Plain `sqlite3` and hand-written SQL over an ORM. Explicit loops over dense comprehensions. Simple functions over class hierarchies. No decorators or metaclass tricks. Boring, linear, readable |
| **Framework surface** | FastAPI used narrowly — routes, templates, static files. No dependency-injection patterns, no background-task abstractions. A plain polling loop in a thread beats an async scheduler you cannot describe |
| **Daily rhythm** | Each build day ends with a short written explanation of what went in and why. Fifteen minutes a day |
| **Debugging** | You cannot diagnose independently, so failures must surface clearly. Verbose, plain-language logging is not optional here — it is what lets you tell me what broke |

### The daily explanation doubles as your report

Do not treat the end-of-day write-up as overhead. It is chapter 5 of your report being
written incrementally while the reasoning is fresh, and it is your viva preparation. By
day 15 you have both, and neither needs reconstructing from memory under deadline.

The correlation engine is the section to invest the most explanation time in. It is
simultaneously your strongest contribution and the most likely thing to be questioned.

---

## 5. Build in vertical slices, not horizontal layers

**This is the single most important process change.**

The 38-week plan was sequenced by layer: pipeline, then registry, then correlation,
then UI. That ordering is correct when you have slack. It is dangerous at 15 days,
because if you run out of time on day 12 you have a beautiful backend and nothing to show.

Instead: get one thin end-to-end slice working by day 5 — one data source, into the
database, out to one ugly web page — and thicken it. **Every day should end with
something demonstrable.** If the project stops on any given day, you still have a demo.

```
Day 5   ▏ugly page showing live DNS queries          ← already demoable
Day 8   ▏+ device list, + flows                      ← recognisably a product
Day 11  ▏+ incidents from 4 signals                  ← the actual thesis
Day 13  ▏+ risk scores, quarantine, styling          ← polished
Day 15  ▏+ results table, report, rehearsed demo     ← submittable
```

---

## 6. Day-by-day

Assumes ~8–10 focused hours/day. Slack is near zero — see §8.

| Day | Work | End-of-day state |
|---|---|---|
| **1** | Fresh Debian 13 on the spare laptop. **Run the three day-1 checks in §2.** Ethernet WAN up. Install Suricata, AdGuard Home, Python. Git repo on Mac + `make deploy` loop | Gateway online, tooling installed, AP mode resolved |
| **2** | `hostapd` + AP running. AdGuard Home serving DHCP + DNS on 10.10.0.0/24. nftables NAT. Join 4–6 devices | **Devices browse the internet through the gateway** |
| **3** | Suricata on the LAN interface, EVE JSON with flow/dns/tls enabled. Curated rule subset. Confirm event flow. AdGuard Home API auth working | Both engines producing data |
| **4** | SQLite schema. Ingest service: EVE tailer with watermark + AdGuard query log | Events landing in the database |
| **5** | FastAPI skeleton + one Jinja page listing recent DNS queries and flows, auto-refreshing | **First end-to-end slice — demoable** |
| **6** | Device registry from DHCP leases + ARP. MAC↔IP↔hostname. First/last seen | Device inventory populated |
| **7** | Devices page with drill-down: per-device flows, DNS history, bandwidth | Recognisably a product |
| **8** | Signal framework (windowed, stateful). Signals 1 & 2: port scan, brute force. Test with `nmap`/`hydra` | **First real detections firing** |
| **9** | Signals 3 & 4: malicious-domain repeat offender, new device. Signal→incident grouping, dedup, evidence chain | Incidents being created |
| **10** | Incidents page: queue, severity, evidence, per-device timeline | The thesis is visible in the UI |
| **11** | Overview dashboard: throughput, active incidents, blocked-query rate, device count. Chart.js | Full console shape |
| **12** | Filtering page: blocklist management + per-device policy via AdGuard Home API. Query log search | Ad blocking controllable from your UI |
| **13** | Risk scoring with explanations. Quarantine + undo. Basic auth. Styling pass | Feature-complete |
| **14** | Scripted test run: all 4 detections, ad-block measurement, resource measurement. Collect results table. Bug fixes | **Results collected** |
| **15** | Report writing, README, demo rehearsal ×3, backup video recording | Submittable |

---

## 7. Minimum evaluation (day 14, one afternoon)

You need *some* numbers. These are the cheapest ones with real value:

| Metric | Method | Time |
|---|---|---|
| Detection rate + time-to-detect, 4 attack types | Run each attack 3×, record detection and latency | 1 h |
| Alert-to-incident reduction ratio | Raw event count ÷ incident count over a 24 h capture | 15 min |
| Ad-block ratio, **third-party** | 10 fixed ad-heavy sites, filtering off vs. on | 30 min |
| Ad-block ratio, **first-party** | YouTube / X — expected ~0%, and that is the point | 10 min |
| False positives | Incidents raised over 24 h of normal use | free (just read the DB) |
| Resource usage | `htop` / `vmstat` samples under load | 20 min |
| Throughput impact | `iperf3` through the gateway vs. direct | 20 min |

Roughly three hours yields a credible results chapter. The reduction ratio is your
headline number — it is what demonstrates the correlation layer earns its place.

### Finding: DNS filtering blocks third-party ads, not first-party ads

Measured during setup and worth its own paragraph in the evaluation chapter.

With 655,974 rules across five blocklists, the gateway reliably blocks **third-party** ad
and tracking domains — `doubleclick.net`, `googleadservices.com`, `ads.x.com`,
`analytics.tiktok.com`, `app-measurement.com` and similar. It blocks **none** of the
first-party ads on YouTube or X, and cannot.

The reason is structural rather than a gap in the blocklists. YouTube serves advertisement
video from `googlevideo.com`, the same domain as the content itself; X serves promoted
posts through the same API endpoint as ordinary posts. A DNS resolver's only available
verdict is per-domain, so blocking those domains removes the service rather than the
advertising. The distinction is invisible at the DNS layer, and equally invisible at the
packet layer once TLS is applied.

Defeating first-party advertising requires operating inside the page — a browser extension
such as uBlock Origin, with DOM access and per-request URL visibility — or TLS
interception at the gateway, which this project excludes on grounds of certificate
pinning, mobile-app incompatibility, and privacy.

**Report this as a measured boundary of the technique, with both numbers side by side.**
A stated third-party block rate alongside a first-party rate of zero, and an explanation
of why the second number cannot be improved without changing layers, demonstrates a
clearer understanding of the mechanism than a single headline percentage would.

---

## 8. Honest risk assessment

**Probability of shipping the full §4 scope: roughly 50–60%**, assuming you are fluent
in Python and nothing external goes wrong. There is no slack. One day lost to a driver
problem consumes the entire buffer.

| Risk | Response |
|---|---|
| Laptop Wi-Fi won't do AP mode | **Check day 1** (§2). Fallback in order: old spare router as dumb AP, then wired-only with a switch |
| Network setup fights you (days 1–2 slip) | Hard stop at end of day 3. If the gateway isn't routing, fall back to Model B (DNS-only) and rebuild the project around DNS security — still a coherent, defensible project |
| Correlation engine slips | Ship 2 signals instead of 4. Two working, well-tested detections beat four half-built ones |
| UI slips | Drop the Overview dashboard; Devices + Incidents alone carry the demo |
| **You cannot explain the code at the viva** | **The top risk now** (§4.5). Mitigated by daily written explanations, three signals rather than four, and deliberately plain code. Budget 15 min/day — do not skip it |
| You become the bottleneck on physical tasks | Anything at the Dell's keyboard, joining devices, or moving cables needs you. Batch these; I will queue them rather than interrupt you piecemeal |

**The 15-day-specific rule:** protect days 8–10 (the correlation engine) at all costs.
That is where the contribution lives. Cut UI polish, cut the dashboard, cut risk scoring
before you cut a single signal.

---

## 9. What the report says

Structure it around the feasibility work you already have — it is the stronger material:

1. **Introduction & problem statement** — small networks face enterprise threats without enterprise tooling
2. **Literature & technology survey** — from the feasibility doc §7, including the rejected-platforms table
3. **Feasibility & topology analysis** — the seven deployment models and their comparison (§5)
4. **Architecture** — the layered design and the integrate-vs-build boundary (§8, §17.2)
5. **Implementation** — what you actually built in 15 days
6. **Evaluation** — the §7 results table above
7. **Limitations & future scope** — *everything in §4 OUT, framed as informed scope decisions*

Section 7 is where the cut features earn their marks. "We evaluated C2 beaconing detection
via flow periodicity analysis and scoped it out given the timeline" reads as engineering
judgement. Silence reads as not having thought of it.

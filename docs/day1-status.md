> **Archived here by `ENHANCEMENT-PLAN.md` step 0.1, 14 September 2026.** A
> point-in-time snapshot from the end of Day 1 of the original 15-day build.
> Kept for the project history; current status lives in `NEXT-SESSION.md`
> and the progress tracker in `ENHANCEMENT-PLAN.md` §8.

# SecurePi Gateway — Status Assessment

**Date:** 12 September 2026, 15:06
**Question:** where do we stand, and how far from the objective?

---

## 1. The headline

**One calendar day has elapsed. Three of fifteen planned days of work are complete,
plus one substantial feature that was never in the plan.**

Every commit, every file, and every configuration change carries today's date. Work
started around 00:00 and it is now 15:06 — a single long session of roughly fifteen hours.

| | |
|---|---|
| Calendar days used | **1 of 15** |
| Calendar days remaining | **14** |
| Plan-days of work completed | **3** (days 1, 2, 3) |
| Plan-days of work remaining | **12** (days 4–15) |
| Unplanned work completed | Tier 2 HTTPS inspection — estimated at 2–4 days in the plan |

So the project is **ahead on calendar, level on work**. That is a better position than it
felt like during the session, when the ad-blocking detour seemed to be consuming the
schedule. It was not: it consumed hours, not days.

---

## 2. What actually exists, verified

### Infrastructure — complete and reboot-tested

| Component | State | Evidence |
|---|---|---|
| Routed gateway: Wi-Fi AP, DHCP, DNS, NAT | Working | 7 services active; survives reboot unattended |
| Router independence | Achieved | Zero configuration on the home router; it is a plain uplink |
| DNS filtering | Working | 655,974 rules across 5 lists; blocking verified |
| DNS bypass prevention | Working | Port-53 DNAT, DoH/DoT blocking, QUIC rejection; 0 bypasses observed |
| Suricata sensor | Working | 52,689 rules, 0 packet drops, 535 MB RSS, 12% of one core |
| Selective HTTPS inspection | Working | YouTube first-party ads removed on two devices; 0 non-allowlisted hosts decrypted |
| Backup | Working | Private GitHub repository, 3 commits, no secrets |
| Operations tooling | Working | `securepi status/devices/enroll/unenroll`, `battery`, `backup.sh` |

### Data being produced right now

```
/var/log/suricata/eve.json           652 KB   flow · dns · tls · http · alert · anomaly
/opt/AdGuardHome/data/querylog.json  688 KB   every DNS decision, per client
DHCP leases                          2 devices with stable identity
```

### Report material — unexpectedly far ahead

| Document | Status |
|---|---|
| Feasibility analysis, topology comparison, technology selection | Complete (~96 KB) |
| 15-day build plan with measured topology and constraints | Complete |
| Ad-blocking subsystem report chapter | Complete, with measured results |
| First-party ad analysis, including a corrected earlier conclusion | Complete |
| Gateway setup runbook, OS install guide, next-session notes | Complete |

Chapters 1–4 of the thesis are effectively written, and chapter 5 has its first section.

---

## 3. What does not exist

`/opt/securepi` does not exist on the gateway. **No application code has been written.**

| Missing | Plan day | Consequence |
|---|---|---|
| SQLite schema | 4 | Nothing is persisted; all analysis is impossible |
| Ingest service (EVE tailer + AGH querylog) | 4 | Events accumulate in log files and are never read |
| FastAPI skeleton + first page | 5 | No end-to-end slice exists |
| Device registry / identity resolution | 6 | No attribution; every later feature depends on this |
| Devices page | 7 | — |
| Signal framework + port scan, brute force | 8 | **No detection at all** |
| Malicious-domain, new-device signals; incidents | 9 | **The core contribution** |
| Incidents page | 10 | The thesis is not visible anywhere |
| Overview dashboard | 11 | — |
| Filtering page | 12 | Ad blocking not controllable from our own UI |
| Risk scoring, quarantine, auth | 13 | — |
| Evaluation campaign | 14 | No results table |
| Report finalisation, demo rehearsal | 15 | — |

**The distinction that matters:** days 1–3 were *configuration* — installing and wiring
mature software. Days 4–13 are *construction* — writing the layer that constitutes the
academic contribution. Configuration went quickly because it was configuration. It does
not predict the pace of the remainder.

---

## 4. Distance to the objective

The stated objective is a unified platform doing network monitoring, ad blocking and
lightweight SOC, presented as one product.

| Pillar | Progress | Notes |
|---|---|---|
| **Ad blocking** | **~90%** | Working at two tiers and measured. Missing only control from our own UI rather than the underlying tool's API |
| **Network monitoring** | **~25%** | Sensor produces the data; nothing reads, stores, attributes or displays it |
| **SOC** | **~5%** | Only the sensor exists. No storage, no correlation, no incidents, no console |
| **Unified platform** | **0%** | There is no console. Nothing is unified yet — it is three good tools on one host |

Roughly **30% of the product**, and the remaining 70% is the part that is not
off-the-shelf. That is the correct shape for this point, but it should not be mistaken
for being most of the way there.

---

## 5. Revised schedule

Twelve plan-days of work remain against fourteen calendar days. Two days of genuine slack
— the first slack this project has had.

| Calendar | Work | Gate |
|---|---|---|
| Day 2 | SQLite schema + ingest service (plan day 4) | Events landing in the database |
| Day 3 | FastAPI + first page (plan day 5) | **First end-to-end slice — demoable** |
| Day 4 | Device registry (plan day 6) | Inventory populated, identity stable |
| Day 5 | Devices page (plan day 7) | Recognisably a product |
| Days 6–7 | Signal framework + first two signals (plan day 8) | **First real detections** |
| Day 8 | Remaining signals, incident grouping (plan day 9) | Incidents created |
| Day 9 | Incidents page (plan day 10) | The contribution is visible |
| Day 10 | Overview dashboard (plan day 11) | Console shape complete |
| Day 11 | Filtering page (plan day 12) | Ad blocking under our own UI |
| Day 12 | Risk scoring, quarantine, auth (plan day 13) | Feature-complete |
| Day 13 | Evaluation campaign (plan day 14) | Results collected |
| Day 14 | Report, demo rehearsal (plan day 15) | Submittable |
| Day 15 | **Slack** | Absorbs one bad day |

Note days 6–7: the signal framework gets two calendar days rather than one. It is the
academic core and the thing most likely to overrun, and the slack exists precisely to
protect it.

---

## 6. The real constraint on pace

Not the schedule. **Everything remaining is Python, and the user does not write Python.**

Consequences that should shape how the next twelve days run:

1. **Every line goes through Claude.** Raw production speed is not the bottleneck.
2. **The user must be able to defend it.** Examiners probe the correlation engine because
   it looks most impressive. "Claude wrote it" is the one unavailable answer.
3. **Therefore: fifteen minutes at the end of each build day** writing down what went in
   and why. This is not overhead — it is chapter 5 being written while the reasoning is
   fresh, and it is viva preparation.
4. **Code style is a hard requirement, not a preference.** Plain constructs, explicit
   loops, hand-written SQL over an ORM, no decorator or async cleverness. Readability is
   the deliverable as much as function.

---

## 7. Risks, reassessed

| Risk | Was | Now | Why |
|---|---|---|---|
| Running out of time | High | **Medium** | 2 days slack now exist; infrastructure risk is retired |
| Correlation engine overruns | High | **High** | Unchanged. Still the core, still unstarted, still the thing to protect |
| User cannot explain the code at viva | High | **High** | Unchanged. Mitigated only by the daily write-up discipline |
| Hardware inadequate | Medium | **Retired** | Measured: 2.3 GB RAM free, 12% CPU, zero packet drops |
| Storage growth | High | **Low** | 146 MB/day measured on 88 GB free; 15-day horizon makes it a non-issue |
| Scope creep | High | **Medium** | One detour already taken (Tier 2). No further detours affordable |

---

## 8. Recommendation

**Start plan day 4 — the SQLite schema and ingest service — and do not add scope.**

Three specific cautions for the next stretch:

**Do not improve the ad blocking further.** It works, it is measured, it is written up.
It is the one pillar near completion and every additional hour there comes directly out
of the SOC.

**Build vertically, as the plan says.** Get one ugly end-to-end slice — one event type,
into SQLite, out to one plain web page — working by calendar day 3. Then thicken it.
If the project stops on any given day thereafter, there is still something to demonstrate.

**Treat calendar day 15 as untouchable slack.** It is the only protection against a bad
day, and this project has already demonstrated that unplanned problems arrive without
warning.

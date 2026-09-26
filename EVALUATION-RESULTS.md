# SecurePi Gateway — Day 14 Evaluation Results

Measured 13 September 2026, against the live gateway, using the scripted test
harness (`gateway/evaluate.py`) run as `sudo python3 evaluate.py` on the Dell.
Everything below is a real measurement, not an estimate. Detection tests ran
against the isolated `ns_attacker`/`ns_victim` namespaces (see
`gateway/setup-test-harness.sh`) and never touched the two real devices on
the network.

---

## 1. Detection rate and time-to-detect

Each of the four signals fired three times. "Detected" means the engine
raised or extended an incident within 90 seconds of the attack starting.

| Signal | Runs detected | Latencies (s) | Average |
|---|---|---|---|
| Port scan | 3/3 | 72.1, 2.0, 2.0 | 25.4s |
| Brute force | 3/3 | 74.1, 14.0, 14.0 | 34.0s |
| Malicious domain (blocked-domain repeat) | 3/3 | 11.0, 12.0, 11.0 | 11.3s — **see caveat below** |
| New device | 3/3 | 45.1, 45.1, 45.1 | 45.1s |

**Why run 1 is consistently the slowest for port scan and brute force:** the
engine cycle is 15s and both signals use a 600s dedup window; run 1 has to
wait for a fresh engine cycle to notice the new pattern, while runs 2 and 3
(fired minutes later, well inside the same dedup window) mostly just extend
the incident the moment the next attempt lands. This merging is not a
measurement artifact — it is the reduction ratio (§3) working exactly as
designed: three attack bursts against the same device within the dedup
window correctly become one incident with three pieces of corroborating
evidence, not three separate alerts.

**New device is the only signal with no run-to-run variance**, because its
latency is structural rather than data-dependent: `NEW_DEVICE_GRACE_SECONDS`
(30s, deliberately waiting for the registry to finish resolving identity)
plus one engine cycle (up to 15s) accounts for the entire 45.1s in every run.

### A real bug found and fixed: new-device detection did not work

Before this evaluation, `new_device_signal` used a persisted watermark
(`get_window_start` / `set_window_start`) the same way an earlier draft of
the other three signals did, before those were corrected to a fresh trailing
window every cycle (see the comments already in `correlation.py`). New-device
detection was never corrected the same way, and it turned out to matter: the
watermark advances to the current cycle's time regardless of whether a given
device's 30-second grace period has elapsed. A device too new to qualify on
its first engine cycle is guaranteed to fall behind the watermark by the very
next cycle — 15 seconds later — and can never match the query again.

Confirmed directly (not inferred): a device created and left alone past its
grace period still did not fire on the following cycle, under the old code.
The reason the three new-device incidents from earlier sessions (devices 1,
2, and the original test-attacker) exist at all is almost certainly luck of
timing around a service restart, not the signal working as designed.

**Fixed** in `app/correlation.py`: `new_device_signal` now recomputes a
trailing window every cycle (`NEW_DEVICE_LOOKBACK_SECONDS = 3600`), exactly
like the other three signals, and relies on `raise_incident`'s own dedup to
avoid re-raising for a device already inside an open incident. The watermark
is still written for the console's signal-health panel, just no longer used
to filter results. Verified live: all three new-device runs above detected
correctly after the fix, at 45.1s every time.

This is the most consequential finding of day 14 — one of the project's four
core signals was not working in normal operation before today.

### Malicious-domain caveat: the number above is not a production latency

`malicious_domain_signal` reads from `events`, which `ingest.py` populates by
tailing the DNS filter's `querylog.json` file on disk. During testing, that
file's on-disk copy went **over 7 hours** without a single new line written,
despite continuous real DNS traffic from both real devices the whole time —
confirmed by comparing the file's own `stat` (last modified 7.5h prior) against
the DNS filter's control API (`/control/querylog`), which showed the same queries
immediately. `ingest.py`'s own watermark was sitting exactly at end-of-file,
correctly waiting for data that the DNS filter had simply not written yet.

The cause is the DNS filter's own `querylog.size_memory: 1000` setting
(`AdGuardHome.yaml`): it buffers up to 1000 queries in memory and only
flushes to disk when that buffer rotates, not on a fixed timer. Firing ~1000
extra DNS queries per test run (visible as the flush-probe traffic in
`evaluate.py`) is what forced each flush and produced the ~11s numbers above.
**In ordinary operation, malicious-domain detection latency is bounded by
whichever is worse: the engine's 15s cycle, or the DNS filter's own flush cadence —
and the flush cadence was observed to be hours, not seconds, under real
traffic.**

This is a genuine limitation, not a bug in this project's own code, and not
fixed here — recorded for the report's limitations chapter. The two
lowest-effort fixes, for future work: lower `querylog.size_memory` in
the DNS filter's own config, or switch `ingest.py`'s DNS source from the file to
the DNS filter's control API (which is current in real time).

---

## 2. Alert-to-incident reduction ratio

Measured over a clean 24-hour window of real operation, **before** today's
evaluation traffic:

| Metric | Value |
|---|---|
| Raw events | 15,884 |
| Incidents | 10 |
| **Reduction ratio** | **1,588 : 1** |

This is the number that argues for the correlation layer existing at all:
sixteen thousand individual observations became ten things a person actually
has to look at.

(For context, not as the headline figure: including today's evaluation
traffic — three deliberate attack runs per signal, plus ~3,000 DNS queries
used purely to force the DNS filter's log to flush — the same 24h window shows
23,788 events against 23 incidents, a ratio of 1,034:1. The ratio drops
because the extra incidents are almost entirely the evaluation's own
deliberate detections, not because dedup got worse.)

---

## 3. False positives

Reviewed every incident ever raised against the two real devices
(`divye-s-s21-fe`, `kushagra-s-a33`):

| Incident | Signal | Verdict |
|---|---|---|
| New device joined: divye-s-s21-fe | new_device | Legitimate — genuinely a new device |
| New device joined: kushagra-s-a33 | new_device | Legitimate — genuinely a new device |
| Repeated blocked-domain lookups (35 in 600s) | malicious_domain | **False positive** |

The third one is real and worth reporting honestly. Reviewing its evidence
chain, the 19 blocked lookups behind it are ordinary Android background
traffic during active phone use — `app-measurement.com`, Firebase
Crashlytics, `googlesyndication.com`, `doubleclick.net` subdomains, ad SDK
telemetry — the kind of thing dozens of installed apps generate continuously
whether or not anything is "wrong." At `MALICIOUS_DOMAIN_THRESHOLD = 15`
blocked lookups in a 600-second window, a phone in active use with several
ad-supported apps open can cross the threshold on ordinary background chatter
alone.

**This is a real, honest limitation of a count-based threshold**, not a
signal that's broken. The signal's own design note already argues for
*distinct* domains over raw count for exactly this reason; this incident (12
distinct domains behind 19 blocked lookups) suggests the current threshold
still admits background noise. Worth tuning in future work — raising the
threshold, weighting by distinct domains more heavily, or requiring a
domain never seen before from that device — but not changed here, since
correctly identifying the boundary is the point of this evaluation, and
retuning a detection threshold two days before the report is due is exactly
the kind of change that deserves its own measurement cycle, not a rushed one.

**Zero false positives** from `port_scan` or `brute_force` against either
real device, over their entire history to date.

---

## 4. Ad-block ratio, third-party

`REPORT-adblocking.md` §9 explicitly left this "to be measured." Measured
now: 10 domains known to be on the DNS filter's active blocklists, resolved through
the DNS filter (`10.10.0.1`) and through a public resolver (`1.1.1.1`) with no
filtering, side by side.

| Domain | Via the DNS filter | Via public resolver |
|---|---|---|
| doubleclick.net | 0.0.0.0 (blocked) | 142.251.223.14 |
| googlesyndication.com | 0.0.0.0 (blocked) | 142.250.66.4 |
| googleadservices.com | 0.0.0.0 (blocked) | 142.251.222.130 |
| adservice.google.com | 0.0.0.0 (blocked) | 142.251.223.2 |
| scorecardresearch.com | 0.0.0.0 (blocked) | 77.72.114.225 |
| adnxs.com | 0.0.0.0 (blocked) | resolved |
| outbrain.com | 0.0.0.0 (blocked) | resolved |
| taboola.com | 0.0.0.0 (blocked) | resolved |
| criteo.com | 0.0.0.0 (blocked) | 23.185.0.4 |
| pubmatic.com | 0.0.0.0 (blocked) | resolved |

**Result: 10/10 (100%) blocked.** Read alongside the first-party figures
already in `REPORT-adblocking.md` §9 (0% via DNS alone, effective via Tier 2
HTTPS inspection), the project now has both halves of the ad-blocking story
measured: complete on third-party, structurally zero on first-party via DNS,
closed by selective inspection for enrolled devices.

---

## 5. Resource usage

Snapshot taken immediately after the full detection battery (i.e. under
load, not idle):

| | |
|---|---|
| Total memory | 3,683 MB |
| Used | 1,457 MB (40%) |
| Available | 2,225 MB |
| Load average (1/5/15 min) | 0.17 / 0.16 / 0.13 |

Per-service memory:

| Service | Memory |
|---|---|
| IDS | 683 MB |
| DNS filter | 235 MB |
| securepi-web | 121 MB |
| securepi-ingest | 15 MB |
| securepi-engine | 5 MB |

Matches the day-1 budget in `SECUREPI-15-DAY-PLAN.md` §2.6 (the IDS ~0.7GB,
DNS filter ~0.2GB, app ~0.3GB) closely, with over 2GB still free even while
three attack simulations were actively running. The 3.6GB constraint that
drove the "no Docker" decision on day 1 has held up in practice.

---

## 6. Throughput

`iperf3` between the two test-harness namespaces (`ns_attacker` ↔
`ns_victim`, over `br-test` — the same bridge the IDS captures on, via
`veth-atk`, exactly as it captures production traffic on `ap0`) against a
loopback baseline with no bridge or capture path at all:

| Path | Throughput |
|---|---|
| Through the bridge + IDS capture | 39.9 Gbps |
| Loopback (no bridge, no capture) | 57.5 Gbps |

Both figures are far beyond anything the gateway's real uplink will ever see
(these are virtual interfaces at host-memory speed, not a physical link) —
which is exactly the point: `SECUREPI-15-DAY-PLAN.md` §2.6 already measured
and explained that the real-world ceiling (~30 Mbps) is the home internet
connection, not the gateway's own processing. This test confirms that
conclusion from the other direction — the software forwarding and inspection
path has roughly three orders of magnitude more headroom than the WAN link
will ever ask of it, on this hardware.

---

## 7. Summary against the plan's evaluation table

| Metric (from `SECUREPI-15-DAY-PLAN.md` §7) | Result |
|---|---|
| Detection rate + time-to-detect, 4 attack types | 4/4 signals, 3/3 runs each — see §1 (one real bug found and fixed) |
| Alert-to-incident reduction ratio | 1,588 : 1 (clean 24h) |
| Ad-block ratio, third-party | 100% (10/10 fixed domains) |
| Ad-block ratio, first-party | 0% via DNS, effective via Tier 2 — already in `REPORT-adblocking.md` |
| False positives | 1 found (malicious_domain, count-threshold noise on a real device) — reported honestly, not hidden |
| Resource usage | 40% memory used under load, >2GB free |
| Throughput impact | WAN-bound (~30Mbps), not gateway-bound (tens of Gbps headroom) |

Reproducible via `gateway/evaluate.py`, which re-runs every measurement in
this document against the live gateway and never touches the two real
devices.

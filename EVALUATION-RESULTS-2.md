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

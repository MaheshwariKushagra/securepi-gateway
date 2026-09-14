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

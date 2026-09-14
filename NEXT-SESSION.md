# Starting the next session

## 0. First, run the health check

```
./session-start.sh
```

This brings up the Mac's SSH tunnel to the console (`http://localhost:8000`),
runs a full gateway status check, and confirms nothing is uncommitted or
unpushed. Do this before anything else — it answers "did we forget to turn
something back on" in one command.

## 1. Power on (if the gateway was shut down)

- Open the Dell's lid and press the power button.
- **The screen stays black.** That is deliberate — the backlight is switched off
  because a lit panel behind a closed lid wastes power and adds heat. The machine
  is running.
- Close the lid again. Sleep is masked, so it keeps running.
- **Leave it on the charger.** The gateway runs from battery when unplugged, and
  a battery-death shutdown is not a clean one.

## 2. Make sure the Mac is sharing

The management link needs the MacBook's Internet Sharing running, or SSH will not
reach the Dell:

**System Settings → General → Sharing → Internet Sharing** — share from Wi-Fi, to
the USB Ethernet adapter, toggle on.

(The Dell's own internet comes from Wi-Fi, not from the Mac. Sharing is only for
the management cable.)

## 3. Only if you want HTTPS inspection

It is **off after every reboot**, on purpose — it decrypts traffic, so it should
be switched on deliberately rather than persisting quietly.

```
ssh maheshwari@192.168.2.5 'sudo securepi enroll all'  # YouTube ad removal ON
ssh maheshwari@192.168.2.5 'sudo securepi unenroll'    # back off
```

DNS filtering (656,000+ rules across curated lists, plus a daily-refreshed
offline-threat-intel list) is always on for every device and needs no action.

---

## Where the project stands

Full detail, reasoning, and live-verification notes for every step are in
`ENHANCEMENT-PLAN.md` (the progress tracker is section 8) — this is the
compact summary. Results from Stage 1 onward are in `EVALUATION-RESULTS-2.md`.

| Stage | Focus | Status |
|---|---|---|
| **0** | Housekeeping — planning docs archived, `make deploy`/`make status`, baseline snapshot | **Complete** |
| **1** | Foundation & correctness — test suite, retention, real-time ingest, audit coverage | **Complete** |
| **2** | **Detection breadth** — scan family, DNS-bypass hardening, IDS alerts, threat intel, DNS tunnelling/DGA, C2 beaconing, suppression rules, campaign correlation + ATT&CK kill chain | **Complete** |
| 3 | Hardening & reliability — session auth, TLS, privilege separation, health supervision, fail-open DNS | Not started — **recommended next stage**, see below |
| 4 | Response & orchestration — policy profiles, timed quarantine, notifications | Not started |
| **5** | Ad blocking & privacy filtering (5.11 scoped to Path 1; Path 2 deferred with reasoning recorded) | **Complete** |
| **6** | Intelligence & console — behavioural baselines, device fingerprinting, settings, incident workbench, hunt/explorer, weekly report, responsive layout | **Complete** |
| 7 | Evaluation 2.0 — expanded benchmark battery | Not started |
| 8 | Documentation & demo | Not started |

Stages 5 and 6 were built before Stages 1–2 deliberately, then Stages 1 and 2
were completed in later sessions — each such out-of-order decision is recorded
with its reasoning in `ENHANCEMENT-PLAN.md` rather than left implicit.

### What Stage 2 added (this session, 14 September 2026)

Ten new correlation signals beyond the original six, closing the plan's own
"never cut" detection core:

- **2.1** `network_sweep`, `slow_port_scan`, `slow_network_sweep` — horizontal
  scans and scans paced too slowly for a fast window to catch.
- **2.2** `dns_bypass` — DoH/DoT/QUIC/Private-Relay evasion. Touched the live
  firewall (new `log prefix` on the reject rules, daily-refreshed
  `doh_resolvers` set); backed up and syntax-checked before applying.
- **2.3** `ids_trojan`/`ids_c2`/`ids_c2_domain`/`ids_exploit_kit`/
  `ids_shellcode`/`ids_privilege_gain`/`ids_credential_theft`/`ids_other` —
  Suricata/ET alerts finally turned into incidents (previously ingested but
  never used).
- **2.4** `threat_intel` — matches against a daily-refreshed `ioc` table
  (Feodo Tracker, URLhaus, ThreatFox — 5,600+ real indicators). New
  `securepi-static` (loopback file server) and `securepi-intel-refresh.timer`
  services.
- **2.5** `dns_tunneling`, `dga` — entropy/TXT-ratio/NXDOMAIN-burst based.
- **2.6** `beacon` — RITA-style timing/size regularity score for C2 check-ins.
- **2.7** Suppression rules — a false-positive verdict can silence a signal
  for one device or network-wide, with audit and optional expiry.
- **2.8** Campaign correlation — links a device's incidents across distinct
  ATT&CK tactics into one campaign with a recorded kill chain, weighted into
  the risk score.

Every step above was deployed to the live gateway and verified against real
data (not just synthetic fixtures) — see `EVALUATION-RESULTS-2.md` §2.1–§2.8
for exactly what was and wasn't observed live, including a few real bugs
found and fixed along the way (a `dns_rcode` capture gap, AdGuard rejecting a
`file://` blocklist URL, a ThreatFox CSV quoting mismatch). Test suite grew
from 110 → **206**, all passing.

Two new systemd timers exist now: `securepi-doh-refresh.timer` and
`securepi-intel-refresh.timer` (both daily), plus `securepi-static.service`
(a loopback-only static file server). All three are in `services.list` /
`sudo securepi status`'s health check already.

The isolated test harness (`gateway/setup-test-harness.sh`) now gives
`ns_victim` ten addresses (`10.10.0.221`–`230`) instead of one, needed for
the network-sweep test scenario — this changed the harness meaningfully
enough that recreating it (`sudo ip netns del ns_attacker ns_victim && sudo
ip link del br-test`, then rerun the script, then `sudo systemctl restart
suricata`) was necessary once, live, this session. Shouldn't be needed again
unless the harness script changes further.

### Recommended next step: Stage 3 (Hardening & reliability)

Session authentication, TLS on the console, privilege separation (the web
app currently calls `nft` directly), a health supervisor, and fail-open DNS.
None of it depends on anything still missing from Stage 4.

### Known real bugs found and fixed (for context, not action)

From earlier sessions: `new_device_signal`'s old persisted-watermark bug,
`raise_incident`'s old cumulative evidence-count bug, and G1/G2/G3/G6 from
the original gap analysis — all fixed with regression tests
(`tests/test_correlation.py`).

From this session (Stage 2): see `EVALUATION-RESULTS-2.md` for full detail
on each — the `dns_rcode`/`status` field ingest.py never captured, AdGuard's
`add_url` rejecting a `file://` scheme, and ThreatFox's CSV quoting (a space
after each comma) silently parsing zero rows under a naive split.

## Two things still outstanding from Day 15 (unrelated to this session's work)

1. **Purge the journal** — it holds URLs captured during the window when the
   SNI allowlist was briefly broken:
   ```
   ssh -t maheshwari@192.168.2.5 'sudo journalctl --rotate && sudo journalctl --vacuum-time=1s'
   ```
2. **Remove the CA from the phone after the demo** — Settings → Security →
   Encryption & credentials → Trusted credentials → User → SecurePi Gateway.

Neither was touched this session; carry them forward until actually done.

## Credentials, and where they are NOT

Nothing sensitive is in this repository. On the gateway:

| What | Where |
|---|---|
| CA private key | `/opt/securepi-dpi/ca/mitmproxy-ca.pem`, root-only |
| DNS admin password | `/root/.securepi-dns-password` |
| Console login password (user `securepi`) | `/root/.securepi-console-password` |
| Wi-Fi AP passphrase | `/etc/hostapd/hostapd.conf` (redacted in the committed copy) |

The user's own GitHub Personal Access Token is stored via `git credential-osxkeychain`
(macOS Keychain) on the Mac, never in a file or a git remote URL — already
configured and working. If given the token again in a future session, no
further setup is needed; just keep pushing after major changes.

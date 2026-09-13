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
  a battery-death shutdown is not a clean one. At the end of this session the
  gateway was on battery at 31% — check the charger is actually connected before
  leaving it.

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

DNS filtering (656,000+ rules across 5 curated lists) is always on for every
device and needs no action.

---

## Where the project stands

Full detail, reasoning, and live-verification notes for every step are in
`ENHANCEMENT-PLAN.md` (the progress tracker is section 8) — this is the
compact summary.

| Stage | Focus | Status |
|---|---|---|
| 0 | Housekeeping | Not started |
| **1** | **Foundation & correctness** — real test suite (110+ tests), retention, real-time AdGuard ingest, complete audit coverage, four detection-accuracy fixes | **Complete** |
| 2 | Detection breadth — beaconing, DNS tunnelling, campaigns, MITRE ATT&CK | Not started — **recommended next stage**, see below |
| 3 | Hardening & reliability — session auth, TLS, health supervision | Not started |
| 4 | Response & orchestration — policy profiles, timed quarantine, notifications | Not started |
| **5** | **Ad blocking & privacy filtering** (5.11 scoped to Path 1; Path 2 deferred with reasoning recorded) | **Complete** |
| **6** | **Intelligence & console** — behavioural baselines, device fingerprinting, settings, incident workbench, hunt/explorer, weekly report, responsive layout | **Complete** |
| 7 | Evaluation 2.0 — expanded benchmark battery | Not started |
| 8 | Documentation & demo | Not started |

Stages 5 and 6 were built before Stage 1 deliberately, then Stage 1 was
completed this session — each such out-of-order decision is recorded with its
reasoning in `ENHANCEMENT-PLAN.md` rather than left implicit.

### Recommended next step: Stage 2 (Detection breadth)

`ENHANCEMENT-PLAN.md` calls Stage 2 the project's academic core and says
"never cut" it. It adds: the scan family (network sweep, slow scan), DNS
bypass hardening + detection, IDS alerts → incidents, offline threat intel,
DNS tunnelling/DGA detection, C2 beaconing, suppression rules, and campaign
correlation with MITRE ATT&CK. None of it depends on anything still missing
from Stages 3/4.

### Known real bugs found and fixed this session (for context, not action)

- `new_device_signal`'s old persisted-watermark bug and `raise_incident`'s old
  cumulative evidence-count bug — both already fixed before this session,
  now permanently regression-tested (`tests/test_correlation.py`).
- A real 5.5-hour timestamp skew affecting every AdGuard-sourced event
  (`to_epoch_agh` hardcoded UTC regardless of the real offset) — fixed in
  step 1.4. Events ingested before that fix still carry the old skewed
  timestamp; this was a deliberate choice (see `ENHANCEMENT-PLAN.md`'s note
  on step 1.4), not an oversight.
- G1/G2/G3/G6 from the original gap analysis (scan-signal naming, incident
  dedup status, malicious-domain false positives, device-attribution
  tie-break) — all fixed in step 1.6, each with a regression test.

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

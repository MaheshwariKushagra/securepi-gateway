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

## 2b. If devices join SecurePi-Test but get no internet

Check the `WAN` line of `sudo securepi status`. If it's blank, the Dell can't
see any saved upstream network (e.g. Babu_Home when away from home). Add the
network you're near, then apply. The password is typed at a hidden prompt:

```
ssh -t maheshwari@192.168.2.5 'sudo securepi-add-uplink "Network Name"'
ssh maheshwari@192.168.2.5 'sudo systemd-run --collect /usr/sbin/netplan apply'
```

Saved networks: Babu_Home, Redmi Note 12 Pro 5G. Avoid networks with a browser
login page (campus "STAFFS"/open networks) - the gateway can't click through one.
`securepi-ap-follow-uplink.service` moves SecurePi-Test onto the uplink's
channel automatically (one radio can't do two channels); the AP is 2.4 GHz
only, so a 5 GHz-only uplink won't work.

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

### Console redesign (14–15 September 2026, separate session)

Front-end only: `app/static/app.css`, `app/static/app.js` and
`app/templates/*.html`. No API routes, template context or backend
behaviour changed, and the test suite is still **206**, all passing. Every
step was deployed with `make deploy`, and all 12 front-end files were
checksum-verified on the gateway afterwards.

| Commit | What |
|---|---|
| `bc43430` | Visual overhaul: design tokens, grouped sidebar + breadcrumbs, KPI icons/meters, incident and device header cards, device Controls card, playbook as three steps, phone bottom tab bar |
| `090e975` | Dark / light theme toggle (topbar button + ⌘K entry, saved per browser in `localStorage` key `sp.theme`, dark is the default) |
| `52942a6` | Theme switch radiates out from the toggle (View Transitions API, crossfade fallback) |
| `4732a88` | Motion system: page-to-page transitions, sliding segmented-control indicator, popover/palette exit animations, new-row highlights, bars and meters that glide on live refresh |
| `4cbeaed` | README screenshots regenerated, including a new light-theme dashboard capture; these notes |

**Real bugs fixed along the way** (all were present before the redesign):
- Bar-list fills (Top Talkers, Detections by Signal, …) never rendered:
  the fill was an inline `<span>`, which ignores width.
- Audit log, weekly report, Hunt saved searches, Related Incidents and the
  status timeline all reused the dashboard's 4-column event grid and
  overlapped or truncated.
- The incidents table overflowed at 1440px, hiding Evidence and Last seen.

**Things a future change needs to know:**
- **Colors are tokens.** A new component should use the CSS variables, never
  hex values, or it won't follow the light theme. The light palette is only
  token overrides under `:root[data-theme="light"]`.
- **Chart colors live in two places.** Chart.js draws on a canvas and can't
  read CSS variables, so `CHART_PALETTES` in `app.js` duplicates the chart
  roles. Keep it in step with `app.css`. On a theme switch every chart is
  rebuilt from its own config (`restyleCharts`), because an in-place
  `chart.update()` leaves bar and doughnut segments in the old colors
  (Chart.js caches them).
- **Clicks during a view transition.** Chromium sends every click to `<html>`
  while one runs, and CSS `pointer-events` can't change that. `app.js`
  finishes the transition and re-dispatches the click to the element under
  the pointer. Don't remove that listener, or quick double-clicks and
  mid-transition navigation silently break.
- **Row animations use `animation-fill-mode: backwards` on purpose.** A
  lingering transform gives each table row its own stacking context and
  traps the incident row menu under the next row.
- **Lists that refresh live are keyed** (`data-key`, `markNewRows`,
  `renderBarList`), so a 5-second refresh only animates what actually
  changed. A new list that re-renders on the live tick should follow the
  same pattern rather than rebuilding with `innerHTML` and animating
  everything.
- **Motion is off under `prefers-reduced-motion`**: page transitions,
  smooth scroll and the theme reveal all check it.
- **Browser support**: page transitions need Chrome/Edge/Brave 126+ or
  Safari 18.2+; exit animations need Chrome 117+ or Safari 18. Older
  browsers fall back to instant changes. Only Chromium (Brave) was tested in
  automation — Safari support is from its documentation, not verified here.

**Regenerating the README screenshots** (`docs/demo/README.md` has the full
steps): run `seed.py` and then **restart** `serve.py`. A demo server left
running from earlier keeps the old, deleted database file open and shows
hours-stale data (empty charts), even after a fresh seed.

**Follow-up done:** the Related Incidents card footer on the incident page
used to say campaign correlation was "not-yet-built". It now describes the
step 2.8 campaign behaviour and links to the device's risk score, where an
open campaign appears as a "Chain" row. The same stale claim in the
docstrings of `webapp.py`'s `_related_open_incidents` and `playbooks.py` was
corrected too.

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
| CA private key (DPI/HTTPS inspection) | `/opt/securepi-dpi/ca/mitmproxy-ca.pem`, root-only |
| Console TLS CA/leaf private keys (step 3.2) | `/opt/securepi-tls/{ca,console}.key`, root-only (certs are `root:securepi`, group-readable) |
| DNS admin password | `/etc/securepi/dns-password` (moved out of `/root` in step 3.3), `root:securepi` |
| Console login password (user `securepi`) | `/etc/securepi/console-password` (moved out of `/root` in step 3.3), `root:securepi` |
| Wi-Fi AP passphrase | `/etc/hostapd/hostapd.conf` (redacted in the committed copy) |

The user's own GitHub Personal Access Token is stored via `git credential-osxkeychain`
(macOS Keychain) on the Mac, never in a file or a git remote URL — already
configured and working. If given the token again in a future session, no
further setup is needed; just keep pushing after major changes.

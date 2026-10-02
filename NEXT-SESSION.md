# Starting the next session

## 0. First, run the health check

```
./session-start.sh
```

This brings up the Mac's SSH tunnel to the console (`https://localhost:8000` — HTTPS-only since step 3.2),
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
| **3** | Hardening & reliability — session auth, TLS, privilege separation, security self-review, health supervision, fail-open DNS | **Complete** |
| **4** | Response & orchestration — policy orchestrator, MAC-keyed timed quarantine, IP/domain blocks, auto-response, filtering profiles & schedules, device trust, notifications | **Complete** (one real-device check pending, see below) |
| **5** | Ad blocking & privacy filtering (5.11 scoped to Path 1; Path 2 deferred with reasoning recorded) | **Complete** |
| **6** | Intelligence & console — behavioural baselines, device fingerprinting, settings, incident workbench, hunt/explorer, weekly report, responsive layout | **Complete** |
| **7** | Evaluation 2.0 — expanded benchmark battery | **Nearly complete** — everything except the 7.0 seven-day run (not yet started) and the 7.9 usability study (needs people); see below |
| 8 | Documentation & demo | Not started |

Stages 5 and 6 were built before Stages 1–2 deliberately, then Stages 1 and 2
were completed in later sessions — each such out-of-order decision is recorded
with its reasoning in `ENHANCEMENT-PLAN.md` rather than left implicit.

### What Stage 2 added (14 September 2026)

Ten new correlation signals beyond the original six, closing the plan's own
"never cut" detection core:

- **2.1** `network_sweep`, `slow_port_scan`, `slow_network_sweep` — horizontal
  scans and scans paced too slowly for a fast window to catch.
- **2.2** `dns_bypass` — DoH/DoT/QUIC/Private-Relay evasion. Touched the live
  firewall (new `log prefix` on the reject rules, daily-refreshed
  `doh_resolvers` set); backed up and syntax-checked before applying.
- **2.3** `ids_trojan`/`ids_c2`/`ids_c2_domain`/`ids_exploit_kit`/
  `ids_shellcode`/`ids_privilege_gain`/`ids_credential_theft`/`ids_other` —
  IDS/ET alerts finally turned into incidents (previously ingested but
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
found and fixed along the way (a `dns_rcode` capture gap, the DNS filter rejecting a
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

### What Stage 3 added (20–21 September 2026)

Every step was deployed to the live gateway and verified there — see
`EVALUATION-RESULTS-2.md` §3.1–§3.6 for exactly what was observed.

- **3.1 Session login** replaces Basic Auth: PBKDF2-hashed password,
  HttpOnly `SameSite=Strict` cookie, login rate limit, Origin check on every
  write, idle + absolute timeout. `Origin: null` is treated as same-origin
  (fix `84dbadf`).
- **3.2 HTTPS only** on the console, from its own CA (separate from the DPI
  CA). Plain HTTP gets no response. To stop the browser warning on the Mac,
  trust `/opt/securepi-tls/ca.crt` once — the command is in `README.md`.
- **3.3 Privilege separation:** `securepi-web` runs as an unprivileged user.
  Quarantine and enroll/unenroll go through `securepi-web-helper`, the only
  thing the sudoers rule allows. Password files moved to `/etc/securepi/`.
- **3.4 Security self-review** → `docs/SECURITY-REVIEW.md`. mitmproxy no
  longer listens on the WAN, and SSH password login is off (keys only).
- **3.5 Health supervisor** (`app/health.py`, run from ingest's loop): a
  stopped service, disk pressure, DB growth or a WAN outage becomes a
  platform incident.
- **3.6 Fail-open DNS** (`app/dns_failopen.py`): if the DNS filter stops
  answering, plaintext DNS on `ap0` is redirected to a public resolver and
  the console shows a "protection degraded" banner; it reverts on recovery.

The console password is now a one-way hash — `sudo cat`-ing the file no
longer gives you something you can log in with. Resetting it is the
emergency SSH procedure in `README.md`.

Test suite: **303**, all passing.

### What Stage 4 added (25–26 September 2026)

Everything the console enforces is now a row in the `policies` table, applied
by `app/orchestrator.py`, read back from nftables/AdGuard, and rolled back if it
didn't take. Every engine cycle it also expires timed policies, follows DHCP
renewals, and repairs anything changed outside the console (audit row +
`policy_drift` incident). The new **Response** page (sidebar) shows all of it.
Full live results: `EVALUATION-RESULTS-2.md` §Stage 4.

- **4.1 Orchestrator.** Console and engine share one `flock`
  (`/var/lib/securepi/orchestrator.lock` since 26 September). Tier 2 enrollment is the exception:
  it's never re-added if something else turned it off.
- **4.2 Response.** Quarantine is keyed on **MAC** (`inet filter
  quarantine_mac`, kernel timeout as a backstop) and can be timed. Block
  IP (`blocked_ip`) and block domain from an incident's Respond card.
  Auto-quarantine for 3-tactic campaigns is **off** by default (Response page).
- **4.3 Profiles.** Standard/Kids/IoT/Strict privacy/Unrestricted on each
  device page, editable on Filtering → Profiles. Daily service-block
  schedules, pause 5/15/60 min per device or for everyone.
- **4.4 Trust.** Approved/unknown/blocked. "Restrict unknown devices" is
  **off**. Turning it on approves the devices already present first.
- **4.5 Notifications.** Settings → Notification Channels (ntfy,
  Telegram, email, signed webhook). None configured on the gateway yet.

**Things a future change needs to know:**
- **Firewall file.** `/etc/nftables.conf` is now the repo's
  `gateway/nftables.conf` (it had been stuck at the pre-2.2 version, so reboots
  kept dropping the DNS-bypass log prefixes). Any future firewall change must
  be installed there too, not only loaded with `nft -f`.
- **DNS-filter rules can't carry comments.** A trailing `# ...` makes the rule
  match nothing. The orchestrator tracks its own rules in
  `orchestrator_state`; don't tag rule text.
- **Don't use `filtering_enabled` alone to "turn filtering off".** It
  leaves blocked services and safe search applying.
- **Backups of `securepi.db` must be mode 600.** They contain session
  tokens and channel secrets; the old ones were 644 (fixed).
- The console password is a one-way hash, so live checks run the orchestrator
  as `sudo -u securepi-web python3 ...` on the gateway rather than over HTTP.

**Done 26 September (was pending): the real-device check (4.2).** "Quarantine survives a DHCP renewal"
needs a phone on SecurePi-Test (the harness can't reach `ap0`). Connect it,
quarantine it for 15 min from its device page, toggle its Wi-Fi off and on,
and confirm it stays offline, then comes back on its own when the time is up
(`sudo nft list chain inet filter forward` - the `quarantined-mac` counter
should rise).

Test suite: **362**, all passing.

### Audit fixes deployed, real-phone checks done (26 September 2026)

An external static audit (`Audit.md`, in the repository root) was triaged item by item;
the accepted fixes are commits `44c8c6c`-`5d616fa` (tests 382 -> 442) and are
**deployed**. What a future change needs to know:

- **Writable data moved out of the code directories.** Database and
  orchestrator lock: `/var/lib/securepi/`. DPI rule set:
  `/var/lib/securepi-dpi/adfilter-rules.json`. `/opt/securepi` and
  `/opt/securepi-dpi` are root-only code now. `make deploy` refuses to run
  if the database isn't at the new path, and also ships
  `dpi/adfilter_rules.py`. Pre-migration backup:
  `/opt/securepi/securepi.db.pre-audit-fixes-20260926-075723.bak`.
- **`/etc/nftables.conf` has four new input-chain rules** (quarantine,
  blocked IP and DoH for proxied HTTPS on :8080). They were added live with
  `nft -f` of just those rules - the full file starts with `flush ruleset`,
  which would empty the quarantine/enrolled/DoH sets.
- **`battery.py` and `evaluate.py` in the repo point at the new database
  path**; copy them to `/opt/securepi-eval/` before the next battery.
- Two stray files owned by `maheshwari` sit in `/opt/securepi` (`app.js`,
  `app.css`, 13 Sep copies); harmless, can be deleted.

The real-phone checks (a Galaxy A33 over `adb`) passed: inspection redirect,
quarantine surviving a reconnect, the new proxied-HTTPS rule, DoT/QUIC
bypass detection, and fail-open DNS (the phone resolved through the
redirect while the DNS filter was down). Details and caveats:
`EVALUATION-RESULTS-2.md`, "Real-device checks". **Device 2 is that phone**,
so its open `slow_network_sweep` incidents come from ordinary phone traffic.

### Stage 7: 7.1 and 7.2 done, pre-run fixes deployed (26 September 2026)

Full results in `EVALUATION-RESULTS-2.md` §Stage 7. In short: the first
five-run battery (05:43) detected **every signal 5/5** and the benign host
stayed quiet; its capture replayed on the Mac agreed on all 45 scored runs.

**Later the same day - the three fixes Stage 7 needed before its final
measurements, all deployed and live** (details in EVALUATION-RESULTS-2.md,
"Pre-run fixes"):
- **Inspection now fails open** (7.7's requirement). New `ip nat dpi_up`
  gate set: the dpi-redirect rule only fires while it holds "ap0". The
  proxy's unit opens it once listening and closes it on any stop
  (`dpi/dpi-gate.sh`); `app/health.py` closes it for a hung-but-running
  proxy and reopens it when the proxy answers (`app/dpi_gate.py`).
  Measured live: stop → closed at once; frozen proxy → closed in 27 s
  (incident #476, a test - resolve it); resumed → reopened in 28 s.
  `/etc/nftables.conf` updated (backup `/etc/nftables.conf.pre-dpi-gate-*.bak`).
- **Sweep false positives fixed:** network_sweep and slow_network_sweep now
  count only private or unanswered destinations.
- **volume_anomaly `first_seen`** is now when the hour's total crossed the
  anomaly line, so campaign tactic chains read in the right order.

### Stage 7 almost done (2 October 2026, one long session)

All results and method notes are in `EVALUATION-RESULTS-2.md` §Stage 7. Headlines:

| Step | Result |
|---|---|
| Audit H1/H2 (`CODEBASE_AUDIT.md`) | Both deployed and verified live: a flushed enrolment stays off; the gateway's own input chain is default-deny (SSH from the uplink now blocked) |
| 7.2 re-run | All 15 signals 5/5 on the final code, benign host quiet, Mac replay agrees 45/45 |
| 7.3 | `tools/sweep.py` over a copy of the live DB: 156 labelled attacks vs the real devices' traffic. False positives 86 → 15, recall 1.00 both. Four detection fixes (dedup `last_seen`, slow-scan dedup window + LAN-only, QUIC not a bypass/sweep host, `ids_alert_max_priority`), 482 tests |
| 7.4 | Signatures 0/53 on LAN scans/brute force vs signals 53/53; beacon caught to 45% jitter (30% if sizes vary too); dedup 32,044 firings → 160 incidents |
| 7.5 | Tier 1 −83% requests, −93% third-party, −58% bytes, −99% tracker companies (matches/beats uBO Lite); breakage 0/48; Tier 2 pre-rolls 30/30 → 0/29; bypass matrix (DoH ×8, Private DNS blocked + detected; VPN leaks); DNS A/B; list utility |
| 7.6 (pre-run) | 5/5 devices one record each, attribution correct, OS 5/5; expired-lease presence bug fixed |
| 7.7 | 8 faults: everything self-recovers; inspection fails open; fail-open carries a DNS-filter outage after ~15 s |
| 7.8 | Retention, console latency at two data volumes, throughput/drops sweep |
| 7.9 | Kit ready in `docs/usability-study/` (piloted), study not run |

**The seven-day run (7.0) has NOT started** — scheduled for the next session.
The run monitor (`securepi-run-monitor.service`, ingest lag + system
snapshots) is already running and stays running; it is harmless and its data
before the run's start time is simply outside the window.

**Next steps, in order:**

1. **Before freezing, decide (user):**
   - `malicious_domain`: redefine or retire? It counts every blocked lookup, ad
     lists included (precision 0.42; its battery test used ad domains).
   - 5.5 resolver tuning: keep it on? (A/B: cold p50 68 → 47 ms, p95 411 → 281
     ms; it changes DNS for every device, so it needs the operator's yes.)
   - Fix before the run, or measure as-is: DNS fail-open engages when the
     *uplink* is down (seen live in 7.7); the IDS TLD-rule noise ("ET INFO …
     .biz TLD", "ET DNS … .cc TLD") and the fast network sweep on ad-heavy
     browsing; the YouTube app's 2-retry pin bypass (trigger 3 → 2?);
     the IDS log rotation (logrotate skips on battery; weekly, no size cap).
   Any code change → tests, `make deploy`, checksum check, then freeze.
2. **Freeze and start 7.0:** tag the deployed commit (`git tag stage7-run`),
   record checksums (`sha256sum /opt/securepi/*.py`), note the start time,
   and install the collector: copy `gateway/collect_run.sh` and
   `tools/run_report.py` to `/opt/securepi-eval/`, then a persistent timer
   (`OnCalendar=<start + 7 days>`, `Persistent=true`) running
   `collect_run.sh START END`. Keep the Dell on its charger. Nothing
   disruptive during the run; tag any test work so it's excluded.
3. **Optional, before the freeze:** the tablet TTFB extension for 7.5's
   TLS-latency cells (time-to-first-byte in every cell + an unenrolled control
   for the passthrough host) - the browser's handshake is *faster* through the
   proxy because it ends on the LAN; the proxy's upstream handshake shows up in
   TTFB, which wasn't recorded. Script: `tools/tls_latency_tablet.py` (already
   records `ttfb_ms`), driven by `tools/tls_cells.sh`. Also untested: whether
   relaunching the YouTube app on the tablet adds the 3rd handshake failure
   and so recovers it via 5.8's bypass (`tools/pinned_app.sh`).
   Note `tools/chaos_phone_probe.sh`'s HTTPS check is invalid on Android 9.
4. **After the run:** `collect_run.sh` output → 7.0 write-up (FP/24 h, uptime,
   storage growth, ingest lag p95, reduction ratio, block % per device) and 7.6
   over the run; the canary log for the week; re-run
   `tools/blocklist_utility.py --days 7 --exclude-device <benchmark Mac>`.
5. **7.9 usability study** with 5-8 people (`docs/usability-study/README.md`).
6. Stage 8 (documentation & demo).
7. Still open from before: whether to rewrite the pushed commits that carry a
   `Co-Authored-By` line (force-push to `main`).

**Test devices (both on SecurePi-Test, USB debugging on):**
- Galaxy A33 — adb `RZCT30NYTSB`, registry device 2, 10.10.0.50, mobile data off.
- Lenovo Tab M7 TB-7305X — adb `HA13T683`, registry device 98 (the "Motorola"
  OUI: Motorola Mobility is Lenovo's), 10.10.0.53, Android 9, Chrome 77, CA
  trusted, no SIM. Android 9's toybox `nc` has no `-z`: use
  `tools/chaos_tablet_probe.sh` for probes on it.
- With both attached, every adb call needs `-s SERIAL` (or `ANDROID_SERIAL`).
- Drive phone Chrome with raw DevTools (`adb forward tcp:9222
  localabstract:chrome_devtools_remote`); open pages by Android intent - tabs
  Playwright creates over DevTools can't resolve names on these phones.
- Inspection only affects connections made after enrolment: force-stop Chrome
  after enrolling a device for any Tier 2 test.

**Environment notes from this session:**
- The Mac's SSH key was regenerated on 28 Sep; the Dell's `authorized_keys`
  was updated by hand on 2 Oct. Claude Code allow-rules for `make deploy`,
  `ssh maheshwari@192.168.2.5` and `scp` are in `.claude/settings.local.json`
  (git-ignored) — remove them when no longer wanted.
- Benchmark tooling lives in `.venv-bench/` (Playwright, Selenium,
  websocket-client, FastAPI for the demo) and `eval/bench-data/` (uBO Lite,
  Disconnect list, Tranco list, Firefox, geckodriver) — both git-ignored.
- Firefox cannot start inside this environment's command sandbox ("Could not
  find profile folder"); the Firefox-DoH row was measured with curl's DoH.

**When running the battery again:** kill processes with bracketed patterns
(`pkill -f "[h]ttp.server"`), never a bare `http.server` - that also kills
`securepi-ca-server` and `securepi-static`. Run it as a transient unit so it
survives an SSH drop:
`sudo systemd-run --unit securepi-battery --collect /usr/bin/python3 -u /opt/securepi-eval/battery.py --runs 5`

### Known real bugs found and fixed (for context, not action)

From earlier sessions: `new_device_signal`'s old persisted-watermark bug,
`raise_incident`'s old cumulative evidence-count bug, and G1/G2/G3/G6 from
the original gap analysis — all fixed with regression tests
(`tests/test_correlation.py`).

From this session (Stage 2): see `EVALUATION-RESULTS-2.md` for full detail
on each — the `dns_rcode`/`status` field ingest.py never captured, the DNS filter's
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

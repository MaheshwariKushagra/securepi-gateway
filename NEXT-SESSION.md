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

DNS filtering (about 392,000 rules across curated lists, plus a daily-refreshed
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
| **7** | Evaluation 2.0 — expanded benchmark battery | **Complete** (3 Oct 2026). 7.0 and 7.9 were replaced by one-session equivalents (user decision); see below |
| **7A** | Ad-blocking enhancement - measured gaps, then Tier 2 for X/Instagram/Facebook/Spotify after a feasibility check (`ADBLOCK-ENHANCEMENT-PLAN.md`) | **Complete** (10 Oct 2026); A33 checks still open |
| **8** | Documentation & demo | **Next** |

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

### Stage 7 complete (3 October 2026, one session)

Everything is in `EVALUATION-RESULTS-2.md` §Stage 7 ("7.0 replaced" and "7.9
replaced"), with the deviations recorded in `ENHANCEMENT-PLAN.md` (the note
after the tracker). **Frozen code: tag `stage7-final` (commit `33c4b0d`), 541
tests**, deployed and checksum-verified (48/48 app files, plus the DPI gate
script, canary and log-rotation units).

**What the day did:**
- **Boot faults found and fixed.**
  - Engine, ingest and the canary hit "database is locked" in the first
    minute of every boot since 20 Sep.
  - The fixes:
    - `app/dbconn.py`: 30 s timeout and a 32 MiB WAL cap;
    - the readers take 5,000 lines per pass;
    - the attribution pass no longer counts the whole events table;
    - every engine step is guarded;
    - the DPI gate waits 75 s and fails open instead of failing the unit.
  - Two reboot tests afterwards: clean.
- **Pre-freeze decisions (user):**
  - `malicious_domain` retired (setting `malicious_domain_enabled`, off);
  - resolver tuning ON (applied via the console endpoint; Cloudflare + Quad9
    DoT, parallel, optimistic cache);
  - DNS fail-open probes `use-application-dns.net` (uplink-aware);
  - 26 TLD-lookup IDS rules don't raise incidents (setting
    `ids_raise_tld_lookup_rules`, off);
  - new IDS log rotation;
  - registry presence follows Wi-Fi association.
- **New IDS log rotation:**
  - `securepi-ids-logrotate.timer` (every 15 min, daily or 100 MB, by rename
    + HUP), config `/etc/securepi/logrotate-suricata.conf`;
  - Ubuntu's `/etc/logrotate.d/suricata` is diverted with `dpkg-divert` (to
    `/etc/securepi/logrotate-suricata.packaged`);
  - the timer is in `services.list`;
  - installer: `gateway/install-ids-logrotate.sh`.
- **7.0 replaced, headline results:**
  - held-out false positives on the Mac's benchmark: 126 (original engine) →
    22 (7.3) → 14 (frozen);
  - rotation 361/361 lines;
  - fail-open held through a 75 s upstream-DNS outage;
  - 17/17 earlier shutdowns clean;
  - canary 265 checks, 0 failures;
  - about 414 B per event.
- **7.9 replaced:** expert review in `docs/usability-study/`
  (`heuristic-evaluation.md`, `cognitive-walkthrough.md`); all 6 expert paths
  succeed; axe audit.
- **A multi-hour soak was dropped by the user.** There is no multi-day run of
  the frozen code; that is stated as a limit.

**Stage 7A (ad-blocking enhancement, `ADBLOCK-ENHANCEMENT-PLAN.md`) is done** (9-10 October 2026); details in `EVALUATION-RESULTS-2.md` Stage 7A and `REPORT-adblocking.md` §13.

**Deployed:**
- **Rules:** schema 2 with per-site modules, version 7 on the gateway: youtube, instagram, facebook.
- **Per device:** each site is switched on per device (device page). Enrolment alone means YouTube only.
- **Canary:** checks both passes.
- **Bypass trigger:** pin bypass after 2 failures.
- **Signals:** VPN note; HTML ad removal now logged.
- **Lists:** OISD Big and AdAway off (DNS filter 271 → 187 MB).

**Results:**
- **Instagram web:** 10/10 → 0/10 runs with ads.
- **Facebook web:** 7/10 → 0/10; breakage not excluded.
- **Spotify:** no-go.
- **X:** not verified (login failed).

**Still open from 7A:**
- **The A33 checks are done** (10 Oct; EVALUATION-RESULTS-2.md Stage 7A):
  - YouTube pre-rolls: 0/30 on, 10/10 off.
  - YouTube app plays under the trigger of 2.
  - Scope check with Instagram on: 0 unexpected decryptions.
  - Instagram web: 0/6 on vs 4/6 off; the Instagram app is unaffected.
- **Follow-ups 1 and 3 (10 Oct):**
  - Enrolment and site switches now apply at once: 6/6 within about 1 s, against 1/4 without the reset (`conntrack` installed on the Dell).
  - Tier 1 blocks AdMob in-app banners: 6/6 off → 0/5 on, on the tablet.
  - **F4 done (10 Oct):** the pin bypass is keyed on a ClientHello fingerprint as well, so a pinned app no longer switches off browser ad removal on the same phone. Checked with curl vs Chrome on the Dell. **Still to check on the A33:** do the YouTube app and Chrome present different fingerprints? Look at `client_fp` in `/var/log/securepi/dpi-events.jsonl`.
  - **Facebook settled (10 Oct): partial.** Scroll-loaded feed ads are removed. The page-embedded first sponsored story and the right-column ads are not, because removing them froze the feed or caused page errors. Rules version 9.
  - **Desktop cosmetic CSS checked (10 Oct):** with ads stripped, nothing is left to hide; injection stays off.
- **The A33 is still enrolled** with Instagram and YouTube for 24 h from about 03:15 on 10 Oct. Unenroll it from its device page when done.
- **Mac Safari check:** the user will try it later (join SecurePi-Test, install the CA, enroll the Mac with Instagram; remove the CA afterwards).
- **Dell test setup** (`~/securepi-browser`: logged-in test-account profile, test proxy script, test CA): stopped, not deleted.
  - To restart it (on the Dell):
    ```
    H=/home/maheshwari/securepi-browser
    sudo systemd-run --unit securepi-testproxy --uid=maheshwari --gid=maheshwari -p MemoryMax=400M \
      /opt/securepi-dpi/bin/mitmdump --mode regular --listen-host 127.0.0.1 --listen-port 8091 \
      --set confdir=$H/test-ca -s $H/testproxy.py
    SPKI=$(openssl x509 -in $H/test-ca/mitmproxy-ca-cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
      | openssl dgst -sha256 -binary | base64)
    sudo systemd-run --unit securepi-testbrowser --uid=maheshwari --gid=maheshwari -E HOME=/home/maheshwari \
      -E XDG_RUNTIME_DIR=/run/user/1000 /snap/bin/chromium --headless=new --remote-debugging-port=9230 \
      --remote-debugging-address=127.0.0.1 --user-data-dir=$H/profile155 --no-first-run --window-size=1366,900 \
      --user-agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36" \
      --proxy-server=http://127.0.0.1:8091 --ignore-certificate-errors-spki-list=$SPKI about:blank
    ```
  - Then cap the browser's own snap scope (`snap.chromium.chromium-*.scope`, not the unit) through its `memory.max`, e.g. 1300M.
  - From the Mac: `ssh -f -N -L 9231:127.0.0.1:9230 maheshwari@192.168.2.5`, then `tools/site_ads_measure.py SITE OUT --runs N`.
  - The Chromium snap and 13 runtime libraries are installed on the Dell.
  - The tablet's leftover tabs were closed.
- **Incidents to close:** #760 and #764 (tablet `adblock_ineffective`) are false positives explained by the HTML-logging bug.

**Start the next session with one of these** (the user's choice, offered on 10 Oct 2026):
- **F4 check on the A33** (the code is done): with the A33 enrolled, open YouTube in Chrome and in the app, and compare their `client_fp` values in the DPI telemetry.
- **Stage 8, step 1:** the 7.9 usability fixes (F17 is already done).

**Then Stage 8 (documentation and demo).** For 8.1: the README's ad-blocking rows, rule count, test count and stage table were updated on 10 Oct 2026; its detection, memory and throughput rows still quote the first evaluation (`EVALUATION-RESULTS.md`) and need Stage 7's numbers. Queued inputs from Stage 7:
1. **The 7.9 recommendations** (`heuristic-evaluation.md`, end), worst first:
   - dark-theme contrast: `--text-3`/`--muted` → about `#8792a6`;
   - a Risk column on the Devices list;
   - device names as real links;
   - keyboard-scrollable regions;
   - a persistent domain-test result with the list named;
   - the console dialog instead of `prompt()` for Allow.
2. **F17: done (10 Oct 2026).** All 13 `TemplateResponse` calls pass the request first. Checked under the gateway's Starlette 0.31.1 with deprecation warnings as errors (every page 200), deployed; `tests/test_template_response_form.py` guards it.
3. **The remaining held-out false positives**, for the next detection work:
   - beacon on ordinary periodic app traffic (Google push 5228, STUN 3478,
     port 80 checks);
   - dga on `omnitagjs.com` and `in-addr.arpa` (a popular-domain allowlist was
     already suggested in 7.3);
   - network_sweep on unanswered ad servers with filtering off.
4. **Optional, if wanted:** the participant study (kit in
   `docs/usability-study/README.md`) and a multi-day run (the collector is
   ready: `sudo /opt/securepi-eval/collect_run.sh mark|collect`).

**Housekeeping for the next session:**
- **Test incidents:**
  - **Closed 10 Oct 2026, with notes:** #760 and #764 (false positives from the HTML-logging bug), #761 (the tablet's timing-test fetches), #476 (resolved).
  - **Still open: 465 incidents**, mostly from deliberate test runs (the 7.2 battery, 7.5 benchmark, 7.7 chaos). Triage them in the console before the demo; bulk-closing needs a person's judgement.
- **The run monitor** (`securepi-run-monitor.service`) is still running. It is
  harmless and useful for any later run; stop and disable it if not wanted.
- **On the gateway:** `/var/lib/securepi-eval/soak-2026-10-03T093855/mark`
  holds the freeze manifest and a 275 MB database copy (mode 600, root only).
  It can be deleted once the write-up is final.
- **The journal purge from Day 15 is now safe:** `collect_run.sh mark`
  extracted the boot, unit and canary history that the reliability table
  needed.
- **Fixed in passing:** a stray database backup in
  `/opt/securepi/.bak-3.6-1789930809/` was mode 644 (world-readable). It is
  now 600.

**Test devices:**
- **Galaxy A33:** adb `RZCT30NYTSB`, registry device 2, 10.10.0.50.
  - It drifted back to Babu_Home twice today.
  - Before relying on it, rejoin SecurePi-Test (and turn off Auto reconnect
    for Babu_Home on the phone while testing).
  - The only C-to-C cable is shared with the Mac's charger.
- **Lenovo Tab M7:** adb `HA13T683`, registry device 98, 10.10.0.53,
  Android 9, Chrome 77, CA trusted.
  - **Now cabled to the Dell, not the Mac.** The Dell has `adb` (apt) and a
    udev rule (`/etc/udev/rules.d/51-securepi-tablet.rules`, Lenovo vendor
    17ef).
  - Reach it from the Mac through an SSH tunnel:
    ```
    ssh -f -N -L 5038:127.0.0.1:5037 -L 9223:127.0.0.1:9223 maheshwari@192.168.2.5
    export ANDROID_ADB_SERVER_PORT=5038      # every adb command then goes to the Dell
    adb -s HA13T683 forward tcp:9223 localabstract:chrome_devtools_remote
    ```
  - The tunnel drops at every gateway reboot. Re-open it, and run
    `adb start-server` on the Dell if `adb devices` is empty.
  - Its YouTube app is disabled (factory 17.49), and the user's choice is
    YouTube in Chrome on the tablet.
- Phone/tablet Chrome is driven with raw DevTools; open pages by Android
  intent (`... com.android.chrome`), never Brave.

**Environment notes:**
- **Demo console:** run it with `.venv-demo` (git-ignored). It is pinned to
  the gateway's FastAPI 0.101.0 / Starlette 0.31.1 / pydantic v1. The
  benchmark venv's Starlette 1.7 can't render the templates (F17).
  `.venv-bench/` still holds Playwright and the other benchmark tools.
- **Tool commands:**
  - Held-out replay: `tools/heldout_replay.py`.
  - Expert paths and axe audit: `tools/usability_expert.py`. axe-core is
    installed outside the repo: `npm install axe-core`, then pass `--axe`.
- **Claude Code allow-rules** for `make deploy`, `ssh` and `scp` are in
  `.claude/settings.local.json` (git-ignored). Remove them when no longer
  wanted.
- **Killing processes:** use bracketed patterns (`pkill -f "[h]ttp.server"`).
  Run the battery as a transient unit:
  `sudo systemd-run --unit securepi-battery --collect /usr/bin/python3 -u /opt/securepi-eval/battery.py --runs 5`.

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

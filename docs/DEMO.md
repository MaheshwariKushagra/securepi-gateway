# SecurePi Gateway: the 15-minute demonstration

This is the demo script for step 8.3. It is the feasibility study's §17.4 demo plus everything the plan
adds to it:

- slow scan, beaconing, DoH bypass blocked and detected, and a campaign;
- kill-Suricata and fail-open DNS;
- timed quarantine, per-device unbreak in 30 s, and a schedule-based service block;
- the privacy canary going red and back to safe when sabotaged;
- Instagram switched on for one device.

Every action has an exact command or click path, the expected result and its timing, and a fallback.
Every timing comes from a measurement on this gateway, with the source cited.

> **Status (10 October 2026).** The script, its two helpers (`gateway/demo_attacks.py` and
> `dpi/canary_demo.py`) and their tests are done. The technical dry-runs are recorded in [§9](#9-rehearsal-record).
> The three rehearsals the plan asks for are a presenter's run-throughs with the phone in hand, and so
> is the backup video ([§10](#10-backup-video)). Neither has been done yet.

---

## 1. What the audience sees, and where each item comes from

| # | Segment | Plan item | Expected timing (source) |
|---|---|---|---|
| 1 | Live overview; slow scan started | F§17.4-1, slow scan | detection ≈ 8 min later (7.2 median 494 s) |
| 2 | Ad-heavy page, filtering paused then on | F§17.4-2 | immediate (7.5: −83 % requests across 20 sites) |
| 3 | A broken link fixed for one device | per-device unbreak in 30 s | first allowed lookup at 11.8 s (`EVALUATION-RESULTS-2.md`, "Unbreak one site") |
| 4 | Device inventory and drill-down | F§17.4-3 | none (it is a page) |
| 5 | Live attack: scan, brute force and beacon, forming a campaign | F§17.4-4, beaconing, campaign | brute force ≈ 78 s, scan ≈ 92 s, campaign ≈ 139 s, beacon ≈ 139 s (7.2 medians) |
| 5b | DoH bypass from the phone, during 5's wait | DoH bypass blocked and detected | refused at once; incident within about one engine cycle after the 3rd attempt (threshold 3 in 300 s) |
| 6 | The slow scan is caught; correlation value | F§17.4-4/5 | it arrives during this segment; reduction 200:1 (3 h live) / 47:1 (replay) (`REPORT.md` §6.1) |
| 7 | Timed quarantine of the phone | F§17.4-6, timed quarantine | effective within one engine cycle; expiry 6-11 s after its time (4.2) |
| 8 | Schedule-based service block | schedule-based block | block at the window's first second (4.3: 00:38:00 → blocked 00:38:01) |
| 9 | Kill the IDS; then stop the DNS filter | F§17.4-7, kill-Suricata, fail-open DNS | IDS back < 1 s, so no incident; fail-open on at +16-18 s and off at +61-62 s, with an incident (7.7, 7B) |
| 10 | Canary sabotaged: red, then safe | canary red→safe | red on the next console refresh (5 s) |
| 11 | Instagram on for the phone only | 7A Instagram | feed ads 10/10 → 0/10 runs (7A); live-message hosts passthrough in every logged connection |
| 12 | Results | F§17.4-8 | `REPORT.md` §6 |

---

## 2. Cast and equipment

| What | Set-up |
|---|---|
| **Gateway** | The Dell, lid closed, **on AC power**, all services active (`sudo securepi status`). |
| **Presenter's Mac** | Not on SecurePi-Test: it stays on its own Wi-Fi and reaches the gateway over the management cable. It shows three windows: (1) Chrome with the console through `./mac-tunnel.sh start`, at `https://localhost:8000`; (2) Terminal **A**, `ssh -t maheshwari@192.168.2.5`, for commands; (3) Terminal **B**, a second SSH session, for the live decision log. |
| **Phone (Samsung A33)** | On **SecurePi-Test**. **Chrome**, not the Instagram or YouTube app (pinned apps bypass inspection by design, §8 of `REPORT-adblocking.md`). The SecurePi inspection CA is installed (Settings → Security → Encryption & credentials → User certificates). The project's **test** Instagram account is signed in at `https://www.instagram.com/` in Chrome. It is mirrored to the Mac over USB with `scrcpy --stay-awake --window-title A33` (`/opt/homebrew/bin/scrcpy`; USB debugging on). |
| **Optional attacker laptop** | Not needed. The attacks run inside the gateway's isolated test harness (`gateway/demo_attacks.py`). For a second, physical attacker, use `redteam/securepi_attack.py` from a laptop on SecurePi-Test instead (`redteam/README.md`). |

The phone's device id and address appear on the Devices page (in the evaluation it was device 2 at
`10.10.0.50`). Below it is called **PHONE**. Note its id and address before the demo.

**Before the close-out.** `docs/CLOSE-OUT.md` removes the inspection CA from the phone and signs the
test account out. Run the demo and its rehearsals **before** that.

---

## 3. The day before

Run on the gateway (Terminal A):

```bash
cd ~/securepi-install && sudo ./gateway/install.sh --check     # expected: 0 change(s) would be made
sudo securepi status                                            # all services active; Tier 1 active
sudo /opt/securepi-dpi/bin/python3 /opt/securepi-dpi/canary_demo.py restore
# expected: "securepi-privacy-canary: ok - ..." and "no open privacy-scope incident"
```

Then:

- **Kids profile at its defaults.** On the console, Filtering → Profiles & Schedules → Kids should
  not show "edited". If it does, click Reset.
- **Auto-quarantine off.** This is the default (Settings → Response). The campaign must not
  quarantine anything by itself during segment 5; quarantine is shown by hand in segment 7.
- **The phone.** Is `t.co` still blocked for it? `dig +short @10.10.0.1 t.co` gives `0.0.0.0`
  (checked 10 Oct 2026, rule `||t.co^`). Is there no "Allow t.co" rule left from a rehearsal?
  (Response → active policies: no `allow_domain` for PHONE.) Chrome's Secure DNS is
  **off** (Settings → Privacy and security → Use secure DNS).
- **Instagram off for the phone.** On the phone's device page, "HTTPS ad removal (Tier 2)" shows
  **Enroll device**, not "Enrolled".

---

## 4. Thirty minutes before

| # | Do | Expected |
|---|---|---|
| 1 | Mac: `cd ~/blah && ./mac-tunnel.sh start`, then open `https://localhost:8000` and sign in | Dashboard |
| 2 | Terminal A: `sudo securepi status` | `-> all services active`, `Tier 1 ... active`, `Tier 2 ... OFF`, test harness `present` |
| 3 | Terminal A: `sudo nft -j list set inet filter doh_resolvers \| jq '.nftables[1].set.elem \| length'` | about 1,400. **If it says 14**, the gateway has rebooted since the last daily refresh (`STAGE8-RECORD.md` M-15). Run `sudo systemctl start securepi-doh-refresh.service` and check again. |
| 4 | Phone: join SecurePi-Test, open Chrome | It appears on the Devices page within 15 s |
| 5 | Mac: `scrcpy --stay-awake --window-title A33` | The phone's screen on the Mac |
| 6 | Terminal B: `sudo tail -n0 -f /var/log/securepi/dpi-events.jsonl \| jq -r --unbuffered '"\(.ts_iso) \(.decision) \(.sni)"'` | Silent: nothing is enrolled |
| 7 | Console tabs, in order: Dashboard · Devices · PHONE's device page · Incidents · Response · Filtering | All load |
| 8 | Phone: Chrome tabs `https://timesofindia.indiatimes.com/` and `https://www.instagram.com/` (signed in) | Both load |

The incidents list shows the newest first. The evaluation's older open incidents stay below the new
ones; set the status filter to **New** for the demo.

---

## 5. The script, minute by minute

The times are targets. **If you are behind at 8:00, drop segment 3 (unbreak) and segment 8
(schedule)**: both are already demonstrated by the measurements cited in §1.

### 0:00-1:00 · 1. A real network, right now; a slow scan starts

- **Say:** "This is a gateway for a small network, running now: the phone here, plus an isolated test
  network inside the gateway for attacks."
- **Terminal A:**
  ```bash
  sudo python3 /opt/securepi-eval/demo_attacks.py slow-scan &
  ```
  Expected, at once:
  ```
  device <N> = "[TEST HARNESS] demo slow scanner HH:MM" at 10.10.0.247
  slow scan started at HH:MM:SS: 9 probes, 50 s apart; expect the incident about 8 minutes from now
  ```
- **Say:** "That is a port scan, one probe every 50 seconds. A per-packet signature does not fire on
  this. We will come back to it in about eight minutes."
- **Console:** Dashboard. Point out the event rate, devices online and the health strip, all green.

### 1:00-3:00 · 2. Ad blocking, off then on

- **Console:** PHONE's device page → Filtering profile row → **Pause** → **5 minutes**.
- **Phone:** reload `timesofindia.indiatimes.com`. Ads and slower loading.
- **Console:** **Resume** (the same row). **Phone:** reload. The ad slots are empty.
- **Terminal A:**
  ```bash
  dig +short @10.10.0.1 doubleclick.net      # 0.0.0.0  (blocked)
  dig +short @10.10.0.1 youtube.com          # real addresses: a DNS filter cannot touch ads served from youtube.com itself
  ```
- **Say:** "Across 20 ad-heavy sites, 83 % fewer requests and 99 % fewer tracker companies. But
  first-party ads, like YouTube's, come from the same domain as the video. That is segment 11."
- **Fallback:** if the page looks the same both ways (a cached page), use `https://www.hindustantimes.com/`.

### 3:00-4:00 · 3. A broken link, fixed for one device in under 30 s

- **Phone:** open `https://t.co/`. It fails (DNS-blocked: `||t.co^`).
- **Say:** "Links shared from X go through t.co, which the tracker list blocks. Someone on this phone
  says 'links are broken'."
- **Console:** PHONE's device page → the recently-blocked list ("test and allow for this device") →
  `t.co` → **Allow 1h** → reason "demo: X links". Start counting. *Allow 1h* removes itself after an hour.
- **Phone:** reload. It opens. Measured: 11.8 s to the first allowed lookup (target 30 s).
- **Say:** "Only this phone. Every other device still has t.co blocked." Show this with the
  Filtering page's domain tester ("test a domain, network-wide or for one device"): network-wide,
  `t.co` is still blocked.
- **Fallback:** if Chrome shows a cached failure, open the link in an Incognito tab.

### 4:00-5:30 · 4. Devices, identified, scored, explained

- **Console:** Devices. Then PHONE's page: type, vendor and OS with the evidence for each (the
  hostname pattern, the connectivity-check lookups), risk score with its explanation, recent DNS, and
  baseline.
- **Say:** "Every incident is tied to a device, not an IP address. Addresses change; the device
  record follows the MAC and hostname."

### 5:30-8:00 · 5. A live attack becomes a campaign; 5b. a DoH bypass, meanwhile

- **Terminal A:**
  ```bash
  sudo python3 /opt/securepi-eval/demo_attacks.py campaign
  ```
  Expected (the 10 October dry-run, verbatim apart from the numbers that change):
  ```
  device 100 = "[TEST HARNESS] demo attacker 14:20" at 10.10.0.248
  campaign started at 14:20:48: port scan, SSH brute force and beacon, all from 10.10.0.248
    port_scan           run 90 (10.10.0.248): detected in 84.6s
    brute_force         run 90 (10.10.0.248): detected in 84.8s
    campaign #43 (Command and Control -> Credential Access -> Discovery) formed 84.5s after the start
    beacon              run 90 (10.10.0.248): detected in 147.1s
    campaign #43 final kill chain: Command and Control -> Credential Access -> Discovery
  ```
  Nothing shows for the first ~80 s. The IDS reports a connection when its flow ends, so the
  incidents all arrive together in one engine cycle. Use the wait for 5b.

  **Two things to know before an examiner asks.**
  - The kill chain is ordered by each tactic's *first evidence*. The beacon starts first, so it reads
    "Command and Control -> Credential Access -> Discovery".
  - The brute force's nine SSH attempts are regular enough that the beacon signal links them too:
    the beacon incident is titled "Possible C2 beacon to 10.10.0.222:22" (the SSH target). The
    check-ins to `10.10.0.223` join the same incident about a minute later. A repeat detection keeps
    the incident's first title, a known behaviour (`EVALUATION-RESULTS-2.md`).
  - The 40-port scan also raises a `slow_port_scan` incident for the attacker. The slow signal
    counts ports over a longer window, and a fast scan satisfies it too. The dedicated slow scanner
    (segment 1) is the one that *only* the slow signal catches.
- **While it runs (5b), on the phone:** Chrome → Settings → Privacy and security → Use secure DNS →
  On → **Custom** → `https://8.8.8.8/dns-query`. Then browse to any new site, twice.
  - Chrome reports it cannot reach the secure DNS provider (the `doh-bypass` rule rejects
    `PHONE → 8.8.8.8:443`; measured: 87 packets rejected and logged).
  - **Console → Incidents:** a **dns_bypass** incident for PHONE, "tried to bypass DNS filtering ... via
    DoH", once three attempts fall inside 5 minutes.
  - **Then turn Secure DNS off again** on the phone, or the rest of the demo has no DNS on it.
- **Console → Incidents** (status New): the attacker's incidents arrive one by one. Open the
  **campaign**: the kill chain with each stage's evidence and its ATT&CK tactic.
- **Say:** "Three alerts became one story: discovery, credential access, command and control, on one
  device."

### 8:00-9:00 · 6. The slow scan is caught; why correlation matters

- **Terminal A:** the background slow scan prints, around 8:15:
  `slow_port_scan      run NN (10.10.0.247): detected in 4xx.xs`.
  **Console:** the **slow_port_scan** incident: nine probes, 50 s apart, linked as evidence.
- **Say:** "Per-packet signatures miss this. The windowed signal does not. Overall, the correlation
  engine turns events into incidents at 200 to 1 on live traffic and 47 to 1 on the replayed
  week, with precision 0.91 and recall 1.00 on the labelled attacks." (`REPORT.md` §6.1)
- **Fallback:** if it has not arrived yet, go on and come back to it in segment 12. The 7.2 range is
  478-514 s from the start.

### 9:00-10:00 · 7. Timed quarantine

- **Console:** PHONE's device page → **Quarantine** → **15 minutes** → reason "demo".
- **Phone:** reload any page. It fails within one engine cycle (15 s). Ping and DNS both stop; the
  MAC is in `quarantine_mac`.
- **Console → Response:** the active policy with its expiry time, and the audit entry.
- **Release early:** device page → **Release**. The phone browses again. (The menu offers 15 min,
  1 h, 24 h or until released; the 4.2 expiry measurement used a 120 s policy made through the API.)
- **Say:** "Every response is a policy with an expiry, verified against the kernel, and undone
  automatically. Measured: expired 6-11 s after its time."

### 10:00-11:00 · 8. A schedule-based service block

- **Console:** Filtering → **Profiles & Schedules** → **Kids** → **Edit**. "Also block some services
  during a daily window" is ticked. Keep the **Social networks** group (`group:social_network`, which
  includes reddit) and set start = **the next minute** (e.g. now 10:42 → `10:43`), end = one hour
  later → **Save and apply**.
- **Console:** PHONE's device page → filtering profile → **Kids**. The row then reads
  "Kids · schedule 10:43-11:43 ...", and "(active now)" once the window opens.
- **Console:** PHONE's device page → **Test a domain** box: `www.reddit.com`.
  - Before the start minute: allowed.
  - From the start minute: **blocked (blocked service)**.
- **Say:** "Kids' default window is 21:00-07:00. I moved it so it opens in front of you."
- **Phone:** after the start minute, open `https://www.reddit.com/`. Blocked.
- **Fallback:** if the start minute passed while you were talking, the block is already on. Show the
  domain test, then the profile's schedule.

### 11:00-12:30 · 9. Resilience: kill the IDS, then take DNS away

- **Terminal A:**
  ```bash
  sudo python3 /opt/securepi-eval/chaos.py kill-ids --watch 30 | jq -c '.timeline[]?' | head -20
  ```
  - Suricata is SIGKILLed and systemd restarts it **within the same second**. In the 10 Oct dry-run
    the 1-second timeline never once saw it inactive.
  - Because it is back before the health supervisor's next look, **no incident is raised**. The
    proof is the restart itself:
    ```bash
    systemctl show suricata -p NRestarts -p ExecMainStartTimestamp      # NRestarts goes up by 1; start time = just now
    journalctl -u suricata -n 8 -o short --no-pager                     # "Sent signal SIGKILL" ... "Starting suricata.service"
    ```
  - The phone notices nothing.
- **Terminal A:**
  ```bash
  sudo python3 /opt/securepi-eval/chaos.py stop-dns --watch 75 | jq -c '.timeline[]?' | tail -20
  ```
  - The DNS filter is down for 60 s, with an independent undo armed. The 10 Oct dry-run, from the
    timeline:

    | When | What |
    |---|---|
    | +0.1 s | AdGuardHome inactive |
    | +11.3 s | incident `platform_service_down` |
    | +17.4 s | the `dns-failopen` rules are in place, and incident `platform_dns_failopen` is raised. The **phone keeps resolving new sites**, unfiltered (7.7: 4 fresh names resolved through the redirect) |
    | +61.3 s | AdGuardHome active again, and the fail-open rules are gone |
  - Show both incidents on the console. Afterwards, `dig +short @10.10.0.1 doubleclick.net` gives
    `0.0.0.0` again.
- **Say:** "A security box that takes the network down when it fails gets switched off. This one
  fails open, says so, and recovers by itself."
- `chaos.py` prints its JSON once, when the watch period ends (30 s and 75 s here). Meanwhile, narrate from the console, where the effects show live.
- **Fallback:** if `jq` prints nothing, run without the pipe. The JSON timeline is the output.

### 12:30-13:30 · 10. The privacy canary: sabotaged, red, then safe

- **Console:** Filtering → the **Privacy scope** chip (top of the page), "verified N min ago", green.
- **Terminal A:**
  ```bash
  sudo /opt/securepi-dpi/bin/python3 /opt/securepi-dpi/canary_demo.py break
  ```
  Expected:
  ```
  addon copy with the report-6 typo: /tmp/securepi-canary-demo-.../securepi_adfilter_broken.py (the live addon is untouched)
  securepi-privacy-canary: FAIL - example.com, ... would be decrypted although no site module should cover it - ...
  open privacy-scope incident(s): #K
  ```
  The badge turns **red**. A high-severity "Tier 2 privacy-scope check failed" incident appears, and
  every enrolled device is unenrolled (the fail-safe).
- **Say:** "This is the real bug from my report: one misspelt attribute that would have decrypted
  everything. The canary runs the deployed decision code every 15 minutes, and when it is wrong it
  switches inspection off for everyone and tells me."
- **Terminal A:**
  ```bash
  sudo /opt/securepi-dpi/bin/python3 /opt/securepi-dpi/canary_demo.py restore
  ```
  Expected: `securepi-privacy-canary: ok - passthrough and decrypt decisions correct for every site
  module`, then `resolve on the console to turn the badge green: incident #K (new)`.
- **Console:** Incidents → #K → **Resolved**. The badge is **green** again.

### 13:30-14:30 · 11. Instagram, for one device only

- **Console:** PHONE's device page → **HTTPS ad removal (Tier 2)** → tick **Instagram** only (hover
  shows its privacy note) → **Enroll device**. The toast says on for 24 h, for new connections only.
- **Phone:** **close Chrome fully** (recent apps → swipe it away) and reopen it. Its connections to
  Instagram from the prep are still open, and inspection applies only to new ones. Then go to
  `https://www.instagram.com/` and scroll the feed. **No "Sponsored" posts.** Open the **inbox**. It
  loads.
- **Terminal B** shows the decisions as they happen:
  ```
  2026-..Z decrypt www.instagram.com
  2026-..Z passthrough gateway.instagram.com
  2026-..Z passthrough edge-chat.instagram.com
  2026-..Z passthrough static.cdninstagram.com
  ```
- **Say:** "Only `www.instagram.com` is decrypted, and only for this phone. The live-message hosts,
  `edge-chat` and `gateway`, are passed through untouched. In the evaluation log, every one of their
  connections (2 and 60) was passthrough, never decrypted."
- **Console:** **Enrolled · Unenroll**, then restart Chrome. The feed shows ads again.
- **Fallback:** if Instagram shows a sign-in page, the test session has expired. Show the decision
  log and the 10/10 → 0/10 result from `REPORT-adblocking.md` §13 instead. **Never sign in a personal
  account for the demo.**

### 14:30-15:00 · 12. Results

Show `REPORT.md` §6 (or the README's "At a glance"):

- 15 signal types, 5 of 5 runs each, detected;
- precision 0.91 and recall 1.00;
- 400 Mbit/s with no loss;
- every chaos fault recovered on its own;
- ad blocking at −83 % requests, with first-party ads removed where it is opted in;
- the privacy scope verified continuously.

---

## 6. If something goes wrong

| Symptom | Do |
|---|---|
| A console page is blank or stale | Reload it. The tunnel runs from the Mac: `./mac-tunnel.sh status`, then `stop` and `start`. |
| No attacker incidents after 3 min | `sudo securepi status`. Check that ingest and engine are active; `journalctl -u securepi-engine -n 20`. Re-run `demo_attacks.py campaign` (it registers a new device and uses new ports). |
| The phone has no internet after segment 5b | Chrome Secure DNS is still on Custom. Turn it off. |
| The phone has no internet after segment 7 | Release on the device page; check Response for an active quarantine; `sudo nft list set inet filter quarantine_mac`. |
| Fail-open did not engage | `chaos.py` already scheduled its own undo. Check `systemctl is-active AdGuardHome`, then `sudo systemctl start AdGuardHome`. |
| The canary badge stays red after `restore` | The incident is still open: resolve it. If `restore` printed FAIL, the live addon really is wrong: stop and leave inspection off. |
| Instagram ads still show | Was Chrome restarted after enrolling? Does the device page show "Enrolled" with Instagram ticked, and is the phone's IP in `sudo nft list set ip nat enrolled`? Is it Chrome, not the app? Is the inspection CA still installed? |
| Anything else | Go on to the next segment and play that part of the backup video (§10). |

---

## 7. Putting everything back afterwards

Run all of these. They return the gateway to the state in §3.

| # | Undo | How |
|---|---|---|
| 1 | Phone's t.co allow | It ends by itself after the hour. To end it now: Response → the `allow_domain` policy for PHONE → End. |
| 2 | Phone's profile | Device page → filtering profile → **Standard**. |
| 3 | Kids schedule | Filtering → Profiles & Schedules → Kids → **Reset** (back to 21:00-07:00). |
| 4 | Instagram | Device page → **Enrolled · Unenroll** (if it was not ended on stage). |
| 5 | Chrome Secure DNS on the phone | Off. |
| 6 | Harness addresses | `sudo python3 /opt/securepi-eval/demo_attacks.py cleanup` |
| 7 | Demo incidents | Leave them, or mark them resolved. The demo devices are labelled `[TEST HARNESS] demo ...`. |
| 8 | Check | `sudo securepi status`; `sudo nft list set ip nat enrolled` (no elements); `canary_demo.py restore` (ok, no open incident). |

---

## 8. What is real and what is staged, said plainly

- **Real:** every detection, policy, block and fail-safe above. They run the deployed code on live
  traffic: the IDS, ingest, engine, orchestrator, nftables and the DNS filter.
- **Staged:**
  - The attacks come from the gateway's isolated test namespaces, not from a compromised device.
    For a physical attacker, use `redteam/securepi_attack.py`.
  - The canary's sabotage runs the real check against a deliberately broken *copy* of the addon. The
    live addon is never broken: mitmproxy reloads that file when it changes, so breaking it would
    really decrypt traffic.
  - The schedule's start time is moved so the window opens on stage.

---

## 9. Rehearsal record

**Technical dry-runs** (helpers and commands only, no audience, no phone) on the live gateway. Each
records the time, what ran and the result. See `STAGE8-RECORD.md`, 8.3.

| Run | Date and time (IST) | Segment | Result |
|---|---|---|---|
| 1a | 10 Oct 14:20:46-14:23:15 | 5, campaign | `port_scan` 84.6 s, `brute_force` 84.8 s, campaign #43 formed at 84.5 s (C2 → Credential Access → Discovery), `beacon` 147.1 s. Device 100. All within the 7.2 ranges. |
| 1b | 10 Oct 14:23:53-14:31:59 | 1 and 6, slow scan | `slow_port_scan` detected in **486.1 s** (7.2: median 494 s, range 478-514). Device 101. |
| 1c | 10 Oct 14:32:20-14:32:26 | 10, canary | `break`: FAIL. The check named every look-alike host, plus `example.com`, `edge-chat.instagram.com` and `gateway.instagram.com`, as hosts the broken addon would decrypt. Incident #806 raised. The enrolled set was empty before and after. The live addon's SHA-256 was unchanged (`308a5407…`, the same as the repo's). `restore`: ok. **#806 left open, to be resolved on the console** (needs the console password). |
| 1d | 10 Oct 14:32:35-14:33:05 | 9, kill-ids | SIGKILL; systemd restarted Suricata in the same second (`NRestarts=1`); never seen inactive; no incident. |
| 1e | 10 Oct 14:33:31-14:34:47 | 9, stop-dns | Inactive at +0.1 s; `platform_service_down` #808 at +11.3 s; fail-open on and `platform_dns_failopen` #809 at +17.4 s; filter back and fail-open off at +61.3 s; blocking `doubleclick.net` again afterwards. |
| 2 | 10 Oct 14:35:09-14:43:23 | 1, 5, 6, **overlapped as in the demo**: slow scan at 0:00, campaign at +5:30 | Campaign: `brute_force` 80.6 s, campaign #44 80.7 s, `port_scan` 81.2 s, `beacon` 142.9 s (device 103). Slow scan: **489.2 s** (device 102), so it arrived at 8:09 on the demo clock, inside segment 6. The two did not affect each other. Harness addresses removed afterwards (`demo_attacks.py cleanup`). |

Not dry-run, because they need the phone in hand and a console sign-in: segments 2, 3, 4, 5b, 7, 8
and 11. Each was measured live earlier, with the results cited in §1. They are what the presenter
rehearsals cover.

**Presenter rehearsals** (the plan's "rehearsed 3×", with the phone, against a clock):

| Rehearsal | Date | Total time | Segments that ran long or failed | Fix |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |

---

## 10. Backup video

Record one full rehearsal that went well. A live demo fails at the worst moment (F§17.4); the
video is what you play instead.

1. **Mac screen:** press `Cmd + Shift + 5` → *Record Entire Screen* → Options → save to `~/Movies`.
   The Mac's screen shows the console, Terminal A and B, and the phone through scrcpy.
2. **Phone, at full resolution (optional, a second file):**
   `scrcpy --stay-awake --record ~/Movies/securepi-demo-phone.mp4`
3. **Name it** `securepi-demo-backup-YYYYMMDD.mov` and keep it **outside the repository**. A
   15-minute screen recording is several hundred MB.
4. **Before trusting it:**
   - watch it once end to end;
   - check that no password, test-account credential, or personal notification is visible;
   - record with *Do Not Disturb* on both the Mac and the phone.

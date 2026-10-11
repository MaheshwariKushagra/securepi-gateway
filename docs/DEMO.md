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

> **Phone-free since 11 October 2026.** The Samsung A33 the script was written for can no longer be
> connected, so no segment needs a phone in hand any more (the user's decision, 11 Oct).
> - **Segments 3, 7 and 8:** their policies are applied to the A33's existing device record (#2,
>   `kushagra-s-a33`). The gateway enforces and verifies them for real, in the DNS filter and in the
>   firewall's sets. Their effect is shown with the console's per-device domain test and the kernel
>   sets, not with live traffic from the phone.
> - **Segment 2:** shown network-wide, with `dig` from the gateway.
> - **Segments 5b and 11:** shown from what the phone recorded when it was connected.
>
> §8 says this plainly. The phone version of the script is in git history (commit `79e8396`). The
> helpers (`gateway/demo_attacks.py`, `dpi/canary_demo.py`) and their tests are unchanged. The dry-runs
> and the three run-throughs of this version are recorded in [§9](#9-rehearsal-record), and the backup
> recording in [§10](#10-backup-video).

---

## 1. What the audience sees, and where each item comes from

| # | Segment | Plan item | Expected timing (source) |
|---|---|---|---|
| 1 | Live overview; slow scan started | F§17.4-1, slow scan | detection ≈ 8 min later (7.2 median 494 s) |
| 2 | Filtering paused for everyone, then on, seen with `dig` | F§17.4-2 | immediate (7.5: −83 % requests across 20 sites) |
| 3 | A broken link fixed for one device (the A33's record) | per-device unbreak in 30 s | first allowed lookup at 11.8 s (`EVALUATION-RESULTS-2.md`, "Unbreak one site"); on stage, the device's domain test |
| 4 | Device inventory and drill-down | F§17.4-3 | none (it is a page) |
| 5 | Live attack: scan, brute force and beacon, forming a campaign | F§17.4-4, beaconing, campaign | brute force ≈ 78 s, scan ≈ 92 s, campaign ≈ 139 s, beacon ≈ 139 s (7.2 medians) |
| 5b | DoH bypass, during 5's wait: the rule and the phone's recorded incident #447 | DoH bypass blocked and detected | recorded 26 Sep: refused at once, 87 packets logged, linked to #447; incident once 3 indicators fall inside 300 s |
| 6 | The slow scan is caught; correlation value | F§17.4-4/5 | it arrives during this segment; reduction 200:1 (3 h live) / 47:1 (replay) (`REPORT.md` §6.1) |
| 7 | Timed quarantine of the A33's record | F§17.4-6, timed quarantine | in the firewall's `quarantine_mac` set within one engine cycle; expiry 6-11 s after its time (4.2) |
| 8 | Schedule-based service block | schedule-based block | block at the window's first second (4.3: 00:38:00 → blocked 00:38:01) |
| 9 | Kill the IDS; then stop the DNS filter | F§17.4-7, kill-Suricata, fail-open DNS | IDS back < 1 s, so no incident; fail-open on at +16-18 s and off at +61-62 s, with an incident (7.7, 7B) |
| 10 | Canary sabotaged: red, then safe | canary red→safe | red on the next console refresh (5 s) |
| 11 | Instagram for one device: the recorded result | 7A Instagram | recorded: feed ads 10/10 → 0/10 runs (7A); live-message hosts passthrough in every logged connection |
| 12 | Results | F§17.4-8 | `REPORT.md` §6 |

---

## 2. Cast and equipment

| What | Set-up |
|---|---|
| **Gateway** | The Dell, lid closed, **on AC power**, all services active (`sudo securepi status`). |
| **Presenter's Mac** | Not on SecurePi-Test: it stays on its own Wi-Fi and reaches the gateway over the management cable. It shows three windows: (1) Chrome with the console through `./mac-tunnel.sh start`, at `https://localhost:8000`; (2) Terminal **A**, `ssh -t maheshwari@192.168.2.5`, for commands; (3) Terminal **B**, a second SSH session, for the live decision log. |
| **No phone** | Since 11 Oct the script needs none. The A33's device record stays on the gateway (Devices → #2, "Shri-Maheshwari-Ji", `kushagra-s-a33`, last address `10.10.0.50`) and stands in for it. Below it is called **PHONE**. |
| **Optional attacker laptop** | Not needed. The attacks run inside the gateway's isolated test harness (`gateway/demo_attacks.py`). For a second, physical attacker, use `redteam/securepi_attack.py` from a laptop on SecurePi-Test instead (`redteam/README.md`). |

**Before the close-out.** `docs/CLOSE-OUT.md` deletes the Dell's test browser and purges the journal.
Run the demo and its rehearsals **before** that.

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
- **PHONE's record is clean.** `dig +short @10.10.0.1 t.co` gives `0.0.0.0` (rule `||t.co^`, checked
  11 Oct 2026). Response has no active policy for PHONE (no `allow_domain`, no quarantine), and
  `sudo nft list set inet filter quarantine_mac` has no elements. PHONE's filtering profile is
  **Standard**, and its Tier 2 row shows **Enroll device**, not "Enrolled".

---

## 4. Thirty minutes before

| # | Do | Expected |
|---|---|---|
| 1 | Mac: `cd ~/blah && ./mac-tunnel.sh start`, then open `https://localhost:8000` and sign in | Dashboard |
| 2 | Terminal A: `sudo securepi status` | `-> all services active`, `Tier 1 ... active`, `Tier 2 ... OFF`, test harness `present` |
| 3 | Terminal A: `sudo nft -j list set inet filter doh_resolvers \| jq '.nftables[1].set.elem \| length'` | about 1,400. **If it says 14**, the gateway has rebooted since the last daily refresh (`STAGE8-RECORD.md` M-15). Run `sudo systemctl start securepi-doh-refresh.service` and check again. |
| 4 | Terminal B: `ssh -t maheshwari@192.168.2.5`, then `watch -n 2 'sudo nft list set inet filter quarantine_mac'` | No elements (it shows PHONE's MAC during segment 7) |
| 5 | Console tabs, in order: Dashboard · Devices · PHONE's device page (`/devices/2`) · Incidents · Response · Filtering | All load |
| 6 | `REPORT-adblocking.md` §13 open in a second browser window | For segment 11 |

The incidents list shows the newest first. The evaluation's older open incidents stay below the new
ones; set the status filter to **New** for the demo.

---

## 5. The script, minute by minute

The times are targets. **If you are behind at 8:00, drop segment 3 (unbreak) and segment 8
(schedule)**: both are already demonstrated by the measurements cited in §1.

### 0:00-1:00 · 1. A real network, right now; a slow scan starts

- **Say:** "This is a gateway for a small network, running now, with an isolated test network inside
  the gateway for attacks."
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

- **Terminal A:** `dig +short @10.10.0.1 doubleclick.net`. Expected: `0.0.0.0` (blocked).
- **Console:** Filtering → **Pause for everyone** (top right) → **5 minutes** → reason "demo" →
  **Pause filtering**. A chip "Paused · 4m left" and **Resume now** appear. (The separate "Filtering is
  on" button beside them is the DNS filter's own on/off state, and still reads "on" during a pause.)
- **Terminal A:** the same `dig`. Expected: real addresses. The pause is a policy with an expiry, and
  the DNS filter's own timer ends it too, so it resumes on time even if the orchestrator stops.
- **Console:** **Resume now**. **Terminal A:** the same `dig`. Expected: `0.0.0.0` again, at once.
- **Terminal A:** `dig +short @10.10.0.1 youtube.com`. Real addresses: a DNS filter cannot touch ads
  served from youtube.com itself.
- **Say:** "Across 20 ad-heavy sites, 83 % fewer requests and 99 % fewer tracker companies. But
  first-party ads, like YouTube's, come from the same domain as the video. That is segment 11."
- **Fallback:** if `dig` still shows `0.0.0.0` while paused, wait one engine cycle (15 s) and repeat.

### 3:00-4:00 · 3. A broken link, fixed for one device in under 30 s

- **Say:** "Links shared from X go through t.co, which the tracker list blocks. Someone on this phone
  says 'links are broken'."
- **Say:** "Someone says the Myntra shopping app on this phone is broken."
- **Console:** PHONE's device page → **Recently Blocked** ("test and allow for this device") lists the
  domains the phone was blocked on. Type `touch.myntra.com` in its box → **Check**: the toast says
  **Blocked**. (Allow buttons appear only for domains the device was really blocked on. The list is its
  last 500 blocked lookups, and DNS events are kept for 30 days, so the phone's list lasts until
  about 9 November 2026.)
- **Console:** the `touch.myntra.com` row → **Allow 1h** → the dialog "Allow touch.myntra.com for this
  device for an hour?" → reason "demo: Myntra app" → **Allow for 1 hour**. *Allow 1h* removes itself
  after an hour. **Check** again: **Allowed** ("Allowed by an explicit rule"). In the 11 Oct
  run-throughs this was 1.1 s after the click.
- **Say:** "Only this phone. Every other device still has it blocked." Filtering → **Why is this
  blocked?** → `touch.myntra.com`, **Network-wide** → **Check domain**: still blocked.
- **Measured live, when the phone was connected:** 11.8 s from the click to the phone's first allowed
  lookup (target 30 s).

### 4:00-5:30 · 4. Devices, identified, scored, explained

- **Console:** Devices → **Hide test devices** (the list otherwise starts with 100-odd harness
  entries). Then PHONE's page: type, vendor and OS with the evidence for each (the hostname pattern,
  the connectivity-check lookups), risk score with its explanation, recent DNS, and baseline.
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
- **While it runs (5b), the DoH bypass:**
  - **Terminal A:**
    ```bash
    sudo nft list chain inet filter forward | grep -E 'doh-bypass|dot-bypass|doq-bypass'
    sudo nft -j list set inet filter doh_resolvers | jq '.nftables[1].set.elem | length'   # about 1,400
    ```
    DoH to a known resolver, DoT (853/tcp) and DoQ (853/udp) from the Wi-Fi are rejected and logged.
    The counters start at 0 after every boot.
  - **Console:** Incidents → **#447, "Device tried to bypass DNS filtering 6 times"** (PHONE, 26 Sep).
    Its evidence includes the phone's real DoH attempt: Chrome's Secure DNS set to
    `https://8.8.8.8/dns-query`, 182 `doh-bypass` rejections (plus 4 DoT and 1 DoQ) at 08:30-08:31,
    with 87 packets logged when it was measured (`EVALUATION-RESULTS-2.md`, real-device checks). The
    incident's text still says "quic-blocked x4": an incident keeps the description it opened with,
    and #447 opened on the phone's QUIC fallbacks at 08:06. (The phone's other bypass incidents, #580
    among them, are QUIC only.) The signal raises an incident once three bypass indicators fall
    inside 5 minutes.
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
- **Terminal B:** within one engine cycle (15 s) PHONE's MAC, `ca:25:f0:57:6d:87`, appears in
  `quarantine_mac` with a timeout of about 15 minutes. The kernel drops everything from that MAC on
  the Wi-Fi, so it holds across DHCP renewals, and the timeout ends it even if the orchestrator stops.
- **Console → Response:** the active policy with its expiry time, and the audit entry.
- **Release early:** device page → **Release** (no dialog). The toast says "Quarantine released", and
  the MAC leaves the set within one engine cycle. (The
  menu offers 15 min, 1 h, 24 h or until released; the 4.2 expiry measurement used a 120 s policy made
  through the API.)
- **Say:** "Every response is a policy with an expiry, verified against the kernel, and undone
  automatically. Measured: expired 6-11 s after its time."

### 10:00-11:00 · 8. A schedule-based service block

- **Console:** Filtering → **Profiles & Schedules** → **Kids** → **Edit**. "Also block some services
  during a daily window" is ticked. Under "Blocked during the window" keep **Social media** ticked
  (it includes reddit) and set **From** = **the next minute** (e.g. now 10:42 → `10:43`), **Until** =
  one hour later. (The time boxes show 12-hour times in a browser with that locale.) Type a reason,
  which is required → **Save and apply**. The row then reads "edited" and gains **Reset**.
- **Console:** PHONE's device page → DNS filtering profile → **Kids**. The toast says "Kids - verified
  in the DNS filter", and the row reads "Kids · schedule 10:43-11:43 daily".
- **Console:** PHONE's device page → **Recently Blocked** box: `www.reddit.com` → **Check**.
  - Before the start minute: allowed.
  - From the start minute: **Blocked** ("part of a blocked service"). In the 11 Oct run-throughs it
    switched within 7 s of the start minute.
- **Say:** "Kids' default window is 21:00-07:00. I moved it so it opens in front of you."
- Network-wide (Filtering → Why is this blocked?) `www.reddit.com` stays allowed: only PHONE is on
  Kids.
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
- **Terminal A:**
  ```bash
  sudo python3 /opt/securepi-eval/chaos.py stop-dns --watch 75 | jq -c '.timeline[]?' | tail -20
  ```
  - The DNS filter is down for 60 s, with an independent undo armed. The 10 Oct dry-run, from the
    timeline:

    | When | What |
    |---|---|
    | +0.1 s | AdGuardHome inactive |
    | +1 to +29 s | incident `platform_service_down` (+11.3 s on 10 Oct, +1.2 s and +28.7 s in the 11 Oct run-throughs: it depends on where the health check's cycle is) |
    | +17.4 s | the `dns-failopen` rules are in place, and incident `platform_dns_failopen` is raised. Devices keep resolving new sites, unfiltered (7.7: 4 fresh names resolved through the redirect) |
    | +61.3 s | AdGuardHome active again, and the fail-open rules are gone |
  - Show both incidents on the console. Afterwards, `dig +short @10.10.0.1 doubleclick.net` gives
    `0.0.0.0` again.
- **Say:** "A security box that takes the network down when it fails gets switched off. This one
  fails open, says so, and recovers by itself."
- `chaos.py` prints its JSON once, when the watch period ends (30 s and 75 s here). Meanwhile, narrate from the console, where the effects show live.
- **Fallback:** if `jq` prints nothing, run without the pipe. The JSON timeline is the output.

### 12:30-13:30 · 10. The privacy canary: sabotaged, red, then safe

- **Console:** Filtering → the **Tier 2: HTTPS Ad Removal** card → the **Privacy scope** chip,
  "verified N min ago", green.
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

### 13:30-14:30 · 11. Instagram, for one device only (recorded)

- **Console:** PHONE's device page → **HTTPS ad removal (Tier 2)**. Hover over Instagram for its
  privacy note: each site is ticked per device, off after every reboot, deny-by-default.
- **Console:** the same page's Tier 2 tile, recorded while the phone was connected: **435 decrypted,
  2,133 passed through, ads stripped from 91 responses, 265 ad objects removed.**
- **Second window:** `REPORT-adblocking.md` §13. Instagram feed ads in **10 of 10 runs → 0 of 10**
  with it on. The live-message hosts `edge-chat.instagram.com` and `gateway.instagram.com` were
  passthrough in every logged connection (2 and 60), never decrypted.
- **Say:** "Only `www.instagram.com` is decrypted, and only for the one device it is ticked for. The
  canary in segment 10 checks that scope every 15 minutes."
- **Not shown live:** enrolling needs a device that trusts the inspection CA, and none is connected.

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
| PHONE's MAC stays in `quarantine_mac` after Release | Wait one engine cycle; check Response for an active quarantine. The set's own timeout ends it anyway. |
| The domain test still says allowed after the schedule's start minute | Check that PHONE's profile row reads "Kids · schedule ... (active now)"; the schedule applies within one engine cycle (15 s). |
| Fail-open did not engage | `chaos.py` already scheduled its own undo. Check `systemctl is-active AdGuardHome`, then `sudo systemctl start AdGuardHome`. |
| The canary badge stays red after `restore` | The incident is still open: resolve it. If `restore` printed FAIL, the live addon really is wrong: stop and leave inspection off. |
| Anything else | Go on to the next segment and play that part of the backup video (§10). |

---

## 7. Putting everything back afterwards

Run all of these. They return the gateway to the state in §3.

| # | Undo | How |
|---|---|---|
| 1 | PHONE's touch.myntra.com allow | It ends by itself after the hour. To end it now: PHONE's device page → Active Policies → the Allow domain row → **End** (reason optional) → **End policy**. |
| 2 | PHONE's profile | Device page → DNS filtering profile → **Standard**. |
| 3 | Kids schedule | Filtering → Profiles & Schedules → Kids → **Reset** (back to 21:00-07:00). |
| 4 | Quarantine | Ended on stage by Release; if not, Response → the quarantine policy for PHONE → End. |
| 5 | Harness addresses | `sudo python3 /opt/securepi-eval/demo_attacks.py cleanup` |
| 6 | Demo incidents | Leave them, or mark them resolved. The demo devices are labelled `[TEST HARNESS] demo ...`. |
| 7 | Check | `sudo securepi status`; `sudo nft list set ip nat enrolled` and `... quarantine_mac` (no elements); `canary_demo.py restore` (ok, no open incident); Response: no active policy for PHONE. |

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
  - **No device is connected (since 11 Oct 2026).** Segments 3, 7 and 8 apply real policies to the
    A33's existing record. The gateway enforces them in the DNS filter and in the firewall's sets,
    but no live traffic from the phone shows their effect: the domain test and the kernel sets do.
    Segment 2 is shown with `dig` from the gateway. Segments 5b and 11 show what the phone recorded
    when it was connected; nothing in them happens live.

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

**Run-throughs of the phone-free script (11 October 2026).** The whole script, end to end, on the
live gateway. Claude Code drove the console in Chrome through the Mac's tunnel and ran Terminal A's
commands over SSH. There was no presenter and no audience, so they test the script and the gateway,
not the delivery. The wall-clock times include the tools' own latency, so a presenter's timing still
has to be found against a clock.

| Run | Time (IST) | Result |
|---|---|---|
| 1 | 18:28:54-18:39 | **Aborted at segment 3, after finding two console bugs.** Segment 1's slow scan was detected in 490.8 s. Segment 2 passed, but the first item of "Pause for everyone" (5 minutes) was hidden behind the page tabs, and 15 minutes had to be used (`STAGE8-RECORD.md` M-22). In segment 3, every **Allow 1h** click had sent no domain and been refused with 422, since the button was added on 13 Sep. Its native `prompt()` also froze the browser until the operator dismissed it (M-23). Both bugs were fixed test-first, 770 tests pass, deployed at 18:38. The run's one-hour allow (policy #114) was ended. |
| 2 | 18:40:12-18:53:45 | **Every segment passed.** 2: paused for 5 min from the fixed menu; `doubleclick.net` resolved at once, then was blocked again at once after **Resume now**. 3: the new dialog; PHONE allowed `touch.myntra.com` **1.1 s** after the click, still blocked network-wide. 5: campaign #45: brute force 75.7 s, port scan 91.7 s, beacon 152.2 s, kill chain C2 → Credential Access → Discovery. 6: slow scan **487.1 s**. 7: MAC in `quarantine_mac` within 1 s (timeout 15m59s), out of it after Release. 8: Kids 18:48-19:48; `www.reddit.com` allowed at 18:47:44, blocked at **18:48:07**, allowed network-wide. 9: kill-ids: never inactive, no incident. stop-dns: #826 at +1.2 s, fail-open #827 at +16.5 s, back at +60.4 s, off at +66.6 s. 10: #828, live addon SHA-256 unchanged (`308a5407…`), badge red, then green after Resolve. Put back by the console's own controls. |
| 3 | 18:54:43-19:06:47 | **Every segment passed.** 2: as in run 2. 3: toasts "Blocked", then "Allowed for this device", then "Allowed by an explicit rule"; network-wide still blocked (`||touch.myntra.com^`). 4: **Hide test devices** leaves 6 devices. 5: campaign #46: port scan 79.1 s, brute force 79.6 s, beacon 140.8 s; the console showed four "New high-severity incident" toasts. 5b: #447 (320 linked events). 7: quarantined, "enforced at the firewall"; MAC in the set by 19:00:30, out by 19:00:44. 8: Kids 19:02-20:02; reddit allowed at 19:01:38, blocked at **19:02:14**. 6: slow scan **494.5 s**. 9: kill-ids clean; stop-dns: fail-open #835 at +18.5 s, #836 at +28.7 s, back at +60.4 s, off at +62.4 s. 10: #837, badge red, then green. Recorded for §10. |
| 4 | 19:07:11-19:32:18 | **Every segment passed.** The long span is the agent's own tool latency (about 15 min lost in its waits), not the gateway. 2: pause and resume as before. 3: allowed for PHONE, blocked network-wide. 5: campaign #47: brute force 79.7 s, port scan 80.1 s, beacon 141.0 s. 7: MAC in the set by 19:12:10, out by 19:12:22. 8: Kids 19:14-20:14; reddit blocked by **19:14:02** (the before-reading was lost to a tool timeout). 6: slow scan **486.1 s**. 9: kill-ids clean; stop-dns: #844 at +13.4 s, fail-open #845 at +15.4 s, back at +61.4 s, off at +66.5 s. 10: #846, red, then green. |

**What the run-throughs changed in this script.** Segment 3 uses `touch.myntra.com`, because Allow
buttons exist only for domains the device was really blocked on. Segment 2 has its confirmation
step. Segment 4 adds Hide test devices. Segment 5b uses incident #447, not #580 (#580 is QUIC only).
Segment 8 says Social media and the required reason. Segment 9 gives the `platform_service_down`
range. Segment 10 gives the badge's real place.

**Seen, not fixed** (recorded in `STAGE8-RECORD.md`):
- The console still has five native `prompt()`/`confirm()` dialogs off the demo path.
- "Filtering is on" stays on during a network-wide pause.
- In the automated runs, the first click on a menu right after a page load sometimes did not open
  it (twice, both times right after navigation); it was not seen when the page had been idle a
  moment, and may be the automation's own focus handling.

**The presenter's own rehearsal**, against a clock with the script in hand, is still the
presenter's to do: these run-throughs cannot rehearse the talk.

---

## 10. Backup video

Record one full rehearsal that went well. A live demo fails at the worst moment (F§17.4); the
video is what you play instead.

**Recorded on 11 Oct 2026 (console only).** Run-through 3 (§9) was recorded in Chrome as an
animated GIF: 50 frames, the recorder's maximum, from the dashboard through the segments it
reached before the limit. It shows the console only, not Terminal A or B, and has no sound. It is
kept outside the repository (`~/Downloads/securepi-demo-backup-20261011.gif` once exported). It is a
fallback for the console segments; a full recording with the terminals and the talk still needs the
steps below.

1. **Mac screen:** press `Cmd + Shift + 5` → *Record Entire Screen* → Options → save to `~/Movies`.
   The Mac's screen shows the console and Terminals A and B.
2. **Name it** `securepi-demo-backup-YYYYMMDD.mov` and keep it **outside the repository**. A
   15-minute screen recording is several hundred MB.
3. **Before trusting it:**
   - watch it once end to end;
   - check that no password, test-account credential, or personal notification is visible;
   - record with *Do Not Disturb* on the Mac.

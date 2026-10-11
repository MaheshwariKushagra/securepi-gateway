# Stage 8 record (documentation and demonstration)

*Started 10 October 2026, 13:15 IST, from commit `8a5343f`. Steps 8.1 to 8.4
of `ENHANCEMENT-PLAN.md`. Progress is also tracked in that file's §8.
8.4 (close-out) is prepared but **not executed**: it waits for the user's
confirmation before any destructive command.*

## 1. The live gateway this stage documents (inventory, 10 Oct 2026)

Taken read-only from the Dell over SSH (`maheshwari@192.168.2.5`). Secrets
were redacted on the gateway before anything was copied.

### Host

| Item | Value |
|---|---|
| Hardware | Dell Vostro 3501, 4 CPU threads, 3,683 MiB RAM, 98 GB root LV (13 GB used) |
| OS | Ubuntu 24.04.1 LTS (`VERSION_ID="24.04"`), kernel `6.8.0-146-generic`, `x86_64` |
| Hostname | `maheshwari` |
| Admin user | `maheshwari` (uid 1000; groups adm, cdrom, sudo, dip, plugdev, lxd), passwordless sudo via `/etc/sudoers.d/securepi` (`maheshwari ALL=(ALL) NOPASSWD: ALL`) |
| Service user / group | `securepi-web` (uid 999, shell `/usr/sbin/nologin`) / `securepi` (gid 988) |
| Timezone | `Asia/Kolkata` (see `gateway/REBOOT-SAFETY.md`) |
| Sleep | `sleep.target`, `suspend.target`, `hibernate.target`, `hybrid-sleep.target` masked; `/etc/systemd/logind.conf.d/99-securepi.conf`: `HandleLidSwitch=ignore`, `HandleLidSwitchExternalPower=ignore`, `HandleLidSwitchDocked=ignore`, `IdleAction=ignore` |
| Forwarding | `/etc/sysctl.d/99-securepi.conf`: `net.ipv4.ip_forward=1`. IPv6 forwarding 0 |

### Network

| Interface | Role | Configuration |
|---|---|---|
| `enp1s0` (built-in RJ45) | Management link to the Mac | `/etc/netplan/01-ethernet.yaml`: static `192.168.2.5/24`, no gateway, no DNS. The Mac shares Internet over its USB Ethernet adapter and is `192.168.2.1` |
| `wlp2s0` (Wi-Fi, station) | WAN uplink | `/etc/netplan/99-wifi.yaml`: DHCP, saved networks `Babu_Home` (BSSID pinned) and `Redmi Note 12 Pro 5G` |
| `ap0` (virtual AP on the same radio) | Project LAN `SecurePi-Test` | Created by `securepi-ap0.service` → `/usr/local/sbin/securepi-ap0-up` (MAC = station MAC with the locally-administered bit flipped), `10.10.0.1/24`. `hostapd` (`/etc/hostapd/hostapd.conf`, 2.4 GHz, WPA2-PSK/CCMP, `country_code=IN`, `ap_isolate=1`). `securepi-ap-follow-uplink.service` rewrites `channel=` to the uplink's channel |
| `br-test`, `veth-atk`, `veth-vic`, netns `ns_attacker` (10.10.0.220), `ns_victim` (10.10.0.221-230) | Isolated test harness | `securepi-test-harness.service` → `/opt/securepi/setup-test-harness.sh`; Suricata waits for it (`suricata.service.d/override.conf`) |

`/etc/netplan/50-cloud-init.yaml` is empty (cloud-init's). DNS for the
gateway itself: `systemd-resolved` stub (`127.0.0.53`) on the uplink's DHCP
DNS. LAN DNS: AdGuard Home on `10.10.0.1:53` only.

### Software versions

| Component | Version | Source |
|---|---|---|
| Suricata | `1:7.0.3-1build3` (`suricata -V`: 7.0.3 RELEASE) | Ubuntu archive |
| suricata-update | package `suricata-update` (`/usr/bin/suricata-update`) | Ubuntu archive |
| ET Open rules | `/var/lib/suricata/rules/suricata.rules`, 52,688 `alert` lines, written 2026-09-12 14:57 | `suricata-update`, run once |
| hostapd / wpasupplicant | `2:2.10-21ubuntu0.4` | Ubuntu archive |
| nftables | `1.0.9-1build1` | Ubuntu archive |
| AdGuard Home | `v0.107.79`, binary sha256 `7e247573e63ce771a5925d16ca4ca9344e6e888673244289dc302f0fdfdfbf4e` (identical to the official `AdGuardHome_linux_amd64.tar.gz`, sha256 `c48f4a43000665484c5ec28177de11a004759b620dae8f77b2aabefc9ef3687f`) | GitHub release |
| Console / engine Python | system `python3` 3.12.3 with apt packages: `python3-fastapi 0.101.0-3`, `python3-starlette 0.31.1-1`, `python3-pydantic 1.10.14-1`, `python3-uvicorn 0.27.1-1`, `python3-jinja2 3.1.2-1ubuntu1.3`, `python3-markupsafe 2.1.5-1build2`, `python3-anyio 4.2.0-1`, `python3-h11 0.14.0-1ubuntu0.24.04.1`, `python3-click 8.1.6-2`, `python3-sniffio 1.3.0-2`, `python3-idna 3.6-2ubuntu0.2`, `python3-typing-extensions 4.10.0-1`, `python3-multipart 0.0.9-1`, `python3-yaml 6.0.1-2build2` | Ubuntu archive |
| DPI environment | venv `/opt/securepi-dpi` (Python 3.12.3, `include-system-site-packages = false`), `mitmproxy==12.2.3` and 43 pinned dependencies (`gateway/requirements-dpi.txt`) | PyPI |
| Other tools | `bind9-dnsutils 1:9.18.39-0ubuntu0.24.04.7`, `conntrack 1:1.4.8-1ubuntu1`, `tcpdump 4.99.4-3ubuntu4.24.04.1`, `nmap 7.94+git20230807.3be01efb1+dfsg-3build2`, `iperf3 3.16-1build2`, `iw 6.7-1build1`, `ethtool 1:6.7-1build1`, `curl 8.5.0-2ubuntu10.15`, `jq 1.7.1-3ubuntu0.24.04.2`, `apache2-utils` (for `htpasswd`), `hydra` (test harness), `adb 1:34.0.4-1build3` (tablet), snap `chromium 155.0.8059.39` (Dell test browser only) | Ubuntu archive / snap |

### Services (all `enabled`)

`hostapd`, `nftables`, `AdGuardHome`, `suricata`, `securepi-ap0`,
`securepi-ap-follow-uplink`, `securepi-backlight-off`,
`securepi-test-harness`, `securepi-ingest`, `securepi-engine`,
`securepi-web`, `securepi-static`, `securepi-dpi`,
`securepi-privacy-canary`, `securepi-ca-server`, `securepi-run-monitor`
(evaluation only); timers `securepi-doh-refresh.timer`,
`securepi-intel-refresh.timer` (both `OnCalendar=daily`,
`RandomizedDelaySec=30m`, `Persistent=true`) and
`securepi-ids-logrotate.timer` (every 15 min).

### Suricata: the four changes from the packaged `suricata.yaml`

Diffed against `etc/suricata/suricata.yaml` extracted from
`suricata_1%3a7.0.3-1build3_amd64.deb`:

1. `HOME_NET: "[10.10.0.0/24]"` (was `[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]`)
2. `community-id: true` (was `false`)
3. `dhcp` logger `extended: yes` (was `no`)
4. `af-packet`: `veth-atk` (threads 1, cluster-id 98, cluster_flow, defrag) **and** `ap0` (threads 2, cluster-id 99) instead of `eth0`

`/etc/default/suricata` is the packaged default (unused under systemd).

### AdGuard Home (`/opt/AdGuardHome/AdGuardHome.yaml`, schema 34)

- `http.address: 127.0.0.1:3000`, user `securepi` (bcrypt hash; the
  plaintext is `/etc/securepi/dns-password`, which `app/adguard.py` reads).
- `dns.bind_hosts: [10.10.0.1]`, port 53, `ratelimit: 0`,
  `upstream_dns: [tls://1.1.1.1, tls://9.9.9.9]`, `upstream_mode: parallel`,
  `bootstrap_dns: [1.1.1.1, 9.9.9.9]`, `fallback_dns: [tls://1.0.0.1, tls://149.112.112.112]`,
  cache 4 MiB with optimistic caching (`cache_optimistic_answer_ttl: 30s`,
  `cache_optimistic_max_age: 12h`), `enable_dnssec: true`, `refuse_any: true`.
- `querylog`: on, file on, `interval: 30d`, `size_memory: 1000`.
- `dhcp`: on, `interface_name: ap0`, gateway `10.10.0.1/24`, range
  `10.10.0.50`-`10.10.0.150`, lease 86,400 s, local domain `securepi`.
- Filters on: AdGuard DNS filter (id 1), HaGeZi Pro, Peter Lowe List, HaGeZi
  Encrypted DNS Bypass (DoH), Offline Threat Intel
  (`http://127.0.0.1:8082/ioc-domains.txt`, written by `app/intel.py`).
  Off: AdAway Default, OISD Big, HaGeZi DoH/VPN/Proxy Bypass. User rules: the
  three canary rewrites (`use-application-dns.net`, `mask.icloud.com`,
  `mask-h2.icloud.com` → NXDOMAIN). `filters_update_interval: 24`.
- Persistent clients are created by the orchestrator at run time (not
  installation data).

### Files and permissions the code depends on

| Path | Owner, mode | Written by |
|---|---|---|
| `/opt/securepi/` (code: `app/*`, `dpi/adfilter_rules.py`, `gateway/setup-test-harness.sh`, `gateway/refresh-doh-set.sh`) | `root:root`, dirs 755, files 644 (scripts 755) | `make deploy` (rsync) for `app/`; scripts by hand |
| `/opt/securepi/static/ioc-domains.txt` | `root:root` 644 | `intel.py` (daily) |
| `/opt/securepi-dpi/` (venv + `securepi_adfilter.py`, `adfilter_rules.py`, `privacy_canary.py`, `dpi-gate.sh`; CA in `ca/`) | `root:root`; `ca/mitmproxy-ca.pem` 600 | `deploy-dpi.sh`, `deploy-privacy-canary.sh`, mitmproxy (CA on first start) |
| `/opt/securepi-tls/` (`ca.key` 600, `ca.crt` 644, `console.key` `root:securepi` 640, `console.crt` 644) | `root:root` 755 | `gateway/generate-console-tls.sh` |
| `/var/lib/securepi/` (`securepi.db` + `-wal`/`-shm` 664, `orchestrator.lock` 644, `firewall/` 2700) | `root:securepi` 2770 | services |
| `/var/lib/securepi-dpi/` (`adfilter-rules.json` 664, `device-sites.json` 664) | `root:securepi` 2770 | deploy seed; console; orchestrator |
| `/etc/securepi/` (`console-password` 660, `dns-password` 660, `logrotate-suricata.conf` 644, `logrotate-suricata.packaged` 644) | `root:securepi` 2770 | setup scripts; console |
| `/var/www-ca/securepi-ca.crt` | `root:root` 644 | `deploy-dpi.sh` |
| `/var/log/securepi/` (`dpi-events.jsonl`, `dpi-rule-stats.json`) | **`maheshwari:maheshwari` 755** (see M-8) | DPI addon (root) |
| `/usr/local/sbin/securepi-web-helper` | `root:root` 700 | `setup-privilege-separation.sh` |
| `/etc/sudoers.d/securepi-web` | `root:root` 440 | `setup-privilege-separation.sh` |

## 2. Repo / doc / gateway mismatches found

| ID | What disagrees | Detail | Resolution in Stage 8 |
|---|---|---|---|
| M-1 | `GATEWAY-SETUP-RUNBOOK.md` vs the live network | The runbook's Plan A puts the WAN on the RJ45 port and management on a USB adapter at `192.168.100.1/24` (Mac `192.168.100.2`), names the netplan file `01-securepi.yaml`, uses an SSH alias `securepi`, an `rsync --delete` deploy to `~/securepi` and a plain-HTTP console at `http://192.168.100.1:8000`. Live: management on the built-in RJ45 `enp1s0` at `192.168.2.5/24` (Mac `192.168.2.1` via Internet Sharing); WAN on the Wi-Fi station `wlp2s0` with the AP `ap0` on the same radio; netplan `01-ethernet.yaml` + `99-wifi.yaml`; no SSH alias (the `Makefile` says so); `make deploy` rsyncs `app/` to `/opt/securepi` without `--delete`; the console is HTTPS-only on `10.10.0.1:8000`, reached from the Mac through `mac-tunnel.sh` | Runbook kept as the historical day-1 plan, with a banner pointing to `docs/INSTALL.md` (8.2), which documents the live layout |
| M-2 | Units and scripts that exist only on the gateway | 12 unit files, 2 timers and 2 scripts had no copy in the repo: `AdGuardHome.service`, `securepi-ap0.service`, `securepi-backlight-off.service`, `securepi-ca-server.service`, `securepi-doh-refresh.service`/`.timer`, `securepi-dpi.service` (only as a heredoc in `deploy-dpi.sh`), `securepi-engine.service`, `securepi-ingest.service`, `securepi-intel-refresh.service`/`.timer`, `securepi-privacy-canary.service` (heredoc in `deploy-privacy-canary.sh`), `securepi-static.service`, `securepi-test-harness.service`, `suricata.service.d/override.conf`; `/usr/local/sbin/securepi-ap0-up`, `/usr/local/bin/sni-capture`. `gateway/REBOOT-SAFETY.md` says the harness units are "not committed here in full" Committed in 8.2: the gateway units in `gateway/systemd/` (`AdGuardHome.service` differs only by M-12), the three DPI units in `dpi/` (identical to the live units and to the heredocs they replace), and `gateway/securepi-ap0-up` and `gateway/sni-capture`, byte-identical. `gateway/REBOOT-SAFETY.md` updated |
| M-3 | `EVALUATION-RESULTS-2.md` line 574 | Says `/etc/nftables.conf` and `/opt/securepi/nftables.conf` are identical. The `/opt` copy is now 105 diff lines stale (later firewall changes, including 7B.7, only went to `/etc`). Nothing loads the `/opt` copy | Noted here; the installer no longer copies `nftables.conf` into `/opt/securepi`. The stale copy is harmless and left alone |
| M-4 | Comment wording | The live `AdGuardHome.service.d/securepi-wait-for-ap0.conf` and `/opt/securepi/setup-test-harness.sh` still say "AdGuard"/"Suricata" where the repo (commit `bfc9ce1`) says "the DNS filter"/"the IDS". Comments only | The installer installs the repo versions |
| M-5 | `hostapd.conf` | Live `channel=1` vs repo `channel=6` (expected: `securepi-ap-follow-uplink` rewrites it to the uplink's channel) and the live file has no comments (rewritten by the same script). **The live file is mode 644, so the Wi-Fi passphrase is readable by any local user** The installer writes a new file as 600 `root:root` from the redacted repo copy plus the passphrase typed at a hidden prompt. It never replaces an existing file, but sets it to 600 (`--check` reports it). **Applied 11 Oct 2026 17:51** (the operator's installer run): `/etc/hostapd/hostapd.conf` is now `600 root:root` |
| M-6 | IDS rules freshness | ET Open rules last updated 2026-09-12 by a single `suricata-update` run; no timer updates them | Installer runs `suricata-update` once. A rule-update timer is listed in future scope (8.1), not added silently |
| M-7 | DPI environment | `adblock==0.6.0` is installed in `/opt/securepi-dpi` but nothing in the repo imports it (left over from an experiment) | Kept in `requirements-dpi.txt` so the reinstall matches the measured environment exactly; flagged here |
| M-8 | `/var/log/securepi` ownership | `maheshwari:maheshwari` 755 (`deploy-dpi.sh` chowns it to the admin user) although only root writes to it | Installer makes it `root:root` 755; nothing else changes |
| M-9 | `NEXT-SESSION.md` vs the plan | `NEXT-SESSION.md` lists "Stage 8, step 1: the 7.9 usability fixes"; the plan's Stage 8 table has no such step | Not done: the user decided on 10 Oct 2026 to leave 7.9 as it is. The six recommendations stay recorded in `docs/usability-study/heuristic-evaluation.md` and in future scope |
| M-10 | DPI venv creation | `dpi/deploy-dpi.sh` assumes `/opt/securepi-dpi` already is a venv with mitmproxy; no repo file creates it (it was made by hand on 12 Sep: `python3 -m venv /opt/securepi-dpi`) | Installer creates it and installs `requirements-dpi.txt` |
| M-11 | `README.md` numbers | The detection, memory and throughput rows still quote Day 14 (`EVALUATION-RESULTS.md`), not Stage 7 | Updated in 8.1 |
| M-12 | `AdGuardHome.service` | `WorkingDirectory=/home/maheshwari` (written by `AdGuardHome -s install` run from the admin's home) | Installer writes `WorkingDirectory=/opt/AdGuardHome` |
| M-13 | `STEP-1-INSTALL-UBUNTU.md` §7-9 | Describes the hand-over with the Plan A wiring of M-1 | Same banner as M-1 |
| M-14 | README demo instructions | `python3 seed.py && python3 serve.py` cannot run on the Mac (Homebrew Python 3.14 has no FastAPI); the demo used a git-ignored `.venv-demo` | `docs/demo/requirements.txt`, installed with `--no-deps` (details in §3, 8.1) |
| M-15 | DoH resolver set after a reboot (**found by the 8.2 check run**) | `nftables.conf` seeds `inet filter doh_resolvers` with 14 addresses; `securepi-doh-refresh.timer` (`OnCalendar=daily`, `RandomizedDelaySec=30m`, `Persistent=true`) refills it with ~1,436 from HaGeZi. `Persistent=true` only catches up a run that was *missed* while the machine was off, so after a reboot (or any full `nft -f /etc/nftables.conf`) the set keeps only the 14 seeds until the next daily run, up to ~24 h. Live on 10 Oct 2026: booted 12:14, last refresh 00:28 that day, set = 14 at 13:57, next refresh ~00:21 on 11 Oct. No document mentions this; `EVALUATION-RESULTS-2.md` §2.2 reports the 1,445 figure from a manual run. DNS-level DoH blocking (the HaGeZi DoH filter in AdGuard) and the DoH detection are unaffected; only the IP-level block of DoH by address is weakened | Installer refreshes the set whenever it holds fewer than 500 entries and `--check` reports it; `docs/INSTALL.md` §7.1 shows how to check it. **Fixed in the repo on 11 Oct 2026 (`8eb7532`), at the operator's go-ahead:** `OnBootSec=2min` added to the `[Timer]` of `gateway/systemd/securepi-doh-refresh.timer` (the service already runs `After=nftables.service`), pinned by `tests/test_doh_refresh_timer.py`. **Applied 11 Oct 17:51** by the operator's installer run; `systemctl show` lists `OnBootUSec=2min` next to the daily `OnCalendar`. On the 11 Oct boot the set refilled anyway (1,434 at 17:17), because the Dell was off at midnight and `Persistent=true` caught up the missed run |
| M-16 | `redteam/README.md` | The pre-demo checklist told the presenter to open `http://localhost:8000` / `http://10.10.0.1:8000`. The console has been HTTPS-only since step 3.2, so plain HTTP gets no answer | Fixed to `https://` (8.3) |
| M-17 | The URL lines in the journal, against the report | `REPORT-adblocking.md` §6 and `REPORT.md` §5.1 say mitmdump wrote 5,163 decrypted request URLs "over the 14 days before" 7B.5. That is exact for 26 Sep-10 Oct (94 + 1,515 + 56 + 923 + 2,575). The journal also still holds 4,065 such lines from 12 Sep, so **9,228 in total**. None was written after 10 Oct 03:40:35; the running unit has `flow_detail=0` | Recorded in `docs/CLOSE-OUT.md` §7, whose journal purge removes all 9,228. The report figures stay as they are (they name their window) |
| M-18 | The inspection CA's subject | The live CA (`/opt/securepi-dpi/ca/`, 12 Sep 2026 07:06, valid to 9 Sep 2036) is "CN = SecurePi Gateway, O = SecurePi Gateway, OU = Network Security Platform". mitmproxy wrote its own files at 07:04 (`dhparam`), and the CA was replaced by hand two minutes later. No script in the repo makes this CA: `dpi/deploy-dpi.sh` lets mitmproxy create its default "mitmproxy" CA. So a reinstall, or a rotation (`docs/CLOSE-OUT.md` 6b), shows "mitmproxy" in a phone's user certificates, not "SecurePi Gateway" | Documented in `docs/CLOSE-OUT.md` §5 and §6b; not scripted |
| M-19 | README signal count | "A correlation engine runs fourteen signal checks" and the badge `detection_signals-14`. `SIGNALS` in `app/correlation.py` lists 15 (campaign included). The README's own architecture diagram and file list already said 15 | Both fixed to 15 (8.3) |
| M-20 | Retention held the database write lock for its whole pass (**found at the 11 Oct 2026 17:15 boot**) | The engine's first retention pass after a day powered off (17:15:47-17:16:28) deleted 2,960 events in one transaction and held the write lock for about 40 s. Every service waits at most 30 s (`dbconn.BUSY_TIMEOUT_S`): the privacy canary crashed with `database is locked` (restarted after 10 s, then passed; incident #816), and ingest's DNS-filter reader skipped a pass. Cause: the disk is a 5,400 rpm hard drive (Toshiba MQ04ABF1), and each deleted event is a random write in all nine indexes on `events`. Measured on a copy of the live database: rollup catch-up 1.0 s; retention of 5,329 events cold held the lock 29.5 s, 10,887 warm 22.5 s. In about a week the Stage 7 campaign's flow/TLS rows (3-10 Oct) pass their 14-day limit, so daily passes would grow to tens of thousands of rows | **Fixed (`8eb7532`) and applied 11 Oct 17:51** (engine restarted on the new code): `app/retention.py` finds old events with a plain read (no write lock), deletes them in sorted batches of 100 with a commit and a 0.2 s pause after each (longer than SQLite's 100 ms retry interval), and does at most 1,000 per engine cycle, carrying a backlog to the next cycles so the engine never goes near the 60 s heartbeat threshold. Measured on the copy, cold: a 1,000-event cycle took 22 s and no batch held the lock longer than 4.4 s. 4 new tests in `tests/test_retention.py` failed on the old code (a second writer blocked 3 times; one delete removed 120 rows; no pauses; a 120-row backlog went in one cycle). The database copy was deleted afterwards |
| M-21 | `docs/CLOSE-OUT.md` §8 against the database copies on the gateway (**found 11 Oct 2026**) | §8 listed three database backups (`/var/lib/securepi/*.bak`). A search of the whole disk found about 750 MB more old device data: 11 `securepi.db.pre-*` copies in `/opt/securepi` (125 MB) plus an 18 MB copy in `/opt/securepi/.bak-3.6-1789930809/`; the 7B rollback set in `/var/backups/securepi-7B/` (a 286 MB copy, and a tarball holding four more); and the Stage 7 soak start mark (275 MB), which §3 said did not exist. The "code backups" row said "10 files, only old code", but its `find -name '*.bak*' -delete` matched 92 code files, nine of those database copies and a directory it could not delete | §8 corrected: the code-backup command now excludes `securepi.db*`, and the three missed locations have rows of their own, each marked irreversible. Nothing was deleted |

## 3. Progress

- **Inventory (Stage 8 started 13:22 IST)** - done; recorded above.
- **8.1 report (committed 13:38 IST, `0551c1e`)** - done.
  - **`REPORT.md` (new):** the consolidated report material. It covers problem, final technology table with versions, topology as built, architecture and the **contribution boundary** (feasibility §17.2 brought up to date with what was built), implementation by stage including 7A and 7B, evaluation (every Stage 7/7A/7B figure with its source), the **final deviations table** (plan §1's decisions → outcome), limitations, future scope, and an appendix giving the command and result file behind every figure. It states plainly that the original replay input databases were not kept.
  - **`REPORT-adblocking.md`:**
    - upstream row corrected (DoT 1.1.1.1 + 9.9.9.9 in parallel with fallbacks, not 1.1.1.1/1.0.0.1);
    - DoT/DoQ control row updated;
    - §6 and §11 corrected: mitmdump's default output wrote 5,163 decrypted request URLs to the journal until 7B.5;
    - metrics table gains the bypass matrix, list utility and canary rows;
    - new §14 on deny-by-default consent, **the privacy canary as a verification method** (and what it does not cover), and the updated bypass matrix (DoQ blocked since 7B, VPN flagged since 7A).

    The A12 correction was already in `FIRST-PARTY-ADS-ANALYSIS.md` §5.1 and §8; the SSAI boundary already in §8.
  - **`README.md` (M-11):**
    - "At a glance" rows now quote Stage 7 (reduction 200:1 / 47:1, detection 15×5 with precision 0.91, memory peaks, throughput 400 Mbit/s without loss, resilience);
    - the Evaluation section rewritten from Day 14 to Stage 7 (TTD medians, memory);
    - the claim "every number can be reproduced with `gateway/evaluate.py`" replaced (most figures come from other tools; `REPORT.md` §10 lists them);
    - 7B and 8 roadmap rows; "six detection signals" → 15; badge stages 0-7B; the "24 hours" inspection claim made exact; docs index extended.
  - **Demo console (M-14, new mismatch):** the README's `python3 seed.py && python3 serve.py` cannot work on the Mac, whose Homebrew Python 3.14 has no FastAPI; the screenshots and 7.9 used a git-ignored `.venv-demo` that nothing in the repo recreated. Added `docs/demo/requirements.txt` (versions from `.venv-demo`). **It must be installed with `--no-deps`**: PyPI's fastapi 0.101.0 declares `starlette<0.28`, while the gateway (Ubuntu) runs it with Starlette 0.31.1. Verified in a fresh venv: `seed.py` (12,089 events), `serve.py`, sign-in with `demo` (303 to `/`), and `/`, `/devices`, `/incidents`, `/filtering`, `/api/overview?range=6h`, `/api/devices`, `/api/incidents?status=open` all 200.
  - **Banners and notes:** `GATEWAY-SETUP-RUNBOOK.md` and `STEP-1-INSTALL-UBUNTU.md` marked historical, pointing to `docs/INSTALL.md` (M-1, M-13); the stale `/opt/securepi/nftables.conf` claim in `EVALUATION-RESULTS-2.md` annotated (M-3); the plan's §1 points to the final table.
  - **Not done, by decision:** the 7.9 usability recommendations (M-9), listed as future scope.
  - **Gate:** 751 tests pass; all relative links in the edited documents resolve except the three Stage 8 documents still to be written (`docs/INSTALL.md`, `docs/DEMO.md`, `docs/CLOSE-OUT.md`).
- **8.2 installer (13:40-14:00)** - written and checked against the live gateway. Two parts are **still open**: applying it on the live gateway, and a fresh-machine install. Both are below.
  - **`gateway/install.sh` (new, 14 steps).**
    - `--check` reports every change as `would:` and changes nothing. Apply mode changes only what differs and keeps each replaced file as `<file>.bak-install-<timestamp>`.
    - It never disables or removes anything. It never overwrites `hostapd.conf`, netplan files, `AdGuardHome.yaml`, either password, either CA, the rules file, the site map or the database.
    - Secrets are asked at hidden prompts and passed to Python through the environment, never argv.
    - Settings via environment variables (defaults = the Dell): `WAN_IF`, `MGMT_IF`, `MGMT_ADDR`, `AP_SSID`, `AP_COUNTRY`, `AP_CHANNEL`, `AP_PASSPHRASE`, `UPLINK_SSID`, `TIMEZONE`, `INSTALL_DPI`, `INSTALL_EVAL_TOOLS`, `ENABLE_RUN_MONITOR`, `TEST_WITHOUT_WIFI`.
    - HTTPS inspection is installed off: the `enrolled` set is empty and `device-sites.json` is `{}`.
  - **New repo files.**
    - `gateway/systemd/` (11 units and timers, plus the Suricata drop-in) and `dpi/securepi-{dpi,ca-server,privacy-canary}.service` (M-2).
    - `gateway/securepi-ap0-up`, `gateway/sni-capture`, `gateway/logind-securepi.conf`, `gateway/sysctl-securepi.conf`.
    - `gateway/adguard/AdGuardHome.yaml.template`: the live config with the password hash as a placeholder and the persistent clients emptied. Parsed with PyYAML on the gateway: schema 34; values as in §1.
    - `gateway/suricata-securepi.patch`: the four changes in §1. Verified that applying it to the packaged `suricata.yaml` gives a file identical to the live one, and that a reverse dry-run against the live file detects it as already applied.
    - `dpi/requirements-dpi.txt`: the live `pip freeze`, 44 packages (M-10).
    - `gateway/requirements-console.txt`: the apt versions, for reference only.
  - **Rewritten:**
    - `dpi/deploy-dpi.sh` creates the venv and installs the pins (M-10); takes the unit files from `dpi/` instead of heredocs; seeds `device-sites.json` as `{}`; sets `/var/log/securepi` to `root:root 755` (M-8).
    - `dpi/deploy-privacy-canary.sh` installs `dpi/securepi-privacy-canary.service`.
  - **`docs/INSTALL.md` (new).** Covers:
    - hardware checks, including the `iw list` interface combinations;
    - the Ubuntu install choices;
    - the management link on both ends, and copying the repo;
    - running the installer: prompts, a settings table, what each step does, expected end output;
    - verification commands with the outputs measured on the Dell;
    - console and DNS-filter access, the file table, the pinned versions;
    - the check-run evidence;
    - rollback per change, plus a full-removal list (destructive; documented, not scripted);
    - the VM procedure.
  - **Verification done.**
    - `bash -n` and `shellcheck` (every level) are clean on `install.sh`, `deploy-dpi.sh`, `deploy-privacy-canary.sh`, `securepi-ap0-up` and `sni-capture`. `make test`: 751 pass.
    - Read-only facts confirmed on the gateway:
      - all 30 packages are installed;
      - the 8 key versions match;
      - `htpasswd -inBC 10 ""` produces a `$2y$10$` hash that `htpasswd -vb` accepts for the password without its trailing newline, which is how `app/adguard.py` reads it (`.strip()`);
      - `AdGuardHome --version` prints `AdGuard Home, version v0.107.79`;
      - Ubuntu's `hostapd.service` already sets `DAEMON_CONF`, so the installer does not write `/etc/default/hostapd`;
      - `/etc/nftables.conf` is 644, and the installer uses 644;
      - `af-packet` interfaces are `veth-atk`, `ap0`, `default`;
      - the canary's last line is `ok - passthrough and decrypt decisions correct for every site module`.
    - `sudo ./gateway/install.sh --check` on the live gateway, from a copy in `~/securepi-install-check`: 13:51 run 7 changes; 13:57 re-run 8 changes, 0 warnings, exit 0, nothing changed. The 8 are M-5, M-4 (×2), M-12, M-8 (re-runs `deploy-dpi.sh`), `dns_ab.py`, `dash_latency.py`, and the DoH refresh (M-15). Transcript in `docs/INSTALL.md` §10.
  - **Bugs found and fixed in the installer before any apply:**
    1. The "first DoH refill" test (`grep '\.'`) was always true because of the 14 seeds, so it never refreshed. It now counts elements with `nft -j ... | jq` and refreshes below 500. This check is what exposed M-15.
    2. `securepi-ap0.service` hard-codes `wlp2s0` in `After=`, so it is now rendered like the other interface-specific files.
    3. A `/etc/default/hostapd` rewrite that would have replaced Ubuntu's commented default file was removed: not needed.
  - **Applied on 11 Oct 2026 at 17:51 by the operator** (see the 11 Oct entry below). Before that: `sudo ./gateway/install.sh` on the Dell was refused by the session's permission policy ("Production Deploy") at 13:53 and **has not run**. It needs the operator's go-ahead. What it would do is exactly the 8 items above, then: daemon-reload; a restart of `securepi-dpi` (no device enrolled, so no user impact) and of `securepi-ca-server`; no AdGuard restart, so the new `WorkingDirectory` takes effect at its next restart. After applying, `--check` must report 0 changes.
  - **Open: fresh-machine install (the 8.2 exit criterion).** Not done. Even a read-only probe for Lima on the Mac (`which limactl`) was refused by the same policy at 13:54. The VM procedure is in `docs/INSTALL.md` §12 and has not been run. Until it is, the fresh-install path is checked only piece by piece against the live system, as listed above.
- **8.3 demo (14:05-14:50)** - script written, helpers built and tested, the gateway-side segments dry-run twice. **Still open:** the three presenter rehearsals with the phone, and the backup video. Both need a person.
  - **`docs/DEMO.md` (new).** Covers:
    - a table mapping every plan item to its segment and expected timing, with sources;
    - equipment and set-up (Mac via `mac-tunnel.sh`, two gateway terminals, the A33 in Chrome mirrored with `scrcpy`);
    - day-before and 30-minute checklists, including the M-15 DoH set check;
    - a minute-by-minute script of 12 segments with exact commands and console click paths. Every click path was checked against `app/static/app.js` and the templates; four were corrected: quarantine offers 15 min/1 h/24 h/until released, not 2 min; the profile schedule editor is under Filtering → Profiles & Schedules; Tier 2 is site ticks plus "Enroll device"; Tier 2 needs a browser restart because it applies to new connections only;
    - a recovery table and a put-it-all-back table;
    - what is real versus staged, the rehearsal record, and how to record the backup video.
  - **Helpers (new).**
    - `gateway/demo_attacks.py` (`slow-scan`, `campaign`, `cleanup`) calls the 7.2 battery's attack functions unchanged, from new harness addresses `.247`/`.248`, each run as a new `[TEST HARNESS] demo ...` device.
    - `dpi/canary_demo.py` (`break`, `restore`) runs the canary's real `run_check()`, including its real fail-safe, against a temporary *copy* of the addon with the report §6 `ignore_conn` typo. The live addon is never written: mitmproxy reloads it on change.
    - Both are installed by `gateway/install.sh` (steps 13 and 14).
    - `tests/test_demo_helpers.py`: 6 tests, written after the helpers rather than first (a deviation from the step rule). They check that the live addon is byte-for-byte untouched and the path restored, that a passing check is refused, that the broken copy fails the real decision logic, that the demo addresses never collide with battery or victim addresses, and that `campaign` runs the three battery functions unchanged.
  - **Technical dry-runs on the live gateway** (`docs/DEMO.md` §9):
    - campaign: 84.6/84.8/84.5/147.1 s;
    - slow scan: 486.1 s;
    - canary break → incident #806, live addon SHA-256 unchanged; restore → ok;
    - kill-ids: restarted in the same second, `NRestarts=1`, no incident;
    - stop-dns: `platform_service_down` at +11.3 s, fail-open on at +17.4 s, back at +61.3 s;
    - an overlapped second run: slow scan 489.2 s, campaign 80.7 s.
  - **Found by the dry-runs, now in the script:**
    - Killing the IDS raises no incident: it is back before the health supervisor looks. The script used to claim one.
    - The campaign's chain reads "Command and Control → Credential Access → Discovery": tactics are ordered by first evidence, and the beacon starts first.
    - The brute force's nine SSH attempts are periodic enough that the beacon signal links them too (incident titled "Possible C2 beacon to 10.10.0.222:22").
    - The fast 40-port scan also raises `slow_port_scan`.
  - **Left on the gateway by the dry-runs, as test data:**
    - devices 100-103 (`[TEST HARNESS] demo ...`) with their incidents;
    - campaigns #43 and #44;
    - platform incidents #808 and #809;
    - **privacy-scope incident #806, still open**, so the console's privacy badge reads red until it is resolved on the console (Incidents → #806 → Resolved). Resolving it needs a console sign-in, so it was left to the operator.
  - **Not dry-run:** segments 2, 3, 4, 5b, 7, 8 and 11 need the phone and a console sign-in. The A33 was not connected (no device seen in the 30 minutes before 14:15).
  - **M-16 fixed** (redteam README's `http://` console URLs). **M-19:** the README said "fourteen signal checks" and its badge said 14, but `SIGNALS` in `app/correlation.py` has 15. Both fixed.
- **8.4 close-out (14:25-14:50)** - `docs/CLOSE-OUT.md` written. **Nothing in it was executed.**
  - **Read-only pre-checks** on the gateway at 14:25, recorded per item:
    - nothing enrolled, and `device-sites.json` is `{}`;
    - no test browser or proxy process;
    - `~/securepi-browser` is 1.8 GB, holding the test-account profiles and the test CA's private key;
    - the inspection CA's subject and SHA-256;
    - the journal is 430.2 MB over 21 boots, with **9,228 decrypted-URL lines** (M-17), the last at 10 Oct 03:40:35;
    - the run monitor is enabled and active;
    - three pre-change DB backups (29 MB, 34 MB, 274 MB);
    - 10 code `.bak` files;
    - the 36 MB DNS query log;
    - the Mac's locked `a33-checks` worktree.
  - **For each item:** the exact command, how to verify it, and whether it can be undone. Items 4, 6 and 7 are marked IRREVERSIBLE.
  - **The CA rotation path** documents M-18: the live CA's "SecurePi Gateway" subject was made by hand, so a rotated CA shows as "mitmproxy".
  - **The "soak DB copy" leftover** listed in the session notes does not exist on either machine (searched `/var/tmp`, `/tmp`, home directories and the repo), so it is not in the runbook. **Wrong, corrected on 11 Oct (M-21):** it is `/var/lib/securepi-eval/soak-2026-10-03T093855/mark/securepi-start.db` (275 MB); `/var/lib` was not searched.
- **11 Oct 2026 session (17:15-18:05 IST)** - the Dell was powered on (booted 17:14:58).
  - **Health:** all 17 services active, on the charger at 100%, internet over Babu_Home, Tier 2 off. The DoH set held 1,434 entries at 17:17: the Dell had been off at midnight, so `Persistent=true` caught up the missed run (M-15 does not show after a power-off across midnight, only after a daytime reboot).
  - **GitHub:** the four Stage 8 commits (`0551c1e`..`79e8396`) had only been committed locally. Pushed after a scan of the diff for tokens, keys, password hashes and passphrases (none; the repository is public).
  - **Incidents:** #806 is still open (resolving it needs a console sign-in). #815 (WAN ping at the 10 Oct shutdown) and #817 (no DNS-filter events on an idle network) are boot noise; #816 is M-20.
  - **M-20 found and fixed in the repo (`8eb7532`):** retention in short batches, at most 1,000 events per engine cycle. Measured on a copy of the live database, which was deleted afterwards.
  - **M-15 fixed in the repo (`8eb7532`):** `OnBootSec=2min` on the DoH refresh timer. `systemd-analyze verify` on the gateway: exit 0.
  - **Tests:** 765 pass (4 new retention tests and 1 new timer test, each failing on the old code first, except the evidence-chain guard, which passes on both). `shellcheck` clean on `install.sh`.
  - **Installer:** the gateway's copy (`~/securepi-install-check`) was refreshed with the documented rsync. `--check` at 17:45: **11 changes, 0 warnings**: M-5, M-4 (×2), M-12, M-8 (`deploy-dpi.sh`), the DoH timer (M-15), `retention.py` (M-20), `canary_demo.py`, `dns_ab.py`, `dash_latency.py`, `demo_attacks.py`. The DoH refill item of 10 Oct is gone (the set is full). Apply was refused three times by the session's permission policy ("Production Deploy"), the last after the operator's go-ahead, so **the operator ran it at 17:51:54** from this session (`ssh ... 'cd ~/securepi-install-check && sudo ./gateway/install.sh'`): **11 changes made, 0 warnings**; the installer's own service check found every always-on service active, the DNS filter answered `0.0.0.0` for `doubleclick.net`, and the console returned 200.
  - **After the apply (read-only checks, 17:52-17:55):**
    - `--check` again: **0 changes, 0 warnings**. The 8.2 apply is closed.
    - `securepi-doh-refresh.timer`: `OnBootUSec=2min` and `OnCalendar=*-*-* 00:00:00` (M-15).
    - `/etc/hostapd/hostapd.conf` `600 root:root` (M-5); `/var/log/securepi` `755 root:root` (M-8).
    - ingest, engine and web restarted at 17:51:56 with no errors, the engine on the new `retention.py` (M-20); the proxy restarted at 17:52:01 with nothing enrolled.
    - `AdGuardHome.service` now says `WorkingDirectory=/opt/AdGuardHome` (M-12), the only line that differs from its backup, and `systemd-analyze verify` passes. The running process still has `/home/maheshwari` as its working directory, because the installer does not restart the DNS filter; the new setting applies at its next restart. Safe: `ExecStart` is the absolute `/opt/AdGuardHome/AdGuardHome`, whose configuration sits next to it.
    - The privacy canary's first check against the reinstalled addon, 18:01:36: `ok - passthrough and decrypt decisions correct for every site module`. `sudo securepi status` at 17:58: all services active, internet ok, DoH set 1,434.
    - Every replaced file has a `.bak-install-20261011-175154` copy next to it; the full run log is `~/install-apply-20261011.log` on the Dell.
  - **M-21:** close-out §8 corrected (database copies it missed, a code-backup command that would have deleted nine of them). Nothing deleted.
  - **Fresh-machine install (8.2 exit criterion): not run, by the user's decision (11 Oct, after the apply).** The user asked for "educated synthetic data" in its place. The agent declined to present invented results as a measured run. The report gives the outcome instead as **estimated results (not measured)**, labelled "estimated" at the user's request: `REPORT.md` §7.4 (8.2) and §8 (a new platform limitation), and `docs/INSTALL.md` (status box and §12). These pages also list what only a real fresh install would test. No timings or change counts were invented. While writing §12 the agent found that a failed first-install IDS-rules download is never retried (no rules timer, M-6), and wrote that, not "retried daily".

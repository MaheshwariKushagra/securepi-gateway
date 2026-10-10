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
| M-2 | Units and scripts that exist only on the gateway | 12 unit files, 2 timers and 2 scripts had no copy in the repo: `AdGuardHome.service`, `securepi-ap0.service`, `securepi-backlight-off.service`, `securepi-ca-server.service`, `securepi-doh-refresh.service`/`.timer`, `securepi-dpi.service` (only as a heredoc in `deploy-dpi.sh`), `securepi-engine.service`, `securepi-ingest.service`, `securepi-intel-refresh.service`/`.timer`, `securepi-privacy-canary.service` (heredoc in `deploy-privacy-canary.sh`), `securepi-static.service`, `securepi-test-harness.service`, `suricata.service.d/override.conf`; `/usr/local/sbin/securepi-ap0-up`, `/usr/local/bin/sni-capture`. `gateway/REBOOT-SAFETY.md` says the harness units are "not committed here in full" | Committed under `gateway/systemd/` and `gateway/sbin/` (8.2), byte-identical to the live copies |
| M-3 | `EVALUATION-RESULTS-2.md` line 574 | Says `/etc/nftables.conf` and `/opt/securepi/nftables.conf` are identical. The `/opt` copy is now 105 diff lines stale (later firewall changes, including 7B.7, only went to `/etc`). Nothing loads the `/opt` copy | Noted here; the installer no longer copies `nftables.conf` into `/opt/securepi`. The stale copy is harmless and left alone |
| M-4 | Comment wording | The live `AdGuardHome.service.d/securepi-wait-for-ap0.conf` and `/opt/securepi/setup-test-harness.sh` still say "AdGuard"/"Suricata" where the repo (commit `bfc9ce1`) says "the DNS filter"/"the IDS". Comments only | The installer installs the repo versions |
| M-5 | `hostapd.conf` | Live `channel=1` vs repo `channel=6` (expected: `securepi-ap-follow-uplink` rewrites it to the uplink's channel) and the live file has no comments (rewritten by the same script). **The live file is mode 644, so the Wi-Fi passphrase is readable by any local user** | Installer installs it as 600 `root:root`; the repo copy keeps the passphrase redacted and the installer asks for it |
| M-6 | IDS rules freshness | ET Open rules last updated 2026-09-12 by a single `suricata-update` run; no timer updates them | Installer runs `suricata-update` once. A rule-update timer is listed in future scope (8.1), not added silently |
| M-7 | DPI environment | `adblock==0.6.0` is installed in `/opt/securepi-dpi` but nothing in the repo imports it (left over from an experiment) | Kept in `requirements-dpi.txt` so the reinstall matches the measured environment exactly; flagged here |
| M-8 | `/var/log/securepi` ownership | `maheshwari:maheshwari` 755 (`deploy-dpi.sh` chowns it to the admin user) although only root writes to it | Installer makes it `root:root` 755; nothing else changes |
| M-9 | `NEXT-SESSION.md` vs the plan | `NEXT-SESSION.md` lists "Stage 8, step 1: the 7.9 usability fixes"; the plan's Stage 8 table has no such step | Not done: the user decided on 10 Oct 2026 to leave 7.9 as it is. The six recommendations stay recorded in `docs/usability-study/heuristic-evaluation.md` and in future scope |
| M-10 | DPI venv creation | `dpi/deploy-dpi.sh` assumes `/opt/securepi-dpi` already is a venv with mitmproxy; no repo file creates it (it was made by hand on 12 Sep: `python3 -m venv /opt/securepi-dpi`) | Installer creates it and installs `requirements-dpi.txt` |
| M-11 | `README.md` numbers | The detection, memory and throughput rows still quote Day 14 (`EVALUATION-RESULTS.md`), not Stage 7 | Updated in 8.1 |
| M-12 | `AdGuardHome.service` | `WorkingDirectory=/home/maheshwari` (written by `AdGuardHome -s install` run from the admin's home) | Installer writes `WorkingDirectory=/opt/AdGuardHome` |
| M-13 | `STEP-1-INSTALL-UBUNTU.md` §7-9 | Describes the hand-over with the Plan A wiring of M-1 | Same banner as M-1 |

## 3. Progress

- **Inventory (13:15-13:35)** - done; recorded above.
- **8.1 report (13:35-14:20)** - done.
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

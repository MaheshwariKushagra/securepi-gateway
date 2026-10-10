# Installing SecurePi Gateway

This guide builds a SecurePi Gateway on a blank machine and checks an existing one. The work is done by
one script, [`gateway/install.sh`](../gateway/install.sh). The guide covers what to do before running
it, what it installs, what to check afterwards, and how to undo it. It replaces the day-1 notes
`GATEWAY-SETUP-RUNBOOK.md` and `STEP-1-INSTALL-UBUNTU.md`, which describe a network plan the gateway
was never actually built with (`STAGE8-RECORD.md` M-1, M-13).

> **Verification status (10 October 2026).**
>
> | Check | Result |
> |---|---|
> | `bash -n` and `shellcheck` (all levels) | Clean. |
> | `sudo ./gateway/install.sh --check` on the live gateway | Read-only. Reported 8 differences and no package-version warnings: the 7 known from the inventory, plus a post-reboot gap in the DoH resolver set that this check found (`STAGE8-RECORD.md` M-15). Transcript in [§10](#10-evidence-the-check-run-on-the-live-gateway). |
> | `sudo ./gateway/install.sh` (apply) on the live gateway | **Not run.** The session's permission policy blocked it as a production deploy; it is waiting on the operator's decision. |
> | Fresh install on a blank machine or VM | **Not done yet**, so the step 8.2 exit criterion ("fresh-machine install from the docs alone") is still open. §12 describes how to run it in a VM. |
>
> The fresh-install path has therefore not been run end to end. Every command it runs was checked
> against the live gateway's files, versions and permissions, as listed in this guide.

---

## 1. What you get

| Part | Version installed | Where it comes from |
|---|---|---|
| Ubuntu Server | 24.04 LTS (built on 24.04.1, kernel 6.8.0-146-generic) | You install it (§3) |
| Access point | hostapd `2:2.10-21ubuntu0.4` on `ap0`, a virtual interface on the Wi-Fi radio | Ubuntu archive |
| DNS filter and DHCP | AdGuard Home `v0.107.79` in `/opt/AdGuardHome` | GitHub release, SHA-256 checked |
| IDS | Suricata `1:7.0.3-1build3`, ET Open rules through `suricata-update` `1.3.0-2` | Ubuntu archive; rules downloaded at install |
| Firewall and NAT | nftables `1.0.9-1build1`, ruleset from `gateway/nftables.conf` | Ubuntu archive plus the repo |
| Console, ingest, correlation engine | Python 3.12.3 with Ubuntu's `python3-fastapi 0.101.0-3`, `python3-starlette 0.31.1-1`, `python3-pydantic 1.10.14-1`, `python3-uvicorn 0.27.1-1`, `python3-jinja2 3.1.2-1ubuntu1.3` (full list: `gateway/requirements-console.txt`) | The repo's `app/` plus the Ubuntu archive |
| HTTPS inspection (Tier 2), **installed off** | mitmproxy `12.2.3` in the venv `/opt/securepi-dpi` (44 pinned packages: `dpi/requirements-dpi.txt`) | PyPI, exact pins |
| Privacy-scope canary | `dpi/privacy_canary.py`, a service in the same venv | The repo |

**The off state.** HTTPS inspection is installed off. The proxy runs and its CA is created. However,
the nftables set `ip nat enrolled` is empty and `/var/lib/securepi-dpi/device-sites.json` is `{}`, so
no traffic from any device is redirected to it or decrypted. It is switched on per device later, from
the console (§7.6).

---

## 2. Hardware and what to check first

| Requirement | The machine this was built on | How to check |
|---|---|---|
| x86_64 (`amd64`) or `arm64` | Dell Vostro 3501, i3-1005G1, 4 threads, `amd64` | `dpkg --print-architecture` |
| RAM of 4 GB or more | 3,683 MiB total; about 1.5 GiB used in steady state | `free -m` |
| Disk of 20 GB or more | 98 GB, 13 GB used after 4 weeks | `df -h /` |
| A Wi-Fi radio that can be a client **and** an access point at the same time | Intel, `wlp2s0` | Two checks below |
| A wired Ethernet port for management | Built-in RJ45, `enp1s0` | `ip -br link` |

The Wi-Fi check is the one that decides whether this hardware can work at all:

```bash
iw list | sed -n '/Supported interface modes/,/Band/p'      # must list "* AP"
iw list | sed -n '/valid interface combinations/,/^$/p'     # must allow "#{ managed } ... #{ AP ...}" together
```

On the Dell, the second command prints
`#{ managed } <= 2, #{ AP, mesh point, P2P-client, P2P-GO } <= 2, ... total <= 4, #channels <= 1`.
This means one station and one AP can run together, but only on a single channel. That is why the AP
follows whatever channel the uplink uses (`securepi-ap-follow-uplink`). A radio without `* AP` cannot
be used: the installer stops at step 1 with an error.

---

## 3. Install Ubuntu Server 24.04

1. Install **Ubuntu Server 24.04 LTS**, not Desktop. Use the default "Ubuntu Server" choice, not
   "minimized". Accept the default LVM layout on the whole disk.
2. At the profile screen, create your admin user (on the Dell this is `maheshwari`). The installer
   does not depend on the name.
3. **Tick "Install OpenSSH server".**
4. Skip the snaps.
5. Network during installation: leave it at the defaults. The installer configures the management
   link itself, and you can configure Wi-Fi then or later.
6. After the first boot, update and reboot once:
   ```bash
   sudo apt-get update && sudo apt-get -y full-upgrade && sudo reboot
   ```

The installer sets the timezone itself (`TIMEZONE`, default `Asia/Kolkata`). The console renders
times in the system timezone, and Ubuntu's default of `Etc/UTC` makes every timestamp in it wrong
(`gateway/REBOOT-SAFETY.md`).

---

## 4. The management link (development machine ↔ gateway)

The gateway is run headless over a cable. In the project, a MacBook shares its Internet connection over
a USB-C Ethernet adapter, which puts the Mac at `192.168.2.1` on that link. The gateway's end is a
static `192.168.2.5/24` with **no default route and no DNS**. The gateway's own Internet comes from the
Wi-Fi uplink, and a default route on this link would capture its traffic.

**On the Mac:** System Settings → General → Sharing → Internet Sharing. Share from your Wi-Fi to the USB
Ethernet adapter and turn it on. This gives the Mac `192.168.2.1` on that adapter.

**On the gateway:** nothing by hand. Step 4 of the installer writes `/etc/netplan/01-ethernet.yaml`
when no netplan file mentions `MGMT_IF` yet:

```yaml
network:
  version: 2
  ethernets:
    enp1s0:
      dhcp4: false
      addresses:
        - 192.168.2.5/24
```

If you need SSH before the installer has run, use the gateway's keyboard to set the address for this
boot only: `sudo ip addr add 192.168.2.5/24 dev enp1s0`.

**SSH key:** run this on the Mac.

```bash
ssh-keygen -t ed25519 -C securepi                 # only if you have no key yet
ssh-copy-id maheshwari@192.168.2.5
ssh maheshwari@192.168.2.5 'echo ok'              # expected: ok
```

The `Makefile` (`GATEWAY_HOST := maheshwari@192.168.2.5`), `session-start.sh` and `mac-tunnel.sh` all
assume this address and user. Edit those three files if yours differ.

---

## 5. Copy the repository to the gateway

From the repository root on your development machine:

```bash
rsync -az --exclude '__pycache__' --exclude '*.pyc' --exclude '.DS_Store' \
    app gateway dpi tools maheshwari@192.168.2.5:securepi-install/
```

The installer needs `app/`, `gateway/` and `dpi/`, plus `tools/run_report.py` for the evaluation tools.
A `git clone` on the gateway works just as well. With a clone, the preflight line also prints the
commit hash.

---

## 6. Run the installer

```bash
ssh -t maheshwari@192.168.2.5
cd ~/securepi-install
sudo ./gateway/install.sh --check      # 1. see what it would do; changes nothing
sudo ./gateway/install.sh              # 2. do it
sudo ./gateway/install.sh --check      # 3. expected now: "0 change(s) would be made"
```

Use `ssh -t` (a terminal). On a blank machine the installer asks for two secrets at hidden prompts. It
never takes them as arguments, so they stay out of shell history and process listings:

| Prompt | When | Where it is stored |
|---|---|---|
| `Upstream Wi-Fi network name for wlp2s0:`, then `Wi-Fi password for "<name>":` | No netplan file mentions `WAN_IF` yet | `/etc/netplan/99-wifi.yaml`, `600 root:root`. Add more networks later with `sudo securepi-add-uplink "Name"`. |
| `Passphrase for the SecurePi-Test access point (8-63 characters):` | `/etc/hostapd/hostapd.conf` does not exist | `/etc/hostapd/hostapd.conf`, `600 root:root` |

You can preset the network name with `UPLINK_SSID` and the AP passphrase with `AP_PASSPHRASE`, for
example `sudo AP_PASSPHRASE='...' ./gateway/install.sh`. The prompt is the safer choice.

**Run it from the local console or over the management link it configures.** Step 4 runs
`netplan apply` when it has just written a netplan file, which can drop links for a few seconds.

### 6.1 Settings

All settings are environment variables. The defaults reproduce the Dell.

| Variable | Default | Meaning |
|---|---|---|
| `WAN_IF` | `wlp2s0` | Wi-Fi interface for the uplink. Substituted for `wlp2s0` in `nftables.conf`, `securepi`, `securepi-ap0-up`, `securepi-ap0.service`, `securepi-ap-follow-uplink(.service)`, `securepi-add-uplink` and `chaos.py`. |
| `MGMT_IF` | `enp1s0` | Wired management interface. Substituted for `enp1s0` in the same files. |
| `MGMT_ADDR` | `192.168.2.5/24` | Static address on `MGMT_IF`. Used only when no netplan file configures `MGMT_IF`. |
| `AP_SSID` | `SecurePi-Test` | AP name. Used only when `hostapd.conf` is first written. |
| `AP_COUNTRY` | `IN` | `country_code` for hostapd (regulatory domain). Set your own. |
| `AP_CHANNEL` | `6` | Initial channel. `securepi-ap-follow-uplink` moves it to the uplink's channel. |
| `AP_PASSPHRASE` | (prompt) | WPA2 passphrase for the AP. |
| `UPLINK_SSID` | (prompt) | Upstream Wi-Fi name. |
| `TIMEZONE` | `Asia/Kolkata` | System timezone. |
| `INSTALL_DPI` | `yes` | Install HTTPS inspection and the canary, in the off state. |
| `INSTALL_EVAL_TOOLS` | `yes` | Install `/opt/securepi-eval` and the attack-tool packages `nmap hydra iperf3 openssh-server`. |
| `ENABLE_RUN_MONITOR` | `no` | Enable `securepi-run-monitor.service`, which records evaluation runs. |
| `TEST_WITHOUT_WIFI` | `no` | VM testing only (§12): `ap0` becomes a dummy interface, and the hostapd and uplink steps are skipped. |

### 6.2 What each step does

The installer prints `==> N/14` for each step. In apply mode it prints a `change:` line for every change;
in check mode it prints `would:` instead. `WARNING:` lines are counted and repeated in the summary.

| Step | What it checks and, only if needed, changes |
|---|---|
| 1 preflight | Requires root, Ubuntu 24.04 (warns otherwise), `amd64`/`arm64`, the repo files, `MGMT_IF` and `WAN_IF` present, and AP mode in `iw list`. It changes nothing. |
| 2 host | Sets the timezone. Masks `sleep`, `suspend`, `hibernate` and `hybrid-sleep` targets. Installs `/etc/systemd/logind.conf.d/99-securepi.conf` (lid, power and idle actions all `ignore`) and `/etc/sysctl.d/99-securepi.conf` (`net.ipv4.ip_forward=1`), then runs `sysctl --system` if forwarding is off. |
| 3 packages | `apt-get install` of whatever is missing from: `suricata suricata-update hostapd iw wpasupplicant nftables conntrack python3 python3-fastapi python3-starlette python3-pydantic python3-uvicorn python3-jinja2 python3-multipart python3-yaml python3-venv bind9-dnsutils curl jq rsync patch openssl apache2-utils ethtool tcpdump iproute2`, plus `nmap hydra iperf3 openssh-server` with the eval tools. It then compares eight key packages with the versions in §1 and warns about any difference. |
| 4 network | Writes the management and uplink netplan files only when absent, then `netplan generate && netplan apply`. Installs `securepi-ap0-up` and `securepi-ap0.service`. Writes `hostapd.conf` from `gateway/hostapd.conf` (SSID, country and channel substituted, your passphrase appended) only when absent; if it exists, it only checks `ap_isolate=1` and `interface=ap0` and sets mode 600. Unmasks hostapd, installs the uplink-follow and add-uplink helpers, and enables and starts `securepi-ap0`, `hostapd` and `securepi-ap-follow-uplink`. |
| 5 firewall | Renders `gateway/nftables.conf` and validates it with `nft -c`. Only if it differs from `/etc/nftables.conf`: installs it (`644`) and loads it with `nft -f`. Enables `nftables`. |
| 6 users | Runs `gateway/setup-privilege-separation.sh` if any of these is missing or different: group `securepi`, user `securepi-web`, the helper and sudoers file, or `2770 root:securepi` on `/var/lib/securepi`, `/var/lib/securepi-dpi` and `/etc/securepi`. |
| 7 code | `rsync -rlpc` of `app/` and `dpi/adfilter_rules.py` to `/opt/securepi`, the same copy `make deploy` makes, without `--delete`. Installs `setup-test-harness.sh`, `refresh-doh-set.sh`, the CLI tools and the `securepi-db` symlink. |
| 8 TLS, passwords | Runs `gateway/generate-console-tls.sh` if `/opt/securepi-tls/ca.crt` is absent. Creates a random 24-character console password, hashed with the console's own PBKDF2-SHA256 (`app/session_auth.py`) and **printed once at the end**. Creates a random 24-character DNS-filter admin password in `/etc/securepi/dns-password`. Existing password files are never touched. |
| 9 DNS filter | Downloads `AdGuardHome_linux_<arch>.tar.gz` `v0.107.79` and checks its SHA-256 (below) unless that exact version is already installed. Writes `AdGuardHome.yaml` from `gateway/adguard/AdGuardHome.yaml.template`, with the bcrypt hash of the DNS password, **only if absent**. Installs the unit and the `securepi-wait-for-ap0.conf` drop-in, then enables and starts it. |
| 10 IDS | Applies `gateway/suricata-securepi.patch` to `/etc/suricata/suricata.yaml` (it detects an already-applied patch). Installs the test-harness unit and the `suricata.service.d/override.conf` drop-in. Runs `suricata-update` if there is no rules file. Runs `gateway/install-ids-logrotate.sh` if the rotation is not installed. Enables and starts Suricata. |
| 11 database | Creates `/var/lib/securepi/securepi.db` from `schema.sql` (`ingest.open_db()`) if it is absent, as `664 root:securepi`. |
| 12 services | Installs and enables `securepi-ingest`, `securepi-engine`, `securepi-web`, `securepi-static`, both refresh timers and, on a laptop with `intel_backlight`, `securepi-backlight-off`. Restarts ingest, engine and web if step 7 changed code. Refreshes the DoH resolver set if it holds fewer than 500 entries (only the 14-address seed from `nftables.conf`), and runs the threat-intel refresh if `ioc-domains.txt` is missing. |
| 13 HTTPS inspection | Runs `dpi/deploy-dpi.sh` if anything differs: the venv's `pip freeze` against `dpi/requirements-dpi.txt`, the addon, the rules module, the gate script, either unit, a missing site map, or `/var/log/securepi` not `root:root`. Runs `dpi/deploy-privacy-canary.sh` if the canary or its unit differs. |
| 14 eval tools | Installs `battery.py chaos.py collect_run.sh run_monitor.py throughput_sweep.py dns_ab.py dash_latency.py` (from `gateway/`) and `run_report.py` (from `tools/`) into `/opt/securepi-eval`, plus the run-monitor unit. It enables that unit only if `ENABLE_RUN_MONITOR=yes`. |

AdGuard Home archive checksums, taken from the release's `checksums.txt`. The amd64 binary inside the
archive matches the Dell's binary byte for byte (`7e247573e63ce771a5925d16ca4ca9344e6e888673244289dc302f0fdfdfbf4e`).

```
c48f4a43000665484c5ec28177de11a004759b620dae8f77b2aabefc9ef3687f  AdGuardHome_linux_amd64.tar.gz
3f7893c18e8aaadc456d0452839190561c306ca95175a2254958be80a769c1ae  AdGuardHome_linux_arm64.tar.gz
```

### 6.3 Expected end of a successful run

```
================================================================
 Done: <N> change(s) made, 0 warning(s).

 Service check (every always-on service in /opt/securepi/services.list):
   all active
   DNS filter blocks doubleclick.net: 0.0.0.0
   console: 200 (200 expected)

 Console password for user 'securepi' (shown ONCE - save it now,
 then change it on the console's Settings page):
   <24 characters>

 Next: docs/INSTALL.md, 'After installing'.
================================================================
```

If the summary prints `NOT active: <unit>`, start with `journalctl -u <unit> -n 40`. After the first
start, `AdGuardHome` needs a minute to download its five enabled filter lists. Until then the
`doubleclick.net` line can be empty; re-check with the command in §7.

---

## 7. After installing

### 7.1 Verify

Run on the gateway. The expected output is on the right.

| Command | Expected |
|---|---|
| `sudo securepi status` | `-> all services active`; `Tier 1 (DNS filtering): active`; `Tier 2 (HTTPS inspection): OFF`; test harness `present` |
| `sudo ./gateway/install.sh --check` | `0 change(s) would be made, 0 warning(s).` |
| `dig +short @10.10.0.1 doubleclick.net` | `0.0.0.0` |
| `dig +short @10.10.0.1 example.com` | one or more IPv4 addresses (`172.66.147.243`, `104.20.23.154` on 10 October 2026) |
| `curl -sk -o /dev/null -w '%{http_code}\n' https://10.10.0.1:8000/login` | `200` |
| `curl -s -o /dev/null -w '%{http_code}\n' --max-time 3 http://10.10.0.1:8000/login` | `000` (HTTPS only: plain HTTP gets no answer) |
| `sudo nft -j list set inet filter doh_resolvers \| jq '.nftables[1].set.elem \| length'` | about 1,400 (1,436 on 10 October 2026). `14` means only the static seed from `nftables.conf` is loaded: after a reboot, until the next daily refresh (M-15). Fix it now with `sudo systemctl start securepi-doh-refresh.service`. |
| `sudo nft list set ip nat enrolled` | a set with **no** `elements =` line: the off state |
| `sudo cat /var/lib/securepi-dpi/device-sites.json` | `{}` |
| `systemctl is-active securepi-dpi securepi-privacy-canary securepi-ca-server` | `active` three times |
| `journalctl -u securepi-privacy-canary -n 1 -o cat` | `securepi-privacy-canary: ok - passthrough and decrypt decisions correct for every site module` |
| `sudo suricata --dump-config \| grep -E '^af-packet\.[0-9]+\.interface'` | `af-packet.0.interface = veth-atk`, `af-packet.1.interface = ap0`, `af-packet.2.interface = default` |
| `ip -br link show br-test` | `br-test ... UP` |
| `sudo ls /var/lib/suricata/rules/suricata.rules && sudo grep -c '^alert' /var/lib/suricata/rules/suricata.rules` | about 50,000 or more (the Dell had 52,688 on 12 September 2026) |

Then join `SecurePi-Test` from a phone. It should get a `10.10.0.50`-`10.10.0.150` address and appear on
the console's device list within one engine cycle (15 s).

### 7.2 Sign in to the console

- **From a device on SecurePi-Test:** `https://10.10.0.1:8000`, user `securepi`, with the password
  printed at the end of the run.
- **From the Mac:** `./mac-tunnel.sh start`, then open `https://localhost:8000`.

To trust the console's own CA on the Mac once, so there is no certificate warning:

```bash
scp maheshwari@192.168.2.5:/opt/securepi-tls/ca.crt /tmp/securepi-console-ca.crt
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/securepi-console-ca.crt
```

Change the password on the console's Settings page. If you missed the printed password, reset it as
described in README §3 ("Logging in").

### 7.3 The DNS filter's own admin page

It listens only on `127.0.0.1:3000`. Reach it through a tunnel:

```bash
ssh -L 3000:127.0.0.1:3000 maheshwari@192.168.2.5     # then http://localhost:3000
```

The user is `securepi`. The password is in `/etc/securepi/dns-password` (`sudo cat` it). The console
uses the same account through `app/adguard.py`, so if you change the password, change it in **both**
places.

### 7.4 Later code updates

From the development machine: `make deploy`. It runs the same rsync as step 7, then restarts ingest,
engine and web. Re-run `sudo ./gateway/install.sh` after changing anything under `gateway/`
or `dpi/`. It changes only what differs.

### 7.5 IDS rules

The installer downloads the rules once. The project kept the 12 September 2026 rules for the whole
evaluation, on purpose (`STAGE8-RECORD.md` M-6). To update them: `sudo suricata-update && sudo systemctl
restart suricata`. Detection results may then differ from `REPORT.md` §6.

### 7.6 Switching HTTPS inspection on for one device

Use the console: open the device's page, then "HTTPS ad removal". This enrols that one device for 24
hours with YouTube only, unless other sites are ticked. The device must have the inspection CA
installed first, from `http://10.10.0.1:8081/securepi-ca.crt`; the steps are in `REPORT-adblocking.md`.
The command-line alternative is `sudo securepi enroll 10.10.0.50` and `sudo securepi unenroll 10.10.0.50`.

---

## 8. What the installer puts where

| Path | Mode, owner | Source |
|---|---|---|
| `/etc/systemd/logind.conf.d/99-securepi.conf` | 644 root:root | `gateway/logind-securepi.conf` |
| `/etc/sysctl.d/99-securepi.conf` | 644 root:root | `gateway/sysctl-securepi.conf` |
| `/etc/netplan/01-ethernet.yaml` (only if `MGMT_IF` is unconfigured) | 600 root:root | written by step 4 |
| `/etc/netplan/99-wifi.yaml` (only if `WAN_IF` is unconfigured) | 600 root:root | written by step 4 from the prompts |
| `/usr/local/sbin/securepi-ap0-up` | 755 root:root | `gateway/securepi-ap0-up` (rendered) |
| `/etc/systemd/system/securepi-ap0.service` | 644 root:root | `gateway/systemd/securepi-ap0.service` (rendered) |
| `/etc/hostapd/hostapd.conf` (only if absent) | 600 root:root | `gateway/hostapd.conf`, substituted |
| `/usr/local/sbin/securepi-ap-follow-uplink`, `/etc/systemd/system/securepi-ap-follow-uplink.service` | 755 / 644 root:root | `gateway/` (rendered) |
| `/usr/local/sbin/securepi-add-uplink` | 755 root:root | `gateway/securepi-add-uplink` (rendered) |
| `/etc/nftables.conf` | 644 root:root | `gateway/nftables.conf` (rendered) |
| group `securepi`, system user `securepi-web`, `/usr/local/sbin/securepi-web-helper` (700), `/etc/sudoers.d/securepi-web` (440) | | `gateway/setup-privilege-separation.sh` |
| `/var/lib/securepi`, `/var/lib/securepi-dpi`, `/etc/securepi` | 2770 root:securepi | the same script |
| `/opt/securepi/` (code, templates, static, `schema.sql`, `services.list`) | 755/644 root:root | `app/`, `dpi/adfilter_rules.py` |
| `/opt/securepi/setup-test-harness.sh`, `/opt/securepi/refresh-doh-set.sh` | 755 root:root | `gateway/` |
| `/usr/local/bin/securepi` (rendered), `battery`, `sni-capture`; `securepi-db` → `/opt/securepi/status.py` | 755 root:root | `gateway/` |
| `/opt/securepi-tls/` `ca.key` 600, `ca.crt` 644, `console.key` 640 root:securepi, `console.crt` 644 | dir 755 | `gateway/generate-console-tls.sh` |
| `/etc/securepi/console-password` (PBKDF2 hash), `/etc/securepi/dns-password` (plaintext, for the API) | 660 root:securepi | step 8 |
| `/opt/AdGuardHome/AdGuardHome` | 755 root:root, dir 700 | release `v0.107.79` |
| `/opt/AdGuardHome/AdGuardHome.yaml` (only if absent) | 600 root:root | `gateway/adguard/AdGuardHome.yaml.template` |
| `/etc/systemd/system/AdGuardHome.service`, `AdGuardHome.service.d/securepi-wait-for-ap0.conf` | 644 root:root | `gateway/systemd/`, `gateway/AdGuardHome.service.d/` |
| `/etc/suricata/suricata.yaml` (patched in place) | 644 root:root | `gateway/suricata-securepi.patch` |
| `/etc/systemd/system/securepi-test-harness.service`, `suricata.service.d/override.conf` | 644 root:root | `gateway/systemd/` |
| `/var/lib/suricata/rules/suricata.rules` (only if absent) | 644 root:root | `suricata-update` |
| `/etc/securepi/logrotate-suricata.conf`, `securepi-ids-logrotate.{service,timer}`; `/etc/logrotate.d/suricata` diverted to `/etc/securepi/logrotate-suricata.packaged` | 644 root:root | `gateway/install-ids-logrotate.sh` |
| `/var/lib/securepi/securepi.db` (only if absent) | 664 root:securepi | `app/schema.sql` |
| `/etc/systemd/system/securepi-{ingest,engine,web,static,doh-refresh,intel-refresh,backlight-off}.*` | 644 root:root | `gateway/systemd/`, `gateway/securepi-web.service` |
| `/opt/securepi-dpi/` (venv, `securepi_adfilter.py`, `adfilter_rules.py`, `dpi-gate.sh`, `privacy_canary.py`, `ca/`) | 755 root:root; `ca/mitmproxy-ca.pem` 600 | `dpi/deploy-dpi.sh`, `dpi/deploy-privacy-canary.sh` |
| `/var/lib/securepi-dpi/adfilter-rules.json` (only if absent), `device-sites.json` = `{}` (only if absent) | 664 root:securepi | `dpi/` |
| `/var/log/securepi/` | 755 root:root | `dpi/deploy-dpi.sh` |
| `/var/www-ca/securepi-ca.crt` | 644 root:root | the proxy's public CA certificate |
| `/etc/systemd/system/securepi-{dpi,ca-server,privacy-canary}.service` | 644 root:root | `dpi/` |
| `/opt/securepi-eval/*`, `/etc/systemd/system/securepi-run-monitor.service` | see §6.2 | `gateway/`, `tools/run_report.py` |

**What the installer never does.**

- It never disables, stops or removes a unit, package or file.
- It never overwrites the following once they exist: `hostapd.conf`, the netplan files,
  `AdGuardHome.yaml`, either password file, the console TLS CA, the inspection CA,
  `adfilter-rules.json`, `device-sites.json`, the database, or the IDS rules file.
- Every file it replaces is kept first as `<file>.bak-install-<YYYYmmdd-HHMMSS>`.
- It does not install `adblock==0.6.0` for any reason. That package is in `requirements-dpi.txt` only
  because it is in the live venv; nothing imports it (`STAGE8-RECORD.md` M-7).

---

## 9. Pinned versions

| File | Pins | Install with |
|---|---|---|
| `dpi/requirements-dpi.txt` | The proxy venv: the full `pip freeze` of `/opt/securepi-dpi` (44 packages: `mitmproxy==12.2.3`, `mitmproxy_rs==0.12.11`, `cryptography`, ...) | `dpi/deploy-dpi.sh` (`pip install -r`) |
| `gateway/requirements-console.txt` | The console, ingest and engine dependencies **as Ubuntu packages** (`python3-fastapi 0.101.0-3` ...). It records versions only. | `apt`, step 3. **Do not `pip install` it on the gateway.** PyPI's fastapi 0.101.0 requires `starlette<0.28`, which conflicts with Ubuntu's 0.31.1. |
| `docs/demo/requirements.txt` | The same versions, for the offline demo in a venv on another machine | `pip install --no-deps -r` (README §2) |
| `gateway/install.sh` `AGH_VERSION`, `AGH_SHA256_*` | AdGuard Home `v0.107.79` | step 9 |

---

## 10. Evidence: the check run on the live gateway

This ran on 10 October 2026 at 13:57 IST on the Dell (a first run at 13:51 had found the same 7, before the DoH check was added), from a copy of the working tree in
`~/securepi-install-check`, as `sudo ./gateway/install.sh --check`. Exit code 0. Nothing was changed.
Steps that reported nothing are shortened here to their heading.

```
==> 1/14  preflight
   repository /home/maheshwari/securepi-install-check (not a git checkout), mode check, Ubuntu 24.04.1 LTS amd64
   WAN_IF=wlp2s0 MGMT_IF=enp1s0 MGMT_ADDR=192.168.2.5/24 AP_SSID=SecurePi-Test TIMEZONE=Asia/Kolkata TEST_WITHOUT_WIFI=no
==> 2/14  host settings: timezone, no sleep, lid ignored, IPv4 forwarding
==> 3/14  packages from the Ubuntu archive
==> 4/14  network: management link, Wi-Fi uplink, access point
   would: chmod 600 /etc/hostapd/hostapd.conf (it holds the Wi-Fi passphrase; is 644)
==> 5/14  firewall (/etc/nftables.conf)
==> 6/14  service user, data directories, privileged helper (setup-privilege-separation.sh)
==> 7/14  console, ingest and engine code (/opt/securepi), command-line tools
   would: replace /opt/securepi/setup-test-harness.sh (old copy kept as ....bak-install-20261010-135741)
==> 8/14  console TLS certificate and passwords
==> 9/14  DNS filter and DHCP: AdGuard Home v0.107.79
   would: replace /etc/systemd/system/AdGuardHome.service (old copy kept as ...)
   would: replace /etc/systemd/system/AdGuardHome.service.d/securepi-wait-for-ap0.conf (old copy kept as ...)
==> 10/14  IDS: Suricata configuration, rules, log rotation, test harness
==> 11/14  database (/var/lib/securepi/securepi.db)
==> 12/14  core services and timers
   would: refresh the DoH resolver set (it has 14 entries, only the static seed)
==> 13/14  HTTPS inspection, installed in its off state (dpi/)
   /var/log/securepi is not root:root
   would: install or update the proxy (dpi/deploy-dpi.sh; nothing is enrolled, so nothing is decrypted)
==> 14/14  evaluation tools (/opt/securepi-eval)
   would: install /opt/securepi-eval/dns_ab.py
   would: install /opt/securepi-eval/dash_latency.py
   securepi-run-monitor is enabled (left as it is; the installer never disables anything)
 CHECK ONLY - nothing was changed.
 8 change(s) would be made, 0 warning(s).
```

Seven are known, intended differences, and one is a gap the run found (`STAGE8-RECORD.md` §2):

| Reported | Why | Record |
|---|---|---|
| `hostapd.conf` 644 → 600 | The file holds the AP passphrase; 644 lets every local user read it. | M-5 |
| `setup-test-harness.sh` replaced | The live copy predates a comment-only wording change ("Suricata" → "the IDS"). The code is identical. | M-4 |
| `AdGuardHome.service` replaced | `WorkingDirectory=/home/maheshwari` → `/opt/AdGuardHome`. AdGuard finds its data next to its binary, so this changes nothing at run time; it only removes the home-directory dependency. | M-12 |
| `securepi-wait-for-ap0.conf` replaced | Comment-only wording ("AdGuard Home" → "the DNS filter"). | M-4 |
| `deploy-dpi.sh` re-run | `/var/log/securepi` is `maheshwari:maheshwari`; it becomes `root:root 755`. Its two files are already `root:root 644`, and the console (`securepi-web`) only reads them. The re-run also restarts the proxy, which has no enrolled device. | M-8 |
| `dns_ab.py`, `dash_latency.py` added | The evaluation reproduction commands in `REPORT.md` §10 had them copied to `/tmp` by hand. | REPORT §10 |
| DoH set refresh | The gateway rebooted at 12:14. `nftables.service` loaded the 14 seed addresses, and the daily timer had already run at 00:28, so it will not refill the set until about 00:21 tomorrow. DoH-IP blocking covers 14 addresses instead of 1,436 until then. | **M-15 (new)** |

Also confirmed by the same run: all 30 packages are installed and the eight key packages match the
versions in §1; the rendered `nftables.conf` is identical to the live `/etc/nftables.conf` (including the
7B DoQ rule); `suricata-securepi.patch` is detected as already applied; the console, ingest and engine
code in `/opt/securepi` is identical to `app/`; the AdGuard binary is `v0.107.79`; the venv's
`pip freeze` equals `dpi/requirements-dpi.txt`; and every TLS, password, database and rule file
already exists, so none would be created.

---

## 11. Rollback

**One change.** Every replaced file has a dated copy next to it:

```bash
sudo find /etc /opt /usr/local -name '*.bak-install-*' 2>/dev/null      # list them
sudo cp -p /etc/systemd/system/AdGuardHome.service.bak-install-<timestamp> \
          /etc/systemd/system/AdGuardHome.service                       # example: restore one
sudo systemctl daemon-reload && sudo systemctl restart AdGuardHome
```

| Change | Undo |
|---|---|
| Suricata patch | `sudo patch -R /etc/suricata/suricata.yaml < gateway/suricata-securepi.patch && sudo systemctl restart suricata`, or restore `suricata.yaml.bak-install-*`. |
| `hostapd.conf` mode | `sudo chmod 644 /etc/hostapd/hostapd.conf` (not recommended). |
| `/var/log/securepi` owner | `sudo chown maheshwari:maheshwari /var/log/securepi`. Nothing depends on this owner. |
| nftables ruleset | Restore `/etc/nftables.conf.bak-install-*`, then `sudo nft -f /etc/nftables.conf`. |
| IDS log rotation | `sudo systemctl disable --now securepi-ids-logrotate.timer && sudo rm /etc/systemd/system/securepi-ids-logrotate.* && sudo dpkg-divert --local --rename --remove /etc/logrotate.d/suricata`. |
| Netplan written by the installer | Remove `/etc/netplan/01-ethernet.yaml` or `99-wifi.yaml`, then `sudo netplan try`, which reverts after 120 s unless confirmed. |
| A unit | `sudo systemctl disable --now <unit>`. |
| Masked sleep targets | `sudo systemctl unmask sleep.target suspend.target hibernate.target hybrid-sleep.target`. |

**Removing everything.** These are **destructive**: they delete the database, CAs and credentials. They
are documented here, not run by any script. Use them only on a machine you are giving up as a gateway.
The CA and enrolment clean-up for a paused project is in [`docs/CLOSE-OUT.md`](CLOSE-OUT.md).

```bash
sudo systemctl disable --now securepi-ingest securepi-engine securepi-web securepi-static \
    securepi-doh-refresh.timer securepi-intel-refresh.timer securepi-dpi securepi-privacy-canary \
    securepi-ca-server securepi-test-harness securepi-run-monitor securepi-ids-logrotate.timer \
    securepi-ap-follow-uplink securepi-backlight-off AdGuardHome hostapd securepi-ap0
sudo rm -rf /opt/securepi /opt/securepi-dpi /opt/securepi-eval /opt/securepi-tls /opt/AdGuardHome \
    /var/lib/securepi /var/lib/securepi-dpi /etc/securepi /var/log/securepi /var/www-ca
sudo rm -f /etc/systemd/system/securepi-* /etc/systemd/system/AdGuardHome.service \
    /usr/local/bin/{securepi,battery,sni-capture,securepi-db} \
    /usr/local/sbin/securepi-{ap0-up,ap-follow-uplink,add-uplink,web-helper} /etc/sudoers.d/securepi-web
sudo rm -rf /etc/systemd/system/AdGuardHome.service.d /etc/systemd/system/suricata.service.d
sudo systemctl daemon-reload
sudo userdel securepi-web && sudo groupdel securepi
```

---

## 12. Testing the installer in a VM (no Wi-Fi)

A VM has no radio that can be an AP, so `TEST_WITHOUT_WIFI=yes` replaces `ap0` with a dummy interface at
`10.10.0.1/24` and skips hostapd and the uplink. Everything else installs and runs as on the gateway:
DNS filter, DHCP server, IDS, firewall, console, engine, proxy and canary. On a Mac with Apple
silicon, using Lima (`brew install lima`):

```bash
limactl start --name securepi-test --cpus 2 --memory 3 --disk 20 template://ubuntu-24.04
limactl copy -r app gateway dpi tools securepi-test:/tmp/securepi-install/     # from the repo root
limactl shell securepi-test -- sudo env TEST_WITHOUT_WIFI=yes WAN_IF=eth0 MGMT_IF=eth0 \
    /tmp/securepi-install/gateway/install.sh
limactl shell securepi-test -- sudo env TEST_WITHOUT_WIFI=yes WAN_IF=eth0 MGMT_IF=eth0 \
    /tmp/securepi-install/gateway/install.sh --check                    # expected: 0 changes
limactl delete --force securepi-test && brew uninstall lima              # clean up
```

**Not yet run.** These commands follow Lima 2.x's documented CLI and have not been executed. With
`WAN_IF=MGMT_IF=eth0`, the rendered input chain accepts SSH on `eth0` (`ssh-management`), which is
how `limactl shell` reaches the VM.

The dummy `ap0` does not survive a VM reboot. The summary's service check skips `hostapd`,
`securepi-ap0` and `securepi-ap-follow-uplink` in this mode.

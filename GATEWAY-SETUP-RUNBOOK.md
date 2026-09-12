# Gateway Setup Runbook — Dell Vostro 3501

Goal: a headless Linux gateway I can operate fully over a dedicated wired link,
with the MacBook as the development machine.

---

## 0. The one risk that decides the topology

The **Dell Vostro 3501 ships with different Wi-Fi cards depending on configuration.**
Common options are the Intel Wireless-AC 9462 / AX201 and the **Realtek RTL8821CE**.

This matters more than anything else in this document:

| Chipset | Linux support | `hostapd` AP mode |
|---|---|---|
| Intel 9462 / AX201 (`iwlwifi`) | Excellent, in-tree | **Yes** |
| Realtek RTL8821CE | Poor — often needs an out-of-tree DKMS driver | **No** |

**Run this before planning anything else:**

```
lspci -nnk | grep -iA3 'network\|wireless'
iw list | grep -A10 'Supported interface modes'
```

If `AP` appears in the supported modes, use Plan A. If not, use Plan B. Do not
attempt to make a Realtek card do AP mode — people lose weeks to this.

Also check while you are there:

```
free -h          # 8 GB strongly preferred; 4 GB works with a reduced Suricata ruleset
lscpu | head -20 # i3-1005G1 (2c/4t) is the weakest likely config, still adequate
ip link          # confirm the built-in RJ45 port is present and named
```

---

## 1. Interface allocation

You have three interfaces on the Dell: built-in RJ45, one USB Ethernet adapter,
and Wi-Fi. Your second USB adapter goes on the MacBook, which has no RJ45 port.

### Plan A — Wi-Fi supports AP mode

| Interface | Role | Addressing |
|---|---|---|
| Built-in RJ45 | **WAN** — to existing router | DHCP client |
| USB Ethernet | **Management** — Cat7 direct to MacBook | Static `192.168.100.1/24` |
| Wi-Fi (`hostapd`) | **Project LAN** — test devices join | Static `10.10.0.1/24`, serves DHCP |

This is the ideal layout: out-of-band management, wireless test devices, nothing bought.

### Plan B — Wi-Fi cannot do AP mode

| Interface | Role | Addressing |
|---|---|---|
| Built-in RJ45 | **WAN** — to existing router | DHCP client |
| USB Ethernet | **Project LAN** — to a switch, plus an old router used as a dumb AP | Static `10.10.0.1/24`, serves DHCP |
| Wi-Fi | Unused | — |

Management then happens over the project LAN: the MacBook plugs its adapter into the
same switch and becomes a monitored device. You lose the out-of-band property, so
**take a config snapshot before every network change** (see §6).

To recover out-of-band management under Plan B, a third USB Ethernet adapter (~₹800
from any local shop) restores the Plan A layout. Worth it if you can get one same-day.

---

## 2. Operating system

**Ubuntu Server 24.04 LTS.** This is a change from the earlier Debian recommendation,
made specifically for this hardware: Ubuntu carries broader out-of-box enablement for
Dell laptops and Realtek wireless, and if you land on the RTL8821CE the DKMS path is
far better documented there. Ship-stopping driver problems are the top risk in a
15-day schedule, so optimise against them.

- Choose **Server**, not Desktop. This box is an appliance; a GUI wastes RAM you need.
- **Tick "Install OpenSSH server"** during installation. Without it you are typing on
  the Dell's keyboard to fix it.
- Suricata 7.x is in the 24.04 archive. The OISF PPA has newer builds if needed.
- If the Wi-Fi card needs a kernel newer than 24.04's, use Ubuntu Server 26.04 LTS.

---

## 3. Management link — wiring and addressing

Cat7 is fine (Cat5e would be too; auto-MDI-X means no crossover cable needed).
Both ends need static addresses — there is no DHCP server on a point-to-point link,
and link-local autoconfiguration is unreliable for this.

**On the Dell** — `/etc/netplan/01-securepi.yaml`. Identify the USB adapter name first
with `ip link` (it will look like `enx00e04c680001`):

```yaml
network:
  version: 2
  ethernets:
    enp1s0:                       # built-in RJ45 -> WAN
      dhcp4: true
    enx00e04c680001:              # USB adapter -> management
      dhcp4: false
      addresses: [192.168.100.1/24]
```

Apply with `sudo netplan apply`. Use `sudo netplan try` for risky changes — it reverts
automatically after 120 seconds unless confirmed.

**On the MacBook** — System Settings → Network → the USB adapter → Details → TCP/IP →
Configure IPv4: Manually → IP `192.168.100.2`, mask `255.255.255.0`, **no router, no DNS**.
Leaving the router field blank is important: it keeps your default route on Wi-Fi so the
Mac still reaches the internet normally.

Verify: `ping 192.168.100.1` from the Mac.

---

## 4. Full access setup

Four steps. Skipping any of them will make my access slow or broken.

**1. SSH key authentication**
```
ssh-keygen -t ed25519 -C "securepi"        # on the Mac, if you have no key
ssh-copy-id user@192.168.100.1
```
Every command I run is a separate non-interactive SSH session. A password prompt on
each one is crippling, and I cannot answer an interactive prompt.

**2. Passwordless sudo** — on the Dell:
```
echo "$USER ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/securepi
sudo chmod 440 /etc/sudoers.d/securepi
sudo visudo -c                              # validate before logging out
```
Nearly all gateway work is privileged: `nftables`, `systemctl`, Suricata, `hostapd`,
netplan. Without this, those commands hang forever waiting on a prompt.

*This grants effective root over SSH. That is a reasonable trade for a wiped, dedicated
project machine — it is not something to replicate on a laptop holding personal data.*

**3. SSH config alias** — `~/.ssh/config` on the Mac:
```
Host securepi
    HostName 192.168.100.1
    User <your-username>
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 30
    ServerAliveCountMax 6
    ControlMaster auto
    ControlPath ~/.ssh/cm-%r@%h:%p
    ControlPersist 10m
```
`ControlMaster` reuses one TCP connection across commands, which makes a sequence of
calls noticeably faster. Then `ssh securepi <command>` is all I need.

**4. Stop the laptop from sleeping** — it is a server now:
```
sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
```
And in `/etc/systemd/logind.conf`, set `HandleLidSwitch=ignore` and
`HandleLidSwitchExternalPower=ignore`, then `sudo systemctl restart systemd-logind`.
You can now close the lid without killing the gateway.

---

## 5. Deploy loop

Repo lives on the Mac; the Dell only runs code.

```
# Makefile on the Mac
deploy:
	rsync -az --delete --exclude '.git' --exclude '__pycache__' ./ securepi:~/securepi/
	ssh securepi 'sudo systemctl restart securepi'

logs:
	ssh securepi 'journalctl -u securepi -f'
```

Never edit files directly on the Dell — `rsync --delete` will erase them.

Reach the console from the Mac browser at `http://192.168.100.1:8000` over the
management link, which works even when the project LAN is broken.

---

## 6. Lockout insurance

Before every network configuration change:

```
sudo cp /etc/netplan/01-securepi.yaml /etc/netplan/01-securepi.yaml.bak
sudo nft list ruleset > ~/nft-lastgood.rules
```

Recovery order if you lose access: (1) the management link, which survives project-LAN
mistakes; (2) `netplan try`'s 120-second auto-revert; (3) the Dell's own keyboard.
Keep the third option genuinely available — do not deploy the machine somewhere awkward.

---

## 7. Day-1 sequence

1. Check the Wi-Fi chipset (§0) → decide Plan A or Plan B
2. Install Ubuntu Server 24.04 LTS, OpenSSH enabled
3. Configure the management link both ends (§3), verify with `ping`
4. SSH keys, NOPASSWD sudo, SSH config, disable sleep (§4)
5. Confirm I can run `ssh securepi 'sudo nft list ruleset'` from the Mac
6. Only then start on WAN/NAT/AP configuration

Step 5 is the gate. Until that command works cleanly, everything after it is slower
than it needs to be.

# Step 1 — Prepare the Dell Vostro 3501 and hand it over

Everything here happens at the Dell's own keyboard, plus a little on the Mac.
No Python, no programming. Once step 9 passes, I take over remotely and you stop
needing to touch the Dell except to plug things in.

**Before you start:** the Dell gets completely erased. Copy anything you want off it now.

---

## 1. Download Ubuntu Server (on the Mac)

Get **Ubuntu Server 24.04 LTS** (not Desktop, not Ubuntu Core):
https://ubuntu.com/download/server → "Download Ubuntu Server 24.04 LTS"

The file is roughly 2.5 GB and ends in `.iso`.

## 2. Write it to a USB stick (on the Mac)

Any USB stick 4 GB or larger. **Its contents will be erased.**

Easiest way — download balenaEtcher (https://etcher.balena.io), open it, then:
Flash from file → pick the `.iso` → Select target → pick the USB stick → Flash.

Ignore macOS if it pops up "The disk you inserted was not readable" afterwards.
Click Ignore, do not Initialize. That message is normal.

## 3. Fix the Dell's BIOS settings first — do not skip this

This is the single most common reason Ubuntu installation fails on Dell laptops:
Dell ships with the disk controller in "RAID On" mode, and **the Ubuntu installer
cannot see the SSD at all in that mode.** You will get a confusing "no disks found"
error much later if you skip this.

1. Shut the Dell down completely.
2. Power on and press **F2** repeatedly and immediately to enter BIOS Setup.
3. Find **SATA Operation** (usually under System Configuration or Storage).
   Change **RAID On** → **AHCI**.
4. Find **Secure Boot** (under Boot Configuration or Security). Set it to **Disabled**.
5. Save and exit (**F10**).

If Windows was installed on this machine it will now refuse to boot. That is expected
and fine — you are erasing it anyway.

## 4. Boot from the USB stick

1. Plug the USB stick into the Dell.
2. Power on and press **F12** repeatedly for the one-time boot menu.
3. Choose the USB device under **UEFI Boot** (its name will include the stick's brand).
4. At the GRUB menu choose **Try or Install Ubuntu Server**.

## 5. Install Ubuntu Server

The installer is text-based; navigate with arrow keys, Tab, and Enter. Accept the
defaults except where noted:

| Screen | What to do |
|---|---|
| Language / keyboard | English, then your layout |
| Type of install | **Ubuntu Server** (not minimized) |
| Network connections | Plug the Dell's Ethernet into your router now so it gets an address. Wi-Fi here is optional |
| Proxy / mirror | Leave blank / accept default |
| Guided storage | **Use an entire disk**. Uncheck "Set up this disk as an LVM group" — simpler to reason about |
| Storage confirm | Confirm the destructive write |
| Profile setup | Your name; server name **`securepi`**; **pick a username and password and write them down** — I will need the username |
| Ubuntu Pro | Skip |
| **SSH Setup** | **✅ Tick "Install OpenSSH server"** — this is the critical one. Without it there is no remote access at all |
| Featured snaps | Select nothing |

Installation takes 10–20 minutes. When it offers **Reboot Now**, take it and pull the
USB stick out when prompted.

## 6. First login and updates

Log in at the Dell with the username and password you chose, then:

```
sudo apt update && sudo apt upgrade -y
```

## 7. Hardware check — this determines the network design

Run these four commands and **send me all the output**:

```
lspci -nnk | grep -iA3 'network\|wireless'
iw list | grep -A10 'Supported interface modes'
ip link
free -h
```

The second command matters most. If `AP` appears in the list of supported interface
modes, the Dell's own Wi-Fi can serve your test devices. If it does not, we use an old
router as an access point instead. Either way the project works — I just need to know
which before designing the network layout.

## 8. Find the Dell's IP address

```
ip -4 addr show | grep inet
```

Note the address on the Ethernet interface — something like `192.168.1.37`.
This is temporary; we set up the dedicated Cat7 link once I have access.

## 9. Give me access (mostly on the Mac)

**On the Dell**, allow administrative commands without a password prompt. This is
required because each command I run is a separate session and I cannot answer a
password prompt — anything that asks will simply hang forever:

```
echo "$USER ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/securepi
sudo chmod 440 /etc/sudoers.d/securepi
sudo visudo -c
```

That last command must print `parsed OK`. Do not log out until it does.

Stop the laptop suspending when you close the lid — it is a server now:

```
sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
sudo sed -i 's/^#*HandleLidSwitch=.*/HandleLidSwitch=ignore/' /etc/systemd/logind.conf
sudo sed -i 's/^#*HandleLidSwitchExternalPower=.*/HandleLidSwitchExternalPower=ignore/' /etc/systemd/logind.conf
sudo systemctl restart systemd-logind
```

**On the Mac**, create a key if you have none and copy it across, substituting your
username and the address from step 8:

```
ls ~/.ssh/id_ed25519.pub || ssh-keygen -t ed25519 -C securepi
ssh-copy-id yourusername@192.168.1.37
```

It asks for the Dell password once. After that, keys are used instead.

## 10. Confirm it worked

From the Mac:

```
ssh yourusername@192.168.1.37 'sudo nft list ruleset && echo ACCESS-OK'
```

If that prints `ACCESS-OK` without asking for anything, **you are done.** Tell me the
username and IP address, paste the step 7 output, and I take it from there — installing
Suricata, the DNS filter, and everything else remotely.

---

## What I can and cannot do once connected

**I can:** install and configure all software, write and deploy every line of code,
set up the firewall, routing, DHCP, DNS and access point, read logs, diagnose faults,
and run tests.

**I cannot:** plug in cables, press power buttons, enter BIOS, join a phone to Wi-Fi,
or see the Dell's physical screen. Those stay with you, and there will not be many.

**One real limitation:** each command I run is its own SSH session, so nothing carries
over between them — no persistent directory changes or shell variables. It affects how
I write commands, not what I can accomplish.

## If you get stuck

Tell me the step number and the exact error text. Most installer problems trace back
to step 3 (SATA mode still set to RAID) or a USB stick that did not write cleanly.

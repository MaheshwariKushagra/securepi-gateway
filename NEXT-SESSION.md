# Starting the next session

The gateway is shut down. Bringing it back takes about a minute, and nothing
needs configuring — every service starts automatically. This was verified by a
full reboot test.

## 1. Power on

- Open the Dell's lid and press the power button.
- **The screen stays black.** That is deliberate — the backlight is switched off
  because a lit panel behind a closed lid wastes power and adds heat. The machine
  is running.
- Close the lid again. Sleep is masked, so it keeps running.
- Leave it on the charger.

## 2. Make sure the Mac is sharing

The management link needs the MacBook's Internet Sharing running, or SSH will not
reach the Dell:

**System Settings → General → Sharing → Internet Sharing** — share from Wi-Fi, to
the USB Ethernet adapter, toggle on.

(The Dell's own internet comes from Wi-Fi, not from the Mac. Sharing is only for
the management cable.)

## 3. Check it came up

```
ssh maheshwari@192.168.2.5 'sudo securepi status'
```

Expected: six services active, WAN connected to Babu_Home, AP serving
SecurePi-Test, internet ok, ad domain blocked.

## 4. Only if you want HTTPS inspection

It is **off after every reboot**, on purpose — it decrypts traffic, so it should
be switched on deliberately rather than persisting quietly.

```
ssh maheshwari@192.168.2.5 'sudo securepi enroll'     # YouTube ad removal ON
ssh maheshwari@192.168.2.5 'sudo securepi unenroll'   # back off
```

DNS filtering (655,974 rules) is always on for every device and needs no action.

---

## Where the project stands

| Component | State |
|---|---|
| Gateway: routing, NAT, DHCP, Wi-Fi AP | Done, survives reboot |
| DNS filtering + bypass prevention | Done |
| Selective HTTPS inspection, YouTube ad removal | Done |
| Suricata sensor | Done |
| Event pipeline and unified schema | Done |
| Device registry and identity resolution | Done |
| Correlation engine and incidents (4 signals) | Done — verified against live traffic, the academic core |
| SOC console: overview, devices, incidents | Done — live, interactive (command palette, notifications, heatmap, health panel) |
| Filtering page (blocklist mgmt, per-device policy) | **Next** — plan day 12 |
| Quarantine action + undo | Not started — nftables `quarantine` set exists, no console control |
| Risk scoring | Not started |
| Basic auth on the console | Not started |
| Evaluation (detection rate, ad-block ratio, resource usage) | Not started — plan day 14 |
| Report + demo rehearsal | Not started — plan day 15 |

## Two things still outstanding

1. **Purge the journal** — it holds URLs captured during the window when the SNI
   allowlist was broken:
   ```
   ssh -t maheshwari@192.168.2.5 'sudo journalctl --rotate && sudo journalctl --vacuum-time=1s'
   ```
2. **Remove the CA from the phone after the demo** — Settings → Security →
   Encryption & credentials → Trusted credentials → User → SecurePi Gateway.

## Credentials, and where they are NOT

Nothing sensitive is in this repository. On the gateway:

| What | Where |
|---|---|
| CA private key | `/opt/securepi-dpi/ca/mitmproxy-ca.pem`, root-only |
| DNS admin password | `/root/.securepi-dns-password` |
| Wi-Fi AP passphrase | `/etc/hostapd/hostapd.conf` (redacted in the committed copy) |

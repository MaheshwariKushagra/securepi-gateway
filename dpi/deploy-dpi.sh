#!/bin/bash
# SecurePi Gateway - install or update selective HTTPS inspection (Tier 2).
#
# Run this ON THE GATEWAY, from a copy of the repository's dpi/ directory
# (gateway/install.sh calls it for a fresh install; run it alone to update
# the proxy after changing its files):
#
#   sudo ./dpi/deploy-dpi.sh
#
# What it sets up: mitmproxy in transparent mode, which decrypts ONLY the
# hosts a site module in adfilter-rules.json claims (YouTube by default;
# Instagram and Facebook only for a device that has them switched on), ONLY
# for devices an operator explicitly enrols, and removes first-party ad
# scheduling from those responses. Every other site, and every device that
# is not enrolled, passes through untouched and undecrypted. A device with
# no entry in the site map gets nothing decrypted at all (Audit10Oct C1).
#
# Safe to run again: each step leaves an already-correct installation as it
# is (the venv's packages, the seeded rule file and the CA are never
# replaced), installs changed files, and restarts the proxy so the running
# process uses them.
set -e

HERE=$(cd "$(dirname "$0")" && pwd)
DPI=/opt/securepi-dpi

echo "==> 0/5  Python environment ($DPI) with the pinned packages"
# Created here, not by hand, so a reinstall gets the exact versions the
# project was measured with (STAGE8-RECORD.md M-10). python3-venv must be
# installed (gateway/install.sh does it).
if [ ! -x "$DPI/bin/python3" ]; then
    sudo python3 -m venv "$DPI"
fi
sudo "$DPI/bin/python3" -m pip install --quiet --disable-pip-version-check \
    -r "$HERE/requirements-dpi.txt"
sudo "$DPI/bin/mitmdump" --version | head -1

echo "==> 1/5  installing the addon, its rules module and the gate script"
sudo install -m 644 -o root -g root "$HERE/securepi_adfilter.py" $DPI/securepi_adfilter.py
# The addon imports its rule-set validation from this shared module
# (`from adfilter_rules import ...`) - it has to sit next to the addon.
# The console's own copy goes to /opt/securepi via `make deploy`.
sudo install -m 644 -o root -g root "$HERE/adfilter_rules.py" $DPI/adfilter_rules.py
# Opens/closes the inspection gate from the unit below (fail-open, 7.7).
sudo install -m 755 -o root -g root "$HERE/dpi-gate.sh" $DPI/dpi-gate.sh
# The rule set itself is DATA the console edits, so it lives outside the
# root-only code directory (Audit.md C1). Seeded from the repository copy
# only if there isn't one yet - never overwrites the live, edited rules.
# The securepi group exists once gateway/setup-privilege-separation.sh has
# run (gateway/install.sh runs it first).
sudo mkdir -p /var/lib/securepi-dpi
sudo chown root:securepi /var/lib/securepi-dpi
sudo chmod 2770 /var/lib/securepi-dpi
if ! sudo test -f /var/lib/securepi-dpi/adfilter-rules.json; then
    sudo install -m 664 -o root -g securepi "$HERE/adfilter-rules.json" /var/lib/securepi-dpi/adfilter-rules.json
fi
# The per-device site map starts empty: no device is enrolled, so nothing is
# decrypted for anyone until an operator enrols a device (the "off" state).
if ! sudo test -f /var/lib/securepi-dpi/device-sites.json; then
    echo '{}' | sudo tee /var/lib/securepi-dpi/device-sites.json >/dev/null
    sudo chown root:securepi /var/lib/securepi-dpi/device-sites.json
    sudo chmod 664 /var/lib/securepi-dpi/device-sites.json
fi
# The addon writes one structured line per decrypt/passthrough decision here
# for ingest.py to pick up (step 5.1). Only root (the proxy) writes it; the
# console reads the rule-stats file in it (STAGE8-RECORD.md M-8: it used to
# be owned by the admin user for no reason).
sudo mkdir -p /var/log/securepi
sudo chown root:root /var/log/securepi
sudo chmod 755 /var/log/securepi

echo "==> 2/5  the proxy's service unit (dpi/securepi-dpi.service)"
# The unit file, with the reasoning for every flag, is dpi/securepi-dpi.service.
# Notably --listen-host 10.10.0.1 (never the WAN) and --set flow_detail=0
# (no request URLs in the journal, Audit10Oct H9).
sudo install -m 644 -o root -g root "$HERE/securepi-dpi.service" /etc/systemd/system/securepi-dpi.service

echo "==> 3/5  starting the proxy (it generates the CA on its first start)"
sudo systemctl daemon-reload
# enable, then an explicit restart: `enable --now` only STARTS a unit, so
# re-running this script against an already-running securepi-dpi left the old
# process (and the old unit file) in place (Audit10Oct M18).
sudo systemctl enable securepi-dpi
sudo systemctl restart securepi-dpi
sleep 6
sudo systemctl is-active securepi-dpi || { echo "FAILED - check: journalctl -u securepi-dpi -n 40"; exit 1; }

echo "==> 4/5  firewall: confirm the redirect rule's set is in place"
# The redirect rule and the 'enrolled' set it reads both live in `ip nat` -
# see nftables.conf. They are not created here: nftables sets are per-table,
# so a set created in a different table (an earlier version of this script
# created one in `inet filter`, which the redirect rule never reads) looks
# like it worked but silently enrolls nothing. If nftables.conf hasn't been
# loaded yet, load it now rather than improvising a rule here.
if ! sudo nft list set ip nat enrolled >/dev/null 2>&1; then
    echo "   ** 'ip nat enrolled' set not found - load gateway/nftables.conf first: **"
    echo "      sudo nft -f gateway/nftables.conf"
    exit 1
fi
sudo nft list set ip nat enrolled

echo "==> 5/5  publishing the CA certificate for device install (dpi/securepi-ca-server.service)"
# Wait for the proxy to have written its CA (first start only takes a moment).
for _ in $(seq 1 20); do
    sudo test -f $DPI/ca/mitmproxy-ca-cert.pem && break
    sleep 1
done
sudo mkdir -p /var/www-ca
sudo install -m 644 -o root -g root $DPI/ca/mitmproxy-ca-cert.pem /var/www-ca/securepi-ca.crt
sudo install -m 644 -o root -g root "$HERE/securepi-ca-server.service" /etc/systemd/system/securepi-ca-server.service
sudo systemctl daemon-reload
sudo systemctl enable securepi-ca-server
sudo systemctl restart securepi-ca-server
sleep 2

echo
echo "================================================================"
echo " DONE. The proxy is running, but NO DEVICE IS ENROLLED: nothing is"
echo " decrypted for anyone until you switch it on for one device."
echo
echo " Prefer the console's per-device 'HTTPS ad removal' toggle (device"
echo " page) - it enrols one device you choose, for 24 hours, YouTube"
echo " unless you tick other sites, and shows the CA install page."
echo
echo " From the command line instead (YouTube only, adopted by the engine"
echo " within about 15 s):"
echo "   sudo securepi enroll 10.10.0.50"
echo "   sudo securepi unenroll 10.10.0.50"
echo
echo " On the phone, install the CA first:"
echo "   browse to  http://10.10.0.1:8081/securepi-ca.crt"
echo "   Android: Settings > Security > Encryption & credentials"
echo "            > Install a certificate > CA certificate"
echo
echo " Then install the privacy canary: sudo ./dpi/deploy-privacy-canary.sh"
echo " Watch the proxy: sudo journalctl -u securepi-dpi -f"
echo "================================================================"

#!/bin/bash
# SecurePi Gateway - deploy selective HTTPS inspection.
#
# Run this ON THE DELL. It sets up mitmproxy to decrypt ONLY YouTube traffic,
# ONLY from devices you explicitly enrol, and strips ad scheduling from the
# YouTube player response.
#
# Everything else - every other site, and every device not enrolled - passes
# through untouched and undecrypted.
set -e

DPI=/opt/securepi-dpi
echo "==> 1/5  installing addon"
sudo install -m 644 "$(dirname "$0")/securepi_adfilter.py" $DPI/securepi_adfilter.py

echo "==> 2/5  creating the proxy service"
sudo tee /etc/systemd/system/securepi-dpi.service >/dev/null <<'UNIT'
[Unit]
Description=SecurePi Gateway - selective HTTPS inspection
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# --mode transparent : act on traffic redirected to us by the firewall
# --set confdir      : keep our CA here, not in root's home
# --showhost         : log the real hostname rather than the IP
ExecStart=/opt/securepi-dpi/bin/mitmdump \
    --mode transparent \
    --listen-host 0.0.0.0 \
    --listen-port 8080 \
    --set confdir=/opt/securepi-dpi/ca \
    --set block_global=false \
    --showhost \
    -s /opt/securepi-dpi/securepi_adfilter.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

echo "==> 3/5  starting proxy (generates our CA on first run)"
sudo systemctl daemon-reload
sudo systemctl enable --now securepi-dpi
sleep 6
sudo systemctl is-active securepi-dpi || { echo "FAILED - check: journalctl -u securepi-dpi -n 40"; exit 1; }

echo "==> 4/5  firewall: confirm the redirect rule is in place"
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

echo "==> 5/5  publishing the CA certificate for device install"
sudo cp $DPI/ca/mitmproxy-ca-cert.pem /var/www-ca/securepi-ca.crt 2>/dev/null || {
    sudo mkdir -p /var/www-ca
    sudo cp $DPI/ca/mitmproxy-ca-cert.pem /var/www-ca/securepi-ca.crt
}
sudo tee /etc/systemd/system/securepi-ca-server.service >/dev/null <<'UNIT'
[Unit]
Description=SecurePi Gateway - serve the CA certificate to enrolling devices
# Binds 10.10.0.1, which only exists once ap0 is up. Without the ordering and
# a real RestartSec, a boot race burned through systemd's restart limit in
# under a second and left the unit failed after reboot (15 September 2026).
After=securepi-ap0.service hostapd.service
Wants=securepi-ap0.service
[Service]
ExecStart=/usr/bin/python3 -m http.server 8081 --bind 10.10.0.1 --directory /var/www-ca
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload && sudo systemctl enable --now securepi-ca-server
sleep 2

echo "==> 5.5/5  making sure the DPI telemetry log directory exists"
# The addon writes one structured line per decrypt/passthrough decision here
# for ingest.py to pick up - see ENHANCEMENT-PLAN.md step 5.1. Created here,
# not by the addon on first write, so a permissions mistake is caught at
# deploy time rather than as a silently-empty telemetry feed.
sudo mkdir -p /var/log/securepi
sudo chown maheshwari:maheshwari /var/log/securepi 2>/dev/null || true

echo
echo "================================================================"
echo " DONE. Inspection is ACTIVE but NO DEVICE IS ENROLLED yet."
echo
echo " Prefer the console's per-device 'HTTPS ad removal' toggle over the"
echo " commands below where it's available (step 5.6) - it enrols one"
echo " device you choose, never all of them, and shows the CA install page."
echo
echo " To enrol your test phone (10.10.0.50) directly instead:"
echo "   sudo securepi enroll 10.10.0.50"
echo
echo " To un-enrol it:"
echo "   sudo securepi unenroll 10.10.0.50"
echo
echo " (securepi enroll now requires an explicit IP or the word 'all' -"
echo "  see ENHANCEMENT-PLAN.md finding A2 for why a bare 'enroll' used to"
echo "  silently enrol every device on the network.)"
echo
echo " On the phone, install the CA:"
echo "   browse to  http://10.10.0.1:8081/securepi-ca.crt"
echo "   Android: Settings > Security > Encryption & credentials"
echo "            > Install a certificate > CA certificate"
echo
echo " Watch it working:"
echo "   sudo journalctl -u securepi-dpi -f"
echo "================================================================"

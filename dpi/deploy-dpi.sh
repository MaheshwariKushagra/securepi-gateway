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

echo "==> 4/5  firewall: redirect enrolled devices' HTTPS to the proxy"
# The 'enrolled' set starts EMPTY. No device is inspected until you add it.
sudo nft add set inet filter enrolled '{ type ipv4_addr ; }' 2>/dev/null || true
sudo nft add rule ip nat prerouting iifname "ap0" ip saddr @enrolled tcp dport 443 counter redirect to :8080 2>/dev/null || true
sudo nft list set inet filter enrolled

echo "==> 5/5  publishing the CA certificate for device install"
sudo cp $DPI/ca/mitmproxy-ca-cert.pem /var/www-ca/securepi-ca.crt 2>/dev/null || {
    sudo mkdir -p /var/www-ca
    sudo cp $DPI/ca/mitmproxy-ca-cert.pem /var/www-ca/securepi-ca.crt
}
sudo tee /etc/systemd/system/securepi-ca-server.service >/dev/null <<'UNIT'
[Unit]
Description=SecurePi Gateway - serve the CA certificate to enrolling devices
[Service]
ExecStart=/usr/bin/python3 -m http.server 8081 --bind 10.10.0.1 --directory /var/www-ca
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload && sudo systemctl enable --now securepi-ca-server
sleep 2

echo
echo "================================================================"
echo " DONE. Inspection is ACTIVE but NO DEVICE IS ENROLLED yet."
echo
echo " To enrol your test phone (10.10.0.50):"
echo "   sudo nft add element inet filter enrolled { 10.10.0.50 }"
echo
echo " To un-enrol it:"
echo "   sudo nft delete element inet filter enrolled { 10.10.0.50 }"
echo
echo " On the phone, install the CA:"
echo "   browse to  http://10.10.0.1:8081/securepi-ca.crt"
echo "   Android: Settings > Security > Encryption & credentials"
echo "            > Install a certificate > CA certificate"
echo
echo " Watch it working:"
echo "   sudo journalctl -u securepi-dpi -f"
echo "================================================================"

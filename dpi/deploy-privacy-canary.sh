#!/bin/bash
# SecurePi Gateway - deploy the Tier 2 privacy-scope canary.
#
# Run this ON THE DELL, after deploy-dpi.sh. Installs privacy_canary.py as
# its own systemd service (independent of securepi-dpi's own lifecycle, so
# restarting one doesn't restart the other) - see ENHANCEMENT-PLAN.md
# step 5.7 for what this checks and why it's scoped the way it is.
set -e

DPI=/opt/securepi-dpi
echo "==> 1/2  installing the canary script"
sudo install -m 644 "$(dirname "$0")/privacy_canary.py" $DPI/privacy_canary.py

echo "==> 2/2  creating the canary service"
sudo tee /etc/systemd/system/securepi-privacy-canary.service >/dev/null <<'UNIT'
[Unit]
Description=SecurePi Gateway - Tier 2 privacy-scope canary
After=securepi-dpi.service
Wants=securepi-dpi.service

[Service]
Type=simple
# Must be the mitmproxy venv's own python3, not /usr/bin/python3 directly -
# confirmed live: the addon file this canary imports does `from mitmproxy
# import http`, and mitmproxy is only installed inside this venv. Even
# though bin/python3 here is itself a symlink to /usr/bin/python3, running
# it via this path is what makes Python pick up the venv's pyvenv.cfg and
# add its site-packages to sys.path - invoking the bare system path skips
# that and fails with "No module named 'mitmproxy'".
ExecStart=/opt/securepi-dpi/bin/python3 /opt/securepi-dpi/privacy_canary.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now securepi-privacy-canary
sleep 3
sudo systemctl is-active securepi-privacy-canary || {
    echo "FAILED - check: journalctl -u securepi-privacy-canary -n 40"; exit 1;
}

echo
echo "================================================================"
echo " DONE. The canary checks every 15 minutes and prints its result to"
echo " the journal; the Filtering page's 'Privacy scope' badge reads the"
echo " same status. On a failure it unenrolls every device automatically -"
echo " re-enrolling has to be done deliberately afterward, it does not"
echo " resume on its own."
echo
echo " Watch it working:"
echo "   sudo journalctl -u securepi-privacy-canary -f"
echo "================================================================"

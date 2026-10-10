#!/bin/bash
# SecurePi Gateway - install or update the Tier 2 privacy-scope canary.
#
# Run this ON THE GATEWAY, after deploy-dpi.sh and after the console code is
# in /opt/securepi (the canary imports correlation, dbconn and dpi_enroll
# from there). gateway/install.sh runs it for a fresh install:
#
#   sudo ./dpi/deploy-privacy-canary.sh
#
# Installs privacy_canary.py as its own systemd service (independent of
# securepi-dpi's own lifecycle, so restarting one doesn't restart the
# other) - see ENHANCEMENT-PLAN.md step 5.7 and REPORT-adblocking.md §14 for
# what it checks and what it does not cover. Safe to run again.
set -e

HERE=$(cd "$(dirname "$0")" && pwd)
DPI=/opt/securepi-dpi
echo "==> 1/2  installing the canary script"
sudo install -m 644 -o root -g root "$HERE/privacy_canary.py" $DPI/privacy_canary.py

echo "==> 2/2  installing the canary service (dpi/securepi-privacy-canary.service)"
# The unit runs the canary with the proxy venv's own python3, because the
# addon it imports needs mitmproxy (see the unit file's comment).
sudo install -m 644 -o root -g root "$HERE/securepi-privacy-canary.service" \
    /etc/systemd/system/securepi-privacy-canary.service
sudo systemctl daemon-reload
# enable, then an explicit restart: `enable --now` only STARTS a unit, so
# re-running this script against an already-running canary left the old
# process (and the old unit file) in place (Audit10Oct M18).
sudo systemctl enable securepi-privacy-canary
sudo systemctl restart securepi-privacy-canary
sleep 3
sudo systemctl is-active securepi-privacy-canary || {
    echo "FAILED - check: journalctl -u securepi-privacy-canary -n 40"; exit 1;
}
sudo journalctl -u securepi-privacy-canary -n 1 --no-pager -o cat

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

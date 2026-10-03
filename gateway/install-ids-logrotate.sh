#!/bin/bash
# SecurePi Gateway - install the IDS log rotation (3 October 2026).
# Run on the gateway as root, from a copy of the repo's gateway/ directory:
#
#   sudo ./install-ids-logrotate.sh
#
# Safe to run again. What it does:
#   1. Moves Ubuntu's packaged /etc/logrotate.d/suricata out of logrotate.d
#      with dpkg-divert, so the system's weekly, AC-power-only logrotate run
#      stops rotating these files (and package upgrades put any new version
#      of that file in the diverted place, not back in logrotate.d).
#   2. Installs gateway/logrotate-suricata.conf as
#      /etc/securepi/logrotate-suricata.conf.
#   3. Installs and starts securepi-ids-logrotate.timer (+ its service).
#   4. Dry-runs the configuration (logrotate -d) to prove it parses.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)

dpkg-divert --local --rename \
    --divert /etc/securepi/logrotate-suricata.packaged \
    --add /etc/logrotate.d/suricata

install -m 0644 -o root -g root "$HERE/logrotate-suricata.conf" /etc/securepi/logrotate-suricata.conf
install -m 0644 -o root -g root "$HERE/securepi-ids-logrotate.service" /etc/systemd/system/
install -m 0644 -o root -g root "$HERE/securepi-ids-logrotate.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now securepi-ids-logrotate.timer

logrotate -d --state /var/lib/logrotate/securepi-ids.status /etc/securepi/logrotate-suricata.conf 2>&1 | tail -5
echo "--- /etc/logrotate.d now:"; ls /etc/logrotate.d/
systemctl list-timers securepi-ids-logrotate.timer --no-pager

#!/bin/bash
# SecurePi Gateway - one-time privilege-separation setup
# (ENHANCEMENT-PLAN.md step 3.3: "unprivileged web app + allowlisted
# root helper for quarantine, block, enroll/unenroll", finding G9).
#
# Run this ON THE DELL, once, BEFORE installing the updated
# gateway/securepi-web.service (which adds User=securepi-web). It:
#   1. creates the securepi group and the unprivileged securepi-web
#      system user
#   2. moves the two /root-only secret files the console reads
#      (console + DNS admin passwords) to /etc/securepi, where the new
#      user's own group can reach them - /root itself is 700, so no
#      permission change on a file INSIDE it would ever have helped
#   3. re-permissions the two data paths the console still needs
#      direct read/write access to (its own SQLite database, and the
#      Tier 2 rule-set JSON file) so the new group can use them,
#      without granting write access to the CODE alongside them (the
#      sticky bit on each directory means only root, or a file's own
#      owner, can rename or delete an existing entry there - a group
#      member can add a new file, or edit one it already owns, but not
#      overwrite or remove app/webapp.py itself)
#   4. fixes up the console's TLS private key (step 3.2) to be group-
#      readable, if it already exists - it's generated root-only, which
#      only worked because the console used to run as root itself
#   5. installs the privileged helper and its sudoers rule
#
# Idempotent: every step checks before acting, so running this twice
# does nothing destructive the second time.
set -e

SUDOERS_TMP="$(mktemp)"

echo "==> 1/6  group and user"
getent group securepi >/dev/null || sudo groupadd --system securepi
if ! getent passwd securepi-web >/dev/null; then
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin -g securepi securepi-web
else
    sudo usermod -g securepi securepi-web
fi

echo "==> 2/6  moving secret files out of /root"
sudo mkdir -p /etc/securepi
sudo chown root:securepi /etc/securepi
sudo chmod 750 /etc/securepi
# `sudo test -f`, not a bare `[ -f ... ]`: this script itself runs as
# the invoking (non-root) user, and both /root (700) and the new
# /etc/securepi (750, no "other" access) block that user from even
# statting a file inside them - a bare test silently reports "doesn't
# exist" regardless of the real answer. Caught live on the gateway's
# first run of this exact script, where it misreported both real,
# existing password files as missing.
for pair in "/root/.securepi-console-password:/etc/securepi/console-password" \
            "/root/.securepi-dns-password:/etc/securepi/dns-password"; do
    old="${pair%%:*}"; new="${pair##*:}"
    if sudo test -f "$new"; then
        echo "   $new already exists - leaving it alone"
    elif sudo test -f "$old"; then
        sudo cp "$old" "$new"
        sudo chown root:securepi "$new"
        sudo chmod 660 "$new"
        echo "   moved $old -> $new (old copy kept as $old.pre-3.3 for now)"
        sudo mv "$old" "$old.pre-3.3"
    else
        echo "   ** neither $old nor $new exists - nothing to move, check this by hand **"
    fi
done

echo "==> 3/6  console database directory and file"
# 1775, not 775: the sticky bit (leading 1) means only root or a file's
# own owner may rename/delete an entry in this directory, even though
# the securepi group can write to it - without it, group write alone
# would let a compromised web process delete or replace webapp.py
# itself, which is a much bigger problem than "can write its own data".
sudo chown root:securepi /opt/securepi
sudo chmod 1775 /opt/securepi
sudo chown root:securepi /opt/securepi/securepi.db
sudo chmod 664 /opt/securepi/securepi.db
# WAL mode's sidecar files: chgrp/chmod them if they already exist
# (created by root's securepi-ingest so far); if they don't exist yet,
# the securepi-web user creating them fresh will already own them
# correctly once the directory itself is group-writable.
for f in /opt/securepi/securepi.db-wal /opt/securepi/securepi.db-shm; do
    [ -f "$f" ] && sudo chown root:securepi "$f" && sudo chmod 664 "$f"
done

echo "==> 4/6  Tier 2 rule-set file"
sudo chown root:securepi /opt/securepi-dpi
sudo chmod 1775 /opt/securepi-dpi
if [ -f /opt/securepi-dpi/adfilter-rules.json ]; then
    # Owned by securepi-web ITSELF, not root:securepi like the other
    # data files above - found live, the hard way: webapp.py's rule
    # editor writes this file via an atomic tmp-then-rename (so the DPI
    # addon, a separate process, never reads a half-written file), and
    # the sticky bit on this directory only lets a file's OWNER replace
    # it via rename - group write access alone isn't enough for a
    # rename onto an EXISTING file, only for creating a brand new one.
    # A root-owned rules.json would make every rule-set edit fail with
    # "Operation not permitted", confirmed by hitting exactly that
    # before this ownership was corrected.
    sudo chown securepi-web:securepi /opt/securepi-dpi/adfilter-rules.json
    sudo chmod 664 /opt/securepi-dpi/adfilter-rules.json
fi

echo "==> 5/6  console TLS private key (if step 3.2 already ran)"
# generate-console-tls.sh leaves console.key root:root 600 when it runs
# before the securepi group exists (as it did the first time these two
# steps' ordering was actually exercised, live) - the unprivileged
# console can't load its own TLS key otherwise. Harmless no-op if 3.2
# hasn't run yet on this box, or already ran after this group existed.
if sudo test -f /opt/securepi-tls/console.key; then
    sudo chown root:securepi /opt/securepi-tls/console.key
    sudo chmod 640 /opt/securepi-tls/console.key
fi

echo "==> 6/6  privileged helper and its sudoers rule"
sudo install -m 700 -o root -g root "$(dirname "$0")/securepi-web-helper" /usr/local/sbin/securepi-web-helper
cp "$(dirname "$0")/securepi-web-sudoers" "$SUDOERS_TMP"
sudo visudo -c -f "$SUDOERS_TMP" || { echo "** sudoers file failed validation - NOT installed **"; rm -f "$SUDOERS_TMP"; exit 1; }
sudo install -m 440 -o root -g root "$SUDOERS_TMP" /etc/sudoers.d/securepi-web
rm -f "$SUDOERS_TMP"
sudo visudo -c

echo
echo "================================================================"
echo " DONE. Not yet active - the service still runs as root until you"
echo " install the updated unit file and restart it:"
echo
echo "   sudo cp gateway/securepi-web.service /etc/systemd/system/securepi-web.service"
echo "   sudo systemctl daemon-reload"
echo "   sudo systemctl restart securepi-web"
echo "   sudo systemctl status securepi-web"
echo
echo " Verify it actually dropped root:"
echo "   ps -o user= -C python3 | grep securepi-web || echo 'check with: systemctl show securepi-web -p User'"
echo
echo " If anything breaks, the previous unit file is the .bak-3.3-<timestamp>"
echo " copy this session's own deploy notes describe restoring."
echo "================================================================"

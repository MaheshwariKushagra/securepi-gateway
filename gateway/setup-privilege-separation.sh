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
#   3. puts everything the console WRITES in dedicated data directories
#      (/var/lib/securepi for the database and orchestrator lock,
#      /var/lib/securepi-dpi for the Tier 2 rule-set JSON) and makes the
#      CODE directories (/opt/securepi, /opt/securepi-dpi) root-owned and
#      writable by root only. Code and writable data must never share a
#      directory: root services import Python from /opt/securepi and
#      /opt/securepi-dpi, and Python looks in a script's own directory
#      BEFORE the standard library, so a console that could create a
#      file there (say, a fake json.py) could get its code run as root.
#      The sticky bit the earlier version of this step relied on doesn't
#      stop that - it only protects files that already exist.
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

echo "==> 3/6  data directories (database, lock, rule set)"
# 2770: owner root, group securepi, read/write/enter for both, nothing
# for anyone else. The leading 2 (setgid) makes every new file created
# inside - including SQLite's -wal/-shm sidecars and the console's
# temporary files during an atomic save - belong to the securepi group
# automatically, whichever process created it.
for d in /var/lib/securepi /var/lib/securepi-dpi; do
    sudo mkdir -p "$d"
    sudo chown root:securepi "$d"
    sudo chmod 2770 "$d"
done
# /etc/securepi holds the console password. It becomes group-writable
# too (still no access for anyone else) so the console can replace the
# password file atomically - write a temporary file, then rename it over
# the old one - instead of emptying and rewriting it in place, which
# briefly left the file empty (Audit.md C2). Nothing in it is code.
sudo chmod 2770 /etc/securepi
if sudo test -f /var/lib/securepi/securepi.db; then
    sudo chown root:securepi /var/lib/securepi/securepi.db
    sudo chmod 664 /var/lib/securepi/securepi.db
    for f in /var/lib/securepi/securepi.db-wal /var/lib/securepi/securepi.db-shm; do
        if sudo test -f "$f"; then
            sudo chown root:securepi "$f"
            sudo chmod 664 "$f"
        fi
    done
elif sudo test -f /opt/securepi/securepi.db; then
    echo "   ** the database is still at /opt/securepi/securepi.db -"
    echo "      run gateway/migrate-data-dirs.sh to move it (it stops the services first) **"
fi

echo "==> 4/6  code directories: root-owned, root-writable only"
for d in /opt/securepi /opt/securepi-dpi; do
    if sudo test -d "$d"; then
        # Everything inside, not just the directory itself (Audit10Oct
        # M19): a code file the console's user could write would undo the
        # whole point of this step. List what was wrong, then fix it.
        wrong=$(sudo find "$d" \( ! -user root -o -perm /022 \) ! -type l)
        if [ -n "$wrong" ]; then
            echo "   fixing ownership or write permission of:"
            echo "$wrong" | sed 's/^/      /'
        fi
        sudo chown -R root:root "$d"
        sudo chmod -R go-w "$d"
        sudo chmod 755 "$d"
    fi
done
if sudo test -f /var/lib/securepi-dpi/adfilter-rules.json; then
    sudo chown root:securepi /var/lib/securepi-dpi/adfilter-rules.json
    sudo chmod 664 /var/lib/securepi-dpi/adfilter-rules.json
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

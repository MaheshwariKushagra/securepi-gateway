#!/bin/bash
# SecurePi Gateway - one-time move of writable data out of the code
# directories (Audit.md finding C1).
#
# Why: the root services (securepi-ingest, securepi-engine, the DPI proxy
# and the privacy canary) run Python from /opt/securepi and
# /opt/securepi-dpi. Python searches a script's own directory BEFORE the
# standard library, so any file the console could create there - a fake
# json.py, say - would be run as root the next time a service started.
# The old layout let the console create files there (group-writable,
# sticky-bit directories) because its database and rule set lived there.
#
# What this does, ON THE GATEWAY:
#   1. stops every service that opens the database or the rule set
#   2. creates /var/lib/securepi and /var/lib/securepi-dpi (root:securepi)
#   3. moves securepi.db (with its -wal/-shm files) and
#      adfilter-rules.json into them; removes the old lock file
#   4. makes /etc/securepi group-writable (atomic password saves, C2)
#   5. makes /opt/securepi and /opt/securepi-dpi root:root 755 and lists
#      anything inside them NOT owned by root, for you to inspect
#
# It deliberately leaves the services STOPPED: the code already on the
# gateway still looks for the old paths. Next steps are printed at the
# end (deploy the new code, then start the rest).
#
# Idempotent: safe to run again - each move only happens if the file is
# still in the old place and not yet in the new one.
set -euo pipefail

OLD_APP=/opt/securepi
OLD_DPI=/opt/securepi-dpi
NEW_APP=/var/lib/securepi
NEW_DPI=/var/lib/securepi-dpi

echo "==> 1/5  stopping services that use the database or the rule set"
for unit in securepi-web securepi-engine securepi-ingest securepi-dpi securepi-privacy-canary \
            securepi-intel-refresh.timer securepi-intel-refresh.service; do
    # `|| true`: a unit that doesn't exist on this box is not an error here.
    sudo systemctl stop "$unit" 2>/dev/null || true
done

echo "==> 2/5  data directories"
for d in "$NEW_APP" "$NEW_DPI"; do
    sudo mkdir -p "$d"
    sudo chown root:securepi "$d"
    sudo chmod 2770 "$d"
done

echo "==> 3/5  moving the database, lock and rule set"
if sudo test -f "$NEW_APP/securepi.db"; then
    echo "   $NEW_APP/securepi.db already exists - leaving the database alone"
elif sudo test -f "$OLD_APP/securepi.db"; then
    # The -wal file can hold recent writes not yet copied into the main
    # file, so the three files move together, with every writer stopped.
    for suffix in "" "-wal" "-shm"; do
        if sudo test -f "$OLD_APP/securepi.db$suffix"; then
            sudo mv "$OLD_APP/securepi.db$suffix" "$NEW_APP/securepi.db$suffix"
            sudo chown root:securepi "$NEW_APP/securepi.db$suffix"
            sudo chmod 664 "$NEW_APP/securepi.db$suffix"
        fi
    done
    echo "   moved $OLD_APP/securepi.db -> $NEW_APP/securepi.db"
else
    echo "   ** no database found in either place - check this by hand **"
fi
if sudo test -f "$OLD_APP/orchestrator.lock"; then
    sudo rm -f "$OLD_APP/orchestrator.lock"
fi

if sudo test -f "$NEW_DPI/adfilter-rules.json"; then
    echo "   $NEW_DPI/adfilter-rules.json already exists - leaving the rule set alone"
elif sudo test -f "$OLD_DPI/adfilter-rules.json"; then
    sudo mv "$OLD_DPI/adfilter-rules.json" "$NEW_DPI/adfilter-rules.json"
    sudo chown root:securepi "$NEW_DPI/adfilter-rules.json"
    sudo chmod 664 "$NEW_DPI/adfilter-rules.json"
    echo "   moved $OLD_DPI/adfilter-rules.json -> $NEW_DPI/adfilter-rules.json"
fi
# Leftover temporary files from the old fixed-name atomic save.
sudo rm -f "$OLD_DPI/adfilter-rules.json.tmp"

echo "==> 4/5  /etc/securepi group-writable (atomic password replacement)"
sudo chmod 2770 /etc/securepi

echo "==> 5/5  code directories: root-owned, root-writable only"
for d in "$OLD_APP" "$OLD_DPI"; do
    sudo chown root:root "$d"
    sudo chmod 755 "$d"
done
echo "   files in the code directories NOT owned by root (should be none -"
echo "   anything listed here was created by another user; inspect it):"
sudo find "$OLD_APP" "$OLD_DPI" -maxdepth 2 ! -user root -print | sed 's/^/     /' || true

echo
echo "================================================================"
echo " DONE. Services are still STOPPED. Next:"
echo
echo "  1. From the Mac:        make deploy"
echo "     (installs the new code, then restarts ingest, engine and web)"
echo "  2. On the gateway:      bash dpi/deploy-dpi.sh"
echo "     (new addon + shared rules module; restarts securepi-dpi)"
echo "  3. On the gateway:      bash dpi/deploy-privacy-canary.sh"
echo "  4. On the gateway:      sudo systemctl start securepi-intel-refresh.timer"
echo "  5. Check everything:    sudo securepi status"
echo "================================================================"

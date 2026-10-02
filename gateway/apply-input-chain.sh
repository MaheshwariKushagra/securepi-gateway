#!/bin/bash
# SecurePi Gateway - replace ONLY the live firewall's input chain with the
# one in nftables.conf (CODEBASE_AUDIT.md H2), with an automatic undo.
#
# Why not just `nft -f /etc/nftables.conf`: that file starts with
# `flush ruleset`, which would also empty the live quarantine, blocked-IP,
# enrolled and DoH sets. This swaps the one chain and leaves everything
# else alone.
#
# Why the automatic undo: a default-deny input chain is exactly the kind
# of change that can lock you out over SSH. `apply` puts the old chain
# back by itself after 3 minutes unless `confirm` is run first - and
# `confirm` should be run from a NEW SSH connection, which proves the new
# rules still let the management link in.
#
# Usage (on the gateway, as root, with the repo's nftables.conf beside it):
#   sudo ./apply-input-chain.sh apply      check, apply, start the 3-minute undo timer
#   sudo ./apply-input-chain.sh confirm    keep it: cancel the undo, install /etc/nftables.conf
#   sudo ./apply-input-chain.sh rollback   put the old chain back now

set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
NEW_CONF="$HERE/nftables.conf"
WORK=/var/lib/securepi/firewall
ROLLBACK="$WORK/input-rollback.nft"
SNIPPET="$WORK/input-new.nft"
UNDO_UNIT=securepi-input-undo

mkdir -p "$WORK"
chmod 700 "$WORK"

case "$1" in
  apply)
    # 1. The whole file must still be valid - it's what loads at boot.
    nft -c -f "$NEW_CONF"

    # 2. Just the input chain, wrapped so it replaces the live one.
    {
        echo "flush chain inet filter input"
        echo "table inet filter {"
        awk '/^    chain input \{/{on=1} on{print} on && /^    \}/{exit}' "$NEW_CONF"
        echo "}"
    } > "$SNIPPET"
    nft -c -f "$SNIPPET"

    # 3. What to go back to.
    { echo "flush chain inet filter input"; nft list chain inet filter input; } > "$ROLLBACK"
    nft -c -f "$ROLLBACK"

    # 4. The undo timer first, then the change.
    systemctl stop "$UNDO_UNIT.timer" 2>/dev/null || true
    systemd-run --quiet --unit "$UNDO_UNIT" --on-active=180 /usr/sbin/nft -f "$ROLLBACK"
    nft -f "$SNIPPET"
    echo "new input chain applied. It will be undone in 3 minutes unless you run"
    echo "'$0 confirm' - from a NEW ssh connection."
    ;;
  confirm)
    systemctl stop "$UNDO_UNIT.timer" 2>/dev/null || true
    cp -p /etc/nftables.conf "/etc/nftables.conf.pre-input-drop-$(date +%Y%m%d-%H%M%S).bak"
    install -m 644 "$NEW_CONF" /etc/nftables.conf
    echo "kept. /etc/nftables.conf updated (old copy saved beside it)."
    ;;
  rollback)
    systemctl stop "$UNDO_UNIT.timer" 2>/dev/null || true
    nft -f "$ROLLBACK"
    echo "old input chain restored."
    ;;
  *)
    echo "usage: $0 apply|confirm|rollback"
    exit 1
    ;;
esac

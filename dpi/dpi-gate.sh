#!/bin/bash
# SecurePi Gateway - open or close the HTTPS inspection gate (Stage 7.7).
#
# The dpi-redirect rule in gateway/nftables.conf only sends enrolled
# devices' HTTPS to the proxy while "ap0" is in the `ip nat dpi_up` set.
# securepi-dpi.service calls this script:
#
#   ExecStartPost=/opt/securepi-dpi/dpi-gate.sh open    once the proxy is listening
#   ExecStopPost=/opt/securepi-dpi/dpi-gate.sh close    whenever it stops or crashes
#
# so a stopped or crashed proxy means enrolled devices browse normally,
# undecrypted, instead of every HTTPS site failing for them. The enrolled
# set itself is left alone, so nobody is un-enrolled by a restart.
# app/health.py covers the one case systemd can't see: a proxy that is
# still running but no longer answering.
#
# Installed by dpi/deploy-dpi.sh. Runs as root (from the unit).

NFT=/usr/sbin/nft
LISTEN="10.10.0.1:8080"

case "$1" in
    open)
        # Wait for the proxy's listening socket, up to 30 s - opening the
        # gate before it listens would redirect traffic into a closed port.
        for _ in $(seq 1 30); do
            if ss -Htln "sport = :8080" | grep -q "$LISTEN"; then
                exec "$NFT" add element ip nat dpi_up '{ "ap0" }'
            fi
            sleep 1
        done
        echo "proxy never started listening on $LISTEN - leaving the inspection gate closed" >&2
        exit 1
        ;;
    close)
        # Deleting an element that isn't there is an error in nft; for a
        # close that just means the gate was already closed.
        "$NFT" delete element ip nat dpi_up '{ "ap0" }' 2>/dev/null
        exit 0
        ;;
    *)
        echo "usage: $0 open|close" >&2
        exit 2
        ;;
esac

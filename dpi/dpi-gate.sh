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

# NFT and DPI_GATE_WAIT_S can be overridden from the environment; the
# unit doesn't, so on the gateway they are always the defaults. The tests
# (tests/test_dpi_gate_script.py) use them to run this script for real
# against a fake nft.
NFT=${NFT:-/usr/sbin/nft}
WAIT_S=${DPI_GATE_WAIT_S:-75}
LISTEN="10.10.0.1:8080"

case "$1" in
    open)
        # Wait for the proxy's listening socket - opening the gate before it
        # listens would redirect traffic into a closed port. Up to 75 s: on
        # 3 October 2026 the old 30 s wait ran out at boot while the disk
        # was busy. This wait counts against the unit's 90 s start limit
        # (systemd's default TimeoutStartSec), so it must stay below that.
        for _ in $(seq 1 "$WAIT_S"); do
            if ss -Htln "sport = :8080" | grep -q "$LISTEN"; then
                exec "$NFT" add element ip nat dpi_up '{ "ap0" }'
            fi
            sleep 1
        done
        # Not an error for the unit: with the gate closed, enrolled devices
        # browse undecrypted (fail-open), and app/health.py's
        # check_dpi_proxy opens the gate as soon as the proxy answers.
        # Exiting 1 here used to mark the whole unit failed and restart it.
        echo "proxy never started listening on $LISTEN within ${WAIT_S}s - leaving the inspection gate closed (health check opens it once the proxy answers)" >&2
        exit 0
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

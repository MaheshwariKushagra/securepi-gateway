#!/bin/bash
# SecurePi Gateway - run this at the start of every working session.
#
# Brings up the Mac's view into the gateway (the SSH tunnel) and runs a full
# health check, so "did we forget to turn something back on after the last
# reboot" is answered in one command instead of discovered later as
# "the ad blocker seems broken" or "why is nothing in the incidents page".
#
# Usage: ./session-start.sh

GATEWAY="maheshwari@192.168.2.5"
PROBLEMS=0

echo "== SecurePi Gateway - session start check =="
echo

echo "-- management link --"
if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$GATEWAY" true 2>/dev/null; then
    echo "   ** cannot reach the gateway. Is Mac Internet Sharing on **"
    echo "   ** (System Settings > General > Sharing > Internet Sharing)? **"
    echo
    echo "Stopping here - nothing else can be checked without this link."
    exit 1
fi
echo "   ok"
echo

echo "-- gateway status --"
ssh -o BatchMode=yes "$GATEWAY" 'sudo securepi status'
ssh -o BatchMode=yes "$GATEWAY" 'sudo securepi status' | grep -q "ONE OR MORE SERVICES" && PROBLEMS=1
echo

echo "-- browser tunnel (http://localhost:8000) --"
"$(dirname "$0")/mac-tunnel.sh" start
echo

echo "-- backup status --"
cd "$(dirname "$0")" || exit 1
UNPUSHED=$(git log --oneline "origin/main..HEAD" 2>/dev/null | wc -l | tr -d ' ')
UNCOMMITTED=$(git status --short | wc -l | tr -d ' ')
if [ "$UNCOMMITTED" != "0" ]; then
    echo "   ** $UNCOMMITTED uncommitted change(s) in the working tree **"
    PROBLEMS=1
fi
if [ "$UNPUSHED" != "0" ]; then
    echo "   ** $UNPUSHED commit(s) not yet pushed to GitHub **"
    PROBLEMS=1
fi
[ "$UNCOMMITTED" = "0" ] && [ "$UNPUSHED" = "0" ] && echo "   up to date with GitHub"
echo

if [ "$PROBLEMS" = "1" ]; then
    echo "== SUMMARY: something above needs attention =="
else
    echo "== SUMMARY: everything is up. Console at http://localhost:8000 =="
fi

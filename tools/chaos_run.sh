#!/bin/bash
# Step 7.7: run one chaos scenario on the gateway while the A33 probes what a
# device on SecurePi-Test experiences, once a second. Both timelines are on
# the same clock (Mac, phone and gateway agree to the second).
#   tools/chaos_run.sh SCENARIO [WATCH_SECONDS]
# Output: eval/results/chaos/<scenario>.json (gateway) and
#         eval/results/chaos/a33-<scenario>.txt (device).
S="$1"; WATCH="${2:-150}"
cd "$(dirname "$0")/.." || exit 1
mkdir -p eval/results/chaos
ANDROID_SERIAL=RZCT30NYTSB tools/chaos_phone_probe.sh $((WATCH + 20)) > "eval/results/chaos/a33-$S.txt" 2>&1 &
PROBE=$!
sleep 15                       # a baseline before anything breaks
ssh maheshwari@192.168.2.5 "sudo python3 /opt/securepi-eval/chaos.py $S --watch $WATCH" > "eval/results/chaos/$S.json"
wait $PROBE
echo "$S: gateway $(wc -c < eval/results/chaos/$S.json) bytes, probe $(wc -l < eval/results/chaos/a33-$S.txt) lines"

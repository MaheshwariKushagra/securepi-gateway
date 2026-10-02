#!/bin/bash
# Step 7.5 helper: put the benchmark Mac (registry device $1) on filtering
# profile $2 through the orchestrator - the console's own code path - and
# print what the DNS filter now answers for a known ad domain for that client.
#   tools/bench_profile.sh 99 standard 10.10.0.54
DEVICE="$1"; PROFILE="$2"; CLIENT_IP="$3"
ssh maheshwari@192.168.2.5 "cd /opt/securepi && sudo -u securepi-web python3 - <<PY
import time, correlation, orchestrator, adguard
c = correlation.connect()
p = orchestrator.create_policy(c, 'profile', $DEVICE, '$PROFILE', None, 'step 7.5 ad-blocking benchmark', actor='bench')
print('policy', p['id'], p['status'], '$PROFILE')
r = adguard.check_host('doubleclick.net', '$CLIENT_IP')
print('doubleclick.net for $CLIENT_IP:', r.get('reason'))
PY"

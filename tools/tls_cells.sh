#!/bin/bash
# Step 7.5 TLS setup latency on the Lenovo tablet (device 98), four cells of
# N loads each (default 25), with time-to-first-byte recorded in every cell
# (tools/tls_latency_tablet.py writes ttfb_ms):
#
#   decrypted_enrolled      m.youtube.com, tablet enrolled -> decrypted by the proxy
#   passthrough_enrolled    wikipedia.org, tablet enrolled -> proxy passes it through
#   (the tablet's active enrolment policy is ended here)
#   same_host_unenrolled    m.youtube.com, direct
#   passthrough_unenrolled  wikipedia.org, direct - the control the 2 October
#                           run lacked for the passthrough host
#
#   tools/tls_cells.sh OUTDIR [N]
#
# The tablet must be enrolled (an active "enroll" policy for device 98)
# before this starts. The policy is looked up, not hard-coded. adb reaches
# whichever server ANDROID_ADB_SERVER_PORT points at (the tablet is cabled
# to the gateway since 3 October; see NEXT-SESSION.md), and DevTools must
# be forwarded to 127.0.0.1:9223.
OUT=${1:?usage: tls_cells.sh OUTDIR [N]}
N=${2:-25}
REPO=$(cd "$(dirname "$0")/.." && pwd)
PY=$REPO/.venv-bench/bin/python
TOOL=$REPO/tools/tls_latency_tablet.py
mkdir -p "$OUT" && cd "$OUT" || exit 1

date +%s > cells-start.txt
$PY "$TOOL" decrypted_enrolled https://m.youtube.com/favicon.ico "$N" decrypted_enrolled.jsonl
$PY "$TOOL" passthrough_enrolled https://www.wikipedia.org/static/favicon/wikipedia.ico "$N" passthrough_enrolled.jsonl

ssh maheshwari@192.168.2.5 'cd /opt/securepi && sudo -u securepi-web python3 -c "
import correlation, orchestrator
c = correlation.connect()
for p in orchestrator.active_policies(c, kind=\"enroll\", device_id=98):
    orchestrator.end_policy(c, p[\"id\"], actor=\"bench\", reason=\"TLS latency: unenrolled cells\")
    print(\"ended enrol policy\", p[\"id\"])"; sudo nft list set ip nat enrolled' < /dev/null | tee unenroll.txt
date +%s > unenrolled-at.txt

$PY "$TOOL" same_host_unenrolled https://m.youtube.com/favicon.ico "$N" same_host_unenrolled.jsonl
$PY "$TOOL" passthrough_unenrolled https://www.wikipedia.org/static/favicon/wikipedia.ico "$N" passthrough_unenrolled.jsonl
date +%s > cells-end.txt
echo CELLS DONE

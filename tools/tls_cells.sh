#!/bin/bash
# Step 7.5 TLS latency, three cells on the tablet (device 98).
cd /Users/maheshwari/blah/eval/results/tls-latency-tablet
PY=/Users/maheshwari/blah/.venv-bench/bin/python
date +%s > cells-start.txt
$PY /tmp/tls_latency_tablet.py decrypted_enrolled https://m.youtube.com/favicon.ico 25 decrypted_enrolled.jsonl
$PY /tmp/tls_latency_tablet.py passthrough_enrolled https://www.wikipedia.org/static/favicon/wikipedia.ico 25 passthrough_enrolled.jsonl
ssh maheshwari@192.168.2.5 'cd /opt/securepi && sudo -u securepi-web python3 -c "
import correlation, orchestrator
c = correlation.connect()
orchestrator.end_policy(c, 41, actor=\"bench\", reason=\"TLS latency: unenrolled cell\")
print(\"policy 41 ended\")"; sudo nft list set ip nat enrolled' < /dev/null
$PY /tmp/tls_latency_tablet.py same_host_unenrolled https://m.youtube.com/favicon.ico 25 same_host_unenrolled.jsonl
ssh maheshwari@192.168.2.5 'cd /opt/securepi && sudo -u securepi-web python3 -c "
import time, correlation, orchestrator
c = correlation.connect()
p = orchestrator.create_policy(c, \"enroll\", 98, None, time.time() + 2*3600, \"step 7.7 kill-proxy client (Lenovo tablet)\", actor=\"bench\")
print(\"re-enrolled, policy\", p[\"id\"])"; sudo nft list set ip nat enrolled | grep elements' < /dev/null
date +%s > cells-end.txt
echo CELLS DONE

#!/bin/bash
# Step 7.7: what a real device on SecurePi-Test experiences during a chaos
# test. Runs on the Mac, probes from the phone over adb once a second for
# $1 seconds, and prints one line per second:
#   <phone epoch> dns=<ok|fail> https=<ok|fail>
# dns: resolve a never-seen name (a fresh nip.io label), so no cache can
#      answer - only a working resolver path can.
# https: open a TCP connection to example.com:443 (what a browser does
#      first; for an enrolled device this goes through the inspection
#      redirect).
DURATION="${1:-150}"
adb shell "end=\$((\$(date +%s) + $DURATION)); i=0;
while [ \$(date +%s) -lt \$end ]; do
  i=\$((i+1)); t=\$(date +%s)
  name=\"c\${t}-\${i}-1-1-1-1.nip.io\"
  if ping -c1 -W1 \$name >/dev/null 2>&1 || ping -c1 -W1 \$name 2>&1 | grep -q PING; then d=ok; else d=fail; fi
  if nc -z -w 2 example.com 443 >/dev/null 2>&1; then h=ok; else h=fail; fi
  echo \"\$t dns=\$d https=\$h\"
  sleep 1
done"

#!/bin/bash
# Tablet copy of tools/chaos_phone_probe.sh (shared file left untouched).
# Android 9 has no plain `nc`, and toybox's nc has no -z and can hang on an
# unreachable address - so the HTTPS check is "toybox nc" opening the
# connection and closing it at once (empty input), inside a 3-second
# toybox timeout. Validated: open port -> 0, closed port -> 1.
DURATION="${1:-150}"
adb -s HA13T683 shell "end=\$((\$(date +%s) + $DURATION)); i=0;
while [ \$(date +%s) -lt \$end ]; do
  i=\$((i+1)); t=\$(date +%s)
  name=\"c\${t}-\${i}-1-1-1-1.nip.io\"
  if ping -c1 -W1 \$name >/dev/null 2>&1 || ping -c1 -W1 \$name 2>&1 | grep -q PING; then d=ok; else d=fail; fi
  if toybox timeout 3 toybox nc -w 2 example.com 443 </dev/null >/dev/null 2>&1; then h=ok; else h=fail; fi
  echo \"\$t dns=\$d https=\$h\"
  sleep 1
done" < /dev/null

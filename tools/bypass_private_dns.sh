#!/bin/bash
# Step 7.5's bypass matrix, Android Private DNS row (ENHANCEMENT-PLAN.md).
# Sets "Private DNS provider hostname" on an Android device over adb, one
# provider at a time, and records whether the device could still resolve
# names (fresh nip.io labels, so no cache answers) and what it got for a
# domain the gateway blocks. Restores the device's own setting at the end.
#   tools/bypass_private_dns.sh SERIAL OUTFILE
SERIAL="$1"; OUT="$2"
A="adb -s $SERIAL shell"
orig_mode=$($A settings get global private_dns_mode); orig_spec=$($A settings get global private_dns_specifier)
probe() {
  $A "t=\$(date +%s); for i in 1 2 3; do n=\"p\${t}-\$i-1-1-1-1.nip.io\"; if ping -c1 -W2 \$n 2>&1 | grep -q PING; then echo fresh_ok; else echo fresh_fail; fi; done; ping -c1 -W2 doubleclick.net 2>&1 | head -1"
}
: > "$OUT"
for spec in dns.google dot.sb one.one.one.one; do
  $A settings put global private_dns_mode hostname
  $A settings put global private_dns_specifier $spec
  sleep 15
  echo "== $(date +%s) private DNS = $spec" | tee -a "$OUT"
  probe | tee -a "$OUT"
  sleep 20
done
# Put the device's own setting back exactly ("null" = never set).
if [ "$orig_mode" = "null" ]; then $A settings delete global private_dns_mode; else $A settings put global private_dns_mode "$orig_mode"; fi
if [ "$orig_spec" = "null" ]; then $A settings delete global private_dns_specifier; else $A settings put global private_dns_specifier "$orig_spec"; fi
echo "== $(date +%s) restored: mode=$($A settings get global private_dns_mode) spec=$($A settings get global private_dns_specifier)" | tee -a "$OUT"
echo "== after restore" | tee -a "$OUT"; sleep 10; probe | tee -a "$OUT"

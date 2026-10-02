#!/bin/bash
# Step 7.5's bypass matrix, DNS-over-HTTPS rows (ENHANCEMENT-PLAN.md).
# What Firefox's "DoH only" mode (network.trr.mode=3 with a bootstrap
# address) does on the wire, done with curl's own DoH resolver: resolve a
# domain the gateway blocks (doubleclick.net) through a DoH provider at a
# fixed address, then fetch it. Run from a device on SecurePi-Test under
# normal (Standard) filtering.
#   blocked  - the DoH connection was refused / nothing resolved
#   leaked   - doubleclick.net resolved through DoH and answered
# (Firefox itself couldn't run here: both Playwright's build and the official
# release exit at start-up with "Could not find profile folder" inside this
# environment's command sandbox.)
OUT="$1"
: > "$OUT"
while read -r name url host ip; do
  t=$(date +%s)
  r=$(curl -s -o /dev/null -m 15 -w "%{http_code}" --resolve "$host:443:$ip" --doh-url "$url" http://doubleclick.net/ 2>&1); rc=$?
  if [ "$rc" = "0" ]; then v=leaked; else v=blocked; fi
  echo "$t $name doh=$url via $ip curl_exit=$rc http=$r verdict=$v" | tee -a "$OUT"
  sleep 3
done <<'LIST'
cloudflare https://mozilla.cloudflare-dns.com/dns-query mozilla.cloudflare-dns.com 1.1.1.1
google https://dns.google/dns-query dns.google 8.8.8.8
quad9 https://dns.quad9.net/dns-query dns.quad9.net 9.9.9.9
dns.sb https://doh.dns.sb/dns-query doh.dns.sb 185.222.222.222
mullvad https://dns.mullvad.net/dns-query dns.mullvad.net 194.242.2.2
alidns https://dns.alidns.com/dns-query dns.alidns.com 223.5.5.5
adguard https://dns.adguard-dns.com/dns-query dns.adguard-dns.com 94.140.14.14
nextdns https://dns.nextdns.io/dns-query dns.nextdns.io 45.90.28.0
LIST

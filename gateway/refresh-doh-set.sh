#!/bin/bash
# SecurePi Gateway - refresh the doh_resolvers nftables set from HaGeZi's
# maintained DoH-resolver IP list (ENHANCEMENT-PLAN.md step 2.2).
#
# Run daily by securepi-doh-refresh.timer. Safe to run by hand too:
#   sudo /opt/securepi/refresh-doh-set.sh
#
# Fails SAFE, not silent: if the download fails, comes back empty, or looks
# implausibly small, the LIVE set is left untouched and this exits non-zero
# (systemd logs it as a failed run, visible in `systemctl status`) rather
# than flushing doh_resolvers down to nothing. A missing or truncated
# refresh should degrade to "yesterday's list, slightly stale" - never to
# "no DoH IP blocking at all until someone notices".
set -u

URL="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh-ips.txt"
MIN_PLAUSIBLE_COUNT=500   # the list has run ~1,445 entries historically;
                          # anything far below that suggests a bad fetch,
                          # not a genuine shrink in public DoH resolvers

tmpfile="$(mktemp)"
trap 'rm -f "$tmpfile"' EXIT

if ! curl -fsS --max-time 30 "$URL" -o "$tmpfile"; then
    echo "refresh-doh-set: download failed, leaving the existing set untouched" >&2
    exit 1
fi

# The file is AdBlock-syntax: one `||1.2.3.4^` line per address, plus
# comment lines starting with `!` or `[`. Extract just the address, and
# only keep lines that are actually a plausible IPv4 address or CIDR -
# skip anything else (a hostname-shaped entry, an IPv6 address - the
# doh_resolvers set is ipv4_addr only, see nftables.conf) rather than
# letting a malformed line abort the whole refresh.
addresses="$(grep -oE '^\|\|[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?\^' "$tmpfile" \
    | sed -E 's/^\|\|//; s/\^$//')"
count="$(echo "$addresses" | grep -c .)"

if [ "$count" -lt "$MIN_PLAUSIBLE_COUNT" ]; then
    echo "refresh-doh-set: only $count plausible addresses parsed (expected $MIN_PLAUSIBLE_COUNT+)," \
         "leaving the existing set untouched - source format may have changed" >&2
    exit 1
fi

# One nft invocation, flush-then-fill in the same transaction, so there is
# no window where the set is empty - a bad actor scanning for exactly that
# gap would need to win a race that never opens.
{
    echo "flush set inet filter doh_resolvers"
    echo -n "add element inet filter doh_resolvers { "
    echo "$addresses" | paste -sd, -
    echo " }"
} | nft -f -

echo "refresh-doh-set: loaded $count addresses from HaGeZi doh-ips.txt"

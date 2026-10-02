#!/bin/bash
# Step 7.5 breakage test: the top-50 sites, once unfiltered (baseline) and once
# under Tier 1, on the benchmark Mac (registry device $1, address $2).
DEVICE="$1"; CLIENT_IP="$2"; OUT="$3"
cd "$(dirname "$0")/.." || exit 1
PY=.venv-bench/bin/python
for cond in none tier1; do
  case "$cond" in none) profile=unrestricted ;; tier1) profile=standard ;; esac
  echo "== top50 condition $cond (gateway profile $profile) $(date '+%H:%M:%S')"
  tools/bench_profile.sh "$DEVICE" "$profile" "$CLIENT_IP"
  sleep 15
  $PY tools/adblock_bench.py load --sites eval/bench-top50.json --condition "top50_$cond" --runs 1 --out "$OUT/top50_$cond.jsonl"
done
echo "== done $(date '+%H:%M:%S')"

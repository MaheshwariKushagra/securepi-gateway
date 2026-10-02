#!/bin/bash
# Step 7.5: the full ad-blocking benchmark. Conditions are interleaved run by
# run (run 1 of all four, then run 2, ...) so time of day can't favour one.
#   tools/bench_run.sh DEVICE CLIENT_IP OUTDIR
DEVICE="$1"; CLIENT_IP="$2"; OUT="$3"
cd "$(dirname "$0")/.." || exit 1
PY=.venv-bench/bin/python
UBOL="$PWD/eval/bench-data/ubol"
for run in 1 2 3; do
  for cond in none tier1 tier1_lists ubol; do
    case "$cond" in
      none)        profile=unrestricted ;;
      tier1)       profile=standard ;;
      tier1_lists) profile=strict_privacy ;;
      ubol)        profile=unrestricted ;;
    esac
    echo "== run $run, condition $cond (gateway profile $profile) $(date '+%H:%M:%S')"
    tools/bench_profile.sh "$DEVICE" "$profile" "$CLIENT_IP"
    sleep 15
    ext=""
    [ "$cond" = "ubol" ] && ext="--extension $UBOL"
    $PY tools/adblock_bench.py load --sites eval/bench-sites.json --condition "$cond" --runs 1 \
        --first-run "$run" $ext --out "$OUT/$cond.jsonl"
  done
done
echo "== done $(date '+%H:%M:%S')"

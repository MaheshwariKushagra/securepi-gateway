#!/bin/bash
# SecurePi Gateway - collect step 7.0's seven-day run (ENHANCEMENT-PLAN.md).
#
# Run by securepi-run-collect.timer when the run ends (or by hand at any time
# for an interim look). Takes a consistent copy of the database, the boot
# list and the run monitor's files, and produces the run report on the
# gateway itself - so the result exists even if nobody is at the Mac on
# the day. Everything lands in /var/lib/securepi-eval/run-<START>/.
#
#   sudo /opt/securepi-eval/collect_run.sh START END     (local times, YYYY-MM-DDTHH:MM:SS)
set -e
START="$1"; END="$2"
OUT="/var/lib/securepi-eval/run-${START//:/}"
mkdir -p "$OUT"
chmod 750 "$OUT"

python3 - "$OUT/securepi.db" <<'PY'
import sqlite3, sys
src = sqlite3.connect("file:/var/lib/securepi/securepi.db?mode=ro", uri=True)
dst = sqlite3.connect(sys.argv[1])
src.backup(dst)
dst.close()
PY
chmod 600 "$OUT/securepi.db"             # holds session tokens - see NEXT-SESSION.md
journalctl --list-boots --no-pager > "$OUT/boots.txt"
journalctl --no-pager -u securepi-privacy-canary --since "${START/T/ }" --until "${END/T/ }" -o short-iso \
    | grep "securepi-privacy-canary:" > "$OUT/canary.log" || true
cp -r /var/lib/securepi-eval/monitor "$OUT/monitor"
sha256sum /opt/securepi/*.py > "$OUT/code-sha256.txt"

python3 /opt/securepi-eval/run_report.py "$OUT/securepi.db" --start "$START" --end "$END" \
    --monitor "$OUT/monitor" --boots "$OUT/boots.txt" --out "$OUT/report.json" > /dev/null
echo "run collected in $OUT"

#!/bin/bash
# Step 7.5's Tier 2 test: does a YouTube video in mobile Chrome start with a
# pre-roll ad? One condition per run (the gateway side - phone enrolled for
# HTTPS inspection or not - is set beforehand through the orchestrator).
#
#   tools/youtube_tier2.sh CONDITION OUTDIR [VIDEOS_JSON]
#
# For each of the 30 videos: open it in Chrome (explicitly - the phone's
# default browser is Brave, which blocks ads itself and would spoil the
# measurement), wait WAIT seconds, read the screen's text through Android's
# UI dump and look for YouTube's ad markers, then save a screenshot so a
# person can check the call. One line per video: id, ad markers found
# (or none), and whether the player was on screen at all.
CONDITION="$1"; OUT="$2"; VIDEOS="${3:-eval/youtube-videos.json}"
WAIT=15
mkdir -p "$OUT/$CONDITION"
ids=$(python3 -c "import json,sys; print(' '.join(v['id'] for v in json.load(open('$VIDEOS'))['videos']))")
adb shell svc power stayon usb
for id in $ids; do
  adb shell am start -a android.intent.action.VIEW -d "https://m.youtube.com/watch?v=$id" com.android.chrome >/dev/null
  sleep "$WAIT"
  adb shell uiautomator dump /sdcard/yt.xml >/dev/null 2>&1
  adb pull /sdcard/yt.xml "$OUT/$CONDITION/$id.xml" >/dev/null 2>&1
  adb exec-out screencap -p > "$OUT/$CONDITION/$id.png"
  markers=$(python3 - "$OUT/$CONDITION/$id.xml" <<'PY'
import re, sys
try:
    xml = open(sys.argv[1], encoding="utf-8", errors="replace").read()
except OSError:
    print("dump-failed"); sys.exit()
texts = re.findall(r'(?:text|content-desc)="([^"]*)"', xml)
found = set()
for t in texts:
    tl = t.lower()
    if re.search(r"\bskip( ad| ads)?\b", tl) or "visit advertiser" in tl or "sponsored" in tl \
       or re.match(r"^ad\b", tl) or re.search(r"\bad ·|\bad [0-9]+ of [0-9]+", tl) or "why this ad" in tl:
        found.add(t.strip()[:40])
player = any(("video player" in t.lower() or "pause video" in t.lower() or "play video" in t.lower()
              or "action menu" in t.lower()) for t in texts)
print(("|".join(sorted(found)) or "none") + " player=" + ("yes" if player else "no"))
PY
)
  echo "$(date +%s) $CONDITION $id $markers" | tee -a "$OUT/$CONDITION/results.txt"
  adb shell input keyevent KEYCODE_HOME >/dev/null
  sleep 2
done

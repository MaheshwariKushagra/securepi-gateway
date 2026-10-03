#!/bin/bash
# Step 5.8 pinned-app check on the Lenovo tablet (device 98, enrolled in
# Tier 2 beforehand): does the YouTube app work through HTTPS inspection?
#
#   tools/pinned_app.sh OUTDIR [LAUNCHES]
#
# Each launch opens one video in the YouTube app, samples its playback state
# every 5 s for a minute (media_session state 3 = playing), takes a
# screenshot, and force-stops the app, so the next launch starts fresh.
# LAUNCHES (default 1) > 1 is the relaunch test added on 3 October 2026: the
# app retries a pinned host only twice per launch, so the question is
# whether a relaunch supplies the third failed handshake that 5.8's
# auto-passthrough waits for.
#
# adb is called plainly, so it reaches whichever adb server the environment
# points at: with the tablet on the Dell, run with ANDROID_ADB_SERVER_PORT
# set to the SSH-tunnelled port (see NEXT-SESSION.md).
OUT=${1:?usage: pinned_app.sh OUTDIR [LAUNCHES]}
LAUNCHES=${2:-1}
SERIAL=HA13T683
mkdir -p "$OUT" && cd "$OUT" || exit 1
S() { adb -s "$SERIAL" shell "$@" < /dev/null; }
VIDEOS=(dQw4w9WgXcQ kJQP7kiw5Fk 9bZkp7q19f0)

S am force-stop com.google.android.youtube; S am force-stop com.android.chrome
T0=$(date +%s); echo "T0 $T0" > timeline.txt; echo $T0 > t0.txt
for launch in $(seq 1 "$LAUNCHES"); do
  vid=${VIDEOS[$(( (launch - 1) % ${#VIDEOS[@]} ))]}
  echo "$(date +%s) launch $launch: open $vid in the YouTube app" >> timeline.txt
  S am start -a android.intent.action.VIEW -d "https://www.youtube.com/watch?v=$vid" com.google.android.youtube >/dev/null
  for i in $(seq 1 12); do
    sleep 5
    st=$(S dumpsys media_session | grep -m1 -oE "state=PlaybackState \{state=[0-9]+, position=[0-9]+")
    echo "$(date +%s) launch $launch $vid $st" >> timeline.txt
  done
  adb -s "$SERIAL" exec-out screencap -p < /dev/null > "launch$launch-$vid.png"
  S am force-stop com.google.android.youtube
  echo "$(date +%s) launch $launch: force-stopped" >> timeline.txt
  sleep 5
done
date +%s > t-end.txt

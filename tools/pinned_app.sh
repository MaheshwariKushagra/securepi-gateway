#!/bin/bash
# Step 7.5 pinned-app check on the Lenovo tablet (device 98, enrolled).
cd /Users/maheshwari/blah/eval/results/pinned-app-tablet
S() { adb -s HA13T683 shell "$@" < /dev/null; }
S am force-stop com.google.android.youtube; S am force-stop com.android.chrome
T0=$(date +%s); echo "T0 $T0" > timeline.txt; echo $T0 > t0.txt
for vid in dQw4w9WgXcQ kJQP7kiw5Fk 9bZkp7q19f0; do
  echo "$(date +%s) open $vid in the YouTube app" >> timeline.txt
  S am start -a android.intent.action.VIEW -d "https://www.youtube.com/watch?v=$vid" com.google.android.youtube >/dev/null
  for i in $(seq 1 12); do
    sleep 5
    st=$(S dumpsys media_session | grep -m1 -oE "state=PlaybackState \{state=[0-9]+, position=[0-9]+")
    echo "$(date +%s) $vid $st" >> timeline.txt
  done
  adb -s HA13T683 exec-out screencap -p < /dev/null > $vid.png
done

#!/usr/bin/env python3
"""
Step 7.5's Tier 2 test (ENHANCEMENT-PLAN.md): does a YouTube video in mobile
Chrome start with a pre-roll ad? One condition per run - the gateway side
(phone enrolled for HTTPS inspection or not) is set beforehand.

    adb forward tcp:9222 localabstract:chrome_devtools_remote
    .venv-bench/bin/python tools/youtube_tier2.py CONDITION OUTDIR [VIDEOS_JSON]

Drives the phone's real Chrome over the DevTools protocol (USB, via adb) -
Chrome, not the phone's default browser Brave, which blocks ads itself.
For each video: a new tab on its watch page, a click on the player to start
playback (mobile Chrome won't autoplay with sound), then the player's own
state is read every second for SAMPLE_S seconds. YouTube marks its player
`ad-showing` while an ad plays, and shows a skip button / ad badge; any of
these at any sample means "pre-roll shown". A screenshot is kept for a
person to check the call. One JSON line per video.
"""

import json
import os
import sys
import time

import urllib.request

SAMPLE_S = 15
STATE_JS = """() => {
  const p = document.querySelector('#movie_player, .html5-video-player');
  const v = document.querySelector('video');
  const q = (s) => !!document.querySelector(s);
  return {
    player: !!p,
    ad_showing: !!(p && (p.classList.contains('ad-showing') || p.classList.contains('ad-interrupting'))),
    skip_button: q('.ytp-ad-skip-button, .ytp-skip-ad-button, .ytp-ad-skip-button-modern, .ytp-ad-skip-button-container'),
    ad_badge: q('.ytp-ad-text, .ytp-ad-preview-container, .ytp-ad-badge, .ytp-ad-simple-ad-badge, ytm-ad-badge-renderer, .ytm-promoted-sparkles-text-search-renderer'),
    video: v ? {paused: v.paused, t: Math.round(v.currentTime * 10) / 10, duration: v.duration} : null,
  };
}"""


DEVTOOLS = "http://127.0.0.1:9222"


class Tab:
    """A raw DevTools connection to one Chrome tab. Playwright's own
    connection to Android Chrome only ever listed some of the tabs (after
    three videos it stopped seeing new ones), so the phone is driven with
    the DevTools protocol directly: a few JSON messages over a websocket."""

    def __init__(self, target):
        import websocket
        self.id = target["id"]
        self.ws = websocket.create_connection(target["webSocketDebuggerUrl"], timeout=30, suppress_origin=True)
        self.n = 0

    def call(self, method, **params):
        self.n += 1
        self.ws.send(json.dumps({"id": self.n, "method": method, "params": params}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == self.n:
                if "error" in msg:
                    raise RuntimeError(msg["error"].get("message"))
                return msg.get("result", {})

    def evaluate(self, js):
        r = self.call("Runtime.evaluate", expression="(%s)()" % js, returnByValue=True, awaitPromise=True)
        return r.get("result", {}).get("value")

    def screenshot(self, path):
        import base64
        data = self.call("Page.captureScreenshot", format="png")["data"]
        with open(path, "wb") as f:
            f.write(base64.b64decode(data))

    def close(self):
        self.ws.close()
        urllib.request.urlopen("%s/json/close/%s" % (DEVTOOLS, self.id), timeout=5).read()


def find_target(vid, timeout_s=20):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        with urllib.request.urlopen(DEVTOOLS + "/json/list", timeout=5) as r:
            for t in json.load(r):
                if t.get("type") == "page" and vid in t.get("url", ""):
                    return t
        time.sleep(1)
    return None


START_JS = """() => {
    const mp = document.getElementById('movie_player');
    if (mp && mp.playVideo) { if (mp.mute) mp.mute(); mp.playVideo(); return 'player-api'; }
    const v = document.querySelector('video');
    if (v) { v.muted = true; v.play(); return 'video-element'; }
    return 'none';
}"""


def run_video(vid, outdir):
    """The page is opened the ordinary way - an Android VIEW intent to
    Chrome - because tabs created over DevTools could not resolve any name
    on this phone (every navigation failed with ERR_NAME_NOT_RESOLVED,
    while the same URLs opened by intent loaded). DevTools then starts
    playback through YouTube's own player API (muted: Android Chrome won't
    start sound without a real tap, muted playback needs none) and reads
    the player's state once a second."""
    import subprocess
    rec = {"id": vid, "t": time.time(), "samples": []}
    subprocess.run(["adb", "shell", "am", "start", "-a", "android.intent.action.VIEW", "-d",
                    "https://m.youtube.com/watch?v=" + vid, "com.android.chrome"], capture_output=True)
    target = find_target(vid)
    if target is None:
        rec["error"] = "tab not found"
    else:
        tab = None
        try:
            tab = Tab(target)
            time.sleep(4)
            rec["url"] = target.get("url")
            rec["start"] = tab.evaluate(START_JS)
            for i in range(SAMPLE_S):
                time.sleep(1)
                rec["samples"].append(tab.evaluate(STATE_JS))
                if i == 4:
                    try:
                        tab.screenshot(os.path.join(outdir, vid + ".png"))
                    except Exception:
                        rec["screenshot"] = "failed"
        except Exception as e:
            rec["error"] = str(e).splitlines()[0][:160]
        finally:
            if tab is not None:
                try:
                    tab.close()
                except Exception:
                    pass
    s = [x for x in rec["samples"] if x]
    rec["preroll_shown"] = any(x["ad_showing"] or x["skip_button"] or x["ad_badge"] for x in s)
    rec["played"] = any(x["video"] and not x["video"]["paused"] and x["video"]["t"] > 0 for x in s)
    return rec


def main():
    condition, outdir = sys.argv[1], sys.argv[2]
    videos_path = sys.argv[3] if len(sys.argv) > 3 else "eval/youtube-videos.json"
    with open(videos_path) as f:
        videos = [v["id"] for v in json.load(f)["videos"]]
    outdir = os.path.join(outdir, condition)
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "results.jsonl"), "a") as out:
        for vid in videos:
            rec = run_video(vid, outdir)
            rec["condition"] = condition
            out.write(json.dumps(rec) + "\n")
            out.flush()
            print("%s %s preroll=%s played=%s %s" % (condition, vid, rec["preroll_shown"], rec["played"],
                                                   rec.get("error", "")), flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()

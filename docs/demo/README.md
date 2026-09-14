# Demo console (README screenshots)

Every console screenshot in the top-level README comes from these three files.
They run the **real, unmodified** console (`app/webapp.py`) on the Mac against a
**synthetic** database, so the images never contain real people's devices or
browsing.

| File | What it does |
|---|---|
| `seed.py` | Builds `securepi.db`: invented devices on `10.10.0.0/24`, 36 hours of flows, DNS, TLS and Tier 2 events, 9 days of hourly baselines, and a scripted attack (a new `kali` host port-scanning and SSH brute-forcing the NAS). The live incidents are raised by running the project's own `correlation.run_all()` over that data — not typed in by hand. |
| `serve.py` | Starts the console on `http://127.0.0.1:8765` (user `securepi`, password `demo`). Things that only exist on the gateway — AdGuard Home's API, nftables sets, the inspection CA — are replaced with small in-memory stand-ins. Also runs the same 15-second engine loop the gateway does. |
| `shoot.js` | Opens each page in a headless Chromium browser (Chrome, Brave or Chromium) and saves a 2× screenshot. |

```bash
cd docs/demo
npm install puppeteer-core@23          # once
python3 seed.py                        # rebuild the synthetic database
python3 serve.py &                     # start the demo console
node shoot.js ../assets/screenshots    # capture every page
for f in ../assets/screenshots/*.png; do sips --resampleWidth 2000 "$f"; done   # macOS: shrink for the repo
```

Run `seed.py` right before `shoot.js`: detection windows are measured from "now",
so a stale database shows older-looking incidents.

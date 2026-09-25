# eval/ - Stage 7 evaluation inputs and results

| Folder | What | In git? |
|---|---|---|
| `labels/` | Ground truth for each capture: which host is which, and what should be detected when | yes |
| `results/` | Result files from the battery (7.2) and the replay (7.1) | yes |
| `pcaps/` | The captures themselves | **no** - third-party data, and large |
| `rules/` | A copy of the gateway's Suricata rule set | **no** - large, and rebuilt daily |
| `replay-out/` | Scratch output of `tools/replay.py` (eve.json, a database) | no |

## Setting up the inputs on a fresh Mac

1. `brew install suricata` (the replay was built against 8.0.7).
2. Copy the gateway's rules:
   ```
   mkdir -p eval/rules
   scp maheshwari@192.168.2.5:/var/lib/suricata/rules/suricata.rules eval/rules/
   scp maheshwari@192.168.2.5:/etc/suricata/classification.config eval/rules/
   ```
3. Download the public captures into `eval/pcaps/public/` from the URLs in
   the labels files, then check each one's sha256 matches the `sha256`
   field in its labels file (`shasum -a 256 eval/pcaps/public/*.pcap`).
   A different hash means a different capture, and the results won't
   compare.

## Running a replay

```
python3 tools/replay.py eval/pcaps/public/botnet-capture-20110816-donbot.pcap \
    eval/labels/ctu13-scenario6-donbot.labels.json
```

The last line printed is a sha256 over the whole result. Same capture, same
rules and same code give the same hash, so if it changes, one of the three
changed. The full result is in `eval/replay-out/<capture>/result.json`.

## Public data used

CTU-13 dataset, scenarios 6 (DonBot) and 7 (Sogou), Stratosphere Laboratory,
Czech Technical University in Prague. Licence: CC BY 2.0. Cite as: Garcia,
S., Grill, M., Stiborek, J. and Zunino, A. (2014) 'An empirical comparison
of botnet detection methods', *Computers and Security* 45, pp. 100-123.

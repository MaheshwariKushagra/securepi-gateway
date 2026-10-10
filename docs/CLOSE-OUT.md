# SecurePi Gateway: close-out (step 8.4)

This runbook removes what the project left behind that should not outlive it: decrypted-request URLs
in the journal, an inspection CA trusted by a phone, test-account sessions, and the Dell's test browser
profile. Every item has a read-only check, the exact command, how to verify it, and whether it can be
undone.

> **Not executed.** Most of these commands are destructive. They were written and pre-checked on
> 10 October 2026 but **not run**: the operator runs them, or confirms each one first. The pre-check
> values below are from 10 Oct 2026 at about 14:25 IST.
>
> **Run the demo first** (`docs/DEMO.md`): items 3, 4 and 5 remove what its Instagram segment needs.

Order matters. Ending the enrolments and logging the accounts out (items 1-3) come before deleting
anything (items 4-7), and the journal purge (item 7) comes last, so it also removes anything logged
along the way.

| # | Item (plan 8.4) | Destructive | Can it be undone? | Done by |
|---|---|---|---|---|
| 1 | End every Instagram/Facebook enrolment | no | yes: enrol again | gateway |
| 2 | Stop the Dell test browser and test proxy | no | yes: start them again | gateway |
| 3 | Log the test accounts out of their other sessions | no (server side) | sign in again | you, on the accounts |
| 4 | Delete `~/securepi-browser` | **yes** | **no** | gateway |
| 5 | Remove the demo CA from the phone | yes (on the phone) | reinstall it from `http://10.10.0.1:8081/securepi-ca.crt` while the CA still exists | you, on the phone |
| 6 | Rotate or destroy the DPI CA (if the project is paused) | **yes** | **no**: devices must install a new CA | gateway |
| 7 | Purge the journal | **yes** | **no** | gateway |
| 8 | Optional leftovers (not in the plan) | some | see the item | gateway / Mac |

All gateway commands run over `ssh -t maheshwari@192.168.2.5`.

---

## 1. End every Instagram/Facebook enrolment

**Pre-check, 10 Oct 14:25:** nothing is enrolled. `ip nat enrolled` has no elements, and
`/var/lib/securepi-dpi/device-sites.json` is `{}`.

```bash
sudo nft list set ip nat enrolled                     # look for an "elements = { ... }" line
sudo cat /var/lib/securepi-dpi/device-sites.json      # {} when nobody is enrolled
```

If anything is enrolled, end it through the console, so the policy is ended and audited: each
device's page → **Enrolled · Unenroll**. Or from the command line:

```bash
sudo securepi unenroll all
```

**Verify:** both commands above show nothing enrolled. The console's Response page has no active
"HTTPS inspection" policy. The decision log stops growing:
`sudo tail -n 3 /var/log/securepi/dpi-events.jsonl`.

## 2. Stop the Dell test browser and test proxy

7A measured Instagram and Facebook in a headless Chromium on the Dell, through a separate test
proxy, both started by hand from `~/securepi-browser`. Neither is a systemd unit.

**Pre-check, 10 Oct 14:25:** neither is running. `pgrep -af "testproxy|mitmdump.*test|chrom|playwright"`
prints nothing, and no `securepi-test*` unit exists apart from the harness.

```bash
pgrep -af "testproxy|mitmdump.*test|chrom|playwright"     # expected: nothing
# if anything is listed:
pkill -f testproxy.py; pkill -f 'securepi-browser/venv'; sleep 2
pgrep -af "testproxy|mitmdump.*test|chrom|playwright"     # nothing
```

## 3. Log the test accounts out of their other sessions

This is done on the accounts themselves, from any browser where you are signed in to the **test**
accounts:

- **Instagram:** Settings → Accounts Center → Password and security → Where you're logged in →
  the account → select every session → **Log out**.
- **Facebook:** the same path in Accounts Center.
- **Then change both test passwords.** The sessions in `~/securepi-browser` and on the phone then
  cannot be resumed even from a copy.
- Sign out in the phone's Chrome too (instagram.com → profile → Settings → Log out).

No credential for these accounts is stored in the repository or on the gateway, apart from the
browser profiles that item 4 deletes.

## 4. Delete `~/securepi-browser` on the Dell

**Pre-check, 10 Oct 14:25:** 1.8 GB. It contains:

- `profile/` and `profile155/`: Chromium profiles with the test accounts' session cookies;
- `test-ca/`: the test proxy's CA, **including its private key**, `mitmproxy-ca.pem`;
- `test-dpi-events.jsonl`: the test proxy's decision log;
- `testproxy.py`, `test-rules.json`, `test-sites.json` (+ `.bak-7B5`), `test-rule-stats.json`;
- `venv/` and `__pycache__/`.

Nothing outside this directory trusts its test CA: only the headless browser in it did. Copy anything
you want to keep first. The measurement results are already in the repository (`eval/results/`).

```bash
du -sh ~/securepi-browser && ls ~/securepi-browser
rm -rf ~/securepi-browser                  # IRREVERSIBLE
ls -d ~/securepi-browser                   # expected: No such file or directory
```

## 5. Remove the demo CA from the phone

The phone trusts the gateway's inspection CA: **"SecurePi Gateway"** (O = SecurePi Gateway,
OU = Network Security Platform), valid to 9 Sep 2036, SHA-256 fingerprint
`64:AC:B0:EF:8D:30:DA:08:5A:91:60:6B:86:E6:C9:63:1B:55:E9:2A:6B:F8:B8:06:3D:90:AD:FE:AE:71:86:95`.
Anyone holding that CA's key could read the phone's HTTPS traffic, so it must not stay installed
after the project.

On the Samsung A33 (One UI): Settings → Security and privacy → More security settings → View
security certificates → **User** → "SecurePi Gateway" → **Remove**. (Or: Settings → search "User
certificates".)

**Verify:** the User tab no longer lists it. A user CA cannot be removed through `adb` without root,
so this is done by hand.

The **console's** CA ("SecurePi Console CA", valid to 17 Sep 2036) holds no power over anyone's
traffic: it only vouches for the console's own address. If you trusted it on the Mac and the project
is paused, remove it too:

```bash
sudo security delete-certificate -c "SecurePi Console CA" /Library/Keychains/System.keychain
```

## 6. Rotate or destroy the DPI CA (if the project is paused)

Choose **one**.

**6a. Destroy: the gateway stays, without HTTPS inspection.**

```bash
sudo securepi unenroll all
sudo systemctl disable --now securepi-dpi securepi-ca-server securepi-privacy-canary
sudo shred -u /opt/securepi-dpi/ca/mitmproxy-ca.pem                     # the private key; IRREVERSIBLE
sudo rm -f /opt/securepi-dpi/ca/mitmproxy-ca-cert.pem /opt/securepi-dpi/ca/mitmproxy-dhparam.pem \
           /var/www-ca/securepi-ca.crt
```

Consequence: `/opt/securepi/services.list` names those three services as always-on. `securepi status`
and the console's health supervisor will then report them as down (a `platform_service_down`
incident). To avoid that, also remove the three lines `securepi-dpi`, `securepi-privacy-canary` and
`securepi-ca-server` from `/opt/securepi/services.list` (keep a `.bak` copy). The repository copy,
`app/services.list`, stays as it is.

**6b. Rotate: inspection continues with a new CA.** Every device must then install the new CA.

```bash
sudo securepi unenroll all
sudo systemctl stop securepi-dpi
sudo mv /opt/securepi-dpi/ca /opt/securepi-dpi/ca.retired-$(date +%Y%m%d)
sudo systemctl start securepi-dpi && sleep 6                              # mitmproxy creates a new CA
sudo install -m 644 -o root -g root /opt/securepi-dpi/ca/mitmproxy-ca-cert.pem /var/www-ca/securepi-ca.crt
sudo openssl x509 -in /var/www-ca/securepi-ca.crt -noout -fingerprint -sha256   # a NEW fingerprint
sudo shred -u /opt/securepi-dpi/ca.retired-*/mitmproxy-ca.pem && sudo rm -rf /opt/securepi-dpi/ca.retired-*
```

Note: the new CA is mitmproxy's own, named "mitmproxy" (CN and O). The current CA's "SecurePi
Gateway" subject was made by hand when the CA was created. No script in the repository makes it
(`STAGE8-RECORD.md` M-18), so on the phone the new certificate is listed as "mitmproxy".

**6c. Power the gateway off** (a full pause). The CA key stays on the disk. Do 6a first if the
machine is going to someone else.

## 7. Purge the journal

**Pre-check, 10 Oct 14:25:**

- The journal is persistent (`/var/log/journal`), 430.2 MB, 21 boots from 12 Sep 03:51 to now.
- It still holds **9,228 decrypted-request URL lines** from `securepi-dpi`: mitmdump's default output
  before 7B.5 set `flow_detail=0`.
  - By day: 12 Sep 4,065 · 26 Sep 94 · 2 Oct 1,515 · 3 Oct 56 · 9 Oct 923 · 10 Oct 2,575.
  - The last one is at 10 Oct 03:40:35; none since.
  - The report's figure of 5,163 is exactly the 14 days it names (26 Sep-10 Oct). The 4,065 lines
    from 12 Sep come on top (`STAGE8-RECORD.md` M-17).

Count them yourself (this prints only counts, never a URL):

```bash
journalctl --disk-usage
sudo journalctl -u securepi-dpi --no-pager -o short-iso | grep -E "\]: [0-9.:]+: (GET|POST|PUT|HEAD|OPTIONS) https?://" | awk '{print substr($1,1,10)}' | sort | uniq -c
```

The purge deletes **every** journal entry of **every** service, not only the proxy's: boot logs,
sudo history, and the logs some evaluation write-ups quote. The evaluation results themselves are in
`eval/results/` and the database, not the journal.

```bash
sudo journalctl --rotate                 # close the active files so they can be removed
sudo journalctl --vacuum-time=1s         # IRREVERSIBLE: removes every archived journal file
```

**Verify:**
- `journalctl --disk-usage` shows a few MB at most (only what was logged since).
- The count command above prints nothing.
- `sudo journalctl --list-boots | wc -l` is 1 or 2.

## 8. Optional leftovers (not in the plan; decide each one)

| Leftover | Found on 10 Oct | Command | Note |
|---|---|---|---|
| Evaluation run monitor | `securepi-run-monitor` enabled and active | `sudo systemctl disable --now securepi-run-monitor` | reversible |
| Pre-change database backups | `/var/lib/securepi/securepi.db.pre-battery-cleanup-20261002-170751.bak` (29 MB), `.pre-lease-fix-20261002-183049.bak` (34 MB), `.pre-stage7-fixes-20261003-084949.bak` (274 MB). They hold old device events. | `sudo rm /var/lib/securepi/securepi.db.pre-*.bak` | **irreversible** |
| Code backups in `/opt/securepi` | 10 files, e.g. `webapp.py.bak-5.10-20260913-165126`, `registry.py.bak-7B-g4-20261010-083944` | `sudo find /opt/securepi -maxdepth 1 -name '*.bak*' -print -delete` | only old code |
| Tier 2 decision log | `/var/log/securepi/dpi-events.jsonl`: device address, hostname and decision per connection (912 KB, no URLs) | `sudo truncate -s 0 /var/log/securepi/dpi-events.jsonl` | **irreversible** |
| DNS query log | `/opt/AdGuardHome/data/querylog.json`, 36 MB: every device's DNS queries | the DNS filter's admin page (§7.3 of `docs/INSTALL.md`) → Settings → General → **Clear query log** | **irreversible** |
| Installer check copy | `~/securepi-install-check` on the Dell (made in 8.2) | `rm -rf ~/securepi-install-check` | a copy of the repo |
| Detection battery output | `/var/tmp/securepi-battery`, 4.8 MB | `sudo rm -rf /var/tmp/securepi-battery` | results already in `eval/results/` |
| Mac: console tunnel | `./mac-tunnel.sh status` | `./mac-tunnel.sh stop` | |
| Mac: the A33 session's git worktree | `.claude/worktrees/a33-checks` (branch `worktree-a33-checks`, locked, at `cd291d4`, already merged) | `git worktree unlock .claude/worktrees/a33-checks && git worktree remove .claude/worktrees/a33-checks && git branch -d worktree-a33-checks` | the commits are on `main` |

---

## Record

After running, note here (or in `STAGE8-RECORD.md`) what was done, when, and the verification output.

| # | Done (date, time) | By | Verification |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |
| 6 | (a / b / c) | | |
| 7 | | | |
| 8 | (which) | | |

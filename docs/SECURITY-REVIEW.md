# SecurePi Gateway — Security Self-Review

**ENHANCEMENT-PLAN.md step 3.4.** Scope: CSRF, XSS, SQL/command injection,
secrets in logs, `pip-audit`, WAN exposure — the plan's own named categories.
Exit criterion: no unmitigated high findings. Performed 20 September 2026,
against the live gateway and the full `app/`/`gateway/`/`dpi/` source, after
Stage 3 steps 3.1–3.3 (session auth, TLS, privilege separation) had already
landed — each of those closed a specific finding this review would otherwise
have raised on its own (Basic Auth, plaintext HTTP, root web process).

Every finding below states what was actually checked and how, not just a
conclusion — several fixes were verified live, not just applied.

---

## 1. CSRF

**Checked:** the session cookie's attributes (`app/webapp.py`'s `/login`
handler) and the Origin check (`app/session_auth.py`'s
`origin_is_allowed()`, wired into `session_auth_middleware`).

**Finding: none.** Two independent layers, deliberately not just one:

- `SameSite=Strict` on `sp_session` means the cookie is never attached to a
  cross-site request at all — a forged form on another page, submitted to
  this console from a victim's browser, arrives with no session cookie and
  is treated as unauthenticated.
- An explicit Origin check on every state-changing request (`POST`/`PUT`/
  `PATCH`/`DELETE`), rejecting a mismatched Origin header with 403 *before*
  authentication is even checked — defense in depth for a browser or proxy
  that doesn't honour `SameSite`, not the only thing standing between a
  cross-site page and this console. **Verified live** (step 3.1): a `POST
  /login` with `Origin: http://evil.example` returns 403 against the real
  gateway.

## 2. XSS

**Checked:** every Jinja2 template for `| safe`/`{% autoescape false %}`
(none found; Starlette's `Jinja2Templates` has autoescape on by default for
`.html` files, confirmed by instantiating it and reading `env.autoescape`),
and `app/static/app.js`'s 91 `innerHTML` assignment sites for any field that
could plausibly hold network- or attacker-observed text (device hostname,
DNS query domain, TLS SNI, blocked-rule text) rendered without escaping.

**Method:** a script-assisted sweep (extracting every `${...}` template-literal
expression and flagging ones with a property access but no `esc(` call),
followed by manual reading of every genuinely data-derived hit — the device
list, the Hunt page's event feed, top-destinations and saved searches, the
Settings thresholds table, and the dashboard's recent-events panel. The
sweep's raw output had ~107 "suspicious" entries; nearly all were false
positives from the script's inability to parse nested template literals
(e.g. `${esc(\`${e.time}|${e.detail}\`)}`, where the outer `esc()` covers
everything inside it) or were plainly safe (numeric counts, booleans,
CSS-class ternaries, hardcoded UI labels).

**Finding: none.** `esc()` (a small, correct HTML-entity-escaping function
in `app.js`) is used consistently everywhere a hostname, domain, SNI value,
or other network-observed string is interpolated into `innerHTML`,
including inside HTML attributes (`title="${esc(...)}"`,
`data-pivot-domain="${esc(...)}"`) where an unescaped `"` could otherwise
break out of the attribute. `toast()`'s message content uses
`.textContent`, not `innerHTML`, for the same reason. This was checked
directly in the source, not inferred from the pattern holding in a few
samples.

**Fixed anyway, as defense in depth, not because a gap was found:**
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and
`Referrer-Policy: no-referrer` are now set on every response
(`security_headers_middleware`, registered to wrap outside the auth
middleware so it also covers 401s and redirects). `X-Frame-Options`
specifically closes a clickjacking angle `SameSite=Strict` already mostly
covers (a cross-site iframe wouldn't carry the session cookie either) but
costs nothing to also state explicitly at the framing level. `make test`:
3 new structural tests (`tests/test_security_headers.py`).

## 3. SQL injection

**Checked:** every `.execute(` call across `app/*.py` for string
concatenation, `%`-formatting, or f-strings that place a *value* (as
opposed to a fixed clause fragment) directly into SQL text rather than
through a bind parameter.

**Method:** grepped for `execute(f"`, `execute(f'`, `") % `, and
`execute(... + `, then read every match. Two real patterns exist, both
already safe:

- `app/correlation.py`'s `dns_bypass_signal`/`brute_force_signal` build an
  `IN (?,?,?...)` placeholder string via an f-string (`",".join("?" for _
  in CANARY_DOMAINS)`) — the f-string only ever inserts a *count* of `?`
  marks derived from a fixed, hardcoded module-level tuple
  (`CANARY_DOMAINS`, `KNOWN_DOH_PROVIDER_SNIS`, `AUTH_PORTS`), never
  user input; the actual values are passed as bind parameters via
  `(*CANARY_DOMAINS, ...)`. Confirmed each constant is a hardcoded
  Python literal, not runtime-editable.
- `app/webapp.py`'s `/api/hunt` (`_hunt_where()`) builds a dynamic `WHERE`
  clause the same way — a list of fixed fragments (`"e.device_id = ?"`,
  `"(e.src_ip = ? OR e.dest_ip = ?)"`) joined with `" AND "` and inserted
  into the query text via `%s % where_sql`, while every actual filter
  value (`ip`, `domain`, `port`, `event_type`, `device_id`) goes into the
  separate `params` list. Read `_hunt_where()` in full to confirm no
  filter value ever reaches the clause-fragment list itself, only the
  params list.

**Finding: none.** Every place SQL text is assembled dynamically only ever
assembles *structure* (which fixed clauses apply), never a value; every
value is a bind parameter. `app/settings.py`'s `/api/settings/{key}`
additionally allowlists `key` against `SETTINGS_SCHEMA` before it ever
reaches a query, on top of already using `WHERE key=?`.

## 4. Command injection

**Checked:** every `subprocess` call and every shell script for `shell=True`,
`os.system()`, `os.popen()`, and unquoted variable expansion.

**Method:** `grep -rn "shell=True\|os.system(\|os.popen("` across
`app/`, `dpi/`, `gateway/` (zero matches — every subprocess call in this
project uses the list-argument form, which never invokes a shell to
interpret its arguments), then installed `shellcheck` (via Homebrew,
not previously on this Mac) and ran it against every `.sh` file and the
three extensionless scripts (`gateway/securepi`,
`gateway/securepi-add-uplink`, `gateway/securepi-ap-follow-uplink`).

**Finding: two trivial, low-severity shellcheck warnings, both fixed:**

- `gateway/setup-test-harness.sh`: an unquoted loop variable
  (`10.10.0.$i/24`) in a `for i in $(seq 222 230)` loop — `$i` is always a
  small integer the script generates itself, never external input, so this
  was never exploitable, but quoted it anyway (`"10.10.0.$i/24"`).
  SC2086.
- `session-start.sh`: `cd "$(dirname "$0")"` without a `|| exit` fallback —
  fixed to `cd "$(dirname "$0")" || exit 1`. SC2164.

Every other script (all of `gateway/`, `dpi/deploy-dpi.sh`,
`mac-tunnel.sh`, this session's own new `generate-console-tls.sh` and
`setup-privilege-separation.sh`) produced zero shellcheck findings.

`gateway/securepi-web-helper` (step 3.3) additionally validates every
argument it's given (`ipaddress.ip_address()`, a bounded integer range)
before building an `nft` argv list, and never uses a shell either — see
`EVALUATION-RESULTS-2.md` §3.3 for the injection-shaped strings tested
directly against it.

## 5. Secrets in logs

**Checked:** every `print()`, `audit.log()`, and `syslog.syslog()` call
across `app/*.py` and `gateway/securepi-web-helper` for a password, hash,
or session-token value being logged rather than just the *fact* that an
action happened.

**Finding: none.** `settings.password_change`'s audit row and print line
both say only that a change happened
(`detail="password changed (value not logged)"`); `auth.login`'s audit
detail is `ip=<address>`, never the password; the privileged helper's
syslog lines log the verb and argument (an IP, an hour count), never a
password or session token, since it never handles either.

## 6. Dependency vulnerabilities (`pip-audit`)

**Not previously run in this project** — `pip-audit` wasn't installed on
either machine. Installed on the Mac (`pip3 install --user pip-audit`);
the gateway has **no `pip` at all** (`python3-fastapi` etc. are installed
via `apt`/`dpkg`, not `pip` — confirmed with `python3 -m pip --version` →
"No module named pip"), so the gateway's *exact* installed versions were
read via `dpkg -l`/`python3 -c "import X; print(X.__version__)"` and
audited from the Mac against those precise version numbers, one package
at a time (auditing them together hit real dependency-resolution
conflicts pip-audit's install step couldn't work around).

| Package (gateway version) | Known CVEs | Fix version | Reachable from this app? |
|---|---|---|---|
| fastapi 0.101.0 | PYSEC-2024-38 | ≥0.109.1 | Yes — the web framework itself |
| starlette 0.31.1 | 7 advisories (PYSEC-2026-161/248/249/1941/1943/2280/2281) | ≥1.3.1 for all | Yes — FastAPI's own base |
| h11 0.14.0 | PYSEC-2026-348 | ≥0.16.0 | Yes — uvicorn's HTTP/1.1 layer, every request |
| anyio 4.2.0 | GHSA-82r6-8w77-94w6, GHSA-5p39-cfhj-2xmp | ≥4.14.2 | Yes — Starlette's async layer |
| jinja2 3.1.2 | 5 advisories (PYSEC-2026-1471/1472/1473/1474/1475) | ≥3.1.6 | Yes — every template render |
| cryptography 41.0.7 | 9 advisories, several rated high | up to 49.0.0 | Yes — TLS/certificate handling (mitmproxy, `python3-openssl`) |
| click 8.1.6 | PYSEC-2026-2132 | ≥8.3.3 | Only at process **startup** (uvicorn's own CLI parsing) — not attacker-reachable, since the command line is fixed by the systemd unit, not user input |
| python-multipart 0.0.9 | 7 advisories | up to 0.0.31 | **No** — confirmed this project never calls `request.form()` (step 3.1's own finding; `parse_qs` is used instead specifically to avoid this dependency) |
| requests 2.31.0 / urllib3 2.0.7 | several | ≥2.32.4/2.33.0, ≥2.6.0+ | **No** — confirmed neither is imported anywhere in `app/`, `dpi/`, or `gateway/`; present only as a transitive `apt` dependency of unrelated system tooling |
| pydantic 1.10.14 | none found | — | Yes, but clean |

**Assessment, not a blanket "critical, fix everything":**

- **Real, and the biggest single factor lowering actual risk: this console
  is not reachable from the WAN or the internet at all** (see §7) — the
  realistic threat model is a device already on `SecurePi-Test`, not an
  anonymous internet attacker, which narrows what "exploitable" means for
  every row above.
- **Structural finding, not something this review can fix by itself:**
  Ubuntu 24.04's own `noble`/`noble-updates`/`noble-security` repositories
  — checked directly with `apt-cache policy` for the highest-risk
  packages — do not currently offer newer versions than what's installed.
  Ubuntu's security team has not (yet, as of this review) backported
  fixes for these specific CVEs into the LTS-frozen package versions.
  Moving off `apt`-managed versions would mean introducing `pip` onto a
  gateway that deliberately has none today, mixing package managers, and
  taking on independent update tracking for exactly the packages this
  review just flagged — a bigger, separate decision than this step's own
  scope, recorded here rather than done unilaterally.
- **python-multipart and requests/urllib3 findings are not real exposure**
  for this deployment specifically, confirmed by checking actual usage,
  not just installed-version tables.
- **click's CVE is not attacker-reachable** here specifically, since the
  vulnerable surface (its own CLI argument parsing) only ever processes
  the fixed argv this project's own systemd unit supplies.
- **fastapi/starlette/h11/anyio/jinja2/cryptography remain a real,
  standing gap** this review could not close within its own scope (an
  `apt`-only upgrade path with no newer packages available, and a
  framework-version bump risks breaking API compatibility across a large
  codebase without the kind of dedicated regression pass that would
  deserve its own step, not a same-day addition to a review). **Recorded
  as the one open item this review did not fully close** — see "Not
  fixed" below.

## 7. WAN exposure

**Checked:** every TCP listener on the gateway not bound to loopback
(`sudo ss -tlnp`), cross-referenced against which interface is the WAN
uplink (`wlp2s0`, the home Wi-Fi) versus the isolated project LAN (`ap0`,
`10.10.0.1`) versus the management link (`enp1s0`, `192.168.2.5`).

**Finding: two real WAN-facing services, both found live and fixed:**

- **`mitmdump` (the Tier 2 HTTPS-inspection proxy) listened on
  `0.0.0.0:8080`** — every interface, including the WAN Wi-Fi uplink —
  when the nftables redirect rule that feeds it
  (`iifname "ap0" ip saddr @enrolled tcp dport 443 ... redirect to :8080`)
  only ever needs it reachable from `ap0`'s own address. `redirect`
  targets the local address a packet actually arrived on, which for
  `ap0`-sourced traffic is `10.10.0.1`, never the WAN address — so
  narrowing the listener doesn't change what real traffic can reach it.
  **Fixed**: `--listen-host 10.10.0.1` in both the live unit and
  `dpi/deploy-dpi.sh`'s tracked copy. **Verified live**: `ss -tlnp` after
  the restart shows `10.10.0.1:8080` only; the nftables rule and its
  comment (`dpi-redirect`) are unchanged and still present. **Not fully
  verified**: an actual redirected connection reaching the relocated
  listener — the same `ap0`-isolation limitation already documented for
  step 5.7 (the test harness's namespaces sit on `br-test`, not `ap0`,
  and using a real enrolled device wasn't available this session without
  disrupting real traffic). The fix is structurally sound (the new bind
  address is exactly the redirect's own implicit target) but this specific
  path should get a deliberate manual check the next time a device is
  actually enrolled.
- **`sshd` listened on `0.0.0.0:22` with `PasswordAuthentication yes`** —
  reachable from the WAN Wi-Fi network, with password guessing possible
  in addition to key-based login. Checked `~/.ssh/authorized_keys` first
  (one key present) and confirmed empirically that this entire session's
  SSH access already worked via key auth throughout, with no password
  ever prompted — disabling password auth could not lock out the actual
  access method in use. **Fixed**: a new
  `/etc/ssh/sshd_config.d/10-securepi-harden.conf` (named to sort before
  the existing `50-cloud-init.conf`, which still sets
  `PasswordAuthentication yes` and would otherwise silently win under
  OpenSSH's first-match-wins config semantics) sets
  `PasswordAuthentication no`. **Verified live**: `sudo sshd -t` passed
  before the reload; after reloading, a fresh connection with
  `-o PubkeyAuthentication=no -o PreferredAuthentications=password`
  was refused ("Permission denied (publickey)"), while an ordinary
  key-based connection succeeded immediately afterward. `sshd`'s own
  WAN-facing bind address (`ListenAddress`) was deliberately **left
  unchanged** — restricting *which interface* SSH listens on, on a
  gateway whose only non-physical administrative access is SSH, was
  judged too high a lockout risk to change without the user doing it
  themselves (this project's own standing rule for system-level access
  changes), even though key-only auth already closes most of the
  practical risk that binding change would have addressed.
- Every other listener (the console at `10.10.0.1:8000`, the DPI CA
  download server at `10.10.0.1:8081`, AdGuard DNS at `10.10.0.1:53`,
  `systemd-resolved`'s stub listeners on loopback) was already correctly
  scoped to an internal interface or loopback — checked, not assumed.

## 8. Stage 4 additions (26 September 2026)

Stage 4 added new privileged operations, outbound network connections and
stored secrets, so each was reviewed on the same terms as sections 1-7.

**Privileged surface.** The helper gained six verbs (`quarantine-mac-add/
-delete/-list`, `blocked-ip-add/-delete/-list`). Each hardcodes its family,
table and set, as before. A MAC must match `^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`,
an IP must parse as IPv4, and a timeout must be 60 s to 30 days. Tested with
injection-shaped input (`"aa:bb:…; flush ruleset"`, `"1.2.3.4 }"`) on the
Mac and live, where the input was rejected and logged. The orchestrator
also refuses to block LAN, loopback, link-local, multicast and reserved
addresses before the helper is ever called. The sudoers rule is unchanged:
still the one program.

**Stored secrets.** Notification channel secrets (a Telegram bot token, an
SMTP password, a webhook signing key) are in the `notification_channels`
table. The API never returns them: `notify.masked_config()` replaces each
secret field with `••••` plus at most its last four characters, and it is
the only form a channel leaves the gateway in. Adding a channel writes an
audit row with its type and name only, never its settings. The database is
`root:securepi` 664, the same trust boundary as the password files in
`/etc/securepi`.

**Backups of that database were world-readable - fixed.** Every
`securepi.db` copy taken before a deploy (eleven of them, in `/opt/securepi`
and the new `/opt/securepi-backups`) was mode 644. Copies from step 3.1 on
include live session tokens, and all of them include the network's device
and DNS history. Any local account could read them. All are now 600 and
`/opt/securepi-backups` is 700; a non-root read was confirmed refused.
Future backups should keep the same modes (`sudo install -m 600` or a
`chmod` straight after the copy).

**Outbound connections.** Notifications are the first feature that sends
data off the gateway on an operator's behalf. HTTPS certificates are
verified (`ssl.create_default_context()`). A channel only sends the
incident title, severity, device name and a console link unless its
"include details" option is on. Webhook bodies can be signed
(HMAC-SHA256, `X-SecurePi-Signature`). A channel URL can point anywhere,
including the gateway itself or the LAN. That is a request-forgery path,
but only for someone already signed in to the console, who can do far more
directly. It is recorded here rather than restricted.

**XSS in the new console code.** Every server-supplied string in the new
pages goes through `esc()`, including policy reasons, device names, channel
summaries and audit details. Raw HTML is only ever built from constants in
`app.js`. The new dialog replaces `window.prompt()`, which had no XSS
exposure but blocked the page.

**Races.** The console and the engine both change the same nftables sets
and AdGuard rule list, and they're serialised by an exclusive `flock` on
`/var/lib/securepi/orchestrator.lock` (moved out of `/opt/securepi` on 26
September - see the audit follow-up below). Without it, a reconcile could remove a
quarantine the console had applied a moment earlier. `securepi-web` could
hold the lock indefinitely and stall the engine's reconcile, but that
process already has every privilege it would take to cause the same harm
another way.

**Lockout.** "Restrict unknown devices" and "Block" only drop *forwarded*
traffic from `ap0`. The input chain (DHCP, DNS, the console) and the
management link are untouched, so no trust setting can lock the operator
out of the console.

## Not fixed, named rather than implied

- **The framework-level `pip-audit` findings in §6** (fastapi, starlette,
  h11, anyio, jinja2, cryptography) remain open. Ubuntu's own repos don't
  yet offer newer versions; a pip-based override would be a separate,
  larger decision (introducing `pip` to a gateway that has none, and the
  regression risk of a framework-version bump) that deserves its own
  scoped step rather than a same-day addition here. The real-world risk
  is meaningfully lower than the raw CVE count suggests, given this
  console has no WAN exposure and no untrusted multi-tenant users — but
  it is a genuine, standing gap, not a false positive like the
  python-multipart/requests findings.
- **The relocated mitmproxy listener's real redirect path** (not just its
  bind address) wasn't exercised by real `ap0` traffic this session, for
  the same reason step 5.7's own privacy-scope canary couldn't be either
  — recorded as a follow-up manual check, not silently assumed correct.
- **SSH's `ListenAddress`** stays `0.0.0.0` (the WAN Wi-Fi can still reach
  port 22), a deliberate choice to leave a lockout-risk system-access
  change to the user rather than do it autonomously, even though password
  auth (the more meaningfully exploitable half of that exposure) is now
  disabled.

None of the above is assessed as a currently-unmitigated **high** finding
against this project's actual deployment (no WAN exposure to the console
itself, key-only SSH, every genuinely exploitable local vector — CSRF,
XSS, SQL/command injection, credential handling — reviewed and found
clean or already fixed by Stage 3's own earlier steps) — this step's exit
criterion is met, with the dependency-version gap and the two "not fixed"
items above carried forward honestly rather than closed out by
overstating what was actually done.

## Audit follow-up (26 September 2026)

An external static audit (`Audit.md`, not committed) was triaged finding by
finding against the code; the accepted fixes are in commits `44c8c6c` to
`5d616fa` and were deployed the same day. The two that change this review's
own conclusions:

- **Code and writable data no longer share a directory.** Step 3.3 made
  `/opt/securepi` and `/opt/securepi-dpi` group-writable (sticky bit) so the
  unprivileged console could write its database and rule set there. The
  root services run Python from those same directories, and Python looks in
  a script's own directory before the standard library, so a compromised
  console could have planted a module (a fake `json.py`) that root would
  run on the next restart - the sticky bit only protects files that already
  exist. The database and orchestrator lock now live in `/var/lib/securepi`,
  the rule set in `/var/lib/securepi-dpi` (both `root:securepi 2770`), and
  both code directories are `root:root 755`
  (`gateway/migrate-data-dirs.sh`). After the move, nothing in either code
  directory was owned by the console's user.
- **Proxied HTTPS now meets the quarantine and block rules.** An enrolled
  device's HTTPS is redirected to the local proxy, so it travelled through
  the input and output chains and never met the forward chain's
  quarantine, blocked-IP and DoH rules. The input chain now repeats those
  checks for port 8080. Verified on a real phone: while quarantined and
  enrolled, 175 of its proxied HTTPS packets were dropped by the new rule.

This also closes the "real redirect path not exercised by `ap0` traffic"
item above - see `EVALUATION-RESULTS-2.md`, "Real-device checks".

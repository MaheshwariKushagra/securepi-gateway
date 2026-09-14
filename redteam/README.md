# SecurePi Gateway — Live Demo Attack Tool

`securepi_attack.py` is a small, self-contained red-team simulator for **demoing
the SecurePi Gateway IDS live**. You run it on a separate laptop that is joined to
the `SecurePi-Test` Wi-Fi; it launches three real attacks at the gateway, and the
SecurePi console detects each one on screen within seconds. Then, when you
quarantine the attacker from the console, the tool visibly gets **blocked** —
proving the system both **detects and stops** an intrusion.

It uses only Python's standard library: **no installs, no admin rights**, and it
runs the same on Windows, macOS, and Linux.

> This is an authorised demo tool for your **own** SecurePi network. It only opens
> ordinary TCP connections plus one benign repeated check-in — no exploitation, no
> password guessing, no malicious payload. Detection is based on the *pattern* of
> connections, so no real attack has to succeed.

---

## What it does

| Stage | Attack | Target | Incident raised on the console |
|------:|--------|--------|--------------------------------|
| (join) | Laptop joins the Wi-Fi | — | `new_device` (Discovery) |
| 1 | Port scan (14 ports) | Gateway `10.10.0.1` | `port_scan` (Discovery / T1046) |
| 2 | SSH brute force (20 attempts) | Gateway `10.10.0.1:22` | `brute_force` (Credential Access / T1110) |
| 3 | C2 beacon (repeats until Ctrl+C) | External `1.1.1.1:443` (through the gateway) | `beacon` (Command & Control / T1071) |

Stage 3 keeps running so you can quarantine the device mid-beacon and watch the
check-ins flip from `OK` to `BLOCKED`.

Each detection appears roughly **15–20 seconds** after its stage (the engine runs
every 15s and the console refreshes every 5s).

---

## Set up the attacker laptop (Windows)

1. Install **Python 3** from <https://www.python.org/downloads/>. On the first
   installer screen, tick **“Add Python to PATH”**, then Install.
2. Copy **`securepi_attack.py`** onto the laptop (USB stick, email to yourself,
   etc.). It’s the only file you need.
3. Open **Command Prompt** or **PowerShell**, `cd` to where you put the file, and
   confirm it runs:
   ```
   python securepi_attack.py --selftest
   ```
   You should see **“SELF-TEST PASSED”**. (On macOS/Linux use `python3` instead of
   `python`.)

---

## Run the demo

```
python securepi_attack.py
```

That’s it — the tool prints a banner, waits ~45 seconds for the gateway to
register the laptop, then runs the three stages and narrates what to watch for.
When you’re done, press **Ctrl+C** to stop the beacon.

Useful options:

| Flag | Purpose |
|------|---------|
| `--selftest` | Prove the tool works on this laptop; no gateway needed. |
| `--settle 0` | Skip the 45s wait (e.g. when re-running). |
| `--gateway <ip>` | Point at a different gateway IP. |
| `--c2 <ip>` `--c2-port <n>` | Change the external beacon target. |
| `--brute-tries <n>` | Number of SSH attempts (default 20). |
| `--beacon-every <s>` | Seconds between beacon check-ins (default 15). |
| `--no-color` | Plain output (for projectors that mangle colour). |
| `--help` | Show everything. |

---

## Pre-demo checklist

1. **Gateway up and services running.** From your Mac:
   ```
   ssh maheshwari@192.168.2.5 'sudo securepi status'
   ```
   Confirm `securepi-ingest`, `securepi-engine`, and `securepi-web` are active.
2. **Console open on the presenter screen.** Either start the tunnel
   (`./mac-tunnel.sh start`, then <http://localhost:8000>) or open
   <http://10.10.0.1:8000> directly on the SecurePi LAN. Log in (`securepi` / the
   console password).
3. **Attacker laptop on the right Wi-Fi.** Join `SecurePi-Test`. Confirm it gets a
   `10.10.0.x` address and shows up as a new device in the console’s Devices page.
4. **Self-test the tool once** on that laptop: `python securepi_attack.py --selftest`.

---

## Demo script (talking points)

1. **“Here’s a brand-new laptop I’m connecting to the network.”** Join
   `SecurePi-Test`. → Point at the console: a **`new_device`** incident appears.
2. **“Now I’ll run an attack from it.”** Run `python securepi_attack.py`. Let the
   settle countdown run.
3. **Stage 1 – port scan.** → **`port_scan`** incident appears (Discovery). “The
   gateway noticed one host touching many ports — classic reconnaissance.”
4. **Stage 2 – brute force.** → **`brute_force`** incident (Credential Access).
   “Now it’s hammering SSH — the system flags a credential attack.”
5. **Stage 3 – C2 beacon.** After ~8 check-ins → **`beacon`** incident (Command &
   Control). “The compromised host is now calling home on a regular heartbeat.”
6. **Stop it.** Open the attacker’s **device page → click Quarantine.** Within a
   few seconds the tool’s check-ins turn **`BLOCKED`**. “The gateway didn’t just
   *see* the attack — it *cut the device off* the network.”
7. Press **Ctrl+C** on the laptop to end.

---

## Reset between runs

- In the console, **release the quarantine** on the attacker device (toggle it
  back off). If the tool is still running, its check-ins return to `OK` — a nice
  way to show the block was live.
- Existing incidents can be left as history or marked resolved. To fire a fresh
  set, just run the tool again (add `--settle 0` to skip the wait).

---

## Troubleshooting

- **“Cannot reach the gateway.”** The laptop isn’t on `SecurePi-Test`, or the
  gateway IP differs — check the Wi-Fi, or pass `--gateway <ip>`.
- **No incidents appear.** Confirm the three `securepi-*` services are running and
  that the laptop shows up as a device in the console (flow-based detections need
  the device to be registered first — that’s what the 45s settle wait is for).
- **The block isn’t visible after quarantine.** The beacon must target an
  **external** address so its traffic passes *through* the gateway (quarantine
  only drops forwarded traffic). The default `1.1.1.1:443` already does this —
  don’t point `--c2` at the gateway itself.
- **Detections are slow or don’t trigger.** Thresholds are tunable from the
  console **Settings** page; you can lower a window/threshold, but the tool’s
  default counts comfortably exceed the defaults.

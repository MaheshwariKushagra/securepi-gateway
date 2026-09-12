# SecurePi Gateway

A unified network monitoring, filtering and security platform for a small-enterprise
network of roughly 15 devices. Final-year engineering project.

The gateway sits between the network and its uplink, providing DNS-based content
filtering for every device, selective HTTPS inspection for enrolled devices, and
a security operations centre built on network telemetry — routing, filtering,
sensing, detection, and a live console are all working; a handful of console-side
controls (quarantine, risk scoring, auth) are still open.

## Status

| Component | State |
|---|---|
| Routed gateway — DHCP, DNS, NAT, Wi-Fi access point | Working |
| DNS filtering — 655,974 rules, bypass prevention | Working |
| Selective HTTPS inspection — first-party ad removal | Working |
| Suricata sensor and event pipeline | Working |
| Device registry and identity resolution | Working |
| Correlation engine — 4 signals, verified against live traffic | Working |
| SOC console — overview, devices, incidents (live, interactive) | Working |
| Filtering page — blocklist management, per-device policy via AdGuard API | Working — verified against live AdGuard on the gateway |
| Quarantine action + undo | nftables `quarantine` set exists; no console control yet |
| Risk scoring | Not started |
| Basic auth on the console | Not started |

## Documents

| File | Contents |
|---|---|
| `SECUREPI-15-DAY-PLAN.md` | Build plan, confirmed topology, scope decisions |
| `GATEWAY-SETUP-RUNBOOK.md` | Host and network setup |
| `STEP-1-INSTALL-UBUNTU.md` | Operating system installation |
| `REPORT-adblocking.md` | Report material for the ad-blocking subsystem |
| `FIRST-PARTY-ADS-ANALYSIS.md` | Analysis of what network-level filtering can and cannot block |
| `dpi/` | Selective HTTPS inspection addon and deployment script |
| `app/` | Ingest pipeline, correlation engine, and the SOC console (FastAPI + Jinja2 + vanilla JS) |

## Architecture

The existing home router is treated purely as an upstream uplink; no configuration
change is required on it. The gateway takes its own internet over Wi-Fi and serves the
project network from an access point on the same radio.

```
Internet -> Home Router -- Wi-Fi --> SecurePi Gateway -- Wi-Fi AP --> test devices
                                     (Dell, Ubuntu 24.04)   10.10.0.0/24
```

## A note on credentials

No keys, certificates or passwords belong in this repository. The certificate authority
used for HTTPS inspection is generated on the gateway and never leaves it. See
`.gitignore`.

## Browsing the console from the Mac

The console is only reachable from the project LAN by default. To view it
from the Mac without joining `SecurePi-Test`:

```
./mac-tunnel.sh start      # then open http://localhost:8000
./mac-tunnel.sh stop
```

Requires the management link (Internet Sharing over the Cat7/USB-C adapter)
to be up.

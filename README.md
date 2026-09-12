# SecurePi Gateway

A unified network monitoring, filtering and security platform for a small-enterprise
network of roughly 15 devices. Final-year engineering project.

The gateway sits between the network and its uplink, providing DNS-based content
filtering for every device, selective HTTPS inspection for enrolled devices, and
(in progress) a lightweight security operations centre built on network telemetry.

## Status

| Component | State |
|---|---|
| Routed gateway — DHCP, DNS, NAT, Wi-Fi access point | Working |
| DNS filtering — 655,974 rules, bypass prevention | Working |
| Selective HTTPS inspection — first-party ad removal | Working |
| Suricata sensor and event pipeline | Not started |
| Device registry and identity resolution | Not started |
| Correlation engine and incident model | Not started |
| SOC console | Not started |

## Documents

| File | Contents |
|---|---|
| `SECUREPI-15-DAY-PLAN.md` | Build plan, confirmed topology, scope decisions |
| `GATEWAY-SETUP-RUNBOOK.md` | Host and network setup |
| `STEP-1-INSTALL-UBUNTU.md` | Operating system installation |
| `REPORT-adblocking.md` | Report material for the ad-blocking subsystem |
| `FIRST-PARTY-ADS-ANALYSIS.md` | Analysis of what network-level filtering can and cannot block |
| `dpi/` | Selective HTTPS inspection addon and deployment script |

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

# Reboot safety: the test harness dependency

Suricata is configured with two capture interfaces: the production `ap0`
(the real project LAN) and `veth-atk`, a virtual interface belonging to an
isolated test-traffic harness used to exercise the correlation engine's
signals safely (see `dpi/` notes and the correlation engine commit for why
this harness exists — real macvlan-to-macvlan traffic turned out to bypass
AF_PACKET capture entirely, and this bridge+veth design was the fix).

Because `veth-atk` only exists once `setup-test-harness.sh` has run, an
earlier version of this setup left it created ad hoc — meaning a reboot
would have started Suricata pointed at an interface that didn't exist yet,
an unverified risk.

Fixed with two systemd units, present on the gateway (not committed here in
full, since they are host configuration, but documented for reference):

- `securepi-test-harness.service` — a oneshot unit, `RemainAfterExit=yes`,
  running `setup-test-harness.sh` (in this directory). Idempotent: checks
  whether `br-test` already exists before creating anything.
- A drop-in at `/etc/systemd/system/suricata.service.d/override.conf` adding
  `After=securepi-test-harness.service` and
  `Wants=securepi-test-harness.service` to the packaged `suricata.service`,
  so the harness is guaranteed to exist before Suricata starts.

Verified with an actual reboot (not just a dry-run of the units): all
eleven gateway services came back active with no manual steps, both
Suricata capture threads (`ap0` and `veth-atk`) started without error, and
the harness's bridge and both network namespaces were present immediately.

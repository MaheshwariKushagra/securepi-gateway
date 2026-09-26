# Reboot safety: the test harness dependency

The IDS is configured with two capture interfaces: the production `ap0`
(the real project LAN) and `veth-atk`, a virtual interface belonging to an
isolated test-traffic harness used to exercise the correlation engine's
signals safely (see `dpi/` notes and the correlation engine commit for why
this harness exists — real macvlan-to-macvlan traffic turned out to bypass
AF_PACKET capture entirely, and this bridge+veth design was the fix).

Because `veth-atk` only exists once `setup-test-harness.sh` has run, an
earlier version of this setup left it created ad hoc — meaning a reboot
would have started the IDS pointed at an interface that didn't exist yet,
an unverified risk.

Fixed with two systemd units, present on the gateway (not committed here in
full, since they are host configuration, but documented for reference):

- `securepi-test-harness.service` — a oneshot unit, `RemainAfterExit=yes`,
  running `setup-test-harness.sh` (in this directory). Idempotent: checks
  whether `br-test` already exists before creating anything.
- A drop-in at `/etc/systemd/system/suricata.service.d/override.conf` adding
  `After=securepi-test-harness.service` and
  `Wants=securepi-test-harness.service` to the packaged `suricata.service`,
  so the harness is guaranteed to exist before the IDS starts.

Verified with an actual reboot (not just a dry-run of the units): all
eleven gateway services came back active with no manual steps, both
IDS capture threads (`ap0` and `veth-atk`) started without error, and
the harness's bridge and both network namespaces were present immediately.


---

## Timezone: the gateway must be set to a real local zone, not UTC

Ubuntu Server defaults to `Etc/UTC` on install. The web console displays
times with Python's `time.localtime(ts)`, which renders whatever timezone
the *system* is set to - so on a fresh install, every timestamp in the
console silently comes out 5.5 hours behind real IST time, with no error or
warning, just a wrong-looking clock.

This is a display-layer issue only. Every stored event timestamp comes from
the IDS's own EVE JSON, which carries an explicit UTC offset
(`+0000`) - the ingest pipeline converts these to timezone-agnostic epoch
seconds correctly regardless of the system's local timezone setting. Nothing
about the data itself was ever wrong; only the human-readable rendering was.

Fixed with:

```
sudo timedatectl set-timezone Asia/Kolkata
sudo systemctl restart securepi-web securepi-ingest securepi-engine
```

The service restart matters: each is a long-running Python process, and
while `time.localtime()` re-reads `/etc/localtime` on most systems rather
than caching it for the process lifetime, restarting removes any doubt
rather than relying on that behaviour.

**If the gateway is ever reinstalled, set the timezone before relying on any
displayed timestamp** - the reboot-safety systemd units in this directory
don't cover this, since it's a one-time OS setting rather than a service
dependency.

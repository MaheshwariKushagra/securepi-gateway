#!/usr/bin/env python3
"""
SecurePi Gateway - policy orchestrator (ENHANCEMENT-PLAN.md step 4.1).

Every response action the console takes - quarantine a device, block an IP
or a domain, give a device a filtering profile, pause filtering, turn on
HTTPS inspection - is stored first as a row in the `policies` table: the
DESIRED state. This module turns the active rows into the real thing
(nftables set elements through the privileged helper, DNS-filter rules
and client settings through its API), and then keeps it that way.

It works in three steps, every time:

  1. Apply. Work out what every enforcement point should hold and change
     only what differs.
  2. Read back. Ask nftables and the DNS filter what they actually hold now, and
     compare. A change that was accepted but didn't take is caught here.
  3. Roll back on a mismatch. Put every touched enforcement point back
     exactly as it was before step 1, mark the policy 'failed', and tell
     the console why. A half-applied change is never left behind.

The engine loop also calls reconcile() every cycle (15 seconds). That:
ends policies whose time is up, applies the device trust rules (step 4.4)
and automatic responses (step 4.2), follows a device to its new IP after a
DHCP renewal, turns scheduled service blocks on and off (step 4.3), and
notices when something outside the console changed what it applied - a
rule deleted in the DNS filter's own UI, an nftables element removed by hand. It
puts those back, writes an audit row, and raises a platform incident.

Drift versus a planned change
------------------------------
To tell those apart, the orchestrator remembers what it LAST APPLIED to
each enforcement point (the orchestrator_state table), not just what's
desired. If the live state no longer matches what it applied, someone
else changed it: that's drift. If the live state matches what it applied
but the desired state has moved on (a policy expired, a schedule window
opened), that's a planned change, and it's just applied. After a reboot
the nftables sets start empty; the kernel's boot id tells the orchestrator
that this is a restart it should quietly restore from, not drift.

One exception, on purpose: HTTPS inspection
--------------------------------------------
Every other kind of policy is put back if it goes missing. An enrollment
(Tier 2 HTTPS inspection) is not. It can disappear because the privacy
canary's fail-safe flushed the set (step 5.7), because the gateway
rebooted (inspection is deliberately off after every reboot), or because
someone unenrolled a device with the CLI. In every one of those cases the
safe answer is to leave inspection off, so the orchestrator ends the
policy instead of re-adding it. It only ever self-heals toward LESS
inspection, never more.

One lock for both processes
----------------------------
The console (securepi-web, unprivileged) applies a policy the moment it's
created, so a quarantine takes effect immediately rather than on the next
engine cycle. The engine (securepi-engine, root) runs reconcile(). Both
change the same nftables sets and the same DNS-filter rules list, so both
hold an exclusive file lock (fcntl.flock) on LOCK_PATH while they work.
Without it, a reconcile that read the policies table a moment before the
console inserted a new policy would see the console's fresh firewall
entry as unexpected and remove it.
"""

import contextlib
import fcntl
import ipaddress
import json
import os
import re
import tempfile
import threading
import time

import adguard
import audit
import dpi_enroll
import firewall_sets
import native_trackers
import profiles
import settings

LOCK_PATH = "/var/lib/securepi/orchestrator.lock"
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
ACTOR = "orchestrator"

# Kernel-side expiry is set this long after a timed policy's own end, so
# the orchestrator (which ends it on time) always gets there first, and
# the kernel is only the backstop if the orchestrator isn't running.
TIMEOUT_MARGIN_S = 60
MAX_DURATION_S = 30 * 24 * 3600  # the privileged helper's own upper bound

LAN_NETWORK = ipaddress.ip_network("10.10.0.0/24")

KINDS = {
    # kind: (needs a device, needs a target, may be network-wide)
    "quarantine":     (True,  False, False),
    "block_ip":       (False, True,  True),
    "block_domain":   (False, True,  True),
    "allow_domain":   (False, True,  True),
    "profile":        (True,  True,  False),
    "pause":          (False, False, True),
    "enroll":         (True,  False, False),
    "native_profile": (True,  True,  False),
}

# Which enforcement points ("domains") each kind of policy touches. Used to
# limit apply/verify/rollback to what a change can actually affect.
KIND_DOMAINS = {
    "quarantine": ("macs",),
    "block_ip": ("ips",),
    "block_domain": ("rules", "clients"),
    "allow_domain": ("rules", "clients"),
    "native_profile": ("rules", "clients"),
    "profile": ("clients", "rules"),
    "pause": ("clients", "protection"),
    "enroll": ("enrolled",),
}
DOMAINS = ("macs", "ips", "rules", "clients", "protection", "enrolled")

DOMAIN_LABELS = {
    "macs": "Quarantine (firewall)",
    "ips": "Blocked IPs (firewall)",
    "rules": "Domain rules (DNS filter)",
    "clients": "Device filtering settings (DNS filter)",
    "protection": "Network-wide filtering (DNS filter)",
    "enrolled": "HTTPS inspection enrollment (firewall)",
}

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")


class PolicyError(Exception):
    """The request itself is invalid - shown to the operator as-is."""


class PolicyApplyError(Exception):
    """The change was attempted, didn't take, and was rolled back."""


class OrchestratorBusy(Exception):
    """Another process held the lock for too long."""


# ------------------------------------------------------------------ lock --

_local = threading.local()


def _open_lock_file():
    try:
        # Lives in /var/lib/securepi (the data directory, group-writable
        # for the console) rather than /opt/securepi (code, root-only).
        # If the console still can't create it, a read-only descriptor to
        # a copy root already made is all flock() needs.
        return os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o644)
    except PermissionError:
        return os.open(LOCK_PATH, os.O_RDONLY)


@contextlib.contextmanager
def lock(timeout_s=20):
    """Exclusive lock across processes. Re-entrant within one thread, so a
    function holding it can call another that also asks for it."""
    depth = getattr(_local, "depth", 0)
    if depth:
        _local.depth = depth + 1
        try:
            yield
        finally:
            _local.depth -= 1
        return
    fd = _open_lock_file()
    deadline = time.time() + timeout_s
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.time() > deadline:
                    raise OrchestratorBusy("another change is still being applied - try again in a moment")
                time.sleep(0.1)
        _local.depth = 1
        try:
            yield
        finally:
            _local.depth = 0
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# -------------------------------------------------------------- backends --

class Backends:
    """Everything the orchestrator reads from or writes to, in one place.
    The real one calls the privileged helper and the DNS filter's API; the tests
    pass a fake with the same methods and in-memory state."""

    def macs(self):
        return firewall_sets.quarantined_macs()

    def mac_add(self, mac, seconds):
        firewall_sets.quarantine_mac(mac, seconds)

    def mac_del(self, mac):
        firewall_sets.release_mac(mac)

    def ips(self):
        return firewall_sets.blocked_ips()

    def ip_add(self, ip, seconds):
        firewall_sets.block_ip(ip, seconds)

    def ip_del(self, ip):
        firewall_sets.unblock_ip(ip)

    def enrolled(self):
        return {e["ip"]: e["expires_in_s"] for e in dpi_enroll.enrolled()}

    def enroll(self, ip, hours):
        dpi_enroll.enroll(ip, hours)

    def unenroll(self, ip):
        dpi_enroll.unenroll(ip)

    def reset_https(self, ip):
        dpi_enroll.reset_https(ip)

    def user_rules(self):
        return adguard.user_rules()

    def set_user_rules(self, rules):
        adguard.set_user_rules(rules)

    def clients(self):
        return adguard.list_clients()

    def add_client(self, obj):
        adguard.add_client(obj)

    def update_client(self, name, obj):
        adguard.update_client(name, obj)

    def delete_client(self, name):
        adguard.delete_client(name)

    def protection(self):
        return adguard.protection_status()

    def set_protection(self, enabled, duration_ms):
        adguard.set_protection(enabled, duration_ms)

    def catalog(self):
        return adguard.service_catalog()


BACKEND_ERRORS = (adguard.AdGuardError, firewall_sets.FirewallSetError, dpi_enroll.DpiEnrollError)


def _backends(b):
    return b if b is not None else Backends()


# ------------------------------------------------------------- validation --

def normalize_domain(value):
    d = (value or "").strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    if not _DOMAIN_RE.match(d):
        raise PolicyError("not a valid domain name: %r" % value)
    return d


def normalize_block_ip(value):
    try:
        ip = ipaddress.IPv4Address((value or "").strip())
    except ValueError:
        raise PolicyError("not a valid IPv4 address: %r" % value)
    # Blocking any of these would be pointless (LAN devices are already
    # isolated from each other) or would break the gateway's own
    # plumbing, so they're refused rather than silently accepted.
    if ip in LAN_NETWORK or ip.is_loopback or ip.is_unspecified or ip.is_multicast \
            or ip.is_link_local or ip.is_reserved or str(ip) == "255.255.255.255":
        raise PolicyError("%s is a local or reserved address - only internet destinations can be blocked" % ip)
    return str(ip)


def _device(conn, device_id):
    row = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if row is None:
        raise PolicyError("device %s not found" % device_id)
    return row


def device_label(row):
    return row["friendly_name"] or row["hostname"] or ("device %d" % row["id"])


def device_macs(conn, device_id):
    return sorted(r["mac"].lower() for r in conn.execute(
        "SELECT mac FROM device_macs WHERE device_id=?", (device_id,)))


def device_ip(conn, device_id):
    """The device's current IP address, or None if it doesn't have one
    any more.

    "The last address this device was seen on" is not enough: once a
    device leaves, DHCP can hand that address to a different device. If
    it has, enrolling or restricting the old device by IP would hit the
    NEW one instead - decrypting someone else's HTTPS, say (Audit.md H3).
    So the address only counts if no other device has been seen on it
    more recently than this one."""
    row = conn.execute(
        "SELECT ip, last_seen FROM device_ips WHERE device_id=? ORDER BY last_seen DESC LIMIT 1",
        (device_id,)).fetchone()
    if row is None:
        return None
    newer_owner = conn.execute(
        "SELECT 1 FROM device_ips WHERE ip=? AND device_id != ? AND last_seen > ? LIMIT 1",
        (row["ip"], device_id, row["last_seen"])).fetchone()
    if newer_owner is not None:
        return None
    return row["ip"]


def _validate(conn, kind, device_id, target, expires_at, now):
    if kind not in KINDS:
        raise PolicyError("unknown policy kind: %s" % kind)
    needs_device, needs_target, may_be_network = KINDS[kind]
    if device_id is None and not may_be_network:
        raise PolicyError("a %s policy needs a device" % kind)
    if device_id is not None:
        _device(conn, device_id)
    if expires_at is not None:
        if expires_at <= now:
            raise PolicyError("the expiry time is already in the past")
        if expires_at - now > MAX_DURATION_S:
            raise PolicyError("a timed policy can last at most 30 days")

    if kind == "quarantine":
        if not device_macs(conn, device_id):
            raise PolicyError("this device has no known MAC address to quarantine")
        return None
    if kind == "block_ip":
        if device_id is not None:
            raise PolicyError("IP blocks apply to every device on the network")
        return normalize_block_ip(target)
    if kind in ("block_domain", "allow_domain"):
        return normalize_domain(target)
    if kind == "profile":
        if target not in profiles.BUILTIN_PROFILES:
            raise PolicyError("unknown filtering profile: %s" % target)
        return target
    if kind == "native_profile":
        if native_trackers.profile(target) is None:
            raise PolicyError("unknown vendor telemetry profile: %s" % target)
        return target
    if kind == "pause":
        if expires_at is None:
            raise PolicyError("a pause must have an end time")
        if expires_at - now > 24 * 3600:
            raise PolicyError("filtering can be paused for at most 24 hours")
        return None
    if kind == "enroll":
        if expires_at is None:
            raise PolicyError("an enrollment must have an end time")
        if device_ip(conn, device_id) is None:
            raise PolicyError("this device has no known IP address to enroll")
        return normalize_sites(target)
    return target


# ---------------------------------------------------------- Tier 2 sites --
# An enrollment's target lists the site modules switched on for that device
# (ADBLOCK-ENHANCEMENT-PLAN.md B2), e.g. "instagram,youtube". None means
# YouTube only - what enrolment meant before other sites existed. The DPI
# addon reads them per device from SITE_MAP_PATH, which every reconcile
# rewrites from the active enrollments.
SITE_MAP_PATH = "/var/lib/securepi-dpi/device-sites.json"
DEFAULT_SITES = ("youtube",)
_SITE_NAME = re.compile(r"^[a-z0-9_]{1,32}$")


def normalize_sites(target):
    """A list or comma-separated string of site names -> the stored form:
    sorted, without repeats, None for YouTube only."""
    if target in (None, "", []):
        return None
    names = target.split(",") if isinstance(target, str) else list(target)
    names = sorted({str(n).strip() for n in names if str(n).strip()})
    if not names or len(names) > 8 or not all(_SITE_NAME.match(n) for n in names):
        raise PolicyError("sites must be 1-8 names of lowercase letters, digits or _")
    return None if tuple(names) == DEFAULT_SITES else ",".join(names)


def policy_sites(target):
    return target.split(",") if target else list(DEFAULT_SITES)


def write_site_map(enrolled, path=None):
    """Write {ip: [sites]} for the addon, only when it changed. Returns the
    IPs whose entry changed (added, removed or different sites). A failure
    is reported, never raised: without the file the addon falls back to
    YouTube only for every device - less decryption, never more."""
    path = path or SITE_MAP_PATH
    want = {ip: info.get("sites") or list(DEFAULT_SITES) for ip, info in sorted(enrolled.items())}
    try:
        with open(path) as f:
            before = json.load(f)
    except (OSError, ValueError):
        before = {}
    if not isinstance(before, dict):
        before = {}
    changed = sorted(ip for ip in set(before) | set(want) if before.get(ip) != want.get(ip))
    if not changed and os.path.exists(path):
        return []
    try:
        fd, tmp = tempfile.mkstemp(prefix=".device-sites.", dir=os.path.dirname(path))
        with os.fdopen(fd, "w") as f:
            json.dump(want, f)
        os.chmod(tmp, 0o664)
        os.replace(tmp, path)
        return changed
    except OSError as e:
        print("orchestrator: could not write %s: %s" % (path, e), flush=True)
        return []


def sync_sites(b, enrolled):
    """Write the site map, then reset the open HTTPS connections of every
    device whose enrolment or sites just changed, so the change applies
    now and not only to connections its browser opens later. A failed
    reset is reported, not raised: the change itself has been made."""
    for ip in write_site_map(enrolled):
        try:
            b.reset_https(ip)
        except BACKEND_ERRORS as e:
            print("orchestrator: %s" % e, flush=True)


# --------------------------------------------------------------- policies --

def _row(conn, policy_id):
    return conn.execute("SELECT * FROM policies WHERE id=?", (policy_id,)).fetchone()


def active_policies(conn, kind=None, device_id=None):
    sql = "SELECT * FROM policies WHERE status='active'"
    args = []
    if kind:
        sql += " AND kind=?"
        args.append(kind)
    if device_id is not None:
        sql += " AND device_id=?"
        args.append(device_id)
    return conn.execute(sql + " ORDER BY id", args).fetchall()


def policy_dict(row, now=None):
    now = now if now is not None else time.time()
    d = dict(row)
    d["applied_state"] = json.loads(row["applied_state"]) if row["applied_state"] else None
    d["remaining_s"] = int(row["expires_at"] - now) if row["expires_at"] and row["status"] == "active" else None
    return d


def _superseded(conn, kind, device_id, target):
    """Active policies a new one of this kind replaces: one profile, one
    pause, one quarantine and one enrollment per device (or network), one
    rule per device+domain."""
    if kind in ("profile", "pause", "enroll", "quarantine"):
        return conn.execute(
            "SELECT * FROM policies WHERE status='active' AND kind=? AND device_id IS ?",
            (kind, device_id)).fetchall()
    if kind in ("block_domain", "allow_domain"):
        # Blocking a domain replaces an allow for it on the same scope and
        # vice versa - the two can't both be meant.
        return conn.execute(
            "SELECT * FROM policies WHERE status='active' AND kind IN ('block_domain','allow_domain')"
            " AND device_id IS ? AND target=?", (device_id, target)).fetchall()
    if kind in ("native_profile", "block_ip"):
        return conn.execute(
            "SELECT * FROM policies WHERE status='active' AND kind=? AND device_id IS ? AND target=?",
            (kind, device_id, target)).fetchall()
    return []


def create_policy(conn, kind, device_id=None, target=None, expires_at=None, reason="",
                  actor="securepi", source="console", backends=None, now=None):
    """Store a new policy and apply it straight away. Returns the policy as
    a dict. Raises PolicyError for a bad request, or PolicyApplyError if the
    change didn't take (in which case everything was put back as it was)."""
    now = now if now is not None else time.time()
    reason = (reason or "").strip()
    if not reason:
        raise PolicyError("a reason is required")
    b = _backends(backends)
    with lock():
        target = _validate(conn, kind, device_id, target, expires_at, now)
        # Quarantine by a person replaces an automatic one on the same
        # device (and vice versa), but a trust-based restriction is a
        # separate thing: approving the device ends it, releasing it
        # doesn't - so it's left alone here.
        replaced = [r for r in _superseded(conn, kind, device_id, target)
                    if not (kind == "quarantine" and r["source"] == "trust" and source != "trust")]
        cur = conn.execute(
            "INSERT INTO policies (kind, device_id, target, reason, source, created_by, created_at,"
            " expires_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')",
            (kind, device_id, target, reason, source, actor, now, expires_at))
        policy_id = cur.lastrowid
        for r in replaced:
            conn.execute("UPDATE policies SET status='replaced', ended_at=?, ended_by=?, ended_reason=?"
                         " WHERE id=?", (now, actor, "replaced by policy #%d" % policy_id, r["id"]))
        conn.commit()
        try:
            _apply_and_verify(conn, b, KIND_DOMAINS[kind], now)
        except PolicyApplyError as e:
            conn.execute("UPDATE policies SET status='failed', ended_at=?, last_error=? WHERE id=?",
                         (now, str(e), policy_id))
            for r in replaced:
                conn.execute("UPDATE policies SET status='active', ended_at=NULL, ended_by=NULL,"
                             " ended_reason=NULL WHERE id=?", (r["id"],))
            conn.commit()
            audit.log(conn, actor, "policy.rolled_back", target="policy:%d" % policy_id,
                      detail="%s %s - %s" % (kind, _describe_target(conn, kind, device_id, target), e))
            raise
        conn.execute("UPDATE policies SET last_verified_at=? WHERE id=?", (now, policy_id))
        conn.commit()
        audit.log(conn, actor, "policy.create", target="policy:%d" % policy_id,
                  detail="%s %s%s - %s" % (kind, _describe_target(conn, kind, device_id, target),
                                          _describe_expiry(expires_at, now), reason))
        return policy_dict(_row(conn, policy_id), now)


def end_policy(conn, policy_id, actor="securepi", reason="", status="removed", backends=None, now=None):
    """End a policy and remove what it enforced. Rolled back (the policy
    stays active) if the removal doesn't verify."""
    now = now if now is not None else time.time()
    b = _backends(backends)
    with lock():
        row = _row(conn, policy_id)
        if row is None:
            raise PolicyError("policy %s not found" % policy_id)
        if row["status"] != "active":
            raise PolicyError("policy %s is already %s" % (policy_id, row["status"]))
        conn.execute("UPDATE policies SET status=?, ended_at=?, ended_by=?, ended_reason=? WHERE id=?",
                     (status, now, actor, reason or None, policy_id))
        conn.commit()
        try:
            _apply_and_verify(conn, b, KIND_DOMAINS[row["kind"]], now)
        except PolicyApplyError as e:
            conn.execute("UPDATE policies SET status='active', ended_at=NULL, ended_by=NULL,"
                         " ended_reason=NULL, last_error=? WHERE id=?", (str(e), policy_id))
            conn.commit()
            audit.log(conn, actor, "policy.rolled_back", target="policy:%d" % policy_id,
                      detail="ending %s failed - %s" % (row["kind"], e))
            raise
        audit.log(conn, actor, "policy.%s" % ("remove" if status == "removed" else status),
                  target="policy:%d" % policy_id,
                  detail="%s %s%s" % (row["kind"], _describe_target(conn, row["kind"], row["device_id"], row["target"]),
                                      (" - " + reason) if reason else ""))
        return policy_dict(_row(conn, policy_id), now)


def _describe_target(conn, kind, device_id, target):
    who = "every device"
    if device_id is not None:
        r = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        who = device_label(r) if r else "device %s" % device_id
    if kind in ("quarantine", "enroll"):
        return who
    if kind == "pause":
        return "filtering for %s" % who
    return "%s for %s" % (target, who)


def _describe_expiry(expires_at, now):
    if not expires_at:
        return ""
    mins = int(round((expires_at - now) / 60))
    if mins < 120:
        return " for %d min" % mins
    return " for %.1f h" % (mins / 60)


# ---------------------------------------------------------- state storage --

def _load_state(conn):
    row = conn.execute("SELECT * FROM orchestrator_state WHERE id=1").fetchone()
    if row is None:
        conn.execute("INSERT OR IGNORE INTO orchestrator_state (id) VALUES (1)")
        conn.commit()
        row = conn.execute("SELECT * FROM orchestrator_state WHERE id=1").fetchone()
    return {
        "applied": json.loads(row["applied"] or "{}"),
        "boot_id": row["boot_id"],
        "domains": json.loads(row["domains"] or "{}"),
        "extra": json.loads(row["extra"] or "{}"),
    }


def managed_rules(conn):
    """The DNS-filter rule lines this orchestrator put there itself (from
    policies). The console's hand-edited rule list must not remove these -
    the next reconcile would only put them straight back."""
    return set(_load_state(conn)["applied"].get("rules") or [])


def _save_applied(conn, applied):
    conn.execute("UPDATE orchestrator_state SET applied=? WHERE id=1", (json.dumps(applied, sort_keys=True),))
    conn.commit()


def current_boot_id():
    try:
        with open(BOOT_ID_PATH) as f:
            return f.read().strip()
    except OSError:
        return None


# ----------------------------------------------------------- desired state --

def _client_identity(conn, device_id, clients):
    """(existing DNS-filter client or None, name to use, ids it should carry).

    ids are the device's MACs plus its current IP. The DNS filter is also this
    network's DHCP server, so it can recognise a device by MAC even after
    its IP changes. Old LAN IPs are left out, so an address later handed to
    a different device isn't still claimed by this one."""
    macs = device_macs(conn, device_id)
    ip = device_ip(conn, device_id)
    wanted = set(macs) | ({ip} if ip else set())
    existing = None
    for cl in clients:
        if wanted & set(i.lower() for i in cl.get("ids") or []):
            existing = cl
            break
    if existing is not None:
        name = existing["name"]
    else:
        name = device_label(_device(conn, device_id))
        taken = {cl["name"] for cl in clients}
        if name in taken:
            name = "%s (device %d)" % (name, device_id)
    ids = sorted(wanted)
    return existing, name, ids


def desired_state(conn, b, now):
    """What every enforcement point should hold right now, from the active
    policies. Also returns who wants each item, for audit messages."""
    macs, ips, enrolled = {}, {}, {}
    rules = []
    rule_owner = {}
    clients = {}
    owners = {"macs": {}, "ips": {}, "enrolled": {}, "clients": {}}
    net_pause = None

    def _later(a, b_):
        # None means "no expiry", which outlasts any time.
        if a is None or b_ is None:
            return None
        return max(a, b_)

    client_list = None
    catalog = None
    local_now = time.localtime(now)

    policies = active_policies(conn)
    by_device = {}
    for p in policies:
        by_device.setdefault(p["device_id"], []).append(p)

    def _client_for(device_id):
        nonlocal client_list
        if device_id in clients:
            return clients[device_id]
        if client_list is None:
            client_list = b.clients()
        existing, name, ids = _client_identity(conn, device_id, client_list)
        clients[device_id] = {"name": name, "ids": ids, "settings": None,
                              "exists": existing is not None}
        return clients[device_id]

    for p in policies:
        kind, dev = p["kind"], p["device_id"]
        if kind == "quarantine":
            for mac in device_macs(conn, dev):
                macs[mac] = _later(macs[mac], p["expires_at"]) if mac in macs else p["expires_at"]
                owners["macs"].setdefault(mac, []).append(p["id"])
        elif kind == "block_ip":
            ip = p["target"]
            ips[ip] = _later(ips[ip], p["expires_at"]) if ip in ips else p["expires_at"]
            owners["ips"].setdefault(ip, []).append(p["id"])
        elif kind in ("block_domain", "allow_domain"):
            action = "block" if kind == "block_domain" else "allow"
            name = _client_for(dev)["name"] if dev is not None else None
            r = adguard.domain_rule(p["target"], action, name)
            if r not in rule_owner:
                rules.append(r)
            rule_owner.setdefault(r, []).append(p["id"])
        elif kind == "native_profile":
            name = _client_for(dev)["name"]
            for domain in native_trackers.profile(p["target"])["domains"]:
                r = adguard.domain_rule(domain, "block", name)
                if r not in rule_owner:
                    rules.append(r)
                rule_owner.setdefault(r, []).append(p["id"])
        elif kind == "pause" and dev is None:
            net_pause = p
        elif kind == "enroll":
            ip = device_ip(conn, dev)
            if ip:
                enrolled[ip] = {"expires_at": p["expires_at"], "policy_id": p["id"],
                                "sites": policy_sites(p["target"])}
                owners["enrolled"].setdefault(ip, []).append(p["id"])

    # Per-device client settings: a profile and/or a pause.
    for dev, plist in by_device.items():
        if dev is None:
            continue
        prof_p = next((p for p in plist if p["kind"] == "profile"), None)
        pause_p = next((p for p in plist if p["kind"] == "pause"), None)
        if prof_p is None and pause_p is None:
            continue
        if catalog is None:
            catalog = b.catalog()
        key = prof_p["target"] if prof_p else profiles.DEFAULT_PROFILE
        prof = profiles.get_profile(conn, key)
        c = _client_for(dev)
        c["settings"] = profiles.client_settings(prof, catalog, local_now, paused=pause_p is not None)
        c["profile"] = key
        owners["clients"][str(dev)] = [p["id"] for p in (prof_p, pause_p) if p]
        if prof.get("native_trackers"):
            for vendor in sorted(native_trackers.NATIVE_PROFILES):
                for domain in native_trackers.profile(vendor)["domains"]:
                    r = adguard.domain_rule(domain, "block", c["name"])
                    if r not in rule_owner:
                        rules.append(r)
                    rule_owner.setdefault(r, []).append(prof_p["id"])

    protection = {"enabled": net_pause is None,
                  "until": net_pause["expires_at"] if net_pause else None}
    return {
        "macs": macs, "ips": ips, "rules": rules, "clients": clients,
        "protection": protection, "enrolled": enrolled,
        "_owners": owners, "_rule_owner": rule_owner,
    }


# ----------------------------------------------------------------- observe --

def _observe(b, domain):
    if domain == "macs":
        return b.macs()
    if domain == "ips":
        return b.ips()
    if domain == "rules":
        return b.user_rules()
    if domain == "clients":
        return b.clients()
    if domain == "protection":
        enabled, remaining_ms = b.protection()
        return {"enabled": enabled, "remaining_ms": remaining_ms}
    if domain == "enrolled":
        return b.enrolled()
    raise ValueError(domain)


def _set_matches(want, have, now):
    """An nftables timeout set holds exactly the wanted elements, each
    lasting at least as long as its policy (or, for a policy with no
    expiry, with no kernel timeout at all)."""
    if set(want) != set(have):
        return False
    for key, expires_at in want.items():
        secs = have[key]
        if expires_at is None:
            if secs is not None:
                return False
        elif secs is None or secs < (expires_at - now) - 5:
            return False
    return True


def _find_client(clients, ids):
    wanted = set(ids)
    for cl in clients:
        if wanted & set(i.lower() for i in cl.get("ids") or []):
            return cl
    return None


def _domain_matches(domain, want, have, applied, now):
    """True if the live state `have` already satisfies `want`."""
    if domain in ("macs", "ips"):
        return _set_matches(want, have, now)
    if domain == "rules":
        managed = set(applied.get("rules", []))
        present = set(have)
        if any(r not in present for r in want):
            return False
        return not any(r in present for r in managed - set(want))
    if domain == "clients":
        for dev, c in want.items():
            cl = _find_client(have, c["ids"])
            if cl is None:
                return False
            have_ids = set(i.lower() for i in cl.get("ids") or [])
            if not set(c["ids"]) <= have_ids:
                return False
            # An old LAN address still on the client is drift too: DHCP may
            # have given it to another device, which the DNS filter would then
            # treat as this one (Audit.md H3). Matches what
            # _converge_clients() removes - it keeps other ids (MACs,
            # names) and drops only LAN IPs this device no longer has.
            if any(_is_lan_ip(i) and i not in c["ids"] for i in have_ids):
                return False
            if c["settings"] is not None and not profiles.client_matches(c["settings"], cl):
                return False
        # A device that had a profile or pause and no longer does has to be
        # back on standard settings.
        for dev, prev in (applied.get("clients") or {}).items():
            if int(dev) in want and want[int(dev)]["settings"] is not None:
                continue
            if prev.get("settings") is None:
                continue
            cl = _find_client(have, prev["ids"])
            if cl is not None and not profiles.client_matches(_standard_settings(), cl):
                return False
        return True
    if domain == "protection":
        return bool(have["enabled"]) == bool(want["enabled"])
    if domain == "enrolled":
        return set(want) <= set(have) and not any(
            ip in have for ip in (applied.get("enrolled") or {}) if ip not in want)
    raise ValueError(domain)


_standard_cache = {}


def _standard_settings():
    # Standard has no services, so the catalogue doesn't matter here.
    if not _standard_cache:
        _standard_cache.update(profiles.client_settings(
            profiles.BUILTIN_PROFILES["standard"], {}, time.localtime()))
    return dict(_standard_cache)


# ---------------------------------------------------------------- converge --

def _seconds_for(expires_at, now):
    if expires_at is None:
        return None
    return int(max(60, min(MAX_DURATION_S, (expires_at - now) + TIMEOUT_MARGIN_S)))


def _converge_set(want, have, add, delete, now):
    for key in [k for k in have if k not in want]:
        delete(key)
    for key, expires_at in want.items():
        if key in have and _set_matches({key: expires_at}, {key: have[key]}, now):
            continue
        if key in have:
            # nft ignores a timeout on an element that already exists, so
            # changing it means taking the element out and adding it back.
            delete(key)
        add(key, _seconds_for(expires_at, now))


def _converge_rules(b, want, have, applied_rules):
    managed = set(applied_rules) | set(want)
    new = [r for r in have if r not in managed] + list(want)
    if new != list(have):
        b.set_user_rules(new)


def _new_client(name, ids, settings_):
    obj = {
        "name": name, "ids": ids, "tags": [],
        "use_global_settings": True, "use_global_blocked_services": True,
        "filtering_enabled": True, "parental_enabled": False, "safebrowsing_enabled": False,
        "blocked_services": [], "upstreams": [],
    }
    if settings_:
        obj.update(settings_)
    return obj


def _converge_clients(b, want, have, applied_clients):
    for dev, c in want.items():
        cl = _find_client(have, c["ids"])
        if cl is None:
            b.add_client(_new_client(c["name"], c["ids"], c["settings"]))
            continue
        obj = dict(cl)
        ids = set(i.lower() for i in cl.get("ids") or [])
        ids = {i for i in ids if not _is_lan_ip(i) or i in c["ids"]} | set(c["ids"])
        changed = ids != set(i.lower() for i in cl.get("ids") or [])
        obj["ids"] = sorted(ids)
        if c["settings"] is not None and not profiles.client_matches(c["settings"], cl):
            obj.update(c["settings"])
            changed = True
        if changed:
            b.update_client(cl["name"], obj)
    for dev, prev in (applied_clients or {}).items():
        if int(dev) in want and want[int(dev)]["settings"] is not None:
            continue
        if prev.get("settings") is None:
            continue
        cl = _find_client(have, prev["ids"])
        if cl is not None and not profiles.client_matches(_standard_settings(), cl):
            obj = dict(cl)
            obj.update(_standard_settings())
            b.update_client(cl["name"], obj)


def _is_lan_ip(value):
    try:
        return ipaddress.ip_address(value) in LAN_NETWORK
    except ValueError:
        return False


def _converge_protection(b, want, have, now):
    if bool(have["enabled"]) == bool(want["enabled"]):
        return
    if want["enabled"]:
        b.set_protection(True, None)
    else:
        remaining_ms = int(max(1, (want["until"] or now) - now) * 1000)
        b.set_protection(False, remaining_ms)


def _converge(conn, b, domain, desired, have, applied, now):
    """Change one enforcement point from `have` to `desired`. Returns the
    record of what was applied, for orchestrator_state."""
    want = desired[domain]
    if domain == "macs":
        _converge_set(want, have, b.mac_add, b.mac_del, now)
        return dict(want)
    if domain == "ips":
        _converge_set(want, have, b.ip_add, b.ip_del, now)
        return dict(want)
    if domain == "rules":
        _converge_rules(b, want, have, applied.get("rules", []))
        return list(want)
    if domain == "clients":
        _converge_clients(b, want, have, applied.get("clients"))
        return {str(dev): {"ids": c["ids"], "settings": c["settings"]} for dev, c in want.items()}
    if domain == "protection":
        _converge_protection(b, want, have, now)
        return dict(want)
    if domain == "enrolled":
        return _converge_enrolled(conn, b, want, have, applied.get("enrolled") or {}, now)
    raise ValueError(domain)


def _converge_enrolled(conn, b, want, have, applied_enrolled, now):
    """Enrollments only move in one direction on their own - see the module
    docstring. Adds every wanted IP that isn't there and removes IPs no
    policy wants any more. It does NOT decide whether a missing IP should
    come back: _reconcile_enrolled must run first (both reconcile() and
    _apply_and_verify do this), and it removes from `want` any enrollment
    that was flushed or cleared by a reboot."""
    for ip in list(have):
        if ip not in want and ip in applied_enrolled:
            b.unenroll(ip)
    record = {}
    for ip, info in want.items():
        if ip not in have:
            hours = max(1, min(720, int((info["expires_at"] - now + 3599) // 3600)))
            b.enroll(ip, hours)
        record[ip] = info["expires_at"]
        conn.execute("UPDATE policies SET applied_state=? WHERE id=?",
                     (json.dumps({"ip": ip}), info["policy_id"]))
    conn.commit()
    # After the firewall change: write the sites, and reset the open
    # connections of every device whose enrolment or sites changed.
    sync_sites(b, want)
    return record


# ---------------------------------------------------- apply/verify/rollback --

def _snapshot(b, domains):
    return {d: _observe(b, d) for d in domains}


def _restore(conn, b, domain, snap, now):
    """Put one enforcement point back exactly as it was in `snap`."""
    have = _observe(b, domain)
    if domain in ("macs", "ips"):
        want = {k: (None if s is None else now + s) for k, s in snap.items()}
        add, delete = (b.mac_add, b.mac_del) if domain == "macs" else (b.ip_add, b.ip_del)
        _converge_set(want, have, add, delete, now)
    elif domain == "rules":
        if list(have) != list(snap):
            b.set_user_rules(snap)
    elif domain == "clients":
        before = {cl["name"]: cl for cl in snap}
        for cl in have:
            if cl["name"] not in before:
                b.delete_client(cl["name"])
            elif cl != before[cl["name"]]:
                b.update_client(cl["name"], before[cl["name"]])
        for name, cl in before.items():
            if not any(h["name"] == name for h in have):
                b.add_client(cl)
    elif domain == "protection":
        if bool(have["enabled"]) != bool(snap["enabled"]):
            b.set_protection(snap["enabled"], snap.get("remaining_ms") or None)
    elif domain == "enrolled":
        for ip in have:
            if ip not in snap:
                b.unenroll(ip)
        for ip, secs in snap.items():
            if ip not in have:
                b.enroll(ip, max(1, int(((secs or 3600) + 3599) // 3600)))


def _apply_and_verify(conn, b, domains, now):
    """Steps 1-3 of the module docstring, for the enforcement points one
    change can touch. Raises PolicyApplyError after rolling back."""
    state = _load_state(conn)
    applied = state["applied"]
    try:
        snap = _snapshot(b, domains)
    except BACKEND_ERRORS as e:
        raise PolicyApplyError("could not read the current state first, so nothing was changed: %s" % e)

    error = None
    new_applied = dict(applied)
    try:
        desired = desired_state(conn, b, now)
        if "enrolled" in domains:
            # The "never re-enable" rule has to run here too, not only in
            # reconcile(). Without it, a console enroll or unenroll on one
            # device put back every device the privacy fail-safe had just
            # flushed, or a reboot had cleared (CODEBASE_AUDIT.md H1).
            # This ends those policies and drops them from `desired`.
            boot_id = current_boot_id()
            restored_after_boot = bool(state["boot_id"]) and boot_id is not None and boot_id != state["boot_id"]
            notes = _reconcile_enrolled(conn, b, desired, snap["enrolled"], applied.get("enrolled") or {},
                                        now, restored_after_boot)
            for note in notes:
                audit.log(conn, ACTOR, "policy.drift_corrected", target="orchestrator", detail=note)
        for d in domains:
            new_applied[d] = _converge(conn, b, d, desired, snap[d], applied, now)
        after = _snapshot(b, domains)
        # Checked against `applied` - what was managed BEFORE this change -
        # not `new_applied`. A removal is only provable against the old
        # record: the new one no longer lists the removed rule, client or
        # enrollment, so a backend that accepted the delete but kept the
        # item used to pass this check (Audit10Oct C2).
        mismatched = [d for d in domains
                      if not _domain_matches(d, desired[d], after[d], applied, now)]
        if mismatched:
            error = "read-back did not match what was applied (%s)" % ", ".join(
                DOMAIN_LABELS[d] for d in mismatched)
    except BACKEND_ERRORS as e:
        error = str(e)

    if error is None:
        _save_applied(conn, new_applied)
        return

    rollback_errors = []
    for d in domains:
        try:
            _restore(conn, b, d, snap[d], now)
        except BACKEND_ERRORS as e:
            rollback_errors.append("%s: %s" % (DOMAIN_LABELS[d], e))
    if rollback_errors:
        _raise_rollback_incident(conn, error, "; ".join(rollback_errors), now)
        raise PolicyApplyError("%s - and rolling back also failed (%s); the next reconcile "
                               "will retry" % (error, "; ".join(rollback_errors)))

    # Read the rollback back too, the same way the change itself was read
    # back. "Nothing was changed" is only said when every touched
    # enforcement point really is as it was before (Audit10Oct C2).
    still_differ = []
    for d in domains:
        try:
            if not _restored_matches(d, snap[d], _observe(b, d)):
                still_differ.append(DOMAIN_LABELS[d])
        except BACKEND_ERRORS as e:
            still_differ.append("%s (could not read it back: %s)" % (DOMAIN_LABELS[d], e))
    if still_differ:
        _raise_rollback_incident(conn, error, "still different from before: " + ", ".join(still_differ), now)
        raise PolicyApplyError("%s - rolling back did not fully take (%s still differ from before); "
                               "the next reconcile will retry" % (error, ", ".join(still_differ)))
    raise PolicyApplyError("%s - rolled back, nothing was changed" % error)


def _restored_matches(domain, snap, have):
    """After a rollback: is this enforcement point back to the snapshot?

    Compared by what matters, not byte for byte - set elements by their
    keys (a timeout keeps counting down), rules as the exact list, DNS-filter
    clients by name, ids and the settings the orchestrator writes."""
    if domain in ("macs", "ips", "enrolled"):
        return set(snap) == set(have)
    if domain == "rules":
        return list(have) == list(snap)
    if domain == "protection":
        return bool(have["enabled"]) == bool(snap["enabled"])
    if domain == "clients":
        before = {cl["name"]: cl for cl in snap}
        now_ = {cl["name"]: cl for cl in have}
        if set(before) != set(now_):
            return False
        for name, cl in before.items():
            ids_before = sorted(i.lower() for i in cl.get("ids") or [])
            ids_now = sorted(i.lower() for i in now_[name].get("ids") or [])
            if ids_before != ids_now:
                return False
            # Only the fields the orchestrator itself writes.
            wanted = {}
            for key in _standard_settings():
                if key == "blocked_services":
                    wanted[key] = cl.get(key) or []
                elif key == "safe_search":
                    wanted[key] = cl.get(key) or {}
                else:
                    wanted[key] = cl.get(key)
            if not profiles.client_matches(wanted, now_[name]):
                return False
        return True
    raise ValueError(domain)


def _raise_rollback_incident(conn, error, what, now):
    """A change that failed AND could not be fully undone leaves enforcement
    in a state nobody asked for, so it is an incident, not just an error
    message on the policy."""
    import correlation
    correlation.raise_incident(
        conn, None, "policy_enforcement_failed", "high",
        "A policy change could not be fully rolled back",
        "A change failed (%s) and rolling it back did not fully take: %s. "
        "The orchestrator will keep retrying every cycle." % (error, what),
        now, now, [])


# ---------------------------------------------------------------- reconcile --

def expire_due(conn, now):
    """End every active policy whose time is up. Returns the ended rows."""
    rows = conn.execute("SELECT * FROM policies WHERE status='active' AND expires_at IS NOT NULL"
                        " AND expires_at <= ?", (now,)).fetchall()
    for r in rows:
        conn.execute("UPDATE policies SET status='expired', ended_at=?, ended_by=?, ended_reason=?"
                     " WHERE id=?", (now, ACTOR, "time limit reached", r["id"]))
        audit.log(conn, ACTOR, "policy.expired", target="policy:%d" % r["id"],
                  detail="%s %s" % (r["kind"], _describe_target(conn, r["kind"], r["device_id"], r["target"])))
    conn.commit()
    return rows


def trust_sweep(conn, now):
    """Step 4.4: keep 'trust' quarantine policies in line with each
    device's trust state. A blocked device is always quarantined; an
    unknown one is quarantined only while restrict_unknown_devices is on.
    Returns the number of policies created or ended."""
    restrict = settings.get(conn, "restrict_unknown_devices")
    changed = 0
    for d in conn.execute("SELECT * FROM devices").fetchall():
        trust = d["trust"]
        should = trust == "blocked" or (restrict and trust == "unknown")
        existing = conn.execute("SELECT * FROM policies WHERE status='active' AND kind='quarantine'"
                                " AND source='trust' AND device_id=?", (d["id"],)).fetchone()
        if should and existing is None and device_macs(conn, d["id"]):
            reason = ("device is blocked" if trust == "blocked"
                      else "unknown device - restricted until approved")
            conn.execute(
                "INSERT INTO policies (kind, device_id, reason, source, created_by, created_at, status)"
                " VALUES ('quarantine', ?, ?, 'trust', ?, ?, 'active')", (d["id"], reason, ACTOR, now))
            audit.log(conn, ACTOR, "policy.create", target="device %d" % d["id"],
                      detail="quarantine %s - %s" % (device_label(d), reason))
            changed += 1
        elif not should and existing is not None:
            conn.execute("UPDATE policies SET status='removed', ended_at=?, ended_by=?, ended_reason=?"
                         " WHERE id=?", (now, ACTOR, "trust is now %s" % trust, existing["id"]))
            audit.log(conn, ACTOR, "policy.remove", target="policy:%d" % existing["id"],
                      detail="quarantine %s - trust is now %s" % (device_label(d), trust))
            changed += 1
    conn.commit()
    return changed


def auto_response(conn, now, state_extra):
    """Step 4.2: opt-in automatic quarantine for high-confidence campaigns.
    Only campaigns created after the feature was switched on are acted on,
    so turning it on never retroactively quarantines devices for old
    campaigns. Returns the new policy ids."""
    import correlation  # imported here: correlation imports settings, and this keeps startup simple

    if not settings.get(conn, "auto_quarantine_enabled"):
        state_extra.pop("auto_quarantine_since", None)
        return []
    since = state_extra.setdefault("auto_quarantine_since", now)
    min_tactics = settings.get(conn, "auto_quarantine_min_tactics")
    minutes = settings.get(conn, "auto_quarantine_minutes")
    created = []
    for camp in conn.execute("SELECT * FROM campaigns WHERE status IN ('new','investigating')"
                             " AND created_at >= ?", (since,)).fetchall():
        tactics = [t.strip() for t in (camp["tactics"] or "").split("->") if t.strip()]
        if len(set(tactics)) < min_tactics:
            continue
        source = "auto:campaign:%d" % camp["id"]
        if conn.execute("SELECT 1 FROM policies WHERE source=?", (source,)).fetchone():
            continue  # already acted on this campaign once - never twice
        dev = conn.execute("SELECT * FROM devices WHERE id=?", (camp["device_id"],)).fetchone()
        if dev is None or not device_macs(conn, dev["id"]):
            continue
        reason = "campaign #%d spans %d ATT&CK tactics (%s)" % (camp["id"], len(set(tactics)), camp["tactics"])
        cur = conn.execute(
            "INSERT INTO policies (kind, device_id, reason, source, created_by, created_at, expires_at,"
            " status) VALUES ('quarantine', ?, ?, ?, 'auto-response', ?, ?, 'active')",
            (dev["id"], reason, source, now, now + minutes * 60))
        created.append(cur.lastrowid)
        audit.log(conn, "auto-response", "policy.create", target="policy:%d" % cur.lastrowid,
                  detail="quarantine %s for %d min - %s" % (device_label(dev), minutes, reason))
        correlation.raise_incident(
            conn, dev["id"], "auto_quarantine", "high",
            "%s was quarantined automatically" % device_label(dev),
            "Auto-response quarantined this device for %d minutes because %s. Release it from the "
            "device page if this is a false positive." % (minutes, reason),
            now, now, [])
    conn.commit()
    return created


def migrate_legacy_rules(conn, b, now):
    """Turn per-device rules written before step 4.1 (with a trailing
    "  # securepi-expires/tag" comment, which the DNS filter never matched - see
    adguard.py) into proper policies, and take the broken lines out.
    Runs every reconcile but costs one rules read when there's nothing to do."""
    rules = b.user_rules()
    legacy = [r for r in rules if "  # securepi-" in r]
    if not legacy:
        return 0
    clients = b.clients()
    migrated = 0
    for r in legacy:
        base, _, comment = r.partition("  #")
        desc = adguard.describe_rule(base)
        m_exp = re.search(r"securepi-expires:(\d+)", comment)
        m_tag = re.search(r"securepi-tag:(\S+)", comment)
        expires_at = int(m_exp.group(1)) if m_exp else None
        device_id = None
        if desc["scope"].startswith("device: "):
            name = desc["scope"][len("device: "):]
            cl = next((c for c in clients if c["name"] == name), None)
            device_id = _device_for_client(conn, cl) if cl else None
            if device_id is None:
                continue  # can't tell which device it was for - leave it alone
        if expires_at is not None and expires_at <= now:
            continue  # already over; just drop the line below
        if m_tag and native_trackers.profile(m_tag.group(1)):
            kind, target = "native_profile", m_tag.group(1)
        elif desc["action"] in ("allow", "block") and desc["domain"]:
            kind, target = ("allow_domain" if desc["action"] == "allow" else "block_domain"), desc["domain"]
        else:
            continue
        exists = conn.execute("SELECT 1 FROM policies WHERE status='active' AND kind=? AND device_id IS ?"
                              " AND target=?", (kind, device_id, target)).fetchone()
        if not exists:
            conn.execute(
                "INSERT INTO policies (kind, device_id, target, reason, source, created_by, created_at,"
                " expires_at, status) VALUES (?, ?, ?, ?, 'migrated', ?, ?, ?, 'active')",
                (kind, device_id, target, "converted from a pre-4.1 rule that the DNS filter never matched",
                 ACTOR, now, expires_at))
            migrated += 1
    conn.commit()
    keep = [r for r in rules if "  # securepi-" not in r]
    b.set_user_rules(keep)
    audit.log(conn, ACTOR, "policy.migrate", target="rules",
              detail="converted %d legacy rule line(s) into policies, removed %d broken line(s)"
                     % (migrated, len(legacy)))
    return migrated


def _device_for_client(conn, cl):
    for ident in cl.get("ids") or []:
        ident = ident.lower()
        row = conn.execute("SELECT device_id FROM device_macs WHERE mac=?", (ident,)).fetchone()
        if row:
            return row["device_id"]
        row = conn.execute("SELECT device_id FROM device_ips WHERE ip=? ORDER BY last_seen DESC LIMIT 1",
                           (ident,)).fetchone()
        if row:
            return row["device_id"]
    return None


def _reconcile_enrolled(conn, b, desired, have, applied_enrolled, now, restored_after_boot):
    """The enrollment special case (module docstring). Returns a list of
    human-readable changes that count as drift."""
    drift = []
    want = desired["enrolled"]
    for ip, info in list(want.items()):
        p = _row(conn, info["policy_id"])
        last_ip = (json.loads(p["applied_state"]) if p["applied_state"] else {}).get("ip")
        # "Was applied, and the address it was applied at has since gone
        # from the set" - whatever the device's address is NOW. This used
        # to test last_ip == ip, so a device that came back on a DIFFERENT
        # address after a reboot or a privacy flush was quietly enrolled
        # again at the new one, breaking the "inspection is always off
        # after a reboot" rule (Audit.md, enrollment after reboot). An
        # ordinary IP change keeps working: the old address is still in
        # the set until _converge_enrolled moves it across.
        if ip not in have and last_ip is not None and last_ip not in have:
            why = ("the gateway restarted" if restored_after_boot
                   else "it was removed outside the console (privacy fail-safe or CLI)")
            conn.execute("UPDATE policies SET status='removed', ended_at=?, ended_by=?, ended_reason=?"
                         " WHERE id=?", (now, ACTOR, "enrollment ended because %s - not re-applied, "
                                         "inspection is only ever turned on deliberately" % why, p["id"]))
            audit.log(conn, ACTOR, "policy.remove", target="policy:%d" % p["id"],
                      detail="enroll %s ended because %s" % (ip, why))
            del want[ip]
            if not restored_after_boot:
                drift.append("HTTPS inspection for %s was turned off outside the console - left off" % ip)
    # Enrolled outside the console (the `securepi enroll` CLI): adopt it
    # so it's visible and ends on time, rather than silently fighting it.
    for ip, secs in have.items():
        if ip in want or ip in applied_enrolled:
            continue
        row = conn.execute("SELECT device_id FROM device_ips WHERE ip=? ORDER BY last_seen DESC LIMIT 1",
                           (ip,)).fetchone()
        if row is None:
            continue
        expires_at = now + (secs if secs else 24 * 3600)
        cur = conn.execute(
            "INSERT INTO policies (kind, device_id, reason, source, created_by, created_at, expires_at,"
            " status, applied_state) VALUES ('enroll', ?, 'enrolled outside the console (CLI)', 'adopted',"
            " ?, ?, ?, 'active', ?)", (row["device_id"], ACTOR, now, expires_at, json.dumps({"ip": ip})))
        want[ip] = {"expires_at": expires_at, "policy_id": cur.lastrowid}
        audit.log(conn, ACTOR, "policy.adopt", target="policy:%d" % cur.lastrowid,
                  detail="enroll %s was found enrolled outside the console - now tracked" % ip)
        drift.append("%s was enrolled outside the console - now tracked by the console" % ip)
    conn.commit()
    return drift


def _describe_drift(domain, desired, have, applied, now):
    """Short, specific description of what changed outside the console."""
    if domain in ("macs", "ips"):
        prev = applied.get(domain) or {}
        missing = [k for k in prev if k not in have]
        extra = [k for k in have if k not in prev]
        bits = []
        if missing:
            bits.append("removed: %s" % ", ".join(sorted(missing)))
        if extra:
            bits.append("added: %s" % ", ".join(sorted(extra)))
        return "%s changed outside the console (%s)" % (DOMAIN_LABELS[domain], "; ".join(bits) or "timeouts")
    if domain == "rules":
        prev = applied.get("rules") or []
        missing = [r for r in prev if r not in set(have)]
        return "%s rule(s) removed or edited in the DNS filter: %s" % (len(missing), ", ".join(missing[:3]))
    if domain == "clients":
        return "a device's filtering settings were changed directly in the DNS filter"
    if domain == "protection":
        return "network-wide filtering was turned %s directly in the DNS filter" % ("on" if have["enabled"] else "off")
    return "%s changed outside the console" % DOMAIN_LABELS[domain]


def _applied_matches(domain, have, applied, now):
    """Does the live state still match what the orchestrator last applied?
    (No: something outside the console changed it.)"""
    if domain not in applied:
        return True  # never applied anything here yet - nothing to drift from
    prev = applied[domain]
    if domain in ("macs", "ips"):
        return set(prev) == set(have)
    if domain == "rules":
        return all(r in set(have) for r in prev)
    if domain == "clients":
        for dev, c in prev.items():
            cl = _find_client(have, c["ids"])
            if cl is None:
                return False
            if c["settings"] is not None and not profiles.client_matches(c["settings"], cl):
                return False
        return True
    if domain == "protection":
        return bool(have["enabled"]) == bool(prev.get("enabled", True))
    return True


def reconcile(conn, backends=None, now=None):
    """One orchestrator cycle - see the module docstring. Returns a summary
    dict (also stored in orchestrator_state for the console)."""
    import correlation

    now = now if now is not None else time.time()
    b = _backends(backends)
    summary = {"expired": 0, "trust": 0, "auto": 0, "drift": [], "errors": {}, "restored": []}
    with lock():
        state = _load_state(conn)
        applied = state["applied"]
        extra = state["extra"]
        boot_id = current_boot_id()
        restored_after_boot = bool(state["boot_id"]) and boot_id is not None and boot_id != state["boot_id"]

        summary["expired"] = len(expire_due(conn, now))
        summary["trust"] = trust_sweep(conn, now)
        summary["auto"] = len(auto_response(conn, now, extra))
        try:
            migrate_legacy_rules(conn, b, now)
        except BACKEND_ERRORS as e:
            summary["errors"]["rules"] = str(e)

        try:
            desired = desired_state(conn, b, now)
        except BACKEND_ERRORS as e:
            desired = None
            summary["errors"]["desired"] = str(e)

        domain_status = {}
        new_applied = dict(applied)
        if desired is not None:
            for d in DOMAINS:
                try:
                    have = _observe(b, d)
                    drifted = not _applied_matches(d, have, applied, now)
                    if d == "enrolled":
                        notes = _reconcile_enrolled(conn, b, desired, have, applied.get("enrolled") or {},
                                                    now, restored_after_boot)
                        summary["drift"].extend(notes)
                        drifted = False
                        # Every cycle: a device's IP can change under the
                        # same enrollment, and the map is keyed by IP.
                        sync_sites(b, desired["enrolled"])
                    if not _domain_matches(d, desired[d], have, applied, now):
                        if drifted and not restored_after_boot:
                            summary["drift"].append(_describe_drift(d, desired, have, applied, now))
                        elif drifted:
                            summary["restored"].append(DOMAIN_LABELS[d])
                        new_applied[d] = _converge(conn, b, d, desired, have, applied, now)
                        after = _observe(b, d)
                        # Against the previous record, for the same reason
                        # as in _apply_and_verify (Audit10Oct C2).
                        if not _domain_matches(d, desired[d], after, applied, now):
                            raise PolicyApplyError("still doesn't match after re-applying")
                    else:
                        new_applied[d] = _record_for(d, desired)
                    domain_status[d] = {"ok": True, "checked_at": now}
                except (PolicyApplyError,) + BACKEND_ERRORS as e:
                    summary["errors"][d] = str(e)
                    domain_status[d] = {"ok": False, "checked_at": now, "error": str(e)}

            ok_domains = {d for d, s in domain_status.items() if s["ok"]}
            for p in active_policies(conn):
                if set(KIND_DOMAINS[p["kind"]]) <= ok_domains:
                    conn.execute("UPDATE policies SET last_verified_at=?, last_error=NULL WHERE id=?",
                                 (now, p["id"]))
                else:
                    bad = [d for d in KIND_DOMAINS[p["kind"]] if d not in ok_domains]
                    conn.execute("UPDATE policies SET last_error=? WHERE id=?",
                                 ("; ".join(summary["errors"].get(d, "not checked") for d in bad), p["id"]))

        for note in summary["drift"]:
            audit.log(conn, ACTOR, "policy.drift_corrected", target="orchestrator", detail=note)
        if summary["drift"]:
            correlation.raise_incident(
                conn, None, "policy_drift", "medium",
                "A response policy was changed outside the console",
                "The orchestrator found enforcement that no longer matched the console and put it "
                "back: " + "; ".join(summary["drift"]) + ".",
                now, now, [])
        if summary["restored"]:
            audit.log(conn, ACTOR, "policy.restored_after_restart", target="orchestrator",
                      detail="re-applied after a gateway restart: %s" % ", ".join(summary["restored"]))
        failing = {d: e for d, e in summary["errors"].items() if d in DOMAINS}
        if failing:
            correlation.raise_incident(
                conn, None, "policy_enforcement_failed", "high",
                "The gateway could not enforce every response policy",
                "The orchestrator could not check or apply: " + "; ".join(
                    "%s (%s)" % (DOMAIN_LABELS[d], e) for d, e in failing.items()) +
                ". It will keep retrying every cycle.",
                now, now, [])

        conn.execute(
            "UPDATE orchestrator_state SET applied=?, boot_id=?, last_run=?, last_ok=?, last_error=?,"
            " domains=?, extra=? WHERE id=1",
            (json.dumps(new_applied, sort_keys=True), boot_id or state["boot_id"], now,
             now if not summary["errors"] else _last_ok(conn),
             "; ".join("%s: %s" % kv for kv in summary["errors"].items()) or None,
             json.dumps(domain_status), json.dumps(extra)))
        conn.commit()
    return summary


def _last_ok(conn):
    row = conn.execute("SELECT last_ok FROM orchestrator_state WHERE id=1").fetchone()
    return row["last_ok"] if row else None


def _record_for(domain, desired):
    want = desired[domain]
    if domain == "clients":
        return {str(dev): {"ids": c["ids"], "settings": c["settings"]} for dev, c in want.items()}
    if domain == "enrolled":
        return {ip: info["expires_at"] for ip, info in want.items()}
    if domain == "rules":
        return list(want)
    return dict(want)


def status(conn, now=None):
    """What the console's Response page shows about the orchestrator itself."""
    now = now if now is not None else time.time()
    row = conn.execute("SELECT * FROM orchestrator_state WHERE id=1").fetchone()
    if row is None:
        return {"last_run": None, "healthy": False, "domains": {}}
    domains = json.loads(row["domains"] or "{}")
    return {
        "last_run": row["last_run"],
        "last_run_age_s": int(now - row["last_run"]) if row["last_run"] else None,
        "last_ok": row["last_ok"],
        "last_error": row["last_error"],
        "healthy": bool(row["last_run"]) and now - row["last_run"] < 90 and not row["last_error"],
        "domains": {d: dict(domains.get(d, {}), label=DOMAIN_LABELS[d]) for d in DOMAINS},
    }

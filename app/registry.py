#!/usr/bin/env python3
"""
SecurePi Gateway - device registry and identity resolution.

The problem this solves
-----------------------
Every event carries a source IP address. That is not an identity. Addresses are
handed out by DHCP and rotate; worse, both phones observed on this network use
randomized MAC addresses, which modern Android and iOS regenerate per network
and refresh periodically.

So neither the IP nor the MAC is stable. If we keyed devices on either, one
physical phone would appear as a stream of unrelated devices, and every
device-scoped detection would reset each time.

How identity is established
---------------------------
1. A DHCP lease gives us (mac, ip, hostname) together - the strongest signal,
   because all three are observed at the same instant.
2. If that MAC is already known, we have the device.
3. If the MAC is new but the hostname matches a known device, we treat it as
   the same device with a re-randomized MAC, and record the new MAC against it.
4. Otherwise it is genuinely a new device.

The hostname is the anchor because Android keeps it stable across MAC
rotation. Where a device announces no hostname, identity falls back to MAC
alone and the console offers manual naming.

Historical attribution
----------------------
Events are attributed using the address intervals in device_ips, not the
current lease. An event from three hours ago belongs to whoever held that
address at that moment. Attributing by current address would silently
reassign history every time a lease rotated.
"""

import json
import os
import re
import subprocess
import time

LEASES_PATH = "/opt/AdGuardHome/data/leases.json"
LAN_PREFIX = "10.10.0."

# A MAC is randomized if the second-least-significant bit of the first octet
# is set - the "locally administered" bit. Real hardware addresses are assigned
# by the manufacturer and do not have it.
def is_randomized(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def read_leases():
    """Current DHCP leases as a list of (mac, ip, hostname)."""
    if not os.path.exists(LEASES_PATH):
        return []
    try:
        with open(LEASES_PATH) as fh:
            data = json.load(fh)
    except Exception:
        return []
    out = []
    for lease in data.get("leases", []):
        mac = (lease.get("mac") or "").lower()
        ip = lease.get("ip") or ""
        host = (lease.get("hostname") or "").strip()
        if mac and ip:
            out.append((mac, ip, host))
    return out


def read_arp():
    """
    Neighbour table as {ip: mac}. This catches devices with a static address
    or an expired lease that are still talking.
    """
    out = {}
    try:
        result = subprocess.run(
            ["ip", "neigh", "show", "dev", "ap0"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return out
    for line in result.stdout.splitlines():
        match = re.match(r"^(\S+)\s+lladdr\s+(\S+)", line)
        if match:
            out[match.group(1)] = match.group(2).lower()
    return out


def touch_interval(conn, table, device_id, value, column, now):
    """
    Record that a device is using this MAC or IP right now.

    If the most recent interval for this value already belongs to this device,
    extend it. Otherwise open a new one. This is what makes historical lookups
    correct across rotation: old intervals keep their original end time.
    """
    row = conn.execute(
        "SELECT id, device_id FROM %s WHERE %s = ? ORDER BY last_seen DESC LIMIT 1"
        % (table, column),
        (value,),
    ).fetchone()

    if row is not None and row["device_id"] == device_id:
        conn.execute("UPDATE %s SET last_seen = ? WHERE id = ?" % table, (now, row["id"]))
        return

    extra = ", is_randomized" if table == "device_macs" else ""
    extra_val = ", ?" if table == "device_macs" else ""
    params = [device_id, value, now, now]
    if table == "device_macs":
        params.append(1 if is_randomized(value) else 0)
    conn.execute(
        "INSERT INTO %s (device_id, %s, first_seen, last_seen%s) VALUES (?, ?, ?, ?%s)"
        % (table, column, extra, extra_val),
        params,
    )


def resolve_device(conn, mac, hostname, now):
    """Find or create the device this MAC belongs to. Returns the device id."""
    # 1. Known MAC - straightforward.
    row = conn.execute(
        "SELECT device_id FROM device_macs WHERE mac = ?", (mac,)
    ).fetchone()
    if row is not None:
        return row["device_id"]

    # 2. New MAC, familiar hostname: the same phone with a re-randomized
    #    address. Attach the new MAC to the existing device.
    if hostname:
        row = conn.execute(
            "SELECT id FROM devices WHERE hostname = ? ORDER BY first_seen LIMIT 1",
            (hostname,),
        ).fetchone()
        if row is not None:
            print("registry: %s reappeared with a new MAC %s (randomization)"
                  % (hostname, mac), flush=True)
            return row["id"]

    # 3. Genuinely new.
    cur = conn.execute(
        "INSERT INTO devices (hostname, first_seen, last_seen) VALUES (?, ?, ?)",
        (hostname or None, now, now),
    )
    print("registry: new device %s (%s)" % (hostname or "unnamed", mac), flush=True)
    return cur.lastrowid


def update_devices(conn):
    """Refresh the registry from DHCP leases and the neighbour table."""
    now = time.time()
    seen = 0

    for mac, ip, hostname in read_leases():
        device_id = resolve_device(conn, mac, hostname, now)
        touch_interval(conn, "device_macs", device_id, mac, "mac", now)
        touch_interval(conn, "device_ips", device_id, ip, "ip", now)
        conn.execute(
            "UPDATE devices SET last_seen = ?, hostname = COALESCE(NULLIF(?, ''), hostname)"
            " WHERE id = ?",
            (now, hostname, device_id),
        )
        seen += 1

    # The neighbour table adds anything that is talking but has no lease.
    for ip, mac in read_arp().items():
        if not ip.startswith(LAN_PREFIX):
            continue
        row = conn.execute("SELECT device_id FROM device_macs WHERE mac = ?", (mac,)).fetchone()
        if row is None:
            device_id = resolve_device(conn, mac, "", now)
            touch_interval(conn, "device_macs", device_id, mac, "mac", now)
        else:
            device_id = row["device_id"]
        touch_interval(conn, "device_ips", device_id, ip, "ip", now)
        conn.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (now, device_id))

    conn.commit()
    return seen


def mac_from_link_local(addr):
    """
    Recover a MAC address from an IPv6 link-local address.

    Addresses like fe80::c825:f0ff:fe57:6d87 are built from the MAC using
    EUI-64: the six MAC bytes are split, ff:fe is inserted in the middle, and
    the locally-administered bit of the first byte is flipped. Reversing that
    gives us identity for IPv6 traffic that carries no other clue.

        fe80::c825:f0ff:fe57:6d87  ->  ca:25:f0:57:6d:87
    """
    try:
        tail = addr.replace(":", "")[-16:]
        if len(tail) != 16 or tail[6:10].lower() != "fffe":
            return None
        octets = [tail[0:2], tail[2:4], tail[4:6], tail[10:12], tail[12:14], tail[14:16]]
        first = int(octets[0], 16) ^ 0x02
        return ":".join([("%02x" % first)] + octets[1:]).lower()
    except Exception:
        return None


def attribute_events(conn, limit=50000):
    """
    Fill in device_id on events that do not have one yet.

    Done in three passes, weakest assumption last. Note that the passes are
    separate statements rather than one clever query: SQLite lets a correlated
    subquery reference the outer table in its WHERE clause but NOT in its
    ORDER BY, so ranking candidate intervals by closeness to the event's
    timestamp is not expressible inline.
    """
    lan = LAN_PREFIX + "%"

    # Pass 1 - the address interval actually contains the event's timestamp.
    # This is the only pass that is unambiguous when an address has been
    # reused by different devices over time.
    conn.execute(
        """
        UPDATE events
           SET device_id = (
               SELECT di.device_id FROM device_ips di
                WHERE di.ip = events.src_ip
                  AND events.ts >= di.first_seen
                  AND events.ts <= di.last_seen + 300
                LIMIT 1)
         WHERE device_id IS NULL AND src_ip LIKE ?
           AND EXISTS (
               SELECT 1 FROM device_ips di
                WHERE di.ip = events.src_ip
                  AND events.ts >= di.first_seen
                  AND events.ts <= di.last_seen + 300)
        """,
        (lan,),
    )

    # Pass 2 - the address has only ever belonged to one device, so the
    # timestamp does not matter. This catches events that predate our first
    # sighting of the lease, which is most of them after a fresh start:
    # an interval begins when we first OBSERVE a lease, not when it was granted.
    conn.execute(
        """
        UPDATE events
           SET device_id = (
               SELECT di.device_id FROM device_ips di
                WHERE di.ip = events.src_ip LIMIT 1)
         WHERE device_id IS NULL AND src_ip LIKE ?
           AND (SELECT count(DISTINCT di.device_id) FROM device_ips di
                 WHERE di.ip = events.src_ip) = 1
        """,
        (lan,),
    )

    # Pass 3 - IPv6 link-local traffic, identified by the MAC embedded in the
    # address itself.
    rows = conn.execute(
        "SELECT DISTINCT src_ip FROM events"
        " WHERE device_id IS NULL AND src_ip LIKE 'fe80%'"
    ).fetchall()
    for row in rows:
        mac = mac_from_link_local(row["src_ip"])
        if not mac:
            continue
        owner = conn.execute(
            "SELECT device_id FROM device_macs WHERE mac = ?", (mac,)
        ).fetchone()
        if owner:
            conn.execute(
                "UPDATE events SET device_id = ? WHERE device_id IS NULL AND src_ip = ?",
                (owner["device_id"], row["src_ip"]),
            )

    done = conn.execute(
        "SELECT count(*) FROM events WHERE device_id IS NOT NULL"
    ).fetchone()[0]
    conn.commit()
    return done

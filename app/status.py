#!/usr/bin/env python3
"""Inspect what the platform currently knows. Run on the gateway: securepi-db"""
import sqlite3

DB = "/var/lib/securepi/securepi.db"
c = sqlite3.connect(DB)
c.row_factory = sqlite3.Row

print("=== DEVICE REGISTRY ===")
for d in c.execute("SELECT * FROM devices ORDER BY id"):
    macs = c.execute(
        "SELECT mac, is_randomized FROM device_macs WHERE device_id=?", (d["id"],)
    ).fetchall()
    ips = c.execute(
        "SELECT ip FROM device_ips WHERE device_id=?", (d["id"],)
    ).fetchall()
    n = c.execute("SELECT count(*) FROM events WHERE device_id=?", (d["id"],)).fetchone()[0]
    print("  [%d] %s" % (d["id"], d["friendly_name"] or d["hostname"] or "unnamed"))
    print("      MACs:   %s" % ", ".join(
        "%s%s" % (m["mac"], " (randomized)" if m["is_randomized"] else "") for m in macs))
    print("      IPs:    %s" % ", ".join(i["ip"] for i in ips))
    print("      events: %d" % n)

print()
print("=== ATTRIBUTION ===")
tot = c.execute("SELECT count(*) FROM events").fetchone()[0]
att = c.execute("SELECT count(*) FROM events WHERE device_id IS NOT NULL").fetchone()[0]
# Attributable = anything from a LAN address or an IPv6 link-local address.
# Traffic from the gateway itself or from external hosts has no device to
# attribute to, and counting it would understate coverage.
lan = c.execute("""SELECT count(*) FROM events
                    WHERE src_ip LIKE '10.10.0.%' OR src_ip LIKE 'fe80%'""").fetchone()[0]
print("  events total        %d" % tot)
print("  attributable        %d  (LAN + link-local)" % lan)
print("  attributed          %d  (%.1f%% of LAN events)" % (att, 100.0 * att / lan if lan else 0))
print("  unattributed sources:")
for r in c.execute("""SELECT src_ip, count(*) n FROM events WHERE device_id IS NULL
                      GROUP BY src_ip ORDER BY n DESC LIMIT 5"""):
    print("     %-44s %d" % (r["src_ip"], r["n"]))

print()
print("=== PER-DEVICE ACTIVITY ===")
q = """
SELECT COALESCE(d.friendly_name, d.hostname, 'device ' || d.id) name,
       SUM(CASE WHEN e.event_type = 'flow' THEN e.bytes_toclient ELSE 0 END) down,
       SUM(CASE WHEN e.event_type = 'flow' THEN e.bytes_toserver ELSE 0 END) up,
       SUM(CASE WHEN e.event_type = 'dns'  THEN 1 ELSE 0 END) dns,
       SUM(CASE WHEN e.event_type = 'tls'  THEN 1 ELSE 0 END) tls,
       SUM(CASE WHEN e.alert_signature IS NOT NULL THEN 1 ELSE 0 END) alerts
  FROM devices d JOIN events e ON e.device_id = d.id
 GROUP BY d.id
"""
for r in c.execute(q):
    print("  %-18s  down %7.2f MB  up %6.0f KB  dns %4d  tls %4d  alerts %d"
          % (r["name"], (r["down"] or 0) / 1048576, (r["up"] or 0) / 1024,
             r["dns"], r["tls"], r["alerts"]))

print()
print("=== TOP DESTINATIONS BY DEVICE ===")
for r in c.execute("""
    SELECT COALESCE(d.friendly_name, d.hostname) name, e.tls_sni, count(*) n
      FROM events e JOIN devices d ON d.id = e.device_id
     WHERE e.tls_sni IS NOT NULL GROUP BY d.id, e.tls_sni ORDER BY n DESC LIMIT 8"""):
    print("  %-18s %-34s %d" % (r["name"], r["tls_sni"], r["n"]))

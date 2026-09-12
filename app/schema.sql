-- SecurePi Gateway - database schema
--
-- One table holds every event, whatever produced it. Suricata's own output
-- already shares a common backbone across its event types (timestamp, source
-- and destination address and port, protocol, flow id), so a single table with
-- those columns plus nullable type-specific ones fits the data naturally.
--
-- The alternative - a separate table per event type - would mean a UNION in
-- every correlation query, because the detections care about a device's whole
-- behaviour and not about one protocol at a time.

PRAGMA journal_mode = WAL;      -- readers do not block the writer
PRAGMA synchronous = NORMAL;    -- durable enough here, much faster

-- ---------------------------------------------------------------- devices --
-- One row per physical device seen on the project network. Events point here,
-- so an incident can say "Divye's phone" rather than an address that changes
-- whenever a DHCP lease rotates.
CREATE TABLE IF NOT EXISTS devices (
    id             INTEGER PRIMARY KEY,
    mac            TEXT UNIQUE NOT NULL,
    ip             TEXT,               -- current address; may change
    hostname       TEXT,               -- as announced over DHCP
    friendly_name  TEXT,               -- set by hand in the console
    first_seen     REAL NOT NULL,
    last_seen      REAL NOT NULL,
    is_active      INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_devices_ip  ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);

-- ----------------------------------------------------------------- events --
CREATE TABLE IF NOT EXISTS events (
    id             INTEGER PRIMARY KEY,

    -- Time is stored twice on purpose: epoch seconds for fast range queries,
    -- and the original string so nothing is lost to rounding or timezone bugs.
    ts             REAL NOT NULL,
    ts_iso         TEXT NOT NULL,

    source         TEXT NOT NULL,      -- 'suricata' or 'adguard'
    event_type     TEXT NOT NULL,      -- flow, dns, tls, alert, http, anomaly

    -- The common backbone, present on nearly every event.
    src_ip         TEXT,
    src_port       INTEGER,
    dest_ip        TEXT,
    dest_port      INTEGER,
    proto          TEXT,
    app_proto      TEXT,
    flow_id        INTEGER,            -- links events from the same connection
    community_id   TEXT,               -- same idea, but comparable across tools

    device_id      INTEGER REFERENCES devices(id),

    -- Flow records: how much was transferred, and in which direction.
    bytes_toserver INTEGER,
    bytes_toclient INTEGER,
    pkts_toserver  INTEGER,
    pkts_toclient  INTEGER,
    flow_state     TEXT,
    flow_age       INTEGER,

    -- DNS
    dns_type       TEXT,               -- 'query' or 'answer'
    dns_rrname     TEXT,               -- the domain asked for
    dns_rrtype     TEXT,               -- A, AAAA, HTTPS, ...
    dns_rcode      TEXT,               -- NOERROR, NXDOMAIN, ...

    -- TLS. The SNI is the hostname the client asked for, visible even though
    -- the rest of the connection is encrypted - the main lever we have on
    -- encrypted traffic.
    tls_sni        TEXT,
    tls_version    TEXT,
    tls_ja3        TEXT,               -- client fingerprint

    -- Suricata rule alerts
    alert_signature    TEXT,
    alert_category     TEXT,
    alert_severity     INTEGER,
    alert_signature_id INTEGER,

    -- Filtering decisions, which come from the DNS resolver rather than Suricata
    blocked        INTEGER,            -- 1 if the query was refused
    block_reason   TEXT
);

-- Indexes chosen for the queries the correlation engine will actually run:
-- "what did this device do in this window", and lookups by domain or name.
CREATE INDEX IF NOT EXISTS idx_events_ts          ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_device_ts   ON events(device_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ts      ON events(src_ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_type_ts     ON events(event_type, ts);
CREATE INDEX IF NOT EXISTS idx_events_dns_rrname  ON events(dns_rrname);
CREATE INDEX IF NOT EXISTS idx_events_tls_sni     ON events(tls_sni);
CREATE INDEX IF NOT EXISTS idx_events_flow_id     ON events(flow_id);

-- ----------------------------------------------------------- ingest state --
-- Where each reader got to. Without this, a restart would either re-read the
-- whole log (duplicates) or skip to the end (silent data loss).
--
-- The inode is stored because log rotation replaces the file: same path, new
-- inode. Seeing a different inode means "start from the beginning of the new
-- file", not "seek to a byte offset that no longer means anything".
CREATE TABLE IF NOT EXISTS ingest_state (
    source      TEXT PRIMARY KEY,
    file_path   TEXT NOT NULL,
    file_inode  INTEGER,
    byte_offset INTEGER NOT NULL DEFAULT 0,
    updated_at  REAL NOT NULL
);

-- ------------------------------------------------------------- statistics --
-- Counters the platform keeps about itself, so the console can show whether
-- ingest is keeping up rather than failing quietly.
CREATE TABLE IF NOT EXISTS ingest_stats (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    events_read  INTEGER NOT NULL DEFAULT 0,
    events_saved INTEGER NOT NULL DEFAULT 0,
    parse_errors INTEGER NOT NULL DEFAULT 0,
    last_run     REAL
);

INSERT OR IGNORE INTO ingest_stats (id) VALUES (1);

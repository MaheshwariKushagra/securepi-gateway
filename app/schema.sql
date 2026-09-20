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
-- Identity is deliberately NOT keyed on MAC address.
--
-- Both phones observed on this network use randomized MACs (the locally
-- administered bit is set: ca:25:... and a2:c8:...). Modern Android and iOS
-- generate a fresh MAC per network and rotate it periodically, so keying on
-- MAC would make one physical phone appear as a stream of new devices - and
-- every device-scoped detection would reset with it.
--
-- A device therefore has its own identity, with MACs and IP addresses
-- recorded beneath it as time intervals. The hostname is the anchor that
-- survives MAC rotation, with manual naming as the fallback when it does not.
CREATE TABLE IF NOT EXISTS devices (
    id             INTEGER PRIMARY KEY,
    hostname       TEXT,               -- as announced over DHCP; survives MAC rotation
    friendly_name  TEXT,               -- set by hand in the console; wins over hostname
    first_seen     REAL NOT NULL,
    last_seen      REAL NOT NULL,
    is_active      INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_devices_hostname ON devices(hostname);

-- Every MAC a device has used. A new randomized MAC with a familiar hostname
-- adds a row here rather than creating a second device.
CREATE TABLE IF NOT EXISTS device_macs (
    id            INTEGER PRIMARY KEY,
    device_id     INTEGER NOT NULL REFERENCES devices(id),
    mac           TEXT NOT NULL UNIQUE,
    is_randomized INTEGER NOT NULL DEFAULT 0,
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_macs_mac ON device_macs(mac);

-- Which device held which address, and when. Attribution has to be historical:
-- an event from three hours ago belongs to whoever held that address then, not
-- to whoever holds it now. Without these intervals, a single DHCP rotation
-- would silently reassign past events to the wrong device.
CREATE TABLE IF NOT EXISTS device_ips (
    id         INTEGER PRIMARY KEY,
    device_id  INTEGER NOT NULL REFERENCES devices(id),
    ip         TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_ips_lookup ON device_ips(ip, first_seen, last_seen);

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
    block_reason   TEXT,

    -- Tier 1 (DNS) filtering telemetry - which blocklist matched, whether
    -- the answer was served from cache, and which upstream resolver
    -- answered, if not cached. These feed the ad-blocking analytics and
    -- blocklist-health pages (ENHANCEMENT-PLAN.md steps 5.3, 5.4) - without
    -- them, "which list is actually earning its place" is unanswerable.
    dns_filter_list_id INTEGER,
    dns_cached         INTEGER,
    dns_upstream       TEXT,
    dns_elapsed_ms     REAL,

    -- Tier 2 (selective HTTPS inspection) telemetry, written by
    -- dpi/securepi_adfilter.py as source='dpi', event_type='dpi_decision'
    -- rows and read by ingest.py's read_dpi_events(). Reusing this same
    -- events table rather than a bespoke one keeps the "one unified event
    -- shape" design (see the file header above) - tls_sni above already
    -- holds the hostname decided on, and block_reason above doubles as the
    -- blocked-path text for a 'path_blocked' decision.
    --   dpi_action:      'decrypt' | 'passthrough' | 'ads_stripped' | 'path_blocked'
    --   dpi_ads_removed: count of ad objects removed, for 'ads_stripped' rows
    dpi_action      TEXT,
    dpi_ads_removed INTEGER,

    -- DHCP option 55 (the Parameter Request List a client sends when
    -- asking for a lease) - device fingerprinting evidence
    -- (ENHANCEMENT-PLAN.md step 6.2). Comma-separated option numbers,
    -- only present on event_type='dhcp' rows once suricata.yaml's dhcp
    -- logger is in extended mode. See app/ingest.py's flatten_suricata
    -- for why this is read defensively.
    dhcp_params TEXT
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
-- Added for step 6.5's Hunt/explorer page - searching and pivoting by
-- destination IP is one of its core operations, and had no index before.
CREATE INDEX IF NOT EXISTS idx_events_dest_ip     ON events(dest_ip);

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
    updated_at  REAL NOT NULL,
    -- Step 1.4: the AdGuard API-polling reader has no file/byte-offset
    -- concept (it's not tailing a file), so it needs a real epoch-seconds
    -- watermark instead - REAL, not byte_offset's INTEGER, since AdGuard's
    -- own timestamps carry nanosecond precision and truncating to whole
    -- seconds could re-ingest (or skip) an entry at a second boundary.
    watermark_ts REAL
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


-- --------------------------------------------------------------- incidents --
-- The correlation engine's output. A signal firing does not itself create an
-- incident - incidents group one or more related signal firings by device
-- and time, so a burst of the same signal produces one incident, not one per
-- firing. This is the alert-to-incident reduction the correlation layer
-- exists to provide.
CREATE TABLE IF NOT EXISTS incidents (
    id             INTEGER PRIMARY KEY,
    device_id      INTEGER REFERENCES devices(id),
    signal_type    TEXT NOT NULL,       -- 'port_scan', 'brute_force', 'malicious_domain', 'new_device'
    severity       TEXT NOT NULL,       -- 'low', 'medium', 'high'
    title          TEXT NOT NULL,       -- plain-language summary for the console
    description    TEXT,                -- one paragraph of detail
    status         TEXT NOT NULL DEFAULT 'new',  -- new, investigating, resolved, false_positive
    first_seen     REAL NOT NULL,       -- start of the activity that caused this
    last_seen       REAL NOT NULL,       -- most recent contributing event
    created_at     REAL NOT NULL,       -- when the engine raised it
    updated_at     REAL NOT NULL,
    evidence_count INTEGER NOT NULL DEFAULT 0,
    campaign_id    INTEGER REFERENCES campaigns(id)  -- ENHANCEMENT-PLAN.md step 2.8
);

CREATE INDEX IF NOT EXISTS idx_incidents_device   ON incidents(device_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status    ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_created   ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_signal_dev_lastseen ON incidents(signal_type, device_id, last_seen);

-- The evidence chain: which specific events justify each incident. This is
-- what lets the console answer "why was this raised?" rather than presenting
-- an unexplained verdict.
CREATE TABLE IF NOT EXISTS incident_events (
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    event_id    INTEGER NOT NULL REFERENCES events(id),
    PRIMARY KEY (incident_id, event_id)
);

-- Bookkeeping for the engine itself: the timestamp each signal last examined,
-- so re-running the engine does not re-scan the entire event history every
-- cycle, and does not re-raise the same incident twice for the same window.
CREATE TABLE IF NOT EXISTS signal_state (
    signal_type TEXT PRIMARY KEY,
    last_run_ts REAL NOT NULL
);

-- ------------------------------------------------------------ device_hourly --
-- One row per device per fully-closed hour: how much it did in that hour.
-- ENHANCEMENT-PLAN.md step 6.1 (behavioural baselines) needs this to compare
-- "this hour" against the same hour-of-day on past days - a windowed query
-- over raw `events` can't do that cheaply once there are weeks of history,
-- the way the four original signals' short trailing windows can.
--
-- This table, and app/rollup.py which fills it, are the minimal prerequisite
-- 6.1 actually needs - not the full Stage 1 F3 feature ("Retention + hourly
-- rollups"), which also prunes old raw events and keeps rollups for 180 days.
-- Nothing here deletes anything; that's F3's job, still to come.
CREATE TABLE IF NOT EXISTS device_hourly (
    device_id   INTEGER NOT NULL REFERENCES devices(id),
    hour_start  INTEGER NOT NULL,   -- epoch seconds, truncated to the top of the hour
    bytes_down  INTEGER NOT NULL DEFAULT 0,
    bytes_up    INTEGER NOT NULL DEFAULT 0,
    dns_queries INTEGER NOT NULL DEFAULT 0,
    dns_blocked INTEGER NOT NULL DEFAULT 0,
    flows       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, hour_start)
);

CREATE INDEX IF NOT EXISTS idx_device_hourly_hour ON device_hourly(hour_start);

-- ---------------------------------------------------------------- settings --
-- Runtime-tunable thresholds (ENHANCEMENT-PLAN.md step 6.3, and the minimal
-- slice of Stage 1's F2 "central config" this step needs). One row per
-- setting; `value` is JSON-encoded so an int, float, bool or string all
-- round-trip cleanly through the same column. A key with no row here simply
-- uses app/settings.py's own built-in default - this table only ever holds
-- OVERRIDES, not a full copy of every setting's value.
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at REAL NOT NULL
);

-- -------------------------------------------------------------- audit_log --
-- One row per console action that changes something (ENHANCEMENT-PLAN.md
-- step 1.5, "Audit log" - built here as the minimal prerequisite step 6.3's
-- "audit viewer" needs, the same way step 6.1 built device_hourly and 6.2
-- built dhcp_params rather than waiting for their own stage). Several
-- endpoints across app/webapp.py already print an audit-shaped line to the
-- journal as a stopgap "until step 1.5 exists" - this table is that step,
-- and those print() calls now also write here. The print() lines stay too:
-- the journal is still useful for someone watching live, this table is what
-- makes the history queryable and displayable in the console itself.
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY,
    ts         REAL NOT NULL,
    actor      TEXT NOT NULL,   -- the console username; there is only one today
    action     TEXT NOT NULL,   -- short verb-object, e.g. 'filtering.allow', 'settings.update'
    target     TEXT,            -- what it acted on, e.g. a domain, a device id, a setting key
    detail     TEXT             -- free-text: the reason given, the before/after values, etc.
);

CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);

-- ----------------------------------------------------------- incident_notes --
-- Free-text analyst notes on an incident (ENHANCEMENT-PLAN.md step 6.4,
-- "Incident workbench"). Status changes are NOT stored here - they already
-- go through audit_log (action='incident.status_change', target=the
-- incident id as text), which is what the workbench's status-change
-- timeline reads from. This table is only for notes an operator writes
-- by hand, e.g. "confirmed this is the new smart TV, false positive".
CREATE TABLE IF NOT EXISTS incident_notes (
    id          INTEGER PRIMARY KEY,
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    ts          REAL NOT NULL,
    author      TEXT NOT NULL,
    note        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incident_notes_incident ON incident_notes(incident_id);

-- ---------------------------------------------------------- saved_searches --
-- Named Hunt/explorer filter sets an operator wants to reuse
-- (ENHANCEMENT-PLAN.md step 6.5). `filters` is a JSON-encoded object
-- (device_id/ip/domain/port/event_type/range) - the same "one JSON
-- column, validated in Python" shape step 6.3's settings table uses,
-- since a saved search is really just a small, named config blob too.
CREATE TABLE IF NOT EXISTS saved_searches (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    filters    TEXT NOT NULL,
    created_at REAL NOT NULL
);

-- -------------------------------------------------------------- campaigns --
-- Multi-stage attack correlation (ENHANCEMENT-PLAN.md step 2.8): links
-- several of one device's OPEN incidents, spanning at least two DISTINCT
-- MITRE ATT&CK tactics (app/playbooks.py's own mapping - an incident
-- with no recognized tactic, like malicious_domain or new_device, can't
-- be a kill-chain stage), into one campaign. `tactics` is the
-- kill-chain itself: the distinct tactics seen, in the order their
-- first incident actually started - "Discovery -> Credential Access ->
-- Command and Control" for the plan's own scan -> brute-force -> beacon
-- example. Mirrors incidents' own status lifecycle (new/investigating/
-- resolved/false_positive) so a campaign can be triaged the same way.
CREATE TABLE IF NOT EXISTS campaigns (
    id         INTEGER PRIMARY KEY,
    device_id  INTEGER NOT NULL REFERENCES devices(id),
    title      TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'new',
    tactics    TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaigns_device ON campaigns(device_id);

-- ------------------------------------------------------------------- ioc --
-- Offline threat intelligence (ENHANCEMENT-PLAN.md step 2.4): confirmed-
-- malicious IPs and domains from abuse.ch's Feodo Tracker (botnet C2 IPs),
-- URLhaus (malware-hosting hostnames) and ThreatFox (mixed IOC types,
-- filtered to just 'ip:port' and 'domain' - see app/intel.py). Fetched
-- daily by a systemd timer, never on a request path.
--
-- `source` matters for de-duplication, not display: the SAME indicator
-- can legitimately appear from more than one feed (all three are curated
-- by the same abuse.ch project), so the UNIQUE constraint is on the
-- (indicator, ioc_type, source) triple - one row per feed's own claim
-- about an indicator, not one row per indicator overall. A refresh
-- extends last_seen for an indicator still present in its feed rather
-- than deleting and re-inserting, so first_seen keeps meaning "since
-- when has THIS gateway believed this indicator is bad" even across
-- daily refreshes.
CREATE TABLE IF NOT EXISTS ioc (
    id          INTEGER PRIMARY KEY,
    indicator   TEXT NOT NULL,       -- an IP address or a domain name
    ioc_type    TEXT NOT NULL,       -- 'ip' or 'domain'
    source      TEXT NOT NULL,       -- 'feodo' | 'urlhaus' | 'threatfox'
    description TEXT,                -- e.g. a malware family name, when the feed supplies one
    first_seen  REAL NOT NULL,       -- when THIS gateway first loaded it
    last_seen   REAL NOT NULL,       -- when THIS gateway most recently saw it still listed
    UNIQUE (indicator, ioc_type, source)
);

CREATE INDEX IF NOT EXISTS idx_ioc_indicator ON ioc(indicator, ioc_type);

-- --------------------------------------------------------------- suppressions --
-- Operator-created "stop raising this" rules (ENHANCEMENT-PLAN.md step
-- 2.7), always starting from a real false-positive verdict on a real
-- incident rather than guessed at in advance. Scoped to (signal_type,
-- device_id) - device_id NULL means network-wide for that signal_type.
-- This is deliberately coarser than per-destination suppression (e.g.
-- "stop threat_intel for THIS ip on THIS device" specifically): each of
-- this project's signals varies its own "what's the specific recurring
-- thing" differently (a destination for port_scan/beacon, a domain for
-- malicious_domain, an alert category for ids_alert, ...), and a truly
-- generic per-signal match key would need its own small schema per
-- signal type - a real, stated scope boundary, not an oversight. An
-- operator who wants THIS destination allowed can already use the
-- Filtering page's "unbreak" tools (step 5.2) for DNS-level cases;
-- suppression here is for "this signal doesn't apply to this device (or
-- this network) at all", the coarser and more common real need.
--
-- `expires_at` NULL means the rule never expires on its own - an
-- operator can still delete it explicitly. correlation.py's
-- raise_incident() checks this table's live (non-expired) rows before
-- ever inserting or extending an incident; app/retention.py's daily run
-- physically removes rows whose expiry has already passed, purely as
-- housekeeping (an expired rule is already inert - see suppression.py's
-- own is_suppressed()).
CREATE TABLE IF NOT EXISTS suppressions (
    id          INTEGER PRIMARY KEY,
    signal_type TEXT NOT NULL,
    device_id   INTEGER REFERENCES devices(id),
    reason      TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  REAL NOT NULL,
    expires_at  REAL
);

CREATE INDEX IF NOT EXISTS idx_suppressions_signal_device ON suppressions(signal_type, device_id);

-- One row per feed: when it last successfully refreshed, and what went
-- wrong the last time it didn't - the "feed age visible" half of this
-- step's own exit criterion. A failed fetch is recorded here but never
-- touches the ioc table itself (fail-safe, the same principle
-- gateway/refresh-doh-set.sh already applies to the doh_resolvers set):
-- yesterday's indicators stay live rather than the whole feed silently
-- going empty because of one bad fetch.
CREATE TABLE IF NOT EXISTS intel_feed_state (
    source          TEXT PRIMARY KEY,
    last_fetched    REAL,
    last_error      TEXT,
    indicator_count INTEGER
);

-- -------------------------------------------------------------- sessions --
-- Console login sessions (ENHANCEMENT-PLAN.md step 3.1, "Session
-- authentication"), replacing the HTTP Basic Auth this console used
-- through Stage 2. `token` is the value the HttpOnly SameSite=Strict
-- cookie carries - a random, unguessable string with no information of
-- its own, so a stolen cookie is useless once its row here is deleted.
-- Kept in the database rather than process memory for the same reason
-- audit_log/settings are tables: a `securepi-web` restart (part of
-- every `make deploy`) shouldn't silently sign everyone out, and this
-- console is a single process, so there's no multi-worker consistency
-- problem a table has to solve either. See app/session_auth.py.
CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    username    TEXT NOT NULL,
    created_at  REAL NOT NULL,
    last_active REAL NOT NULL,   -- refreshed on every authenticated request; drives the idle timeout
    expires_at  REAL NOT NULL    -- absolute cap, regardless of activity
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- -------------------------------------------------------- login_attempts --
-- One row per FAILED login, keyed by client IP (step 3.1's rate limit -
-- see app/session_auth.py's check_rate_limit()). A successful login
-- never adds a row here, and clears any of the same IP's existing rows,
-- so only a sustained guessing pattern from one address is ever
-- throttled, not a legitimate user who mistyped their password once
-- or twice.
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL,
    ts REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_ts ON login_attempts(ip, ts);

INSERT OR IGNORE INTO ingest_stats (id) VALUES (1);

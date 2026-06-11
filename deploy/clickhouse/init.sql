-- OpenNGFW telemetry schema. Vector ships Suricata EVE JSON into these
-- tables (see internal/renderers/vector). Apply with:
--   clickhouse-client --multiquery < init.sql

CREATE DATABASE IF NOT EXISTS openngfw;

-- All EVE events, loosely typed for evolution; query via JSON functions
-- or the materialized columns below.
CREATE TABLE IF NOT EXISTS openngfw.events
(
    ingested_at  DateTime DEFAULT now(),
    timestamp    String,
    event_type   LowCardinality(String),
    src_ip       String,
    src_port     UInt16 DEFAULT 0,
    dest_ip      String,
    dest_port    UInt16 DEFAULT 0,
    proto        LowCardinality(String),
    app_proto    LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ingested_at)
ORDER BY (event_type, ingested_at)
TTL ingested_at + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS openngfw.alerts
(
    ingested_at  DateTime DEFAULT now(),
    timestamp    String,
    src_ip       String,
    src_port     UInt16 DEFAULT 0,
    dest_ip      String,
    dest_port    UInt16 DEFAULT 0,
    proto        LowCardinality(String),
    alert        String  -- full alert object as JSON
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ingested_at)
ORDER BY ingested_at
TTL ingested_at + INTERVAL 90 DAY;

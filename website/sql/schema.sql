-- MNM Combat Parser — PostgreSQL Schema
-- Run: psql -U mnm -d mnm -f schema.sql

BEGIN;

-- =====================================================================
-- Players — deduplicated by (entity_name, class_hid)
-- =====================================================================
CREATE TABLE IF NOT EXISTS players (
    id          BIGSERIAL PRIMARY KEY,
    entity_name VARCHAR(64)  NOT NULL,
    class_hid   VARCHAR(16)  NOT NULL DEFAULT '',
    level       SMALLINT,
    guild_name  VARCHAR(64),
    first_seen  TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (entity_name, class_hid)
);

CREATE INDEX IF NOT EXISTS idx_players_name ON players (entity_name);
CREATE INDEX IF NOT EXISTS idx_players_class ON players (class_hid);

-- =====================================================================
-- NPCs — deduplicated by (entity_name, class_hid, level)
-- =====================================================================
CREATE TABLE IF NOT EXISTS npcs (
    id          BIGSERIAL PRIMARY KEY,
    entity_name VARCHAR(128) NOT NULL,
    entity_type SMALLINT,
    class_hid   VARCHAR(16)  NOT NULL DEFAULT '',
    level       SMALLINT,
    max_health  INT,
    max_mana    INT,
    is_hostile  BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen  TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (entity_name, class_hid, level)
);

CREATE INDEX IF NOT EXISTS idx_npcs_name  ON npcs (entity_name);
CREATE INDEX IF NOT EXISTS idx_npcs_level ON npcs (level);

-- =====================================================================
-- Items — deduplicated by hid (game's internal string ID)
-- =====================================================================
CREATE TABLE IF NOT EXISTS items (
    id              BIGSERIAL PRIMARY KEY,
    hid             VARCHAR(128) UNIQUE NOT NULL,
    name            VARCHAR(128),
    item_type       SMALLINT,
    class_mask      INT,
    race_mask       INT,
    slot_mask       INT,
    required_level  SMALLINT,
    no_drop         BOOLEAN NOT NULL DEFAULT FALSE,
    is_unique       BOOLEAN NOT NULL DEFAULT FALSE,
    is_magic        BOOLEAN NOT NULL DEFAULT FALSE,
    stack_size      SMALLINT,
    charges         SMALLINT,
    damage          INT,
    delay           INT,
    ac              INT,
    strength        INT,
    stamina         INT,
    dexterity       INT,
    agility         INT,
    intelligence    INT,
    wisdom          INT,
    charisma        INT,
    health          INT,
    health_regen    INT,
    mana            INT,
    mana_regen      INT,
    melee_haste     INT,
    ranged_haste    INT,
    spell_haste     INT,
    resist_fire     INT,
    resist_cold     INT,
    resist_poison   INT,
    resist_disease  INT,
    resist_magic    INT,
    resist_arcane   INT,
    resist_nature   INT,
    resist_holy     INT,
    weight          REAL,
    description     TEXT,
    effects         TEXT,  -- JSON array
    first_seen      TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_items_name ON items (name);
CREATE INDEX IF NOT EXISTS idx_items_type ON items (item_type);

-- =====================================================================
-- Combat events — partitioned by month on created_at
-- =====================================================================
CREATE TABLE IF NOT EXISTS combat_events (
    id              BIGSERIAL,
    event_type      VARCHAR(32) NOT NULL,  -- 'kill' or 'dps_snapshot'
    source_name     VARCHAR(64),
    source_class    VARCHAR(16),
    source_level    SMALLINT,
    target_name     VARCHAR(64),
    target_class    VARCHAR(16),
    target_level    SMALLINT,
    damage_total    INT,
    dps             REAL,
    healing_total   INT,
    duration_secs   REAL,
    killer_name     VARCHAR(64),
    pos_x           REAL,
    pos_y           REAL,
    pos_z           REAL,
    submitter_hash  VARCHAR(64),
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

CREATE INDEX IF NOT EXISTS idx_combat_created  ON combat_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_combat_source   ON combat_events (source_name);
CREATE INDEX IF NOT EXISTS idx_combat_target   ON combat_events (target_name);
CREATE INDEX IF NOT EXISTS idx_combat_dps      ON combat_events (dps DESC);
CREATE INDEX IF NOT EXISTS idx_combat_type     ON combat_events (event_type);

-- Create partitions for 2026 (extend as needed)
CREATE TABLE IF NOT EXISTS combat_events_2026_01 PARTITION OF combat_events
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE IF NOT EXISTS combat_events_2026_02 PARTITION OF combat_events
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE IF NOT EXISTS combat_events_2026_03 PARTITION OF combat_events
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE IF NOT EXISTS combat_events_2026_04 PARTITION OF combat_events
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE IF NOT EXISTS combat_events_2026_05 PARTITION OF combat_events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE IF NOT EXISTS combat_events_2026_06 PARTITION OF combat_events
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE IF NOT EXISTS combat_events_2026_07 PARTITION OF combat_events
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE IF NOT EXISTS combat_events_2026_08 PARTITION OF combat_events
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE IF NOT EXISTS combat_events_2026_09 PARTITION OF combat_events
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE IF NOT EXISTS combat_events_2026_10 PARTITION OF combat_events
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE IF NOT EXISTS combat_events_2026_11 PARTITION OF combat_events
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE IF NOT EXISTS combat_events_2026_12 PARTITION OF combat_events
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');

-- =====================================================================
-- Loot events — partitioned by month on created_at
-- =====================================================================
CREATE TABLE IF NOT EXISTS loot_events (
    id              BIGSERIAL,
    player_name     VARCHAR(64),
    player_class    VARCHAR(16),
    player_level    SMALLINT,
    item_hid        VARCHAR(128),
    item_name       VARCHAR(128),
    npc_name        VARCHAR(128),
    quantity        SMALLINT NOT NULL DEFAULT 1,
    submitter_hash  VARCHAR(64),
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

CREATE INDEX IF NOT EXISTS idx_loot_created ON loot_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_loot_item    ON loot_events (item_name);
CREATE INDEX IF NOT EXISTS idx_loot_npc     ON loot_events (npc_name);
CREATE INDEX IF NOT EXISTS idx_loot_player  ON loot_events (player_name);

-- Loot partitions for 2026
CREATE TABLE IF NOT EXISTS loot_events_2026_01 PARTITION OF loot_events
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE IF NOT EXISTS loot_events_2026_02 PARTITION OF loot_events
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE IF NOT EXISTS loot_events_2026_03 PARTITION OF loot_events
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE IF NOT EXISTS loot_events_2026_04 PARTITION OF loot_events
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE IF NOT EXISTS loot_events_2026_05 PARTITION OF loot_events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE IF NOT EXISTS loot_events_2026_06 PARTITION OF loot_events
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE IF NOT EXISTS loot_events_2026_07 PARTITION OF loot_events
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE IF NOT EXISTS loot_events_2026_08 PARTITION OF loot_events
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE IF NOT EXISTS loot_events_2026_09 PARTITION OF loot_events
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE IF NOT EXISTS loot_events_2026_10 PARTITION OF loot_events
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE IF NOT EXISTS loot_events_2026_11 PARTITION OF loot_events
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE IF NOT EXISTS loot_events_2026_12 PARTITION OF loot_events
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');

-- =====================================================================
-- API keys — stores SHA256 hashes of valid keys
-- =====================================================================
CREATE TABLE IF NOT EXISTS api_keys (
    id          SERIAL PRIMARY KEY,
    key_hash    VARCHAR(64) UNIQUE NOT NULL,  -- SHA256 hex of raw key
    label       VARCHAR(64),
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    last_used   TIMESTAMP
);

-- =====================================================================
-- Rate limits — per-key per-window request counts
-- =====================================================================
CREATE TABLE IF NOT EXISTS rate_limits (
    id          SERIAL PRIMARY KEY,
    key_hash    VARCHAR(64) NOT NULL REFERENCES api_keys(key_hash),
    window_start TIMESTAMP NOT NULL,
    request_count INT NOT NULL DEFAULT 0,
    UNIQUE (key_hash, window_start)
);

CREATE INDEX IF NOT EXISTS idx_ratelimit_key ON rate_limits (key_hash, window_start);

COMMIT;

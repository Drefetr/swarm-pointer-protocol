-- SPP v1 durable relay storage schema.
--
-- Accepted signed assertions are stored as canonical bytes and indexed by
-- their identity, channel and referenced object hash. Indexes are derived
-- only after frozen §20 validation succeeds. No referenced content is stored.

CREATE TABLE IF NOT EXISTS assertions (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    id           TEXT    UNIQUE NOT NULL,
    envelope     BLOB    NOT NULL,
    type         TEXT    NOT NULL,
    actor        TEXT    NOT NULL,
    channel      TEXT    NULL,
    object_hash  TEXT    NULL,
    accepted_at  INTEGER NOT NULL
);

-- A channel-description (channel-type) assertion makes its own id advertised.
CREATE TABLE IF NOT EXISTS advertised_channels (
    channel      TEXT PRIMARY KEY,
    assertion_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS assertions_channel_idx     ON assertions(channel);
CREATE INDEX IF NOT EXISTS assertions_object_hash_idx ON assertions(object_hash);
CREATE INDEX IF NOT EXISTS assertions_actor_idx       ON assertions(actor);

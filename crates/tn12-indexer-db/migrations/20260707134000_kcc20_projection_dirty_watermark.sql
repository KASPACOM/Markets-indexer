-- KCC20 read-model refreshes are expensive and should run only after a
-- KCC20-relevant write/revert, not on every projector idle loop.

CREATE TABLE IF NOT EXISTS kcc20_projection_dirty (
    id            BIGSERIAL PRIMARY KEY,
    reason        TEXT NOT NULL,
    txid          BYTEA,
    created_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS kcc20_projection_dirty_id_idx
    ON kcc20_projection_dirty (id DESC);

CREATE TABLE IF NOT EXISTS kcc20_projection_state (
    name          TEXT PRIMARY KEY,
    last_dirty_id BIGINT NOT NULL DEFAULT 0,
    refreshed_at_ms BIGINT NOT NULL
);

INSERT INTO kcc20_projection_dirty (reason, txid, created_at_ms)
SELECT 'migration_initial_refresh', NULL, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
WHERE NOT EXISTS (SELECT 1 FROM kcc20_projection_dirty);

CREATE TABLE IF NOT EXISTS tip_follower_windows (
    cursor_key TEXT NOT NULL,
    window_start BIGINT NOT NULL CHECK (window_start >= 0),
    block_hashes JSONB NOT NULL,
    persisted_acceptances JSONB NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (cursor_key, window_start)
);

CREATE INDEX IF NOT EXISTS tip_follower_windows_updated_at_idx
    ON tip_follower_windows (updated_at_ms);

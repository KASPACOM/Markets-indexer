ALTER TABLE covenant_actions
    ADD COLUMN IF NOT EXISTS canonical_token_id BYTEA;

CREATE INDEX IF NOT EXISTS covenant_actions_canonical_token_time_idx
    ON covenant_actions(canonical_token_id, block_time_ms DESC)
    WHERE canonical_token_id IS NOT NULL;

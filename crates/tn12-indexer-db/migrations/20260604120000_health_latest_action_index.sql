-- Keep /health and /kcc20/freshness from scanning the full action table.
CREATE INDEX IF NOT EXISTS covenant_actions_block_time_desc_idx
    ON covenant_actions (block_time_ms DESC);

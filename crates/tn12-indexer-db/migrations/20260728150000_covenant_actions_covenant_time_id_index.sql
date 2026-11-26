-- no-transaction

CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_actions_covenant_time_id_idx
    ON covenant_actions (covenant_id, block_time_ms DESC, id DESC);

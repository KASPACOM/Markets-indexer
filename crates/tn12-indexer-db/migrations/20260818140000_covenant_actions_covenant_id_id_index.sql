-- no-transaction

CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_actions_covenant_id_id_idx
    ON covenant_actions (covenant_id, id);

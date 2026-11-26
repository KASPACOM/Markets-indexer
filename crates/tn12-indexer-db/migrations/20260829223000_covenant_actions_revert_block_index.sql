-- no-transaction

-- Reorg handling filters and deletes actions by block hash. PostgreSQL does
-- not create an index for the foreign-key column automatically.
CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_actions_revert_block_idx
    ON covenant_actions (block_hash) INCLUDE (action, covenant_id);

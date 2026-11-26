-- no-transaction

-- The first active-status index rollout can leave an invalid index behind if
-- CREATE INDEX CONCURRENTLY is interrupted. IF NOT EXISTS will not repair that
-- state, so drop the non-data index before recreating it.
DROP INDEX CONCURRENTLY IF EXISTS covenant_utxos_status_active_idx;

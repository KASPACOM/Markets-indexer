-- no-transaction

-- Concurrent index builds interrupted by statement_timeout can leave an
-- invalid index that IF NOT EXISTS will not repair.
DROP INDEX CONCURRENTLY IF EXISTS covenant_actions_output_address_time_idx;

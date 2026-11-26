-- no-transaction

-- The original owner-order index also retained holder cells (mode 0).
-- Drop it separately from the concurrent replacement.
DROP INDEX CONCURRENTLY IF EXISTS covenant_utxos_kcc20_owner_order_state_idx;

-- no-transaction
-- Build without blocking canonical writers. The next migration refuses to use
-- an interrupted/invalid index; operators must rebuild it concurrently first.
CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_active_outpoint_backfill_idx
    ON covenant_utxos(txid,vout) INCLUDE(covenant_id,created_block)
    WHERE status='active' AND covenant_id IS NOT NULL;

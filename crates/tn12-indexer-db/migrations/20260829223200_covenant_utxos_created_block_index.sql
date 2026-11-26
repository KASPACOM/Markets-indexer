-- no-transaction

CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_created_block_idx
    ON covenant_utxos (created_block);

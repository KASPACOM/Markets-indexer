-- no-transaction

CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_spent_block_idx
    ON covenant_utxos (spent_block) INCLUDE (covenant_id)
    WHERE spent_block IS NOT NULL;

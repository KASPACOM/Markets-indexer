-- no-transaction

CREATE INDEX CONCURRENTLY IF NOT EXISTS covenants_genesis_block_idx
    ON covenants (genesis_block);

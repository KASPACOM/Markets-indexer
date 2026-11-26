-- no-transaction

-- Continuation families join child covenants by their genesis transaction.
-- Keep full portfolio rebuilds from degrading into repeated covenant scans.
CREATE INDEX CONCURRENTLY IF NOT EXISTS covenants_genesis_txid_idx
    ON covenants (genesis_txid)
    WHERE genesis_txid IS NOT NULL;

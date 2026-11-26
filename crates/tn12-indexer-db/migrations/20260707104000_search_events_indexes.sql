-- no-transaction

-- Speeds direct address lookups in /explorer/search. The table is large on
-- TN10, so keep this concurrent and additive.
CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_address_idx
    ON covenant_utxos (address);

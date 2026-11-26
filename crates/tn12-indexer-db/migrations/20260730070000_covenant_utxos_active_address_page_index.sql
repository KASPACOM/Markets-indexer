-- no-transaction

CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_active_address_amount_outpoint_idx
    ON covenant_utxos (address, amount_sompi DESC, txid ASC, vout ASC)
    INCLUDE (covenant_id)
    WHERE status = 'active';

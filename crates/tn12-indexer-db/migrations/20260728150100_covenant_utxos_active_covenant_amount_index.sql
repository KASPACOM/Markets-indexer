-- no-transaction

CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_active_covenant_amount_outpoint_idx
    ON covenant_utxos (covenant_id, amount_sompi DESC, txid ASC, vout ASC)
    WHERE status = 'active';

-- no-transaction

-- Only order modes need this index; mode 0 holder cells do not enter the
-- owner-order projection.
CREATE INDEX CONCURRENTLY covenant_utxos_kcc20_owner_order_state_idx
    ON covenant_utxos ((state->>'ownerIdentifier'), (state->>'mode'), covenant_id)
    WHERE status = 'active'
      AND state ? 'ownerIdentifier'
      AND state->>'mode' IN ('2', '3');

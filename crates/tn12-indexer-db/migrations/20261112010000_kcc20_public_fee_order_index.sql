-- no-transaction

-- Public market reads also admit fee owners through verified template identity
-- or wrapper backing when a feePolicy key is absent. Keep those rows indexed.
CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_kcc20_public_fee_order_idx
    ON covenant_utxos ((state->>'owner'), (state->>'mode'), covenant_id)
    WHERE status = 'active'
      AND NOT (state ? 'ownerIdentifier')
      AND state->>'feePolicyVersion' = '1'
      AND state ? 'owner'
      AND state->>'mode' IN ('2', '3');

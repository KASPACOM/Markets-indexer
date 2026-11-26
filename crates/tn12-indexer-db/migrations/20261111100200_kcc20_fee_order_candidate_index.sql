-- no-transaction

-- Fee holder cells (mode 0) must stay out of owner-order candidate scans.
CREATE INDEX CONCURRENTLY covenant_utxos_kcc20_fee_order_state_idx
    ON covenant_utxos ((state->>'owner'), (state->>'mode'), covenant_id)
    WHERE status = 'active'
      AND NOT (state ? 'ownerIdentifier')
      AND state->>'feePolicyVersion' = '1'
      AND state ? 'feePolicy'
      AND state ? 'owner'
      AND state->>'mode' IN ('2', '3');

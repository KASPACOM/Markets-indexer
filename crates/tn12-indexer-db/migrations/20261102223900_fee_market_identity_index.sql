-- no-transaction

CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_fee_market_identity_idx
ON covenant_utxos (covenant_id)
WHERE state->>'feePolicyVersion' = '1' AND state ? 'feePolicy';

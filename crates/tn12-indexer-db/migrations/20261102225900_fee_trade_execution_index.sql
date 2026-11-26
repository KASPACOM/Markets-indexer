-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_actions_fee_trades_idx
ON covenant_actions (block_time_ms DESC, txid, covenant_id)
WHERE action='spend' AND entrypoint IN ('buyAsks','sellIntoBids','crossWithBid')
  AND decoded_args->>'feePolicyVersion'='1' AND decoded_args ? 'feePolicy';

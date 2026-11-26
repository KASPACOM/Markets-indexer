-- Read-side market identity only. Do not insert fee roles into the legacy
-- wrapper registry: the backend uses that registry to reject duplicate markets.
CREATE VIEW kcc20_portfolio_market_identities AS
SELECT wrapper_id, canonical_token_id, active_utxos, pending_reveal, fee_ticket_id
FROM kcc20_wrapper_summaries
UNION ALL
SELECT u.covenant_id AS wrapper_id,
       decode(MIN(u.state->>'canonicalTokenId'), 'hex') AS canonical_token_id,
       COUNT(*) FILTER (WHERE u.status = 'active') AS active_utxos,
       FALSE AS pending_reveal,
       decode(MIN(u.state->>'feeTicketId'), 'hex') AS fee_ticket_id
FROM covenant_utxos u
WHERE u.state->>'feePolicyVersion' = '1' AND u.state ? 'feePolicy'
  AND u.state->>'mode' IN ('0', '1', '2', '3')
  AND u.state->>'canonicalTokenId' ~ '^[0-9a-f]{64}$'
  AND u.state->>'feeTicketId' ~ '^[0-9a-f]{64}$'
  AND u.status IN ('active', 'spent')
  AND NOT EXISTS (
      SELECT 1 FROM kcc20_wrapper_summaries w WHERE w.wrapper_id = u.covenant_id
  )
GROUP BY u.covenant_id
HAVING COUNT(DISTINCT u.state->>'canonicalTokenId') = 1
   AND COUNT(DISTINCT u.state->>'feeTicketId') = 1
   AND COUNT(DISTINCT u.state->>'feePolicy') = 1;

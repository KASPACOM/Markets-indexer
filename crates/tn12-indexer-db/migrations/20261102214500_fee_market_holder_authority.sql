-- Fee role artifacts encode owner_scheme; shared holder projections consume
-- ownerScheme. The alias does not replace the authenticated artifact field.
UPDATE covenant_utxos
SET state = state || jsonb_build_object('ownerScheme', (state->>'owner_scheme')::SMALLINT)
WHERE state->>'feePolicyVersion' = '1'
  AND state ? 'feePolicy'
  AND state->>'mode' IN ('0', '1', '2', '3')
  AND state->>'owner_scheme' IN ('0', '1', '2', '3', '4')
  AND state->>'owner' ~ '^[0-9a-f]{64}$';

DELETE FROM kcc20_holders
WHERE covenant_id IN (
    SELECT covenant_id FROM covenant_utxos
    WHERE state->>'feePolicyVersion' = '1' AND state ? 'feePolicy'
      AND state->>'mode' IN ('0', '1', '2', '3') AND state ? 'ownerScheme'
);

INSERT INTO kcc20_holders
    (covenant_id, owner_identifier, identifier_type, amount_total,
     utxo_count, is_minter, last_change_ms)
SELECT u.covenant_id, decode(u.state->>'owner', 'hex'),
       (u.state->>'ownerScheme')::SMALLINT,
       SUM((u.state->>'amount')::NUMERIC), COUNT(*)::INT, FALSE,
       MAX(b.timestamp_ms)
FROM covenant_utxos u
JOIN blocks b ON b.hash = u.created_block
WHERE u.status = 'active' AND u.state->>'feePolicyVersion' = '1'
  AND u.state ? 'feePolicy' AND u.state->>'mode' = '0'
  AND u.state->>'ownerScheme' IN ('0', '1', '2', '3', '4')
GROUP BY u.covenant_id, u.state->>'owner', u.state->>'ownerScheme';

DELETE FROM kcc20_holders;

INSERT INTO kcc20_holders
    (covenant_id, owner_identifier, identifier_type, amount_total,
     utxo_count, is_minter, last_change_ms)
SELECT
    u.covenant_id,
    decode(u.state->>'ownerIdentifier', 'hex') AS owner_identifier,
    (u.state->>'identifierType')::SMALLINT    AS identifier_type,
    SUM((u.state->>'amount')::NUMERIC)        AS amount_total,
    COUNT(*)::INT                             AS utxo_count,
    COALESCE((u.state->>'isMinter')::BOOLEAN, FALSE) AS is_minter,
    MAX(b.timestamp_ms)                       AS last_change_ms
FROM covenant_utxos u
JOIN blocks b ON b.hash = u.created_block
WHERE u.status = 'active'
  AND u.state ? 'ownerIdentifier'
  AND u.state ? 'identifierType'
  AND u.state ? 'amount'
  AND (NOT u.state ? 'mode' OR u.state->>'mode' = '0')
GROUP BY u.covenant_id, owner_identifier, identifier_type, is_minter;

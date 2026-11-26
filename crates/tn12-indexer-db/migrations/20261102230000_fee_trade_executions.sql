-- Actual ABI entrypoints remain on covenant_actions. Expand only the leader's
-- authenticated fills, so a grouped trade is neither omitted nor double-counted.
CREATE VIEW kcc20_fee_trade_executions AS
SELECT a.id AS source_action_id, a.covenant_id AS market_id, a.txid,
       encode(a.txid,'hex') AS txid_hex, a.block_hash, a.block_time_ms, a.entrypoint,
       fill.ordinality AS fill_index,
       fill.value->>'canonicalTokenId' AS token_id_hex,
       fill.value->>'side' AS side, fill.value->>'maker' AS maker,
       fill.value->>'taker' AS taker,
       (fill.value->>'takerScheme')::SMALLINT AS taker_scheme,
       (fill.value->>'makerScheme')::SMALLINT AS maker_scheme, fill.value->>'amount' AS token_amount,
       fill.value->>'unitPriceSompi' AS unit_price_sompi,
       fill.value->>'priceSompi' AS price_sompi,
       fill.value->>'inputIndex' AS input_index, fill.value->>'orderId' AS order_id
FROM covenant_actions a
CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(a.decoded_args->'feeTrades')='array'
         THEN a.decoded_args->'feeTrades' ELSE '[]'::jsonb END
) WITH ORDINALITY AS fill(value, ordinality)
WHERE a.action='spend' AND a.entrypoint IN ('buyAsks','sellIntoBids','crossWithBid')
  AND a.decoded_args->>'feePolicyVersion'='1' AND a.decoded_args ? 'feePolicy';

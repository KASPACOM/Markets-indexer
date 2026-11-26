-- Restrict order modes before joins so holder growth cannot expand the scan.
-- Fee fallback stays disjoint, and keeps legacy states without feePolicy.
WITH orderbook_candidates AS MATERIALIZED (
    SELECT u.* FROM covenant_utxos u
    WHERE u.status = 'active'
      AND u.state ? 'ownerIdentifier'
      AND u.state->>'mode' IN ('2', '3')
    UNION ALL
    SELECT u.* FROM covenant_utxos u
    WHERE u.status = 'active'
      AND NOT (u.state ? 'ownerIdentifier')
      AND u.state->>'feePolicyVersion' = '1'
      AND u.state ? 'owner'
      AND u.state->>'mode' IN ('2', '3')
), bid_raw AS (
    SELECT
        covenant_id,
        script_hash,
        address,
        created_at_ms,
        COALESCE(template_name, claimed_template) AS template_name,
        constructor_args,
        claimed_args
    FROM covenants
    WHERE COALESCE(template_name, claimed_template) IN ('KCC20BuyOrder')
      AND claim_verified = TRUE
),
bid AS (
    SELECT
        covenant_id,
        script_hash,
        address,
        created_at_ms,
        template_name,
        COALESCE(
            NULLIF(constructor_args, 'null'::jsonb),
            (
                SELECT jsonb_object_agg(arg->>'name', arg->'value')
                FROM jsonb_array_elements(
                    CASE
                        WHEN jsonb_typeof(claimed_args->'args') = 'array' THEN claimed_args->'args'
                        ELSE '[]'::jsonb
                    END
                ) AS arg
            )
        ) AS args
    FROM bid_raw
)
SELECT
    encode(b.covenant_id, 'hex') AS order_id,
    NULL::TEXT AS txid_hex,
    NULL::INT AS vout,
    encode(b.covenant_id, 'hex') AS bid_covenant_id_hex,
    encode(b.script_hash, 'hex')  AS bid_script_hash_hex,
    b.address                     AS bid_address,
    b.template_name               AS template_name,
    'bid'                         AS market_side,
    COALESCE(b.args->>'tokenId', b.args->>'orderedTokenId') AS token_id_hex,
    COALESCE(b.args->>'buyer', b.args->>'orderBuyer') AS buyer,
    COALESCE(b.args->>'tokenAmount', b.args->>'orderedTokenAmount') AS token_amount,
    COALESCE(b.args->>'priceSompi', b.args->>'offerPriceSompi') AS price_sompi,
    NULL::TEXT AS unit_price_sompi,
    NULL::TEXT AS min_fill_amount,
    NULL::TEXT AS fee_ticket_id,
    CASE
        WHEN bs.entrypoint IN ('fillBuyOrder') THEN 'filled'
        WHEN bs.entrypoint IN ('cancelBuyOrder') THEN 'cancelled'
        WHEN COUNT(DISTINCT bu.txid) > 0 THEN 'open'
        ELSE 'closed'
    END                           AS status,
    bs.txid_hex                    AS close_txid_hex,
    bs.entrypoint                  AS close_entrypoint,
    COUNT(DISTINCT bu.txid)::BIGINT AS bid_utxos,
    SUM(bu.amount_sompi)::TEXT AS bid_value_sompi,
    b.created_at_ms               AS created_at_ms
FROM bid b
LEFT JOIN LATERAL (
    SELECT
        a.entrypoint AS entrypoint,
        encode(a.txid, 'hex') AS txid_hex
    FROM covenant_actions a
    WHERE a.covenant_id = b.covenant_id
      AND a.action = 'spend'
    ORDER BY a.block_time_ms DESC, a.id DESC
    LIMIT 1
) bs ON TRUE
LEFT JOIN covenant_utxos bu
       ON bu.covenant_id = b.covenant_id
      AND bu.status = 'active'
WHERE ($1::BYTEA IS NULL OR decode(COALESCE(b.args->>'tokenId', b.args->>'orderedTokenId'), 'hex') = $1)
  AND ($2::TEXT IS NULL OR COALESCE(b.args->>'buyer', b.args->>'orderBuyer') = $2)
  AND COALESCE(b.args->>'tokenId', b.args->>'orderedTokenId') IS NOT NULL
GROUP BY b.covenant_id, b.script_hash, b.address, b.template_name, b.args, b.created_at_ms,
         bs.txid_hex, bs.entrypoint
UNION ALL
SELECT
    encode(u.txid, 'hex') || ':' || u.vout::TEXT AS order_id,
    encode(u.txid, 'hex')                        AS txid_hex,
    u.vout                                       AS vout,
    encode(u.txid, 'hex') || ':' || u.vout::TEXT AS bid_covenant_id_hex,
    encode(c.script_hash, 'hex')                 AS bid_script_hash_hex,
    u.address                                    AS bid_address,
    CASE
        WHEN u.state->>'feePolicyVersion' = '1' AND u.state->>'mode' = '2' THEN 'KCC20OrderbookFeeAskV1'
        WHEN u.state->>'feePolicyVersion' = '1' AND u.state->>'mode' = '3' THEN 'KCC20OrderbookFeeBidV1'
        WHEN u.state->>'supplyBacking' = 'kcc20WrapperReserve' THEN 'KCC20Orderbook'
        ELSE COALESCE(c.template_name, c.claimed_template)
    END                                           AS template_name,
    'bid'                                        AS market_side,
    COALESCE(NULLIF(u.state->>'canonicalTokenId', ''), encode(u.covenant_id, 'hex'))
                                                 AS token_id_hex,
    COALESCE(u.state->>'ownerIdentifier', u.state->>'owner')                  AS buyer,
    u.state->>'amount'                           AS token_amount,
    FLOOR((u.state->>'amount')::NUMERIC * (COALESCE(u.state->>'unitPriceSompi', u.state->>'unitPrice'))::NUMERIC
        / CASE WHEN u.state->>'feePolicyVersion' = '1'
            THEN (u.state->>'priceScale')::NUMERIC ELSE 1 END)::TEXT
                                                 AS price_sompi,
    COALESCE(u.state->>'unitPriceSompi', u.state->>'unitPrice')                   AS unit_price_sompi,
    u.state->>'minFillAmount'                    AS min_fill_amount,
    NULLIF(u.state->>'feeTicketId', '')          AS fee_ticket_id,
    'open'                                       AS status,
    NULL::TEXT                                   AS close_txid_hex,
    NULL::TEXT                                   AS close_entrypoint,
    1::BIGINT                                    AS bid_utxos,
    u.amount_sompi::TEXT                         AS bid_value_sompi,
    blk.timestamp_ms                             AS created_at_ms
FROM orderbook_candidates u
JOIN covenants c
  ON c.covenant_id = u.covenant_id
JOIN blocks blk
  ON blk.hash = u.created_block
WHERE u.status = 'active'
  AND (
      COALESCE(c.template_name, c.claimed_template) = 'KCC20Orderbook'
      OR u.state->>'supplyBacking' = 'kcc20WrapperReserve'
      OR (u.state->>'feePolicyVersion' = '1' AND u.state ? 'feePolicy')
  )
  AND (u.state ? 'ownerIdentifier' OR (u.state->>'feePolicyVersion' = '1' AND u.state ? 'owner'))
  AND u.state ? 'mode'
  AND u.state->>'mode' = '3'
  AND ($2::TEXT IS NULL OR COALESCE(u.state->>'ownerIdentifier', u.state->>'owner') = $2)
  AND (
      $1::BYTEA IS NULL
      OR u.covenant_id = $1
      OR (
          NULLIF(u.state->>'canonicalTokenId', '') IS NOT NULL
          AND decode(u.state->>'canonicalTokenId', 'hex') = $1
      )
  )
ORDER BY created_at_ms DESC
LIMIT 5001

-- Restrict order modes before joins so holder growth cannot expand the scan.
-- Fee fallback stays disjoint, and keeps legacy states without feePolicy.
WITH RECURSIVE orderbook_candidates AS MATERIALIZED (
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
), sale_raw AS (
    SELECT
        covenant_id,
        script_hash,
        address,
        created_at_ms,
        COALESCE(template_name, claimed_template) AS template_name,
        constructor_args,
        claimed_args
    FROM covenants
    WHERE COALESCE(template_name, claimed_template) IN ('KCC20Sale', 'KCC20SaleV2')
      AND claim_verified = TRUE
),
sale AS (
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
    FROM sale_raw
),
sale_family(root_covenant_id, covenant_id) AS (
    SELECT covenant_id, covenant_id
    FROM sale
    UNION
    SELECT sf.root_covenant_id, child.covenant_id
    FROM sale_family sf
    JOIN covenant_actions parent_spend
      ON parent_spend.covenant_id = sf.covenant_id
     AND parent_spend.action = 'spend'
    JOIN covenants child
      ON child.genesis_txid = parent_spend.txid
    WHERE COALESCE(child.template_name, child.claimed_template) IN ('KCC20Sale', 'KCC20SaleV2')
      AND child.claim_verified = TRUE
)
SELECT
    encode(s.covenant_id, 'hex') AS order_id,
    NULL::TEXT AS txid_hex,
    NULL::INT AS vout,
    encode(s.covenant_id, 'hex') AS sale_covenant_id_hex,
    encode(s.script_hash, 'hex')  AS sale_script_hash_hex,
    s.address                     AS sale_address,
    s.template_name               AS template_name,
    'ask'                         AS market_side,
    COALESCE(s.args->>'tokenId', s.args->>'listingTokenId') AS token_id_hex,
    COALESCE(s.args->>'seller', s.args->>'listingSeller')    AS seller,
    COALESCE(s.args->>'tokenAmount', s.args->>'listingTokenAmount') AS token_amount,
    COALESCE(s.args->>'priceSompi', s.args->>'listingPriceSompi') AS price_sompi,
    NULL::TEXT AS unit_price_sompi,
    NULL::TEXT AS min_fill_amount,
    NULL::TEXT AS fee_ticket_id,
    CASE
        WHEN ss.entrypoint IN ('buy', 'buyListing') THEN 'filled'
        WHEN ss.entrypoint IN ('cancel', 'cancelListing') THEN 'cancelled'
        WHEN sale_state.sale_utxos > 0
         AND token_state.locked_token_utxos > 0 THEN 'open'
        WHEN sale_state.sale_utxos > 0 THEN 'waitingForLock'
        ELSE 'closed'
    END                           AS status,
    ss.txid_hex                    AS close_txid_hex,
    ss.entrypoint                  AS close_entrypoint,
    sale_state.sale_utxos         AS sale_utxos,
    token_state.locked_token_utxos AS locked_token_utxos,
    token_state.locked_token_amount AS locked_token_amount,
    s.created_at_ms               AS created_at_ms
FROM sale s
LEFT JOIN LATERAL (
    SELECT
        family_spend.entrypoint,
        family_spend.txid_hex
    FROM sale_family spend_family
    JOIN LATERAL (
        SELECT
            a.entrypoint,
            encode(a.txid, 'hex') AS txid_hex,
            a.block_time_ms,
            a.id
        FROM covenant_actions a
        WHERE a.covenant_id = spend_family.covenant_id
          AND a.action = 'spend'
        ORDER BY a.block_time_ms DESC, a.id DESC
        LIMIT 1
    ) family_spend ON TRUE
    WHERE spend_family.root_covenant_id = s.covenant_id
    ORDER BY family_spend.block_time_ms DESC, family_spend.id DESC
    LIMIT 1
) ss ON TRUE
LEFT JOIN LATERAL (
    SELECT COUNT(DISTINCT su.txid)::BIGINT AS sale_utxos
    FROM sale_family active_family
    JOIN covenant_utxos su
      ON su.covenant_id = active_family.covenant_id
     AND su.status = 'active'
    WHERE active_family.root_covenant_id = s.covenant_id
) sale_state ON TRUE
LEFT JOIN LATERAL (
    SELECT
        COUNT(DISTINCT tu.txid)::BIGINT AS locked_token_utxos,
        SUM((COALESCE(tu.state->>'stateAmount', tu.state->>'amount'))::NUMERIC)::TEXT
            AS locked_token_amount
    FROM covenant_utxos tu
    WHERE tu.covenant_id = decode(COALESCE(s.args->>'tokenId', s.args->>'listingTokenId'), 'hex')
      AND tu.status = 'active'
      AND COALESCE(tu.state->>'stateOwner', tu.state->>'ownerIdentifier') = encode(s.covenant_id, 'hex')
      AND (COALESCE(tu.state->>'stateOwnerType', tu.state->>'identifierType'))::INT = 2
) token_state ON TRUE
WHERE ($1::BYTEA IS NULL OR decode(COALESCE(s.args->>'tokenId', s.args->>'listingTokenId'), 'hex') = $1)
  AND ($2::TEXT IS NULL OR COALESCE(s.args->>'seller', s.args->>'listingSeller') = $2)
  AND COALESCE(s.args->>'tokenId', s.args->>'listingTokenId') IS NOT NULL
UNION ALL
SELECT
    encode(u.txid, 'hex') || ':' || u.vout::TEXT AS order_id,
    encode(u.txid, 'hex')                        AS txid_hex,
    u.vout                                       AS vout,
    encode(u.txid, 'hex') || ':' || u.vout::TEXT AS sale_covenant_id_hex,
    encode(c.script_hash, 'hex')                 AS sale_script_hash_hex,
    u.address                                    AS sale_address,
    CASE
        WHEN u.state->>'feePolicyVersion' = '1' AND u.state->>'mode' = '2' THEN 'KCC20OrderbookFeeAskV1'
        WHEN u.state->>'feePolicyVersion' = '1' AND u.state->>'mode' = '3' THEN 'KCC20OrderbookFeeBidV1'
        WHEN u.state->>'supplyBacking' = 'kcc20WrapperReserve' THEN 'KCC20Orderbook'
        ELSE COALESCE(c.template_name, c.claimed_template)
    END                                           AS template_name,
    'ask'                                        AS market_side,
    COALESCE(NULLIF(u.state->>'canonicalTokenId', ''), encode(u.covenant_id, 'hex'))
                                                 AS token_id_hex,
    COALESCE(u.state->>'ownerIdentifier', u.state->>'owner')                  AS seller,
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
    1::BIGINT                                    AS sale_utxos,
    1::BIGINT                                    AS locked_token_utxos,
    u.state->>'amount'                           AS locked_token_amount,
    b.timestamp_ms                               AS created_at_ms
FROM orderbook_candidates u
JOIN covenants c
  ON c.covenant_id = u.covenant_id
JOIN blocks b
  ON b.hash = u.created_block
WHERE u.status = 'active'
  AND (
      COALESCE(c.template_name, c.claimed_template) = 'KCC20Orderbook'
      OR u.state->>'supplyBacking' = 'kcc20WrapperReserve'
      OR (u.state->>'feePolicyVersion' = '1' AND u.state ? 'feePolicy')
  )
  AND (u.state ? 'ownerIdentifier' OR (u.state->>'feePolicyVersion' = '1' AND u.state ? 'owner'))
  AND u.state ? 'mode'
  AND u.state->>'mode' = '2'
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

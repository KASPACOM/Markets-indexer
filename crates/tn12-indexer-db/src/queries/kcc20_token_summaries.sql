WITH fee_wrappers AS (
    -- Only script-authenticated active wrappers are passed by the repository.
    SELECT decode(token_id, 'hex') AS canonical_token_id,
           decode(wrapper_id, 'hex') AS wrapper_id,
           decode(reserve_owner, 'hex') AS reserve_owner
    FROM jsonb_to_recordset($1::JSONB)
      AS w(token_id TEXT, wrapper_id TEXT, reserve_owner TEXT)
),
wrappers AS (
    SELECT wrapper_id, canonical_token_id, NULL::BYTEA AS reserve_owner
    FROM kcc20_wrapper_summaries legacy
    WHERE NOT EXISTS (SELECT 1 FROM fee_wrappers fee WHERE fee.wrapper_id = legacy.wrapper_id)
    UNION ALL
    SELECT wrapper_id, canonical_token_id, reserve_owner FROM fee_wrappers
),
freshness AS (
    SELECT
        (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) AS refreshed_at_ms,
        MAX(blue_score) AS source_blue_score
    FROM blocks
    WHERE is_chain_block
),
token_ids AS (
    SELECT covenant_id AS token_id FROM kcc20_holders
    UNION
    SELECT canonical_token_id AS token_id FROM wrappers
    UNION
    SELECT token_id FROM kcc20_market_summaries
),
holder_summary AS (
    SELECT
        h.covenant_id AS token_id,
        COUNT(*) FILTER (WHERE NOT h.is_minter)::BIGINT AS holder_count,
        COALESCE(SUM(h.amount_total) FILTER (WHERE NOT h.is_minter), 0) AS holder_supply
    FROM kcc20_holders h
    GROUP BY h.covenant_id
),
-- A correlated aggregate keeps this on token-specific UTXO indexes.
-- A global aggregate scans unrelated historical P2SH rows during replay.
mint_authority_summary AS MATERIALIZED (
    SELECT
        token.token_id,
        COALESCE((
            SELECT SUM((active.state->>'remainingSupply')::NUMERIC)
            FROM covenant_utxos active
            WHERE active.covenant_id = token.token_id
              AND active.status = 'active'
              AND active.state->>'isMintAuthority' = 'true'
              AND active.state->>'remainingSupply' ~ '^[0-9]+$'
        ), 0) AS remaining_supply
    FROM token_ids token
),
active_mint_policy AS (
    SELECT
        active.covenant_id AS token_id,
        MIN((active.state->>'mintPolicy')::SMALLINT) AS active_mint_policy_value,
        BOOL_OR(COALESCE((active.state->>'publicMintActive')::BOOLEAN, FALSE)) AS public_mint_active
    FROM token_ids token
    JOIN covenant_utxos active ON active.covenant_id = token.token_id
    WHERE active.status = 'active'
      AND active.state->>'isMintAuthority' = 'true'
      AND active.state->>'mintPolicy' ~ '^[12]$'
    GROUP BY active.covenant_id
),
top_holders AS (
    SELECT
        ranked.covenant_id AS token_id,
        jsonb_agg(
            jsonb_build_object(
                'owner', encode(ranked.owner_identifier, 'hex'),
                'ownerScheme', ranked.identifier_type,
                'ownerSchemeName', CASE ranked.identifier_type
                    WHEN 0 THEN 'p2pk-schnorr/v1'
                    WHEN 1 THEN 'p2pkh-schnorr/v1'
                    WHEN 2 THEN 'p2pkh-ecdsa/v1'
                    WHEN 3 THEN 'p2sh/v1'
                    WHEN 4 THEN 'covenant-id/v1'
                    ELSE 'unknown'
                END,
                'amount', ranked.amount_total::TEXT,
                'utxoCount', ranked.utxo_count
            )
            ORDER BY ranked.amount_total DESC, ranked.owner_identifier ASC
        ) AS top_holders
    FROM (
        SELECT
            h.*,
            ROW_NUMBER() OVER (
                PARTITION BY h.covenant_id
                ORDER BY h.amount_total DESC, h.owner_identifier ASC
            ) AS rn
        FROM kcc20_holders h
        WHERE NOT h.is_minter
    ) ranked
    WHERE ranked.rn <= 10
    GROUP BY ranked.covenant_id
),
wrapper_reserve_supply AS (
    SELECT
        w.canonical_token_id AS token_id,
        w.wrapper_id,
        COALESCE(SUM(h.amount_total), 0) AS wrapper_reserve_supply
    FROM wrappers w
    LEFT JOIN kcc20_holders h
      ON h.covenant_id = w.canonical_token_id
     AND (
       (w.reserve_owner IS NOT NULL AND h.identifier_type = 3
         AND h.owner_identifier = w.reserve_owner)
       OR (w.reserve_owner IS NULL AND h.identifier_type = 4 AND (
         h.owner_identifier = w.wrapper_id
         OR h.owner_identifier IN (
             SELECT decode(u.state->>'wrapperCovenantId', 'hex')
             FROM covenant_utxos u
             WHERE u.covenant_id = w.wrapper_id
               AND u.status = 'active'
               AND u.state->>'wrapperCovenantId' ~ '^[0-9a-fA-F]{64}$'
         )
       ))
     )
     AND NOT h.is_minter
    GROUP BY w.canonical_token_id, w.wrapper_id
),
wrapper_tradeable_supply AS (
    SELECT
        w.canonical_token_id AS token_id,
        w.wrapper_id,
        COALESCE(SUM(h.amount_total) FILTER (WHERE NOT h.is_minter), 0) AS orderbook_tradeable_supply
    FROM wrappers w
    LEFT JOIN kcc20_holders h ON h.covenant_id = w.wrapper_id
    GROUP BY w.canonical_token_id, w.wrapper_id
),
-- The per-token lateral lookup must reuse the aggregate across all tokens.
wrapper_supply AS MATERIALIZED (
    SELECT
        COALESCE(r.token_id, t.token_id) AS token_id,
        COALESCE(r.wrapper_id, t.wrapper_id) AS wrapper_id,
        COALESCE(r.wrapper_reserve_supply, 0) AS wrapper_reserve_supply,
        COALESCE(t.orderbook_tradeable_supply, 0) AS orderbook_tradeable_supply
    FROM wrapper_reserve_supply r
    FULL OUTER JOIN wrapper_tradeable_supply t
      ON t.token_id = r.token_id AND t.wrapper_id = r.wrapper_id
)
INSERT INTO kcc20_token_summaries (
    token_id, holder_count, holder_supply, remaining_supply,
    active_mint_policy_value, public_mint_active,
    wrapper_reserve_supply, orderbook_tradeable_supply, top_holders,
    wrapper_id, refreshed_at_ms, source_blue_score
)
SELECT
    t.token_id,
    COALESCE(h.holder_count, 0),
    COALESCE(h.holder_supply, 0),
    COALESCE(ms.remaining_supply, 0),
    am.active_mint_policy_value,
    CASE WHEN am.active_mint_policy_value = 2
        THEN COALESCE(am.public_mint_active, FALSE)
        ELSE NULL
    END,
    COALESCE(w.wrapper_reserve_supply, 0),
    COALESCE(w.orderbook_tradeable_supply, 0),
    COALESCE(th.top_holders, '[]'::jsonb),
    w.wrapper_id,
    f.refreshed_at_ms,
    f.source_blue_score
FROM token_ids t
CROSS JOIN freshness f
LEFT JOIN holder_summary h ON h.token_id = t.token_id
LEFT JOIN mint_authority_summary ms ON ms.token_id = t.token_id
LEFT JOIN active_mint_policy am ON am.token_id = t.token_id
LEFT JOIN top_holders th ON th.token_id = t.token_id
LEFT JOIN LATERAL (
    SELECT wrapper_id, wrapper_reserve_supply, orderbook_tradeable_supply
    FROM wrapper_supply ws
    WHERE ws.token_id = t.token_id
    -- An ambiguous token-to-market relationship must not pick a winner.
    AND (SELECT COUNT(*) FROM wrapper_supply candidates
         WHERE candidates.token_id = t.token_id) = 1
) w ON TRUE
ON CONFLICT (token_id) DO UPDATE SET
    holder_count = EXCLUDED.holder_count,
    holder_supply = EXCLUDED.holder_supply,
    remaining_supply = EXCLUDED.remaining_supply,
    active_mint_policy_value = EXCLUDED.active_mint_policy_value,
    public_mint_active = EXCLUDED.public_mint_active,
    wrapper_reserve_supply = EXCLUDED.wrapper_reserve_supply,
    orderbook_tradeable_supply = EXCLUDED.orderbook_tradeable_supply,
    top_holders = EXCLUDED.top_holders,
    wrapper_id = EXCLUDED.wrapper_id,
    refreshed_at_ms = EXCLUDED.refreshed_at_ms,
    source_blue_score = EXCLUDED.source_blue_score

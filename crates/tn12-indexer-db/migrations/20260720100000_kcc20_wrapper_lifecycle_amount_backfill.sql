WITH lifecycle_rows AS (
    SELECT
        feed.id,
        feed.token_id,
        feed.txid,
        feed.entrypoint
    FROM kcc20_activity_feed AS feed
    WHERE feed.kind IN ('wrap', 'unwrap')
      AND feed.token_amount IS NULL
),
unwrap_amounts AS (
    SELECT
        lifecycle.id,
        CASE
            WHEN COUNT(*) = 1 THEN MAX(candidates.amount_candidate)
            ELSE NULL
        END AS token_amount
    FROM lifecycle_rows AS lifecycle
    JOIN kcc20_activity_feed AS feed
      ON feed.id = lifecycle.id
    JOIN covenant_actions AS wrapper_action
      ON wrapper_action.txid = lifecycle.txid
     AND wrapper_action.action = 'spend'
     AND wrapper_action.entrypoint = 'unwrap'
     AND lower(COALESCE(
           encode(wrapper_action.canonical_token_id, 'hex'),
           NULLIF(wrapper_action.decoded_args->>'canonicalTokenId', '')
         )) = encode(lifecycle.token_id, 'hex')
    JOIN LATERAL (
        SELECT COALESCE(
            NULLIF(unwrap_spend.decoded_args->>'tokenAmount', ''),
            NULLIF(unwrap_spend.decoded_args->>'amount', ''),
            NULLIF(unwrap_spend.decoded_args->>'stateAmount', '')
        ) AS amount_candidate
        FROM covenant_actions AS unwrap_spend
        WHERE unwrap_spend.txid = lifecycle.txid
          AND unwrap_spend.action = 'spend'
          AND unwrap_spend.entrypoint = 'unwrapByOwnerSig'
          AND lower(COALESCE(
                encode(unwrap_spend.canonical_token_id, 'hex'),
                NULLIF(unwrap_spend.decoded_args->>'canonicalTokenId', '')
              )) = encode(lifecycle.token_id, 'hex')
          AND (
            NULLIF(wrapper_action.decoded_args->>'wrappedInputIndex', '') IS NULL
            OR unwrap_spend.decoded_args->>'inputIndex'
                = wrapper_action.decoded_args->>'wrappedInputIndex'
          )
    ) AS candidates
      ON candidates.amount_candidate IS NOT NULL
     AND candidates.amount_candidate ~ '^[0-9]+$'
    WHERE feed.entrypoint = 'unwrap'
    GROUP BY lifecycle.id
),
v2_amounts AS (
    SELECT
        lifecycle.id,
        CASE
            WHEN COUNT(*) = 1 THEN MAX(candidates.amount_candidate)
            ELSE NULL
        END AS token_amount
    FROM lifecycle_rows AS lifecycle
    JOIN covenant_actions AS wrapper_action
      ON wrapper_action.txid = lifecycle.txid
     AND wrapper_action.action = 'spend'
     AND wrapper_action.entrypoint = lifecycle.entrypoint
     AND lower(COALESCE(
           encode(wrapper_action.canonical_token_id, 'hex'),
           NULLIF(wrapper_action.decoded_args->>'canonicalTokenId', '')
         )) = encode(lifecycle.token_id, 'hex')
    JOIN LATERAL (
        SELECT COALESCE(
            NULLIF(v2_spend.decoded_args->>'tokenAmount', ''),
            NULLIF(v2_spend.decoded_args->>'amount', ''),
            NULLIF(v2_spend.decoded_args->>'stateAmount', '')
        ) AS amount_candidate
        FROM covenant_actions AS v2_spend
        JOIN covenants AS v2_c
          ON v2_c.covenant_id = v2_spend.covenant_id
        WHERE v2_spend.txid = lifecycle.txid
          AND v2_spend.action = 'spend'
          AND COALESCE(v2_c.template_name, v2_c.claimed_template) = 'KCC20V2'
          AND (
            (
              CASE
                  WHEN wrapper_action.entrypoint = 'wrap'
                      THEN NULLIF(wrapper_action.decoded_args->>'v2InputIndex', '')
                  WHEN wrapper_action.entrypoint = 'unwrap'
                      THEN NULLIF(wrapper_action.decoded_args->>'v2ReserveInputIndex', '')
                  ELSE NULL
              END IS NOT NULL
              AND v2_spend.decoded_args->>'inputIndex' = CASE
                  WHEN wrapper_action.entrypoint = 'wrap'
                      THEN NULLIF(wrapper_action.decoded_args->>'v2InputIndex', '')
                  WHEN wrapper_action.entrypoint = 'unwrap'
                      THEN NULLIF(wrapper_action.decoded_args->>'v2ReserveInputIndex', '')
                  ELSE NULL
              END
            )
            OR lower(COALESCE(
                  encode(v2_spend.canonical_token_id, 'hex'),
                  encode(v2_spend.covenant_id, 'hex')
                )) = encode(lifecycle.token_id, 'hex')
            OR (
              NULLIF(wrapper_action.decoded_args->>'v2InputIndex', '') IS NULL
              AND NULLIF(wrapper_action.decoded_args->>'v2ReserveInputIndex', '') IS NULL
              AND wrapper_action.decoded_args->>'wrappedTokenIdMode' = 'sameCovenantFamily'
              AND v2_spend.entrypoint IN ('transferByOwnerSig', 'transferByWitness')
            )
          )
    ) AS candidates
      ON candidates.amount_candidate IS NOT NULL
     AND candidates.amount_candidate ~ '^[0-9]+$'
    GROUP BY lifecycle.id
),
repairs AS (
    SELECT
        lifecycle.id,
        CASE
            WHEN unwrap_amounts.token_amount IS NOT NULL
             AND v2_amounts.token_amount IS NOT NULL
             AND unwrap_amounts.token_amount <> v2_amounts.token_amount
                THEN NULL
            ELSE COALESCE(unwrap_amounts.token_amount, v2_amounts.token_amount)
        END AS token_amount
    FROM lifecycle_rows AS lifecycle
    LEFT JOIN unwrap_amounts
      ON unwrap_amounts.id = lifecycle.id
    LEFT JOIN v2_amounts
      ON v2_amounts.id = lifecycle.id
)
UPDATE kcc20_activity_feed AS feed
SET token_amount = repairs.token_amount
FROM repairs
WHERE feed.id = repairs.id
  AND repairs.token_amount IS NOT NULL
  AND feed.token_amount IS DISTINCT FROM repairs.token_amount;

UPDATE kcc20_activity_feed AS feed
SET kind = 'deploy'
WHERE feed.kind IN ('wrap', 'unwrap')
  AND feed.entrypoint IS NULL
  AND EXISTS (
    SELECT 1
    FROM covenant_actions AS deploy_action
    WHERE deploy_action.txid = feed.txid
      AND deploy_action.covenant_id = feed.token_id
      AND deploy_action.action = 'deploy'
      AND deploy_action.entrypoint IS NULL
  );

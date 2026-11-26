-- Wrapper and wrapped-holder states share one covenant family. Historical
-- activity cleanup must therefore pair the exact inputs validated by the
-- wrapper instead of depending on the covenants row's template label.
DELETE FROM kcc20_activity_feed AS internal_unwrap
WHERE internal_unwrap.entrypoint = 'unwrapByOwnerSig'
  AND internal_unwrap.kind = 'unwrap'
  -- The feed does not retain the input index, so an ambiguous transaction
  -- with another independent unwrapByOwnerSig cannot be cleaned safely.
  AND 1 = (
      SELECT COUNT(*)
      FROM covenant_actions AS same_token_unwrap
      WHERE same_token_unwrap.txid = internal_unwrap.txid
        AND same_token_unwrap.action = 'spend'
        AND same_token_unwrap.entrypoint = 'unwrapByOwnerSig'
        AND lower(COALESCE(
              encode(same_token_unwrap.canonical_token_id, 'hex'),
              NULLIF(same_token_unwrap.decoded_args->>'canonicalTokenId', '')
            )) = encode(internal_unwrap.token_id, 'hex')
  )
  AND NOT EXISTS (
      SELECT 1
      FROM covenant_actions AS unresolved_unwrap
      WHERE unresolved_unwrap.txid = internal_unwrap.txid
        AND unresolved_unwrap.action = 'spend'
        AND unresolved_unwrap.entrypoint = 'unwrapByOwnerSig'
        AND unresolved_unwrap.canonical_token_id IS NULL
        AND NULLIF(unresolved_unwrap.decoded_args->>'canonicalTokenId', '') IS NULL
  )
  AND EXISTS (
      SELECT 1
      FROM covenant_actions AS wrapper_action
      JOIN covenants AS wrapper_c
        ON wrapper_c.covenant_id = wrapper_action.covenant_id
      JOIN covenant_actions AS wrapped_spend
        ON wrapped_spend.txid = wrapper_action.txid
       AND wrapped_spend.covenant_id = wrapper_action.covenant_id
       AND wrapped_spend.action = 'spend'
       AND wrapped_spend.entrypoint = 'unwrapByOwnerSig'
       AND (
           (
             wrapper_action.decoded_args->>'wrappedInputIndex' IS NOT NULL
             AND wrapped_spend.decoded_args->>'inputIndex'
                 = wrapper_action.decoded_args->>'wrappedInputIndex'
           )
           OR (
             wrapper_action.decoded_args->>'wrappedInputIndex' IS NULL
             AND 1 = (
                 SELECT COUNT(*)
                 FROM covenant_actions AS legacy_wrapped_spend
                 WHERE legacy_wrapped_spend.txid = wrapper_action.txid
                   AND legacy_wrapped_spend.action = 'spend'
                   AND legacy_wrapped_spend.entrypoint = 'unwrapByOwnerSig'
                   AND lower(COALESCE(
                         encode(legacy_wrapped_spend.canonical_token_id, 'hex'),
                         NULLIF(
                           legacy_wrapped_spend.decoded_args->>'canonicalTokenId',
                           ''
                         )
                       )) = lower(COALESCE(
                         encode(wrapper_action.canonical_token_id, 'hex'),
                         NULLIF(wrapper_action.decoded_args->>'canonicalTokenId', '')
                       ))
             )
           )
       )
      WHERE wrapper_action.txid = internal_unwrap.txid
        AND wrapper_action.action = 'spend'
        AND wrapper_action.entrypoint = 'unwrap'
        AND COALESCE(wrapper_c.template_name, wrapper_c.claimed_template) IN (
              'KCC20V2V3Wrapper', 'KCC20V3Wrapped'
            )
        AND lower(COALESCE(
              encode(wrapper_action.canonical_token_id, 'hex'),
              NULLIF(wrapper_action.decoded_args->>'canonicalTokenId', '')
            )) = encode(internal_unwrap.token_id, 'hex')
        AND lower(COALESCE(
              encode(wrapped_spend.canonical_token_id, 'hex'),
              NULLIF(wrapped_spend.decoded_args->>'canonicalTokenId', '')
            )) = encode(internal_unwrap.token_id, 'hex')
  );

-- A partial wrap can expose canonical V2 change as a synthetic transfer. The
-- feed does not retain vout, so delete only when amount+owner identify exactly
-- one continuation and that continuation is authorized by the sole V2 spend.
DELETE FROM kcc20_activity_feed AS internal_v2
WHERE internal_v2.entrypoint IS NULL
  -- Older projector versions inherited the wrapper parent entrypoint and
  -- labelled this same internal continuation as wrap/unwrap; newer versions
  -- exposed it as transfer. The structural predicates below, not that
  -- presentation label, determine whether cleanup is safe.
  AND internal_v2.kind IN ('transfer', 'wrap', 'unwrap')
  AND internal_v2.token_amount IS NOT NULL
  AND internal_v2.owner_identifier IS NOT NULL
  AND EXISTS (
      SELECT 1
      FROM kcc20_activity_feed AS lifecycle
      WHERE lifecycle.token_id = internal_v2.token_id
        AND lifecycle.txid = internal_v2.txid
        AND lifecycle.entrypoint IN ('wrap', 'unwrap')
  )
  AND EXISTS (
      SELECT 1
      FROM covenant_actions AS wrapper_action
      JOIN covenants AS wrapper_c
        ON wrapper_c.covenant_id = wrapper_action.covenant_id
      WHERE wrapper_action.txid = internal_v2.txid
        AND wrapper_action.action = 'spend'
        AND wrapper_action.entrypoint IN ('wrap', 'unwrap')
        AND COALESCE(wrapper_c.template_name, wrapper_c.claimed_template)
            = 'KCC20V2V3Wrapper'
        AND lower(COALESCE(
              encode(wrapper_action.canonical_token_id, 'hex'),
              NULLIF(wrapper_action.decoded_args->>'canonicalTokenId', '')
            )) = encode(internal_v2.token_id, 'hex')
  )
  AND 1 = (
      SELECT COUNT(*)
      FROM covenant_actions AS matching_continuation
      WHERE matching_continuation.txid = internal_v2.txid
        AND matching_continuation.action = 'continuation'
        AND lower(COALESCE(
              encode(matching_continuation.canonical_token_id, 'hex'),
              encode(matching_continuation.covenant_id, 'hex')
            )) = encode(internal_v2.token_id, 'hex')
        AND matching_continuation.outputs->'state'->>'amount'
            = internal_v2.token_amount
        AND lower(matching_continuation.outputs->'state'->>'ownerIdentifier')
            = lower(internal_v2.owner_identifier)
  )
  AND 1 = (
      SELECT COUNT(*)
      FROM covenant_actions AS v2_spend
      JOIN covenants AS v2_c
        ON v2_c.covenant_id = v2_spend.covenant_id
      WHERE v2_spend.txid = internal_v2.txid
        AND v2_spend.action = 'spend'
        AND COALESCE(v2_c.template_name, v2_c.claimed_template) = 'KCC20V2'
        AND lower(COALESCE(
              encode(v2_spend.canonical_token_id, 'hex'),
              encode(v2_spend.covenant_id, 'hex')
            )) = encode(internal_v2.token_id, 'hex')
  )
  AND EXISTS (
      SELECT 1
      FROM covenant_actions AS linked_continuation
      JOIN covenant_actions AS v2_spend
        ON v2_spend.txid = linked_continuation.txid
       AND v2_spend.action = 'spend'
      JOIN covenants AS v2_c
        ON v2_c.covenant_id = v2_spend.covenant_id
      WHERE linked_continuation.txid = internal_v2.txid
        AND linked_continuation.action = 'continuation'
        AND COALESCE(v2_c.template_name, v2_c.claimed_template) = 'KCC20V2'
        AND lower(COALESCE(
              encode(v2_spend.canonical_token_id, 'hex'),
              encode(v2_spend.covenant_id, 'hex')
            )) = encode(internal_v2.token_id, 'hex')
        AND lower(COALESCE(
              encode(linked_continuation.canonical_token_id, 'hex'),
              encode(linked_continuation.covenant_id, 'hex')
            )) = encode(internal_v2.token_id, 'hex')
        AND linked_continuation.outputs->>'vout' IN (
              v2_spend.decoded_args->>'tokenOutputIndex',
              v2_spend.decoded_args->>'changeOutputIndex'
            )
        AND linked_continuation.outputs->'state'->>'amount'
            = internal_v2.token_amount
        AND lower(linked_continuation.outputs->'state'->>'ownerIdentifier')
            = lower(internal_v2.owner_identifier)
  );

-- Older wrapper actions did not persist tokenAmount, so partial unwrap rows
-- could inherit the wrapped change balance. Repair unambiguous historical
-- lifecycle rows from the single canonical V2 spend in the same transaction.
WITH lifecycle_amounts AS (
    SELECT
        lifecycle.id,
        (
            SELECT MAX(NULLIF(v2_spend.decoded_args->>'tokenAmount', ''))
            FROM covenant_actions AS v2_spend
            JOIN covenants AS v2_c
              ON v2_c.covenant_id = v2_spend.covenant_id
            WHERE v2_spend.txid = lifecycle.txid
              AND v2_spend.action = 'spend'
              AND COALESCE(v2_c.template_name, v2_c.claimed_template) = 'KCC20V2'
              AND lower(COALESCE(
                    encode(v2_spend.canonical_token_id, 'hex'),
                    encode(v2_spend.covenant_id, 'hex')
                  )) = encode(lifecycle.token_id, 'hex')
            HAVING COUNT(*) = 1
        ) AS token_amount
    FROM kcc20_activity_feed AS lifecycle
    WHERE lifecycle.entrypoint IN ('wrap', 'unwrap')
      AND 1 = (
          SELECT COUNT(*)
          FROM covenant_actions AS wrapper_action
          JOIN covenants AS wrapper_c
            ON wrapper_c.covenant_id = wrapper_action.covenant_id
          WHERE wrapper_action.txid = lifecycle.txid
            AND wrapper_action.action = 'spend'
            AND wrapper_action.entrypoint = lifecycle.entrypoint
            AND COALESCE(wrapper_c.template_name, wrapper_c.claimed_template) IN (
                  'KCC20V2V3Wrapper', 'KCC20V3Wrapped'
                )
            AND lower(COALESCE(
                  encode(wrapper_action.canonical_token_id, 'hex'),
                  NULLIF(wrapper_action.decoded_args->>'canonicalTokenId', '')
                )) = encode(lifecycle.token_id, 'hex')
      )
      AND EXISTS (
          SELECT 1
          FROM covenant_actions AS legacy_wrapper_action
          WHERE legacy_wrapper_action.txid = lifecycle.txid
            AND legacy_wrapper_action.action = 'spend'
            AND legacy_wrapper_action.entrypoint = lifecycle.entrypoint
            AND lower(COALESCE(
                  encode(legacy_wrapper_action.canonical_token_id, 'hex'),
                  NULLIF(legacy_wrapper_action.decoded_args->>'canonicalTokenId', '')
                )) = encode(lifecycle.token_id, 'hex')
            AND NULLIF(legacy_wrapper_action.decoded_args->>'tokenAmount', '') IS NULL
      )
)
UPDATE kcc20_activity_feed AS lifecycle
SET token_amount = lifecycle_amounts.token_amount
FROM lifecycle_amounts
WHERE lifecycle.id = lifecycle_amounts.id
  AND lifecycle_amounts.token_amount IS NOT NULL
  AND lifecycle.token_amount IS DISTINCT FROM lifecycle_amounts.token_amount;

-- Canonicalization repairs historically projected the same accepted wrapper
-- input under two covenant ids. The public order id is that input's previous
-- outpoint, so duplicate lifecycle rows with the same token, transaction,
-- entrypoint, and order id are the same event. Prefer the richer/newer row;
-- different batched wrapper inputs retain different order ids.
WITH ranked_lifecycle AS (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY token_id, txid, entrypoint, kind, lower(order_id)
            ORDER BY
                (owner_identifier IS NOT NULL) DESC,
                (token_amount IS NOT NULL) DESC,
                id DESC
        ) AS duplicate_rank
    FROM kcc20_activity_feed
    WHERE kind IN ('wrap', 'unwrap')
      AND entrypoint IN ('wrap', 'unwrap')
      AND order_id IS NOT NULL
)
DELETE FROM kcc20_activity_feed AS lifecycle
USING ranked_lifecycle
WHERE lifecycle.id = ranked_lifecycle.id
  AND ranked_lifecycle.duplicate_rank > 1;

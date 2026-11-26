-- Remove historical synthetic wrapper lifecycle rows produced when a KCC20V2
-- continuation inherited the entrypoint of an unrelated wrapper spend in the
-- same transaction. The explicit wrapper spend remains the public activity row.
DELETE FROM kcc20_activity_feed AS synthetic
WHERE (
    (
      synthetic.entrypoint IS NULL
      AND synthetic.kind IN ('wrap', 'unwrap', 'transfer')
      -- Old rows do not retain authorized output indexes. Only clean a null-
      -- entrypoint row when one canonical V2 input proves every V2
      -- continuation in the transaction belongs to that lifecycle. Ambiguous
      -- batched same-token transactions are preserved for a full reindex.
      AND 1 = (
          SELECT COUNT(*)
          FROM covenant_actions AS v2_spend
          JOIN covenants AS v2_c
            ON v2_c.covenant_id = v2_spend.covenant_id
          WHERE v2_spend.txid = synthetic.txid
            AND v2_spend.action = 'spend'
            AND COALESCE(v2_c.template_name, v2_c.claimed_template) = 'KCC20V2'
            AND lower(COALESCE(
                  encode(v2_spend.canonical_token_id, 'hex'),
                  encode(v2_spend.covenant_id, 'hex')
                )) = encode(synthetic.token_id, 'hex')
      )
    )
    OR (
      synthetic.entrypoint = 'unwrapByOwnerSig'
      AND synthetic.kind = 'unwrap'
      AND 1 = (
          SELECT COUNT(*)
          FROM covenant_actions AS wrapped_spend
          JOIN covenants AS wrapped_c
            ON wrapped_c.covenant_id = wrapped_spend.covenant_id
          WHERE wrapped_spend.txid = synthetic.txid
            AND wrapped_spend.action = 'spend'
            AND wrapped_spend.entrypoint = 'unwrapByOwnerSig'
            AND COALESCE(wrapped_c.template_name, wrapped_c.claimed_template) = 'KCC20V3Wrapped'
            AND lower(COALESCE(
                  encode(wrapped_spend.canonical_token_id, 'hex'),
                  NULLIF(wrapped_spend.decoded_args->>'canonicalTokenId', '')
                )) = encode(synthetic.token_id, 'hex')
      )
    )
  )
  AND EXISTS (
      SELECT 1
      FROM kcc20_activity_feed AS lifecycle
      WHERE lifecycle.token_id = synthetic.token_id
        AND lifecycle.txid = synthetic.txid
        AND lifecycle.entrypoint IN ('wrap', 'unwrap')
  )
  AND EXISTS (
      SELECT 1
      FROM covenant_actions AS wrapper_action
      JOIN covenants AS wrapper_c
        ON wrapper_c.covenant_id = wrapper_action.covenant_id
      WHERE wrapper_action.txid = synthetic.txid
        AND wrapper_action.action = 'spend'
        AND wrapper_action.entrypoint IN ('wrap', 'unwrap')
        AND COALESCE(wrapper_c.template_name, wrapper_c.claimed_template) = 'KCC20V2V3Wrapper'
        AND lower(COALESCE(
              encode(wrapper_action.canonical_token_id, 'hex'),
              NULLIF(wrapper_action.decoded_args->>'canonicalTokenId', '')
            )) = encode(synthetic.token_id, 'hex')
  );

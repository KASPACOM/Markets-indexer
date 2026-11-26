-- Bid-side fills transfer tokens from the seller into an existing bid. Older
-- activity-feed rows could inherit the buyer continuation owner; backfill only
-- rows that can be matched to one exact fill action and one seller input spend.
WITH matched AS (
    SELECT
        feed.id,
        COALESCE(
            NULLIF(seller_spend.decoded_args->>'ownerIdentifier', ''),
            NULLIF(fill_action.decoded_args->>'seller', '')
        ) AS seller_owner_identifier,
        COALESCE(
            CASE
                WHEN seller_spend.decoded_args->>'identifierType' ~ '^[012]$'
                    THEN (seller_spend.decoded_args->>'identifierType')::SMALLINT
                ELSE NULL
            END,
            0::SMALLINT
        ) AS seller_owner_identifier_type
    FROM kcc20_activity_feed AS feed
    JOIN LATERAL (
        SELECT candidate.id, candidate.decoded_args
        FROM (
            SELECT
                action.id,
                action.decoded_args,
                COUNT(*) OVER () AS candidate_count
            FROM covenant_actions AS action
            WHERE action.txid = feed.txid
              AND action.action = 'spend'
              AND action.entrypoint = feed.entrypoint
              AND action.entrypoint IN (
                  'fillBidPartial', 'fillBidFromSellerSweep', 'crossBidSide'
              )
              AND feed.order_id IS NOT NULL
              AND action.inputs->'previousOutpoint'->>'hash' IS NOT NULL
              AND lower(
                  (action.inputs->'previousOutpoint'->>'hash')
                  || ':'
                  || (action.inputs->'previousOutpoint'->>'index')
              ) = lower(feed.order_id)
              AND lower(COALESCE(
                  encode(action.canonical_token_id, 'hex'),
                  NULLIF(action.decoded_args->>'canonicalTokenId', ''),
                  encode(action.covenant_id, 'hex')
              )) = encode(feed.token_id, 'hex')
              AND NULLIF(action.decoded_args->>'sellerInputIndex', '') IS NOT NULL
        ) AS candidate
        WHERE candidate.candidate_count = 1
    ) AS fill_action ON TRUE
    JOIN LATERAL (
        SELECT candidate.decoded_args
        FROM (
            SELECT
                spend.decoded_args,
                COUNT(*) OVER () AS candidate_count
            FROM covenant_actions AS spend
            WHERE spend.txid = feed.txid
              AND spend.action = 'spend'
              AND spend.decoded_args->>'inputIndex'
                  = fill_action.decoded_args->>'sellerInputIndex'
        ) AS candidate
        WHERE candidate.candidate_count = 1
    ) AS seller_spend ON TRUE
    WHERE feed.kind = 'trade'
      AND feed.side = 'bid'
      AND feed.entrypoint IN (
          'fillBidPartial', 'fillBidFromSellerSweep', 'crossBidSide'
      )
)
UPDATE kcc20_activity_feed AS feed
SET owner_identifier = matched.seller_owner_identifier,
    owner_identifier_type = matched.seller_owner_identifier_type,
    owner_identifier_type_version = 1
FROM matched
WHERE feed.id = matched.id
  AND matched.seller_owner_identifier IS NOT NULL
  AND (
      feed.owner_identifier IS DISTINCT FROM matched.seller_owner_identifier
      OR feed.owner_identifier_type IS DISTINCT FROM matched.seller_owner_identifier_type
      OR feed.owner_identifier_type_version IS DISTINCT FROM 1
  );

-- A bid fill is authorized by two covenant spends in the same transaction:
-- the priced bid-side fillBidPartial and the seller holder's
-- sellIntoBidByOwnerSig. Public trade/activity projections use the priced bid
-- spend as the authoritative event, so remove the historical authorization
-- leg when its buyer output and amount prove the pair.
DELETE FROM kcc20_activity_feed AS seller_leg
WHERE seller_leg.kind = 'trade'
  AND seller_leg.entrypoint = 'sellIntoBidByOwnerSig'
  AND EXISTS (
      SELECT 1
      FROM covenant_actions AS seller_action
      JOIN covenant_actions AS bid_fill
        ON bid_fill.txid = seller_action.txid
       AND bid_fill.covenant_id = seller_action.covenant_id
       AND bid_fill.action = 'spend'
       AND bid_fill.entrypoint = 'fillBidPartial'
       AND NULLIF(bid_fill.decoded_args->>'buyerOutputIndex', '')
           = NULLIF(seller_action.decoded_args->>'buyerOutputIndex', '')
       AND NULLIF(bid_fill.decoded_args->>'fillAmount', '')
           = NULLIF(seller_action.decoded_args->>'fillAmount', '')
      WHERE seller_action.txid = seller_leg.txid
        AND seller_action.action = 'spend'
        AND seller_action.entrypoint = 'sellIntoBidByOwnerSig'
        AND lower(COALESCE(
              encode(seller_action.canonical_token_id, 'hex'),
              NULLIF(seller_action.decoded_args->>'canonicalTokenId', '')
            )) = encode(seller_leg.token_id, 'hex')
  )
  -- Feed rows do not retain buyerOutputIndex. If any seller leg in the same
  -- token transaction cannot be paired exactly, preserve all historical rows
  -- rather than risk deleting that independent action.
  AND NOT EXISTS (
      SELECT 1
      FROM covenant_actions AS unpaired_seller
      WHERE unpaired_seller.txid = seller_leg.txid
        AND unpaired_seller.action = 'spend'
        AND unpaired_seller.entrypoint = 'sellIntoBidByOwnerSig'
        AND lower(COALESCE(
              encode(unpaired_seller.canonical_token_id, 'hex'),
              NULLIF(unpaired_seller.decoded_args->>'canonicalTokenId', '')
            )) = encode(seller_leg.token_id, 'hex')
        AND NOT EXISTS (
            SELECT 1
            FROM covenant_actions AS paired_fill
            WHERE paired_fill.txid = unpaired_seller.txid
              AND paired_fill.covenant_id = unpaired_seller.covenant_id
              AND paired_fill.action = 'spend'
              AND paired_fill.entrypoint = 'fillBidPartial'
              AND NULLIF(paired_fill.decoded_args->>'buyerOutputIndex', '')
                  = NULLIF(unpaired_seller.decoded_args->>'buyerOutputIndex', '')
              AND NULLIF(paired_fill.decoded_args->>'fillAmount', '')
                  = NULLIF(unpaired_seller.decoded_args->>'fillAmount', '')
        )
  );

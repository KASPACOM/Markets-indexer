-- A crossed orderbook match is authorized by two covenant spends in the same
-- transaction: crossAskSide and crossBidSide. Public trade/activity
-- projections use the ask-side spend as the authoritative event (mirrors the
-- fillBidPartial/sellIntoBidByOwnerSig precedent in
-- 20260716223000_kcc20_paired_bid_trade_dedupe.sql), so remove the
-- historical crossBidSide leg when the decoder's inputIndex cross-reference
-- (or, absent that, the buyerOutputIndex/fillAmount heuristic) proves the
-- pair.
DELETE FROM kcc20_activity_feed AS bid_leg
WHERE bid_leg.kind = 'trade'
  AND bid_leg.entrypoint = 'crossBidSide'
  AND EXISTS (
      SELECT 1
      FROM covenant_actions AS bid_action
      JOIN covenant_actions AS ask_fill
        ON ask_fill.txid = bid_action.txid
       AND ask_fill.action = 'spend'
       AND ask_fill.entrypoint = 'crossAskSide'
       AND (
            (
              NULLIF(ask_fill.decoded_args->>'inputIndex', '') IS NOT NULL
              AND NULLIF(bid_action.decoded_args->>'inputIndex', '') IS NOT NULL
              AND ask_fill.decoded_args->>'inputIndex' = bid_action.decoded_args->>'askInputIndex'
              AND bid_action.decoded_args->>'inputIndex' = ask_fill.decoded_args->>'bidInputIndex'
            )
            OR (
              NULLIF(ask_fill.decoded_args->>'buyerOutputIndex', '')
                  = NULLIF(bid_action.decoded_args->>'buyerOutputIndex', '')
              AND NULLIF(ask_fill.decoded_args->>'fillAmount', '')
                  = NULLIF(bid_action.decoded_args->>'fillAmount', '')
            )
       )
      WHERE bid_action.txid = bid_leg.txid
        AND bid_action.action = 'spend'
        AND bid_action.entrypoint = 'crossBidSide'
        AND lower(COALESCE(
              encode(bid_action.canonical_token_id, 'hex'),
              NULLIF(bid_action.decoded_args->>'canonicalTokenId', '')
            )) = encode(bid_leg.token_id, 'hex')
  )
  -- Feed rows do not retain inputIndex/buyerOutputIndex. If any crossBidSide
  -- leg in the same token transaction cannot be paired exactly (or pairs
  -- ambiguously against more than one crossAskSide candidate), preserve all
  -- historical rows for that transaction rather than risk deleting an
  -- independent action.
  AND NOT EXISTS (
      SELECT 1
      FROM covenant_actions AS unpaired_bid
      WHERE unpaired_bid.txid = bid_leg.txid
        AND unpaired_bid.action = 'spend'
        AND unpaired_bid.entrypoint = 'crossBidSide'
        AND lower(COALESCE(
              encode(unpaired_bid.canonical_token_id, 'hex'),
              NULLIF(unpaired_bid.decoded_args->>'canonicalTokenId', '')
            )) = encode(bid_leg.token_id, 'hex')
        AND (
            SELECT COUNT(*)
            FROM covenant_actions AS candidate_ask
            WHERE candidate_ask.txid = unpaired_bid.txid
              AND candidate_ask.action = 'spend'
              AND candidate_ask.entrypoint = 'crossAskSide'
              AND (
                   (
                     NULLIF(candidate_ask.decoded_args->>'inputIndex', '') IS NOT NULL
                     AND NULLIF(unpaired_bid.decoded_args->>'inputIndex', '') IS NOT NULL
                     AND candidate_ask.decoded_args->>'inputIndex' = unpaired_bid.decoded_args->>'askInputIndex'
                     AND unpaired_bid.decoded_args->>'inputIndex' = candidate_ask.decoded_args->>'bidInputIndex'
                   )
                   OR (
                     NULLIF(candidate_ask.decoded_args->>'buyerOutputIndex', '')
                         = NULLIF(unpaired_bid.decoded_args->>'buyerOutputIndex', '')
                     AND NULLIF(candidate_ask.decoded_args->>'fillAmount', '')
                         = NULLIF(unpaired_bid.decoded_args->>'fillAmount', '')
                   )
              )
        ) <> 1
  );

-- Keep /kcc20/{token}/activity reads and best-effort projection freshness
-- checks bounded while the heavier activity feed refresh runs outside the
-- request path.
CREATE INDEX IF NOT EXISTS kcc20_activity_feed_token_txid_idx
    ON kcc20_activity_feed (token_id, txid);

CREATE INDEX IF NOT EXISTS covenant_actions_tx_covenant_action_id_idx
    ON covenant_actions (txid, covenant_id, action, id);

CREATE INDEX IF NOT EXISTS covenant_actions_spend_tx_entrypoint_idx
    ON covenant_actions (txid, entrypoint, covenant_id, id)
    WHERE action = 'spend'
      AND entrypoint IS NOT NULL;

CREATE INDEX IF NOT EXISTS covenant_actions_continuation_tx_idx
    ON covenant_actions (txid, covenant_id, id DESC)
    WHERE action = 'continuation';

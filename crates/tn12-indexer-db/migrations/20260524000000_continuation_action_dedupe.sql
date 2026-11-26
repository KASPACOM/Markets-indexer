-- KCC20V3 partial fills can create multiple continuation outputs for the same
-- covenant in one transaction. The old de-dupe key collapsed those rows into
-- one action and hid output-level proof data from /tx/{txid}.

DROP INDEX IF EXISTS covenant_actions_uniq;

DELETE FROM covenant_actions a
USING covenant_actions b
WHERE a.id > b.id
  AND a.covenant_id = b.covenant_id
  AND a.txid = b.txid
  AND a.action = b.action
  AND a.action <> 'continuation';

CREATE UNIQUE INDEX IF NOT EXISTS covenant_actions_non_continuation_uniq
    ON covenant_actions (covenant_id, txid, action)
    WHERE action <> 'continuation';

CREATE UNIQUE INDEX IF NOT EXISTS covenant_actions_continuation_vout_uniq
    ON covenant_actions (covenant_id, txid, action, ((outputs->>'vout')))
    WHERE action = 'continuation' AND outputs ? 'vout';

-- covenant_actions has no natural uniqueness today, so re-running the
-- watcher / scanner / ingest path against the same tx creates duplicate
-- rows (seen live: 18× deploy rows for one txid after multiple scans).
-- Add a unique index on (covenant_id, txid, action) so re-ingest is a
-- no-op via ON CONFLICT DO NOTHING.
--
-- Backfill: keep the OLDEST row per (covenant_id, txid, action) and drop
-- the rest so the unique index can be created.

DELETE FROM covenant_actions a
USING covenant_actions b
WHERE a.id > b.id
  AND a.covenant_id = b.covenant_id
  AND a.txid        = b.txid
  AND a.action      = b.action;

CREATE UNIQUE INDEX IF NOT EXISTS covenant_actions_uniq
    ON covenant_actions (covenant_id, txid, action);

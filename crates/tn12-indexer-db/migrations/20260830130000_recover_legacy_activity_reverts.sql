-- Older reorg writers emitted unscoped block_revert markers. Reconcile every
-- currently projected transaction once so stale historical rows can be
-- removed without scanning the full covenant_actions table.
SELECT pg_advisory_xact_lock(6074847039450198576);

WITH activity_state AS (
    SELECT COALESCE(last_dirty_id, 0)::BIGINT AS last_dirty_id
    FROM kcc20_projection_state
    WHERE name = 'activity_feed'
), duplicate_scoped AS (
    SELECT id
    FROM (
        SELECT
            dirty.id,
            ROW_NUMBER() OVER (PARTITION BY dirty.txid ORDER BY dirty.id DESC) AS duplicate_rank
        FROM kcc20_projection_dirty dirty
        CROSS JOIN activity_state state
        WHERE dirty.id > state.last_dirty_id
          AND dirty.txid IS NOT NULL
    ) ranked
    WHERE ranked.duplicate_rank > 1
), compacted AS (
    DELETE FROM kcc20_projection_dirty dirty
    USING duplicate_scoped duplicate
    WHERE dirty.id = duplicate.id
    RETURNING dirty.id
), legacy_reverts AS (
    UPDATE kcc20_projection_dirty dirty
    SET reason = 'block_revert_legacy_repair'
    FROM activity_state state
    WHERE dirty.id > state.last_dirty_id
      AND dirty.reason = 'block_revert'
      AND dirty.txid IS NULL
    RETURNING dirty.id
), feed_txids AS (
    SELECT DISTINCT txid
    FROM kcc20_activity_feed
)
INSERT INTO kcc20_projection_dirty (reason, txid, created_at_ms)
SELECT
    'activity_feed_dirty_txid_backfill',
    feed.txid,
    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
FROM feed_txids feed
WHERE EXISTS (SELECT 1 FROM legacy_reverts)
  AND NOT EXISTS (
      SELECT 1
      FROM kcc20_projection_dirty dirty
      CROSS JOIN activity_state state
      WHERE dirty.id > state.last_dirty_id
        AND dirty.txid = feed.txid
  );

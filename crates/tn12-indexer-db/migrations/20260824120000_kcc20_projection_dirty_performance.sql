-- Bound projector passes by dirty queue order and let tx-scoped activity
-- refreshes find their exact transaction set without scanning the queue.
CREATE INDEX IF NOT EXISTS kcc20_projection_dirty_txid_id_idx
    ON kcc20_projection_dirty (txid, id)
    WHERE txid IS NOT NULL;

CREATE INDEX IF NOT EXISTS kcc20_projection_dirty_unscoped_reason_id_idx
    ON kcc20_projection_dirty (reason, id)
    WHERE txid IS NULL;

ANALYZE kcc20_projection_dirty;

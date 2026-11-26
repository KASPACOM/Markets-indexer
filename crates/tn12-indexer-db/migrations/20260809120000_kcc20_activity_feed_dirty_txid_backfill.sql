-- The activity feed was historically refreshed from
-- MAX(kcc20_activity_feed.block_time_ms) - 1h. Late KCC20 action rows older
-- than that overlap could be present in raw trades/candles while permanently
-- missing from kcc20_activity_feed. Force one full projection pass after the
-- refresh lower-bound fix lands so already-missed rows are backfilled.

INSERT INTO kcc20_projection_dirty (reason, txid, created_at_ms)
VALUES (
    'activity_feed_dirty_txid_backfill',
    NULL,
    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
);

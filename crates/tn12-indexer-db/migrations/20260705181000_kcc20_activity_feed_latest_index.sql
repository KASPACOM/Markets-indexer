CREATE INDEX IF NOT EXISTS kcc20_activity_feed_time_desc_idx
    ON kcc20_activity_feed (block_time_ms DESC, txid DESC, id DESC);

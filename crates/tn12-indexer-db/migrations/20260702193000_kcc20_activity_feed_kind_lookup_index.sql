CREATE INDEX IF NOT EXISTS kcc20_activity_feed_token_kind_time_idx
    ON kcc20_activity_feed (token_id, kind, block_time_ms DESC, txid DESC, id DESC);

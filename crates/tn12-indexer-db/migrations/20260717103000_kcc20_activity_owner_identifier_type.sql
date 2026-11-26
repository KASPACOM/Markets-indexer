ALTER TABLE kcc20_activity_feed
    ADD COLUMN IF NOT EXISTS owner_identifier_type SMALLINT,
    ADD COLUMN IF NOT EXISTS owner_identifier_type_version SMALLINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS kcc20_activity_feed_owner_type_pending_idx
    ON kcc20_activity_feed (block_time_ms ASC, txid ASC, id ASC)
    WHERE owner_identifier_type_version = 0;

CREATE INDEX IF NOT EXISTS kcc20_activity_feed_owner_type_fallback_idx
    ON kcc20_activity_feed (token_id, block_time_ms DESC, txid DESC, id DESC)
    WHERE owner_identifier_type_version <> 1;

-- Existing rows stay available during rolling deploys. The normal projection
-- refresh writes version 1 and classifies older version-0 rows in bounded
-- batches. Version 2 is terminal-but-ambiguous and keeps matching reads on the
-- canonical raw projection without blocking progress through the pending queue.

-- Retain a bounded processed tail so restart can reconstruct the join cache.
-- Its bytes count toward the same durable storage limit as pending intake.
ALTER TABLE wrpc_inbox_streams
    ADD COLUMN retained_bytes BIGINT NOT NULL DEFAULT 0 CHECK (retained_bytes >= 0);

-- Bound audit sealing CPU cost without changing the immutable evidence bytes.
-- Column policy overrides the session default only for these two bytea values.
-- Existing values are not rewritten. PostgreSQL must provide LZ4 support.
SET LOCAL lock_timeout = '2s';
ALTER TABLE historical_acceptance_maps
    ALTER COLUMN window_evidence SET COMPRESSION lz4,
    ALTER COLUMN cohort_evidence SET COMPRESSION lz4;

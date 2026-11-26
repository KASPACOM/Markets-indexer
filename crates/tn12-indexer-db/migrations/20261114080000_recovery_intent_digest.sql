-- Cache the exact existing ownership fingerprint in PostgreSQL. Generated
-- storage recomputes it atomically whenever the journal value changes; callers
-- cannot supply a stale fingerprint. Existing FOR SHARE fencing is unchanged.
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '30s';
ALTER TABLE indexer_state ADD COLUMN value_sha256 BYTEA
    GENERATED ALWAYS AS (pg_catalog.sha256(value::text::bytea)) STORED;

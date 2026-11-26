-- Journal replacements must not reset the age of an unresolved write intent.
ALTER TABLE indexer_state ADD COLUMN created_at_ms BIGINT;
UPDATE indexer_state SET created_at_ms=updated_at_ms;
ALTER TABLE indexer_state ALTER COLUMN created_at_ms SET DEFAULT ((extract(epoch FROM clock_timestamp()) * 1000)::BIGINT);
ALTER TABLE indexer_state ALTER COLUMN created_at_ms SET NOT NULL;

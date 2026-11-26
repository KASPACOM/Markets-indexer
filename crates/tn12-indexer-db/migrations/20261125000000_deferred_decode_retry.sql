-- Additive scheduling metadata. First-seen time and retained evidence never reset.
ALTER TABLE indexer_deferred_decodes
    ADD COLUMN decoder_revision TEXT,
    ADD COLUMN last_attempt_revision TEXT,
    ADD COLUMN attempts BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN next_retry_at_ms BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN last_error TEXT;
CREATE INDEX indexer_deferred_retry_due ON indexer_deferred_decodes(next_retry_at_ms,sequence)
    WHERE status='pending';

-- Scheduling metadata does not change decoding coverage or retained byte usage.
DROP TRIGGER deferred_decode_byte_accounting ON indexer_deferred_decodes;
CREATE TRIGGER deferred_decode_byte_accounting
    AFTER INSERT OR DELETE OR UPDATE OF raw_transaction,status,decoded_at_ms,covenant_ids
    ON indexer_deferred_decodes FOR EACH ROW EXECUTE FUNCTION account_deferred_decode_bytes();

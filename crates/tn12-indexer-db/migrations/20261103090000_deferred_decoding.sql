-- Raw evidence outlives a reorg. Only pending canonical obligations block
-- semantic coverage; receipt/ingestion progress is independent of decoding.
CREATE TABLE indexer_deferred_decodes (
    sequence BIGSERIAL UNIQUE NOT NULL,
    txid BYTEA NOT NULL CHECK (octet_length(txid)=32),
    block_hash BYTEA NOT NULL CHECK (octet_length(block_hash)=32),
    blue_score BIGINT NOT NULL,
    covenant_ids BYTEA[] NOT NULL,
    raw_transaction JSONB NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','resolved','reverted')),
    first_seen_at_ms BIGINT NOT NULL DEFAULT (extract(epoch FROM clock_timestamp())*1000)::BIGINT,
    resolved_at_ms BIGINT,
    PRIMARY KEY(txid,block_hash)
);
CREATE INDEX indexer_deferred_pending_order ON indexer_deferred_decodes(sequence) WHERE status='pending';
CREATE INDEX indexer_deferred_pending_families ON indexer_deferred_decodes USING GIN(covenant_ids) WHERE status='pending';
CREATE INDEX indexer_deferred_block ON indexer_deferred_decodes(block_hash);

-- Retention is bounded across pending, resolved and reverted evidence. A full
-- journal refuses the write atomically rather than advancing without evidence.
-- Count stable logical JSON bytes, independent of TOAST compression. Database
-- capacity planning must additionally allow for rows, indexes, WAL and vacuum.
ALTER TABLE indexer_deferred_decodes ADD COLUMN decoded_at_ms BIGINT;
ALTER TABLE indexer_deferred_decodes ADD CONSTRAINT deferred_payload_limit
    CHECK (octet_length(raw_transaction::text) <= 2097152);
CREATE TABLE indexer_deferred_decode_capacity (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
    retained_bytes BIGINT NOT NULL DEFAULT 0 CHECK(retained_bytes >= 0),
    pending_count BIGINT NOT NULL DEFAULT 0 CHECK(pending_count >= 0),
    generation BIGINT NOT NULL DEFAULT 0,
    byte_limit BIGINT NOT NULL DEFAULT 21474836480 CHECK(byte_limit > 0)
);
INSERT INTO indexer_deferred_decode_capacity(singleton) VALUES(TRUE);
CREATE FUNCTION account_deferred_decode_bytes() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE delta BIGINT; pending_delta BIGINT;
BEGIN
    IF TG_OP='INSERT' THEN delta:=octet_length(NEW.raw_transaction::text); pending_delta:=(NEW.status='pending')::int;
    ELSIF TG_OP='DELETE' THEN delta:=-octet_length(OLD.raw_transaction::text); pending_delta:=-(OLD.status='pending')::int;
    ELSE delta:=octet_length(NEW.raw_transaction::text)-octet_length(OLD.raw_transaction::text); pending_delta:=(NEW.status='pending')::int-(OLD.status='pending')::int;
    END IF;
    UPDATE indexer_deferred_decode_capacity SET retained_bytes=retained_bytes+delta,pending_count=pending_count+pending_delta,generation=generation+1
      WHERE singleton AND retained_bytes+delta BETWEEN 0 AND byte_limit;
    IF NOT FOUND THEN RAISE EXCEPTION 'deferred decoding evidence capacity exhausted; retain ingestion window'; END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER deferred_decode_byte_accounting AFTER INSERT OR UPDATE OR DELETE
    ON indexer_deferred_decodes FOR EACH ROW EXECUTE FUNCTION account_deferred_decode_bytes();

CREATE INDEX indexer_deferred_pending_age ON indexer_deferred_decodes(first_seen_at_ms) WHERE status='pending';

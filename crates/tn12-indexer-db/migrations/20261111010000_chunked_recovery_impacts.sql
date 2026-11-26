-- A large individual block has a durable footprint instead of oversized JSON.
ALTER TABLE tn10_live_recovery_plans ADD COLUMN exclusive_writes BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tn10_live_recovery_blocks ADD COLUMN chunked BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE tn10_live_recovery_block_items (
    intent_key TEXT NOT NULL,
    block_hash BYTEA NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('transaction', 'descendant')),
    item BYTEA NOT NULL CHECK (octet_length(item)=32),
    removed BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY(intent_key,block_hash,kind,item),
    FOREIGN KEY(intent_key,block_hash) REFERENCES tn10_live_recovery_blocks(intent_key,block_hash) ON DELETE CASCADE
);
CREATE INDEX tn10_live_recovery_block_items_pending ON tn10_live_recovery_block_items(intent_key,block_hash,kind,item) WHERE NOT removed;

-- Persist a generation after plan deletion so a request spanning an entire
-- recovery cannot mistake two clear samples for an uninterrupted snapshot.
CREATE TABLE tn10_recovery_read_fence (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
    generation BIGINT NOT NULL DEFAULT 0
);
INSERT INTO tn10_recovery_read_fence(singleton) VALUES(TRUE);
CREATE FUNCTION tn10_advance_recovery_read_fence() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.exclusive_writes AND NOT OLD.exclusive_writes THEN
        UPDATE tn10_recovery_read_fence SET generation=generation+1 WHERE singleton;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER tn10_recovery_read_generation AFTER UPDATE OF exclusive_writes
ON tn10_live_recovery_plans FOR EACH ROW EXECUTE FUNCTION tn10_advance_recovery_read_fence();

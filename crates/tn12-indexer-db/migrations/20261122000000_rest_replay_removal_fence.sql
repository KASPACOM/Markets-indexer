-- Retain removal evidence independently of deleted block/transaction rows.
CREATE SEQUENCE rest_replay_removal_revision;
CREATE TABLE rest_replay_removed_blocks (
    block_hash BYTEA PRIMARY KEY CHECK (octet_length(block_hash)=32),
    revision BIGINT NOT NULL CHECK (revision>0),
    removed_at_ms BIGINT NOT NULL
);

-- Preserve surviving pre-migration removal evidence. Deleted unknown hashes
-- cannot be reconstructed; coordinated rollout establishes the new boundary.
INSERT INTO rest_replay_removed_blocks(block_hash, revision, removed_at_ms)
SELECT hash, nextval('rest_replay_removal_revision'),
       (extract(epoch from clock_timestamp()) * 1000)::bigint
FROM (
    SELECT hash FROM blocks WHERE NOT is_chain_block
    UNION SELECT old_hash FROM canonical_block_replacements
    UNION SELECT old_hash FROM historical_acceptance_map_sources
) removed;

-- Reader fence for a journaled multi-transaction live event. A crash retains
-- this row until verified recovery deletes that exact journal.
CREATE TABLE tn10_live_event_fences (
    intent_key TEXT PRIMARY KEY REFERENCES indexer_state(key) ON DELETE CASCADE
);
CREATE FUNCTION tn10_live_event_read_generation() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    UPDATE tn10_recovery_read_fence SET generation=generation+1 WHERE singleton;
    RETURN NULL;
END;
$$;
CREATE TRIGGER tn10_live_event_read_generation AFTER INSERT OR DELETE
ON tn10_live_event_fences FOR EACH ROW EXECUTE FUNCTION tn10_live_event_read_generation();

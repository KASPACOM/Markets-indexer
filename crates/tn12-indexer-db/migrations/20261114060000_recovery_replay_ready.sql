-- Derived scheduling state only. Source evidence and canonical checkpoints stay
-- authoritative. NULL blockers require bounded initialization before replay.
ALTER TABLE tn10_live_recovery_transactions
    ADD COLUMN replay_blockers BIGINT CHECK (replay_blockers >= 0);
CREATE INDEX tn10_recovery_replay_unprepared_idx
    ON tn10_live_recovery_transactions(intent_key, txid)
    WHERE replay_blockers IS NULL;
CREATE INDEX tn10_recovery_replay_ready_idx
    ON tn10_live_recovery_transactions(intent_key, txid)
    WHERE NOT replayed AND replay_blockers = 0
      AND (source_body->>'is_accepted')::boolean IS TRUE;
-- Parent membership can refer outside the retained closure. Only staged,
-- unreplayed parents block readiness, matching the original selector.
CREATE TABLE tn10_recovery_replay_edges (
    intent_key TEXT NOT NULL,
    parent_txid BYTEA NOT NULL CHECK (octet_length(parent_txid)=32),
    child_txid BYTEA NOT NULL,
    PRIMARY KEY(intent_key,parent_txid,child_txid),
    FOREIGN KEY(intent_key,child_txid) REFERENCES tn10_live_recovery_transactions(intent_key,txid) ON DELETE CASCADE
);
CREATE INDEX tn10_recovery_replay_edges_child_idx
    ON tn10_recovery_replay_edges(intent_key,child_txid,parent_txid);
CREATE TABLE tn10_recovery_replay_releases (
    intent_key TEXT NOT NULL REFERENCES tn10_live_recovery_plans(intent_key) ON DELETE CASCADE,
    parent_txid BYTEA NOT NULL,
    after_child BYTEA,
    PRIMARY KEY(intent_key,parent_txid)
);

CREATE FUNCTION tn10_recovery_release_replay_children() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.replayed AND NOT OLD.replayed THEN
        -- Constant-size journal entry in the canonical commit. Fanout is
        -- released separately in durable pages, never inside this write.
        INSERT INTO tn10_recovery_replay_releases(intent_key,parent_txid)
        VALUES(NEW.intent_key,NEW.txid) ON CONFLICT DO NOTHING;
    ELSIF OLD.replayed AND NOT NEW.replayed THEN
        RAISE EXCEPTION 'replayed checkpoint cannot be reopened in place';
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER tn10_recovery_release_replay_children
    AFTER UPDATE OF replayed ON tn10_live_recovery_transactions
    FOR EACH ROW WHEN (OLD.replayed IS DISTINCT FROM NEW.replayed)
    EXECUTE FUNCTION tn10_recovery_release_replay_children();

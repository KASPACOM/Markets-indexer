-- Receipt/lease heartbeats never count as committed canonical progress.
ALTER TABLE tn10_live_recovery_plans
    ADD COLUMN last_committed_step_at_ms BIGINT,
    ADD COLUMN last_committed_checkpoint TEXT;
ALTER TABLE tn10_live_recovery_blocks
    ADD COLUMN removal_failures INT NOT NULL DEFAULT 0,
    ADD COLUMN last_removal_error TEXT,
    ADD COLUMN last_removal_failure_at_ms BIGINT;
CREATE INDEX tn10_recovery_failed_removals ON tn10_live_recovery_blocks(intent_key,last_removal_failure_at_ms DESC)
    WHERE removal_failures>0;

CREATE FUNCTION tn10_record_removal_checkpoint() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME='tn10_live_recovery_block_items' THEN
        IF OLD.removed OR NOT NEW.removed THEN RETURN NEW; END IF;
        UPDATE tn10_live_recovery_plans SET
            last_committed_step_at_ms=(extract(epoch FROM clock_timestamp())*1000)::bigint,
            last_committed_checkpoint='remove-tx:' || encode(NEW.block_hash,'hex') || ':' || encode(NEW.item,'hex')
        WHERE intent_key=NEW.intent_key;
        UPDATE tn10_live_recovery_blocks SET removal_failures=0,last_removal_error=NULL,
            last_removal_failure_at_ms=NULL
        WHERE intent_key=NEW.intent_key AND block_hash=NEW.block_hash;
    ELSE
        IF OLD.reverted OR NOT NEW.reverted THEN RETURN NEW; END IF;
        UPDATE tn10_live_recovery_plans SET
            last_committed_step_at_ms=(extract(epoch FROM clock_timestamp())*1000)::bigint,
            last_committed_checkpoint='remove-block:' || encode(NEW.block_hash,'hex')
        WHERE intent_key=NEW.intent_key;
        UPDATE tn10_live_recovery_blocks SET removal_failures=0,last_removal_error=NULL,
            last_removal_failure_at_ms=NULL
        WHERE intent_key=NEW.intent_key AND block_hash=NEW.block_hash;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER tn10_record_removal_item_checkpoint AFTER UPDATE OF removed
ON tn10_live_recovery_block_items FOR EACH ROW EXECUTE FUNCTION tn10_record_removal_checkpoint();
CREATE TRIGGER tn10_record_removal_block_checkpoint AFTER UPDATE OF reverted
ON tn10_live_recovery_blocks FOR EACH ROW EXECUTE FUNCTION tn10_record_removal_checkpoint();

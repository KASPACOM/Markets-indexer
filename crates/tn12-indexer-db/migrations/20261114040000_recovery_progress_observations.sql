-- Durable preparation progress is separate from the canonical generation used
-- by summary aggregation. A heartbeat or a failed attempt changes neither.
ALTER TABLE tn10_live_recovery_plans
    ADD COLUMN last_durable_progress_at_ms BIGINT,
    ADD COLUMN last_durable_checkpoint TEXT,
    ADD COLUMN canonical_pause_started_at_ms BIGINT;

UPDATE tn10_live_recovery_plans p SET
    last_durable_progress_at_ms=last_committed_step_at_ms,
    last_durable_checkpoint=last_committed_checkpoint,
    canonical_pause_started_at_ms=CASE WHEN exclusive_writes THEN
        (SELECT created_at_ms FROM indexer_state WHERE key=p.intent_key) END;

CREATE FUNCTION tn10_record_plan_progress() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.last_committed_checkpoint IS DISTINCT FROM OLD.last_committed_checkpoint
       OR NEW.committed_step_sequence<>OLD.committed_step_sequence THEN
        NEW.last_durable_progress_at_ms=NEW.last_committed_step_at_ms;
        NEW.last_durable_checkpoint=NEW.last_committed_checkpoint;
    END IF;
    IF NEW.exclusive_writes AND NOT OLD.exclusive_writes THEN
        NEW.canonical_pause_started_at_ms=(extract(epoch FROM clock_timestamp())*1000)::bigint;
    ELSIF NOT NEW.exclusive_writes THEN
        NEW.canonical_pause_started_at_ms=NULL;
    END IF;
    RETURN NEW;
END $$;
-- Alphabetically after tn10_advance_committed_step_sequence, so checkpoint ABA
-- is observable even when two removals produce the same checkpoint text.
CREATE TRIGGER tn10_record_plan_progress BEFORE UPDATE
ON tn10_live_recovery_plans FOR EACH ROW EXECUTE FUNCTION tn10_record_plan_progress();

CREATE FUNCTION tn10_record_durable_recovery_progress() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE checkpoint TEXT;
BEGIN
    IF TG_TABLE_NAME='tn10_live_recovery_frontier' THEN
        IF OLD.processed OR NOT NEW.processed THEN RETURN NEW; END IF;
        checkpoint='discover-block:' || encode(NEW.block_hash,'hex');
    ELSIF TG_TABLE_NAME='tn10_live_recovery_tx_frontier' THEN
        IF OLD.processed OR NOT NEW.processed THEN RETURN NEW; END IF;
        checkpoint='discover-tx:' || encode(NEW.txid,'hex');
    ELSIF TG_TABLE_NAME='tn10_live_recovery_transactions' THEN
        IF NOT ((NEW.replayed AND NOT OLD.replayed) OR
                (NEW.verified_rejected AND NOT OLD.verified_rejected)) THEN RETURN NEW; END IF;
        checkpoint=CASE WHEN NEW.replayed THEN 'replay:' ELSE 'reject:' END || encode(NEW.txid,'hex');
    ELSE
        IF NEW.active_count<=OLD.active_count THEN RETURN NEW; END IF;
        checkpoint='summary-page:' || encode(NEW.covenant_id,'hex') || ':' || NEW.active_count;
    END IF;
    UPDATE tn10_live_recovery_plans SET
        last_durable_progress_at_ms=(extract(epoch FROM clock_timestamp())*1000)::bigint,
        last_durable_checkpoint=checkpoint
    WHERE intent_key=NEW.intent_key;
    RETURN NEW;
END $$;
CREATE TRIGGER tn10_discovery_progress AFTER UPDATE OF processed ON tn10_live_recovery_frontier
FOR EACH ROW EXECUTE FUNCTION tn10_record_durable_recovery_progress();
CREATE TRIGGER tn10_dependency_progress AFTER UPDATE OF processed ON tn10_live_recovery_tx_frontier
FOR EACH ROW EXECUTE FUNCTION tn10_record_durable_recovery_progress();
CREATE TRIGGER tn10_replay_progress AFTER UPDATE OF replayed,verified_rejected ON tn10_live_recovery_transactions
FOR EACH ROW EXECUTE FUNCTION tn10_record_durable_recovery_progress();
CREATE TRIGGER tn10_summary_page_progress AFTER UPDATE OF active_count ON tn10_recovery_summary_pages
FOR EACH ROW EXECUTE FUNCTION tn10_record_durable_recovery_progress();

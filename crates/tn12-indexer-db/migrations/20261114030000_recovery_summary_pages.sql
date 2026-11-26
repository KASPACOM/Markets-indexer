-- Monotonic canonical removal generation avoids timestamp/checkpoint ABA.
ALTER TABLE tn10_live_recovery_plans ADD COLUMN committed_step_sequence BIGINT NOT NULL DEFAULT 0;
CREATE FUNCTION tn10_advance_committed_step_sequence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.committed_step_sequence=OLD.committed_step_sequence+1; RETURN NEW; END $$;
CREATE TRIGGER tn10_advance_committed_step_sequence BEFORE UPDATE OF last_committed_checkpoint
ON tn10_live_recovery_plans FOR EACH ROW EXECUTE FUNCTION tn10_advance_committed_step_sequence();

CREATE TABLE tn10_recovery_summary_pages (
    intent_key TEXT NOT NULL REFERENCES tn10_live_recovery_plans(intent_key) ON DELETE CASCADE,
    covenant_id BYTEA NOT NULL REFERENCES covenants(covenant_id) ON DELETE CASCADE,
    canonical_sequence BIGINT NOT NULL,
    after_score BIGINT,
    after_txid BYTEA,
    after_vout INT,
    active_count BIGINT NOT NULL DEFAULT 0,
    total_amount NUMERIC NOT NULL DEFAULT 0,
    latest_txid BYTEA,
    latest_vout INT,
    latest_block BYTEA,
    latest_score BIGINT,
    PRIMARY KEY(intent_key,covenant_id)
);

-- Called only under the writer lock and a verified recovery owner. The plan's
-- exclusive fence prevents canonical mutations between these small commits.
-- A different committed canonical generation restarts aggregation, never
-- publishes a mixture of two active sets.
CREATE FUNCTION recovery_summary_page(wanted_intent TEXT,wanted_covenant BYTEA) RETURNS BOOLEAN
LANGUAGE plpgsql AS $$
DECLARE
    generation BIGINT;
    p tn10_recovery_summary_pages%ROWTYPE;
    n BIGINT;
    amount NUMERIC;
    last_score BIGINT;
    last_id BYTEA;
    last_index INT;
    first_score BIGINT;
    first_id BYTEA;
    first_index INT;
    first_block BYTEA;
BEGIN
    SELECT committed_step_sequence INTO STRICT generation FROM tn10_live_recovery_plans
    WHERE intent_key=wanted_intent AND exclusive_writes AND phase='revert' FOR UPDATE;
    IF NOT EXISTS(SELECT 1 FROM covenant_active_output_order_progress WHERE singleton AND phase='ready') THEN
        RAISE EXCEPTION 'active output ordering is not verified';
    END IF;
    INSERT INTO tn10_recovery_summary_pages(intent_key,covenant_id,canonical_sequence)
    VALUES(wanted_intent,wanted_covenant,generation)
    ON CONFLICT(intent_key,covenant_id) DO UPDATE SET canonical_sequence=EXCLUDED.canonical_sequence,
        after_score=NULL,after_txid=NULL,after_vout=NULL,active_count=0,total_amount=0,
        latest_txid=NULL,latest_vout=NULL,latest_block=NULL,latest_score=NULL
    WHERE tn10_recovery_summary_pages.canonical_sequence<>EXCLUDED.canonical_sequence;
    SELECT * INTO STRICT p FROM tn10_recovery_summary_pages
    WHERE intent_key=wanted_intent AND covenant_id=wanted_covenant FOR UPDATE;
    WITH ordered AS MATERIALIZED (
        SELECT o.* FROM covenant_active_output_order o WHERE o.covenant_id=wanted_covenant
          AND ROW(o.blue_score,o.txid,o.vout)<ROW(coalesce(p.after_score,9223372036854775807),
              coalesce(p.after_txid,decode(repeat('ff',33),'hex')),coalesce(p.after_vout,2147483647))
        ORDER BY o.blue_score DESC,o.txid DESC,o.vout DESC LIMIT 500
    ), page AS MATERIALIZED (
        SELECT o.*,u.amount_sompi FROM ordered o JOIN covenant_utxos u USING(txid,vout)
    )
    SELECT (SELECT count(*) FROM page),(SELECT coalesce(sum(amount_sompi),0) FROM page),
        (SELECT blue_score FROM page ORDER BY blue_score,txid,vout LIMIT 1),
        (SELECT txid FROM page ORDER BY blue_score,txid,vout LIMIT 1),
        (SELECT vout FROM page ORDER BY blue_score,txid,vout LIMIT 1),
        (SELECT blue_score FROM page ORDER BY blue_score DESC,txid DESC,vout DESC LIMIT 1),
        (SELECT txid FROM page ORDER BY blue_score DESC,txid DESC,vout DESC LIMIT 1),
        (SELECT vout FROM page ORDER BY blue_score DESC,txid DESC,vout DESC LIMIT 1),
        (SELECT created_block FROM page ORDER BY blue_score DESC,txid DESC,vout DESC LIMIT 1)
    INTO n,amount,last_score,last_id,last_index,first_score,first_id,first_index,first_block;
    IF n>0 THEN
        UPDATE tn10_recovery_summary_pages SET after_score=last_score,after_txid=last_id,after_vout=last_index,
            active_count=active_count+n,total_amount=total_amount+amount,
            latest_txid=coalesce(latest_txid,first_id),latest_vout=coalesce(latest_vout,first_index),
            latest_block=coalesce(latest_block,first_block),latest_score=coalesce(latest_score,first_score)
        WHERE intent_key=wanted_intent AND covenant_id=wanted_covenant;
        RETURN FALSE;
    END IF;
    INSERT INTO covenant_summaries(covenant_id,current_address,active_utxos,total_amount_sompi,
        latest_active_txid,latest_active_vout,latest_active_block,latest_active_blue_score,updated_at_ms)
    SELECT c.covenant_id,coalesce(u.address,c.address),p.active_count,p.total_amount,
        p.latest_txid,p.latest_vout,p.latest_block,p.latest_score,
        (extract(epoch FROM clock_timestamp())*1000)::bigint
    FROM covenants c LEFT JOIN covenant_utxos u ON u.txid=p.latest_txid AND u.vout=p.latest_vout
    WHERE c.covenant_id=wanted_covenant
    ON CONFLICT(covenant_id) DO UPDATE SET current_address=EXCLUDED.current_address,
        active_utxos=EXCLUDED.active_utxos,total_amount_sompi=EXCLUDED.total_amount_sompi,
        latest_active_txid=EXCLUDED.latest_active_txid,latest_active_vout=EXCLUDED.latest_active_vout,
        latest_active_block=EXCLUDED.latest_active_block,latest_active_blue_score=EXCLUDED.latest_active_blue_score,
        updated_at_ms=EXCLUDED.updated_at_ms;
    DELETE FROM tn10_recovery_summary_pages WHERE intent_key=wanted_intent AND covenant_id=wanted_covenant;
    UPDATE tn10_live_recovery_plans SET last_committed_checkpoint='summary:' || encode(wanted_covenant,'hex'),
        last_committed_step_at_ms=(extract(epoch FROM clock_timestamp())*1000)::bigint
    WHERE intent_key=wanted_intent;
    RETURN TRUE;
END $$;

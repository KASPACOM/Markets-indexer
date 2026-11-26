-- Derived ordering only: canonical outputs remain the source of truth.
CREATE TABLE covenant_active_output_order (
    txid BYTEA NOT NULL,
    vout INT NOT NULL,
    covenant_id BYTEA NOT NULL REFERENCES covenants(covenant_id) ON DELETE CASCADE,
    created_block BYTEA NOT NULL REFERENCES blocks(hash) ON DELETE CASCADE,
    blue_score BIGINT NOT NULL,
    PRIMARY KEY(txid,vout),
    FOREIGN KEY(txid,vout) REFERENCES covenant_utxos(txid,vout) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX covenant_active_output_latest_idx ON covenant_active_output_order
    (covenant_id,blue_score DESC,txid DESC,vout DESC) INCLUDE(created_block);
CREATE INDEX covenant_active_output_created_block_idx ON covenant_active_output_order(created_block);
CREATE TABLE covenant_active_output_order_progress (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
    phase TEXT NOT NULL CHECK(phase IN ('fill','verify_source','verify_index','ready')),
    after_txid BYTEA,
    after_vout INT,
    processed_rows BIGINT NOT NULL DEFAULT 0,
    updated_at_ms BIGINT NOT NULL DEFAULT 0
);
INSERT INTO covenant_active_output_order_progress(singleton,phase) VALUES(TRUE,'fill');

CREATE FUNCTION maintain_covenant_active_output_order() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        DELETE FROM covenant_active_output_order WHERE txid=OLD.txid AND vout=OLD.vout;
        RETURN OLD;
    END IF;
    IF TG_OP='UPDATE' THEN
        IF ROW(NEW.txid,NEW.vout,NEW.covenant_id,NEW.created_block,NEW.status)
            IS NOT DISTINCT FROM ROW(OLD.txid,OLD.vout,OLD.covenant_id,OLD.created_block,OLD.status) THEN
            RETURN NEW;
        END IF;
        DELETE FROM covenant_active_output_order WHERE txid=OLD.txid AND vout=OLD.vout;
    END IF;
    IF NEW.status='active' AND NEW.covenant_id IS NOT NULL THEN
        INSERT INTO covenant_active_output_order(txid,vout,covenant_id,created_block,blue_score)
        SELECT NEW.txid,NEW.vout,NEW.covenant_id,NEW.created_block,b.blue_score
        FROM blocks b WHERE b.hash=NEW.created_block
        ON CONFLICT(txid,vout) DO UPDATE SET covenant_id=EXCLUDED.covenant_id,
            created_block=EXCLUDED.created_block,blue_score=EXCLUDED.blue_score;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER maintain_covenant_active_output_order
AFTER INSERT OR UPDATE OR DELETE ON covenant_utxos
FOR EACH ROW EXECUTE FUNCTION maintain_covenant_active_output_order();

-- Keep derived rank correct if a maintenance operation corrects a block score.
CREATE FUNCTION maintain_active_output_block_score() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE covenant_active_output_order SET blue_score=NEW.blue_score WHERE created_block=NEW.hash;
    RETURN NEW;
END $$;
CREATE TRIGGER maintain_active_output_block_score AFTER UPDATE OF blue_score ON blocks
FOR EACH ROW WHEN (OLD.blue_score IS DISTINCT FROM NEW.blue_score)
EXECUTE FUNCTION maintain_active_output_block_score();

-- Each call is one independently committed page. This maintenance takes the
-- normal writer lock but writes only derived rows, even during recovery fencing.
-- A verified prefix stays verified because every later mutation has a trigger.
CREATE FUNCTION active_output_order_backfill_step() RETURNS JSONB LANGUAGE plpgsql AS $$
DECLARE
    p covenant_active_output_order_progress%ROWTYPE;
    row_count BIGINT;
    last_id BYTEA;
    last_vout INT;
    mismatch BOOLEAN;
BEGIN
    PERFORM set_config('lock_timeout','350ms',TRUE);
    PERFORM set_config('statement_timeout','2s',TRUE);
    IF NOT pg_try_advisory_xact_lock(6074847039450202930) THEN
        RETURN jsonb_build_object('phase','waiting_writer');
    END IF;
    SELECT * INTO STRICT p FROM covenant_active_output_order_progress WHERE singleton FOR UPDATE;
    IF p.phase='ready' THEN RETURN to_jsonb(p); END IF;
    IF p.phase IN ('fill','verify_source') THEN
        WITH page AS MATERIALIZED (
            SELECT u.txid,u.vout,u.covenant_id,u.created_block,u.status
            FROM covenant_utxos u
            WHERE ROW(u.txid,u.vout)>ROW(coalesce(p.after_txid,''::bytea),coalesce(p.after_vout,-1))
            ORDER BY u.txid,u.vout LIMIT 500
        ), expected AS MATERIALIZED (
            SELECT u.txid,u.vout,u.covenant_id,u.created_block,b.blue_score
            FROM page u JOIN blocks b ON b.hash=u.created_block
            WHERE u.status='active' AND u.covenant_id IS NOT NULL
        ), inserted AS (
            INSERT INTO covenant_active_output_order(txid,vout,covenant_id,created_block,blue_score)
            SELECT txid,vout,covenant_id,created_block,blue_score FROM expected WHERE p.phase='fill'
            ON CONFLICT(txid,vout) DO UPDATE SET covenant_id=EXCLUDED.covenant_id,
                created_block=EXCLUDED.created_block,blue_score=EXCLUDED.blue_score
        )
        SELECT (SELECT count(*) FROM page),
            (SELECT txid FROM page ORDER BY txid DESC,vout DESC LIMIT 1),
            (SELECT vout FROM page ORDER BY txid DESC,vout DESC LIMIT 1),
            EXISTS(SELECT 1 FROM expected e LEFT JOIN covenant_active_output_order o USING(txid,vout)
                WHERE ROW(o.covenant_id,o.created_block,o.blue_score)
                    IS DISTINCT FROM ROW(e.covenant_id,e.created_block,e.blue_score))
        INTO row_count,last_id,last_vout,mismatch;
        IF p.phase='verify_source' AND mismatch THEN
            RAISE EXCEPTION 'active output ordering source parity failed';
        END IF;
    ELSE
        WITH page AS MATERIALIZED (
            SELECT * FROM covenant_active_output_order o
            WHERE ROW(o.txid,o.vout)>ROW(coalesce(p.after_txid,''::bytea),coalesce(p.after_vout,-1))
            ORDER BY o.txid,o.vout LIMIT 500
        )
        SELECT (SELECT count(*) FROM page),
            (SELECT txid FROM page ORDER BY txid DESC,vout DESC LIMIT 1),
            (SELECT vout FROM page ORDER BY txid DESC,vout DESC LIMIT 1),
            EXISTS(SELECT 1 FROM page o LEFT JOIN covenant_utxos u USING(txid,vout)
                LEFT JOIN blocks b ON b.hash=u.created_block
                WHERE u.status IS DISTINCT FROM 'active' OR
                    ROW(o.covenant_id,o.created_block,o.blue_score)
                    IS DISTINCT FROM ROW(u.covenant_id,u.created_block,b.blue_score))
        INTO row_count,last_id,last_vout,mismatch;
        IF mismatch THEN RAISE EXCEPTION 'active output ordering reverse parity failed'; END IF;
    END IF;
    UPDATE covenant_active_output_order_progress SET
        phase=CASE WHEN row_count>0 THEN p.phase WHEN p.phase='fill' THEN 'verify_source'
            WHEN p.phase='verify_source' THEN 'verify_index' ELSE 'ready' END,
        after_txid=last_id,after_vout=last_vout,
        processed_rows=processed_rows+row_count,
        updated_at_ms=(extract(epoch FROM clock_timestamp())*1000)::bigint
    WHERE singleton RETURNING * INTO p;
    RETURN to_jsonb(p);
END $$;

CREATE FUNCTION latest_active_covenant_output(wanted BYTEA)
RETURNS TABLE(txid BYTEA,vout INT,address TEXT,created_block BYTEA,blue_score BIGINT)
LANGUAGE plpgsql STABLE AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM covenant_active_output_order_progress WHERE singleton AND phase='ready') THEN
        RETURN QUERY WITH latest AS MATERIALIZED (
            SELECT o.txid,o.vout,o.created_block,o.blue_score
            FROM covenant_active_output_order o WHERE o.covenant_id=wanted
            ORDER BY o.blue_score DESC,o.txid DESC,o.vout DESC LIMIT 1
        ) SELECT o.txid,o.vout,u.address,o.created_block,o.blue_score
          FROM latest o JOIN covenant_utxos u ON u.txid=o.txid AND u.vout=o.vout;
    ELSE
        RETURN QUERY SELECT u.txid,u.vout,u.address,u.created_block,coalesce(b.blue_score,0)
        FROM covenant_utxos u LEFT JOIN blocks b ON b.hash=u.created_block
        WHERE u.covenant_id=wanted AND u.status='active'
        ORDER BY coalesce(b.blue_score,0) DESC,u.txid DESC,u.vout DESC LIMIT 1;
    END IF;
END $$;

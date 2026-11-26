-- Preserve the existing outpoint cursor: earlier pages already covered every
-- active output before it. Source/reverse parity still gates the ready flag.
-- Filtering before LIMIT avoids traversing hundreds of millions of spent rows.
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_index i WHERE
            i.indexrelid=to_regclass('covenant_utxos_active_outpoint_backfill_idx')
            AND i.indrelid='covenant_utxos'::regclass AND i.indisvalid AND i.indisready
    ) THEN
        RAISE EXCEPTION 'active outpoint backfill index is missing or invalid; rebuild concurrently before retrying migration';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION active_output_order_backfill_step() RETURNS JSONB LANGUAGE plpgsql AS $$
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
            SELECT u.txid,u.vout,u.covenant_id,u.created_block,'active'::text AS status
            FROM covenant_utxos u
            WHERE u.status='active' AND u.covenant_id IS NOT NULL
              AND ROW(u.txid,u.vout)>ROW(coalesce(p.after_txid,''::bytea),coalesce(p.after_vout,-1))
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

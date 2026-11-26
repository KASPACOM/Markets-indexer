) checked(check_result);
IF bad IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'historical acceptance cohort changed after proof capture'; END IF;

SELECT check_result INTO bad FROM (SELECT EXISTS(SELECT 1 FROM jsonb_to_recordset(t.block_evidence::jsonb) e(hash text,score bigint,time bigint,canonical bool)
        LEFT JOIN public.blocks b ON b.hash=decode(e.hash,'hex')
        WHERE (NOT e.canonical AND b.hash IS NULL) OR (b.hash IS NOT NULL AND
            (b.blue_score<>e.score OR b.timestamp_ms<>e.time OR (e.canonical AND NOT b.is_chain_block))))) checked(check_result);
IF bad IS DISTINCT FROM FALSE THEN RAISE EXCEPTION 'stored block metadata conflicts with historical acceptance proof'; END IF;

SELECT check_result INTO bad FROM (WITH m AS (SELECT old,txid,target FROM pg_temp.historical_transition_mapping m)
        SELECT EXISTS(SELECT 1 FROM m JOIN public.covenant_utxos u ON u.txid=m.txid WHERE u.created_block<>m.old AND u.created_block<>m.target)
        OR EXISTS(SELECT 1 FROM m JOIN public.covenant_actions a ON a.txid=m.txid WHERE a.block_hash<>m.old AND a.block_hash<>m.target)
        OR EXISTS(SELECT 1 FROM m JOIN public.covenants c ON c.genesis_txid=m.txid WHERE c.genesis_block<>m.old AND c.genesis_block<>m.target)) checked(check_result);
IF bad IS DISTINCT FROM FALSE THEN RAISE EXCEPTION 'historical acceptance transaction references a third block'; END IF;

SELECT check_result INTO bad FROM (WITH m AS (SELECT old,txid,target FROM pg_temp.historical_transition_mapping m),
        i AS (SELECT decode(txid,'hex') txid,decode(prev,'hex') prev,vout,amount,decode(script,'hex') script FROM jsonb_to_recordset(t.inputs::jsonb) i(txid text,prev text,vout int,amount bigint,script text)),
        mi AS MATERIALIZED (SELECT i.*, m.old, m.target FROM i JOIN m USING(txid))
        SELECT EXISTS(SELECT 1 FROM mi i JOIN public.covenant_utxos u ON u.txid=i.prev AND u.vout=i.vout
            WHERE u.amount_sompi IS DISTINCT FROM i.amount OR u.script_pubkey IS DISTINCT FROM i.script
            OR ((u.status='active' AND u.spent_by_txid IS NULL AND u.spent_block IS NULL)
                OR (u.status='spent' AND u.spent_by_txid=i.txid AND u.spent_block IN(i.old,i.target))) IS NOT TRUE)
        OR EXISTS(SELECT 1 FROM m
            JOIN (SELECT * FROM public.covenant_actions WHERE block_hash=ANY(t.acceptance_blocks::bytea[]) AND action='spend' OFFSET 0) a ON a.txid=m.txid
            LEFT JOIN i ON i.txid=a.txid AND i.prev=decode(a.inputs#>>'{previousOutpoint,hash}','hex') AND i.vout=(a.inputs#>>'{previousOutpoint,index}')::int
            LEFT JOIN public.covenant_utxos u ON u.txid=i.prev AND u.vout=i.vout
            WHERE a.action='spend' AND (i.txid IS NULL OR u.txid IS NULL OR u.status<>'spent'
                OR u.spent_by_txid IS DISTINCT FROM a.txid OR u.spent_block IS NULL OR u.spent_block NOT IN(m.old,m.target)))) checked(check_result);
IF bad IS DISTINCT FROM FALSE THEN RAISE EXCEPTION 'historical acceptance input has contradictory persisted spend evidence'; END IF;

INSERT INTO public.blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms)
        SELECT DISTINCT target,score,0,ARRAY[]::bytea[],time,TRUE,(extract(epoch from now())*1000)::bigint
        FROM pg_temp.historical_transition_mapping m ON CONFLICT(hash) DO NOTHING;

PERFORM set_config('tn12.defer_acceptance_summary_refresh', 'on', TRUE);
WITH moved AS (
    UPDATE public.covenant_utxos u SET created_block=m.target
    FROM pg_temp.historical_transition_mapping m
    WHERE u.created_block=m.old AND u.txid=m.txid
    RETURNING u.covenant_id,u.status
)
SELECT count(*),array_agg(DISTINCT covenant_id) FILTER (WHERE status='active')
INTO n_created,affected_covenants FROM moved;
PERFORM set_config('tn12.defer_acceptance_summary_refresh', 'off', TRUE);
IF n_created IS DISTINCT FROM t.expected_created THEN RAISE EXCEPTION 'historical acceptance reference count changed for created';END IF;

-- A creation-reference move changes neither active counts nor amounts. Use
-- the moved active outputs and the verified prior latest output to update the
-- latest pointer without scanning a covenant's entire active UTXO set. The
-- prior latest remains a valid comparator when it did not move. If it moved,
-- the best mapped output wins when its new ordering tuple is at least the
-- prior tuple. A lower tuple or stale summary falls back to full recomputation.
WITH affected AS MATERIALIZED (
    SELECT DISTINCT covenant_id FROM unnest(affected_covenants) AS ids(covenant_id)
), mapped_latest AS MATERIALIZED (
    SELECT DISTINCT ON (u.covenant_id)
        u.covenant_id,u.txid,u.vout,u.address,u.created_block,m.score
    FROM pg_temp.historical_transition_mapping m
    JOIN public.covenant_utxos u ON u.txid=m.txid
        AND u.created_block=m.target AND u.status='active'
    JOIN affected a ON a.covenant_id=u.covenant_id
    ORDER BY u.covenant_id,m.score DESC,u.txid DESC,u.vout DESC
), fast AS MATERIALIZED (
    SELECT a.covenant_id,m.txid,m.vout,m.address,m.created_block,m.score,
        (latest_map.txid IS NOT NULL) AS latest_moved,
        s.latest_active_blue_score,s.latest_active_txid,s.latest_active_vout
    FROM affected a
    JOIN public.covenant_summaries s USING (covenant_id)
    JOIN public.covenant_utxos current_u ON current_u.txid=s.latest_active_txid
        AND current_u.vout=s.latest_active_vout
    JOIN public.blocks prior_block ON prior_block.hash=s.latest_active_block
    JOIN mapped_latest m ON m.covenant_id=a.covenant_id
    LEFT JOIN LATERAL (
        SELECT txid,target FROM pg_temp.historical_transition_mapping
        WHERE txid=s.latest_active_txid AND old=s.latest_active_block
        LIMIT 1
    ) latest_map ON TRUE
    WHERE s.active_utxos > 0
      AND current_u.covenant_id=a.covenant_id
      AND current_u.status='active'
      AND current_u.address=s.current_address
      AND prior_block.blue_score=s.latest_active_blue_score
      AND (
          (latest_map.txid IS NULL
              AND current_u.created_block=s.latest_active_block)
          OR (latest_map.txid IS NOT NULL
              AND current_u.created_block=latest_map.target
              AND (m.score,m.txid,m.vout) >=
                  (s.latest_active_blue_score,s.latest_active_txid,s.latest_active_vout))
      )
), updated AS (
    UPDATE public.covenant_summaries s SET
        current_address=f.address,
        latest_active_txid=f.txid,
        latest_active_vout=f.vout,
        latest_active_block=f.created_block,
        latest_active_blue_score=f.score,
        updated_at_ms=(extract(epoch from now())*1000)::bigint
    FROM fast f
    WHERE s.covenant_id=f.covenant_id
      AND (f.latest_moved OR
           (f.score,f.txid,f.vout) >
           (f.latest_active_blue_score,f.latest_active_txid,f.latest_active_vout))
    RETURNING s.covenant_id
)
SELECT array_agg(covenant_id) INTO fast_covenants FROM fast;

WITH affected AS MATERIALIZED (
    SELECT DISTINCT covenant_id FROM unnest(affected_covenants) AS ids(covenant_id)
), repair_needed AS MATERIALIZED (
    SELECT covenant_id FROM affected
    WHERE covenant_id <> ALL(COALESCE(fast_covenants,ARRAY[]::bytea[]))
), active_for_repair AS MATERIALIZED (
    SELECT u.covenant_id,u.txid,u.vout,u.address,u.created_block,u.amount_sompi
    FROM repair_needed a CROSS JOIN LATERAL (
        SELECT covenant_id,txid,vout,address,created_block,amount_sompi
        FROM public.covenant_utxos
        WHERE covenant_id=a.covenant_id AND status='active'
        OFFSET 0
    ) u
), totals AS (
    SELECT covenant_id,count(*)::bigint n,coalesce(sum(amount_sompi),0)::bigint amount
    FROM active_for_repair GROUP BY covenant_id
), latest AS (
    SELECT DISTINCT ON (u.covenant_id)
        u.covenant_id,u.txid,u.vout,u.address,u.created_block,
        coalesce(b.blue_score,0)::bigint blue_score
    FROM active_for_repair u LEFT JOIN public.blocks b ON b.hash=u.created_block
    ORDER BY u.covenant_id,coalesce(b.blue_score,0) DESC,u.txid DESC,u.vout DESC
)
INSERT INTO public.covenant_summaries (
    covenant_id,current_address,active_utxos,total_amount_sompi,
    latest_active_txid,latest_active_vout,latest_active_block,
    latest_active_blue_score,updated_at_ms
)
SELECT c.covenant_id,coalesce(l.address,c.address),
       coalesce(tot.n,0),coalesce(tot.amount,0),
       l.txid,l.vout,l.created_block,l.blue_score,
       (extract(epoch from now())*1000)::bigint
FROM repair_needed a JOIN public.covenants c USING (covenant_id)
LEFT JOIN totals tot USING (covenant_id)
LEFT JOIN latest l USING (covenant_id)
ON CONFLICT (covenant_id) DO UPDATE SET
    current_address=EXCLUDED.current_address,
    active_utxos=EXCLUDED.active_utxos,
    total_amount_sompi=EXCLUDED.total_amount_sompi,
    latest_active_txid=EXCLUDED.latest_active_txid,
    latest_active_vout=EXCLUDED.latest_active_vout,
    latest_active_block=EXCLUDED.latest_active_block,
    latest_active_blue_score=EXCLUDED.latest_active_blue_score,
    updated_at_ms=EXCLUDED.updated_at_ms;

WITH affected AS MATERIALIZED (
            SELECT txid,vout,spent_by_txid,spent_block FROM public.covenant_utxos
            WHERE spent_block=ANY(t.old_hashes::bytea[])
        ), mapped AS MATERIALIZED (
            SELECT a.txid,a.vout,a.spent_by_txid,a.spent_block,m.target target
            FROM affected a JOIN pg_temp.historical_transition_mapping m
            ON a.spent_block=m.old AND a.spent_by_txid=m.txid
        )
        UPDATE public.covenant_utxos u SET spent_block=m.target FROM mapped m
        WHERE u.txid=m.txid AND u.vout=m.vout
          AND u.spent_block=m.spent_block AND u.spent_by_txid=m.spent_by_txid;
GET DIAGNOSTICS n=ROW_COUNT;n_spent:=n;IF n IS DISTINCT FROM t.expected_spent THEN RAISE EXCEPTION 'historical acceptance reference count changed for spent';END IF;

WITH affected AS MATERIALIZED (
            SELECT id,txid,block_hash FROM public.covenant_actions WHERE block_hash=ANY(t.old_hashes::bytea[])
        ), mapped AS MATERIALIZED (
            SELECT a.id,a.txid,a.block_hash,m.target target,m.time
            FROM affected a JOIN pg_temp.historical_transition_mapping m
            ON a.block_hash=m.old AND a.txid=m.txid
        )
        UPDATE public.covenant_actions a SET block_hash=m.target,block_time_ms=m.time FROM mapped m
        WHERE a.id=m.id AND a.block_hash=m.block_hash AND a.txid=m.txid;
GET DIAGNOSTICS n=ROW_COUNT;n_actions:=n;IF n IS DISTINCT FROM t.expected_actions THEN RAISE EXCEPTION 'historical acceptance reference count changed for actions';END IF;

WITH affected AS MATERIALIZED (
            SELECT covenant_id,genesis_txid,genesis_block FROM public.covenants
            WHERE genesis_block=ANY(t.old_hashes::bytea[])
        ), mapped AS MATERIALIZED (
            SELECT c.covenant_id,c.genesis_txid,c.genesis_block,m.target target,m.time
            FROM affected c JOIN pg_temp.historical_transition_mapping m
            ON c.genesis_block=m.old AND c.genesis_txid=m.txid
        )
        UPDATE public.covenants c SET genesis_block=m.target,created_at_ms=m.time FROM mapped m
        WHERE c.covenant_id=m.covenant_id
          AND c.genesis_block=m.genesis_block AND c.genesis_txid=m.genesis_txid;
GET DIAGNOSTICS n=ROW_COUNT;n_genesis:=n;IF n IS DISTINCT FROM t.expected_genesis THEN RAISE EXCEPTION 'historical acceptance reference count changed for genesis';END IF;

SELECT check_result INTO bad FROM (SELECT EXISTS(SELECT 1 FROM public.covenant_utxos WHERE created_block=ANY(t.old_hashes::bytea[]))
        OR EXISTS(SELECT 1 FROM public.covenant_utxos WHERE spent_block=ANY(t.old_hashes::bytea[]))
        OR EXISTS(SELECT 1 FROM public.covenant_actions WHERE block_hash=ANY(t.old_hashes::bytea[]))
        OR EXISTS(SELECT 1 FROM public.covenants WHERE genesis_block=ANY(t.old_hashes::bytea[]))) checked(check_result);
IF bad IS DISTINCT FROM FALSE THEN RAISE EXCEPTION 'historical acceptance left stale old references'; END IF;

INSERT INTO public.rest_replay_removed_blocks(block_hash,revision,removed_at_ms)
SELECT h,nextval('public.rest_replay_removal_revision'),(extract(epoch from clock_timestamp())*1000)::bigint
FROM (SELECT DISTINCT h FROM unnest(t.old_hashes::bytea[]) h) hashes
ON CONFLICT(block_hash) DO UPDATE SET revision=EXCLUDED.revision,removed_at_ms=EXCLUDED.removed_at_ms;
UPDATE public.blocks SET is_chain_block=FALSE WHERE hash=ANY(t.old_hashes);
IF n_genesis>0 THEN
WITH affected AS (SELECT DISTINCT COALESCE(c.template_name,c.claimed_template,'Unknown') template
            FROM public.covenants c WHERE c.genesis_txid=ANY(t.ids))
            UPDATE public.covenant_template_summaries s SET latest_created_at_ms=(SELECT c.created_at_ms FROM public.covenants c
                WHERE COALESCE(c.template_name,c.claimed_template,'Unknown')=s.template ORDER BY c.created_at_ms DESC,c.covenant_id DESC LIMIT 1),
                updated_at_ms=(extract(epoch from now())*1000)::bigint FROM affected WHERE s.template=affected.template;
END IF;


        WITH commit_barrier AS MATERIALIZED (
            SELECT pg_advisory_xact_lock_shared(
                hashtextextended('tn12:kcc20_projection_dirty_commit_barrier', 0)
            )
        ), inserted AS (
            INSERT INTO public.kcc20_projection_dirty (reason, txid, created_at_ms)
            SELECT 'historical_acceptance_map', pending.txid, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
            FROM (
                SELECT DISTINCT txid
                FROM UNNEST(t.ids::BYTEA[]) AS input(txid)
            ) AS pending
            CROSS JOIN commit_barrier
            RETURNING id
        )
        SELECT MAX(id)::BIGINT, pg_notify('kcc20_projection_dirty', MAX(id)::TEXT)
        INTO dirty_result FROM inserted
        ;

INSERT INTO public.historical_acceptance_map_sources(old_hash,proof_hash) SELECT h,t.proof FROM unnest(t.old_hashes) h;
GET DIAGNOSTICS n=ROW_COUNT;IF n<>cardinality(t.old_hashes) THEN RAISE EXCEPTION 'reference count mismatch: sources';END IF;

INSERT INTO public.historical_acceptance_map_entries(proof_hash,old_hash,txid,target_hash,target_score,target_time_ms)
        SELECT t.proof,old,txid,target,score,time FROM pg_temp.historical_transition_mapping m;
GET DIAGNOSTICS n=ROW_COUNT;IF n<>cardinality(t.ids) THEN RAISE EXCEPTION 'reference count mismatch: entries';END IF;

INSERT INTO public.historical_acceptance_maps(proof_hash,source_tip,window_start,window_end,cohort_digest,window_digest,evidence,window_evidence,cohort_evidence)
        VALUES(t.proof,t.source_tip,t.window_start,t.window_end,t.cohort_digest,t.window_digest,t.audit,t.window_evidence,t.cohort_evidence);
GET DIAGNOSTICS n=ROW_COUNT;IF n<>1 THEN RAISE EXCEPTION 'reference count mismatch: parent';END IF;

INSERT INTO pg_temp.historical_transition_result VALUES(t.proof,n_created,n_spent,n_actions,n_genesis);
END $transition$;
SELECT proof,created,spent,actions,genesis FROM pg_temp.historical_transition_result;

DO $transition$ DECLARE t record; dirty_result record; reason text; bad boolean; n bigint; n_created bigint; n_spent bigint; n_actions bigint; n_genesis bigint; affected_covenants bytea[]; fast_covenants bytea[]; BEGIN SELECT * INTO STRICT t FROM pg_temp.historical_transition_input;
SELECT check_result INTO bad FROM (SELECT EXISTS(SELECT 1 FROM public.historical_acceptance_maps WHERE proof_hash=t.proof)) checked(check_result);
IF bad IS DISTINCT FROM FALSE THEN RAISE EXCEPTION 'guard failed: unapplied'; END IF;

SELECT check_result INTO bad FROM (SELECT EXISTS(SELECT 1 FROM public.historical_acceptance_map_sources WHERE old_hash=ANY(t.old_hashes))) checked(check_result);
IF bad IS DISTINCT FROM FALSE THEN RAISE EXCEPTION 'historical acceptance source already has an immutable map'; END IF;

SELECT r.reason INTO reason FROM (
            SELECT 'removed source block'::text FROM public.historical_acceptance_map_sources
                WHERE old_hash=ANY(t.target_hashes::bytea[])
            UNION ALL
            SELECT 'canonical target lost'::text FROM public.historical_acceptance_map_entries e
                JOIN public.historical_acceptance_maps m ON m.proof_hash=e.proof_hash
                WHERE e.txid=ANY(t.ids::bytea[]) AND m.status='target_lost'
            LIMIT 1
        ) r(reason);
IF reason IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='P0H01',MESSAGE=reason; END IF;

SELECT check_result INTO bad FROM (SELECT EXISTS(SELECT 1 FROM public.canonical_block_replacements WHERE old_hash=ANY(t.target_hashes))) checked(check_result);
IF bad IS DISTINCT FROM FALSE THEN RAISE EXCEPTION 'historical acceptance target has been replaced'; END IF;

SELECT check_result INTO bad FROM (WITH expected_input AS (SELECT t.old_hashes old_hashes,t.comparison comparison),

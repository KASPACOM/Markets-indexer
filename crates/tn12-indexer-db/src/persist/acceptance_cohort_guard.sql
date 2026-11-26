created AS MATERIALIZED (
            SELECT * FROM public.covenant_utxos WHERE created_block=ANY((SELECT old_hashes FROM expected_input)::bytea[]) ORDER BY txid,vout LIMIT 8193 FOR UPDATE
        ), spent AS MATERIALIZED (
            SELECT * FROM public.covenant_utxos WHERE spent_block=ANY((SELECT old_hashes FROM expected_input)::bytea[]) ORDER BY txid,vout LIMIT 8193 FOR UPDATE
        ), actions AS MATERIALIZED (
            SELECT * FROM public.covenant_actions WHERE block_hash=ANY((SELECT old_hashes FROM expected_input)::bytea[]) ORDER BY id LIMIT 8193 FOR UPDATE
        ), genesis AS MATERIALIZED (
            SELECT * FROM public.covenants WHERE genesis_block=ANY((SELECT old_hashes FROM expected_input)::bytea[]) ORDER BY covenant_id LIMIT 8193 FOR UPDATE
        ), actual AS MATERIALIZED (
            SELECT 'created'::text COLLATE "C" kind,to_jsonb(s)::text COLLATE "C" data FROM created s
            UNION ALL SELECT 'spent',to_jsonb(s)::text FROM spent s
            UNION ALL SELECT 'action',to_jsonb(s)::text FROM actions s
            UNION ALL SELECT 'genesis',to_jsonb(s)::text FROM genesis s
        ), expected AS MATERIALIZED (
            SELECT kind COLLATE "C",data COLLATE "C" FROM jsonb_to_recordset((SELECT comparison FROM expected_input)) e(kind text,data text)
        ), bounds AS (
            SELECT count(*) rows,COALESCE(sum(octet_length(data)),0) bytes FROM actual
        ) SELECT CASE WHEN bounds.rows BETWEEN 1 AND 8192 AND bounds.bytes<=16777216
            THEN NOT EXISTS (SELECT 1 FROM (
                (SELECT * FROM actual EXCEPT ALL SELECT * FROM expected)
                UNION ALL (SELECT * FROM expected EXCEPT ALL SELECT * FROM actual)
            ) mismatch) ELSE FALSE END FROM bounds

-- Reorg repair previously joined every active UTXO to its block to find the
-- latest output. Check a bounded set of newest blocks first, including all
-- boundary score ties; retain the full lookup when the covenant is older.
-- The array predicate lets PostgreSQL restrict created_block in one scan,
-- avoiding a repeated covenant/status bitmap for each recent block.
-- Existing indexes suffice. This replaces the function without a table rebuild.

CREATE OR REPLACE FUNCTION refresh_covenant_summary(target_covenant_id BYTEA)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF target_covenant_id IS NULL THEN
        RETURN;
    END IF;

    INSERT INTO covenant_summaries (
        covenant_id,
        current_address,
        active_utxos,
        total_amount_sompi,
        latest_active_txid,
        latest_active_vout,
        latest_active_block,
        latest_active_blue_score,
        updated_at_ms
    )
    WITH recent_blocks AS MATERIALIZED (
        SELECT hash, blue_score
        FROM blocks
        ORDER BY blue_score DESC
        FETCH FIRST 64 ROWS WITH TIES
    ), recent_active AS MATERIALIZED (
        SELECT u.txid, u.vout, u.address, u.created_block, b.blue_score
        FROM covenant_utxos u
        JOIN recent_blocks b ON b.hash = u.created_block
        WHERE u.covenant_id = target_covenant_id
          AND u.status = 'active'
          AND u.created_block = ANY(ARRAY(SELECT hash FROM recent_blocks))
        ORDER BY b.blue_score DESC, u.txid DESC, u.vout DESC
        LIMIT 1
    )
    SELECT
        c.covenant_id,
        COALESCE(active_current.address, c.address) AS current_address,
        COALESCE(active_stats.active_utxos, 0)::BIGINT AS active_utxos,
        COALESCE(active_stats.total_amount_sompi, 0)::BIGINT AS total_amount_sompi,
        active_current.txid,
        active_current.vout,
        active_current.created_block,
        active_current.blue_score,
        EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 AS updated_at_ms
    FROM covenants c
    LEFT JOIN LATERAL (
        SELECT
            COUNT(*)::BIGINT AS active_utxos,
            COALESCE(SUM(u.amount_sompi), 0)::BIGINT AS total_amount_sompi
        FROM covenant_utxos u
        WHERE u.covenant_id = c.covenant_id
          AND u.status = 'active'
    ) active_stats ON TRUE
    LEFT JOIN LATERAL (
        SELECT * FROM recent_active
        UNION ALL
        SELECT * FROM (
            SELECT
                u.txid,
                u.vout,
                u.address,
                u.created_block,
                COALESCE(b.blue_score, 0)::BIGINT AS blue_score
            FROM covenant_utxos u
            LEFT JOIN blocks b ON b.hash = u.created_block
            WHERE u.covenant_id = c.covenant_id
              AND u.status = 'active'
              AND NOT EXISTS (SELECT 1 FROM recent_active)
            ORDER BY COALESCE(b.blue_score, 0) DESC, u.txid DESC, u.vout DESC
            LIMIT 1
        ) fallback
    ) active_current ON TRUE
    WHERE c.covenant_id = target_covenant_id
    ON CONFLICT (covenant_id) DO UPDATE SET
        current_address = EXCLUDED.current_address,
        active_utxos = EXCLUDED.active_utxos,
        total_amount_sompi = EXCLUDED.total_amount_sompi,
        latest_active_txid = EXCLUDED.latest_active_txid,
        latest_active_vout = EXCLUDED.latest_active_vout,
        latest_active_block = EXCLUDED.latest_active_block,
        latest_active_blue_score = EXCLUDED.latest_active_blue_score,
        updated_at_ms = EXCLUDED.updated_at_ms;

    IF NOT FOUND THEN
        DELETE FROM covenant_summaries WHERE covenant_id = target_covenant_id;
    END IF;
END;
$$;

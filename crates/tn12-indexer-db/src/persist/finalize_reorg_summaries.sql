-- Repair only covenants touched by this removal. Materializing their active
-- outputs through a keyed lookup avoids scanning the entire active UTXO set
-- when a dense block affects many otherwise small covenants.
WITH repair AS MATERIALIZED (
    SELECT DISTINCT a.covenant_id
    FROM unnest($1::bytea[]) AS a(covenant_id)
), removed AS (
    DELETE FROM covenant_summaries s USING repair r
    WHERE s.covenant_id=r.covenant_id
      AND NOT EXISTS (SELECT 1 FROM covenants c WHERE c.covenant_id=r.covenant_id)
), active_for_repair AS MATERIALIZED (
    SELECT u.covenant_id,u.txid,u.vout,u.address,u.created_block,u.amount_sompi
    FROM repair r CROSS JOIN LATERAL (
        SELECT covenant_id,txid,vout,address,created_block,amount_sompi
        FROM covenant_utxos
        WHERE covenant_id=r.covenant_id AND status='active'
        OFFSET 0
    ) u
), totals AS (
    SELECT covenant_id,count(*)::bigint AS n,
           coalesce(sum(amount_sompi),0)::bigint AS amount
    FROM active_for_repair GROUP BY covenant_id
), latest AS (
    SELECT DISTINCT ON (u.covenant_id)
        u.covenant_id,u.txid,u.vout,u.address,u.created_block,
        coalesce(b.blue_score,0)::bigint AS blue_score
    FROM active_for_repair u LEFT JOIN blocks b ON b.hash=u.created_block
    ORDER BY u.covenant_id,coalesce(b.blue_score,0) DESC,u.txid DESC,u.vout DESC
)
INSERT INTO covenant_summaries (
    covenant_id,current_address,active_utxos,total_amount_sompi,
    latest_active_txid,latest_active_vout,latest_active_block,
    latest_active_blue_score,updated_at_ms
)
SELECT c.covenant_id,coalesce(latest.address,c.address),
       coalesce(totals.n,0),coalesce(totals.amount,0),
       latest.txid,latest.vout,latest.created_block,latest.blue_score,
       EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
FROM repair r JOIN covenants c USING (covenant_id)
LEFT JOIN totals USING (covenant_id)
LEFT JOIN latest USING (covenant_id)
ON CONFLICT (covenant_id) DO UPDATE SET
    current_address=EXCLUDED.current_address,
    active_utxos=EXCLUDED.active_utxos,
    total_amount_sompi=EXCLUDED.total_amount_sompi,
    latest_active_txid=EXCLUDED.latest_active_txid,
    latest_active_vout=EXCLUDED.latest_active_vout,
    latest_active_block=EXCLUDED.latest_active_block,
    latest_active_blue_score=EXCLUDED.latest_active_blue_score,
    updated_at_ms=EXCLUDED.updated_at_ms;

-- Bound the affected set to this staged transaction page. The same baseline
-- validity rules as removal's delta path apply before any output is mutated.
WITH affected AS MATERIALIZED (
    SELECT DISTINCT covenant_id FROM covenant_utxos
    WHERE covenant_id IS NOT NULL AND
        ((created_block=$1 AND txid=ANY($2::bytea[])) OR
         (spent_block=$1 AND spent_by_txid=ANY($2::bytea[])))
)
SELECT a.covenant_id FROM affected a
LEFT JOIN covenant_summaries s USING(covenant_id)
LEFT JOIN covenant_utxos u ON u.txid=s.latest_active_txid AND u.vout=s.latest_active_vout
LEFT JOIN blocks b ON b.hash=u.created_block
WHERE s.covenant_id IS NULL OR s.active_utxos<0 OR s.total_amount_sompi<0
    OR (s.active_utxos>0 AND (u.txid IS NULL OR u.status<>'active' OR
        ROW(u.covenant_id,u.address,u.created_block,b.blue_score) IS DISTINCT FROM
        ROW(s.covenant_id,s.current_address,s.latest_active_block,s.latest_active_blue_score)))
    OR (s.active_utxos=0 AND (s.latest_active_txid IS NOT NULL OR s.total_amount_sompi<>0))
    OR (s.active_utxos=0 AND EXISTS(SELECT 1 FROM covenant_active_output_order o WHERE o.covenant_id=a.covenant_id))
ORDER BY a.covenant_id LIMIT 1;

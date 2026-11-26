-- Apply the active-set delta captured under the reorg writer lock.
-- Missing baselines are rebuilt separately after the mutations.
WITH changes AS MATERIALIZED (
    SELECT decode(cid,'hex') AS covenant_id, count_delta, amount_delta,
           decode(txid,'hex') AS txid, vout, address, decode(block,'hex') AS created_block
    FROM jsonb_to_recordset($1::jsonb) AS r(
        cid TEXT, count_delta BIGINT, amount_delta BIGINT, txid TEXT,
        vout INT, address TEXT, block TEXT)
), deltas AS (
    SELECT covenant_id, sum(count_delta)::bigint AS n, sum(amount_delta) AS amount
    FROM changes WHERE NOT covenant_id=ANY($2::bytea[]) GROUP BY covenant_id
), added AS MATERIALIZED (
    SELECT DISTINCT ON (c.covenant_id) c.covenant_id,c.txid,c.vout,c.address,
           c.created_block,coalesce(b.blue_score,0)::bigint AS blue_score
    FROM changes c LEFT JOIN blocks b ON b.hash=c.created_block
    WHERE c.count_delta=1
    ORDER BY c.covenant_id,coalesce(b.blue_score,0) DESC,c.txid DESC,c.vout DESC
), prior AS MATERIALIZED (
    SELECT s.*,d.n,d.amount,c.address AS genesis_address,
           coalesce(pointer.matches AND pointer.status='active',false) AS old_active,
           coalesce(pointer.matches,false) AS old_pointer_matches
    FROM deltas d JOIN covenant_summaries s USING(covenant_id)
    JOIN covenants c USING(covenant_id)
    LEFT JOIN LATERAL (
        SELECT u.status, ROW(u.address,u.created_block,coalesce(b.blue_score,0))
                   IS NOT DISTINCT FROM ROW(s.current_address,s.latest_active_block,s.latest_active_blue_score) AS matches
        FROM covenant_utxos u LEFT JOIN blocks b ON b.hash=u.created_block
        WHERE u.txid=s.latest_active_txid AND u.vout=s.latest_active_vout
          AND u.covenant_id=s.covenant_id
    ) pointer ON true
), needs_latest AS MATERIALIZED (
    SELECT p.covenant_id
    FROM prior p LEFT JOIN added a USING(covenant_id)
    WHERE NOT p.old_active AND p.active_utxos+p.n>0
      AND (NOT p.old_pointer_matches OR a.txid IS NULL OR p.latest_active_txid IS NULL OR
           ROW(a.blue_score,a.txid,a.vout)<ROW(p.latest_active_blue_score,p.latest_active_txid,p.latest_active_vout))
), recent_blocks AS MATERIALIZED (
    SELECT hash,blue_score FROM blocks ORDER BY blue_score DESC
    FETCH FIRST 64 ROWS WITH TIES
), recent_outputs AS MATERIALIZED (
    -- Materialize block-selected rows before filtering by covenant. Otherwise
    -- a bitmap AND can read a million-entry covenant index for a tiny window.
    SELECT u.txid,u.vout,u.address,u.created_block,u.covenant_id,b.blue_score
    FROM covenant_utxos u JOIN recent_blocks b ON b.hash=u.created_block
    WHERE u.status='active' AND EXISTS(SELECT 1 FROM needs_latest)
      AND u.created_block=ANY(ARRAY(SELECT hash FROM recent_blocks))
), recent_latest AS MATERIALIZED (
    -- Join and rank once for the affected set, not once per covenant.
    SELECT DISTINCT ON(u.covenant_id) u.*
    FROM recent_outputs u JOIN needs_latest n USING(covenant_id)
    ORDER BY u.covenant_id,u.blue_score DESC,u.txid DESC,u.vout DESC
), candidates AS (
    SELECT covenant_id,latest_active_txid AS txid,latest_active_vout AS vout,
           current_address AS address,latest_active_block AS created_block,
           latest_active_blue_score AS blue_score FROM prior WHERE old_active
    UNION ALL
    SELECT covenant_id,txid,vout,address,created_block,blue_score FROM added
    UNION ALL
    SELECT covenant_id,txid,vout,address,created_block,blue_score FROM recent_latest
    UNION ALL
    -- Older families without a recent output require the complete lookup;
    -- counts and amounts still come only from the captured delta.
    SELECT n.covenant_id,u.txid,u.vout,u.address,u.created_block,u.blue_score
    FROM needs_latest n LEFT JOIN recent_latest r USING(covenant_id)
    CROSS JOIN LATERAL (
        SELECT u.txid,u.vout,u.address,u.created_block,u.blue_score
        FROM latest_active_covenant_output(n.covenant_id) u
        WHERE r.txid IS NULL
    ) u
), latest AS (
    SELECT DISTINCT ON(covenant_id) * FROM candidates
    ORDER BY covenant_id,blue_score DESC,txid DESC,vout DESC
)
UPDATE covenant_summaries s SET
    active_utxos=p.active_utxos+p.n, total_amount_sompi=p.total_amount_sompi+p.amount,
    current_address=coalesce(l.address,p.genesis_address),
    latest_active_txid=l.txid,latest_active_vout=l.vout,latest_active_block=l.created_block,
    latest_active_blue_score=l.blue_score,updated_at_ms=EXTRACT(EPOCH FROM NOW())::BIGINT*1000
FROM prior p LEFT JOIN latest l USING(covenant_id)
WHERE s.covenant_id=p.covenant_id AND p.active_utxos+p.n>=0 AND p.total_amount_sompi+p.amount>=0
  AND ((p.active_utxos+p.n=0 AND l.txid IS NULL) OR (p.active_utxos+p.n>0 AND l.txid IS NOT NULL));

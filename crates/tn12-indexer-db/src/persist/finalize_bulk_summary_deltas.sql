-- Input contains only rows changed by this independent batch, never attempted
-- inserts or already-spent inputs. Older replay retains a newer active pointer.
WITH changes AS MATERIALIZED (
    SELECT decode(cid,'hex') AS covenant_id, count_delta, amount_delta,
           decode(txid,'hex') AS txid, vout, address, decode(block,'hex') AS created_block
    FROM jsonb_to_recordset($1::jsonb) AS r(
        cid TEXT, count_delta BIGINT, amount_delta BIGINT, txid TEXT,
        vout INT, address TEXT, block TEXT)
), deltas AS (
    SELECT covenant_id, sum(count_delta)::bigint AS n, sum(amount_delta) AS amount
    FROM changes GROUP BY covenant_id
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
), candidates AS (
    SELECT covenant_id,latest_active_txid AS txid,latest_active_vout AS vout,
           current_address AS address,latest_active_block AS created_block,
           latest_active_blue_score AS blue_score FROM prior WHERE old_active
    UNION ALL
    SELECT covenant_id,txid,vout,address,created_block,blue_score FROM added
    UNION ALL
    -- Scan remaining active outputs only when the old maximum was spent and
    -- the new output cannot prove it beats every previously active output.
    SELECT p.covenant_id,u.txid,u.vout,u.address,u.created_block,u.blue_score
    FROM prior p LEFT JOIN added a USING(covenant_id)
    CROSS JOIN LATERAL (
        SELECT u.txid,u.vout,u.address,u.created_block,coalesce(b.blue_score,0)::bigint AS blue_score
        FROM covenant_utxos u LEFT JOIN blocks b ON b.hash=u.created_block
        WHERE u.covenant_id=p.covenant_id AND u.status='active'
          AND NOT p.old_active AND p.active_utxos+p.n>0
          AND (NOT p.old_pointer_matches OR a.txid IS NULL OR p.latest_active_txid IS NULL OR
               ROW(a.blue_score,a.txid,a.vout) <
               ROW(p.latest_active_blue_score,p.latest_active_txid,p.latest_active_vout))
        ORDER BY coalesce(b.blue_score,0) DESC,u.txid DESC,u.vout DESC LIMIT 1
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

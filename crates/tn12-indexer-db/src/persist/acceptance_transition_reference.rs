// Test-only pre-batch implementation for snapshot parity.
use super::*;
pub(in crate::persist) async fn transition_reference(
    conn: &mut Transaction<'_, Postgres>,
    proof: &HistoricalAcceptanceMapProof,
    prepared: &PreparedTransition,
    deadline: impl Into<Option<Instant>>,
) -> Result<AcceptanceReconciliationStats> {
    let deadline = deadline.into();
    macro_rules! query {
        ($query:expr) => {{
            remaining_budget(conn, deadline).await?;
            $query.await?
        }};
    }
    let old = proof.cohort.old_hashes();
    let PreparedTransition {
        ids,
        target_hashes,
        mapping,
        block_evidence,
        inputs,
        acceptance_blocks,
        audit,
    } = prepared;
    let recorded:bool=query!(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM historical_acceptance_map_sources WHERE old_hash=ANY($1::bytea[]))")
        .bind(old).fetch_one(&mut **conn));
    // Committing/idempotent entry points must classify an existing ledger before
    // reaching this transition; only unapplied proofs reach the writes below.
    ensure!(
        !recorded,
        "historical acceptance source already has an immutable map"
    );
    query!(PgPersister::check_historical_acceptance_map_guards(
        conn,
        &ids,
        &target_hashes
    ));
    let removed_target: bool = query!(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM canonical_block_replacements WHERE old_hash=ANY($1::bytea[]))"
    )
    .bind(&target_hashes)
    .fetch_one(&mut **conn));
    ensure!(
        !removed_target,
        "historical acceptance target has been replaced"
    );
    verify_cohort(conn, &proof.cohort, deadline).await?;
    let bad_blocks:bool=query!(sqlx::query_scalar(r#"SELECT EXISTS(SELECT 1 FROM jsonb_to_recordset($1::jsonb) e(hash text,score bigint,time bigint,canonical bool)
        LEFT JOIN blocks b ON b.hash=decode(e.hash,'hex')
        WHERE (NOT e.canonical AND b.hash IS NULL) OR (b.hash IS NOT NULL AND
            (b.blue_score<>e.score OR b.timestamp_ms<>e.time OR (e.canonical AND NOT b.is_chain_block))))"#)
        .bind(&block_evidence).fetch_one(&mut **conn));
    ensure!(
        !bad_blocks,
        "stored block metadata conflicts with historical acceptance proof"
    );
    let third_block:bool=query!(sqlx::query_scalar(r#"WITH m AS (SELECT decode(old,'hex') old,decode(txid,'hex') txid,decode(target,'hex') target FROM jsonb_to_recordset($1::jsonb) m(old text,txid text,target text))
        SELECT EXISTS(SELECT 1 FROM m JOIN covenant_utxos u ON u.txid=m.txid WHERE u.created_block<>m.old AND u.created_block<>m.target)
        OR EXISTS(SELECT 1 FROM m JOIN covenant_actions a ON a.txid=m.txid WHERE a.block_hash<>m.old AND a.block_hash<>m.target)
        OR EXISTS(SELECT 1 FROM m JOIN covenants c ON c.genesis_txid=m.txid WHERE c.genesis_block<>m.old AND c.genesis_block<>m.target)"#)
        .bind(&mapping).fetch_one(&mut **conn));
    ensure!(
        !third_block,
        "historical acceptance transaction references a third block"
    );
    // The preceding third-block check rejects mapped actions outside these
    // blocks. Bound the spend-action scan by their block index before joining
    // the transaction map; probing every txid on the full history is costly
    // on a cold database. Keep both old and target blocks in the check.
    let bad_inputs:bool=query!(sqlx::query_scalar(r#"WITH m AS (SELECT decode(old,'hex') old,decode(txid,'hex') txid,decode(target,'hex') target FROM jsonb_to_recordset($1::jsonb) m(old text,txid text,target text)),
        i AS (SELECT decode(txid,'hex') txid,decode(prev,'hex') prev,vout,amount,decode(script,'hex') script FROM jsonb_to_recordset($2::jsonb) i(txid text,prev text,vout int,amount bigint,script text)),
        mi AS MATERIALIZED (SELECT i.*, m.old, m.target FROM i JOIN m USING(txid))
        SELECT EXISTS(SELECT 1 FROM mi i JOIN covenant_utxos u ON u.txid=i.prev AND u.vout=i.vout
            WHERE u.amount_sompi IS DISTINCT FROM i.amount OR u.script_pubkey IS DISTINCT FROM i.script
            OR ((u.status='active' AND u.spent_by_txid IS NULL AND u.spent_block IS NULL)
                OR (u.status='spent' AND u.spent_by_txid=i.txid AND u.spent_block IN(i.old,i.target))) IS NOT TRUE)
        OR EXISTS(SELECT 1 FROM m
            JOIN (SELECT * FROM covenant_actions WHERE block_hash=ANY($3::bytea[]) AND action='spend' OFFSET 0) a ON a.txid=m.txid
            LEFT JOIN i ON i.txid=a.txid AND i.prev=decode(a.inputs#>>'{previousOutpoint,hash}','hex') AND i.vout=(a.inputs#>>'{previousOutpoint,index}')::int
            LEFT JOIN covenant_utxos u ON u.txid=i.prev AND u.vout=i.vout
            WHERE a.action='spend' AND (i.txid IS NULL OR u.txid IS NULL OR u.status<>'spent'
                OR u.spent_by_txid IS DISTINCT FROM a.txid OR u.spent_block IS NULL OR u.spent_block NOT IN(m.old,m.target)))"#)
        .bind(&mapping).bind(&inputs).bind(&acceptance_blocks).fetch_one(&mut **conn));
    ensure!(
        !bad_inputs,
        "historical acceptance input has contradictory persisted spend evidence"
    );
    query!(sqlx::query(r#"INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms)
        SELECT DISTINCT decode(target,'hex'),score,0,ARRAY[]::bytea[],time,TRUE,(extract(epoch from now())*1000)::bigint
        FROM jsonb_to_recordset($1::jsonb) m(target text,score bigint,time bigint) ON CONFLICT(hash) DO NOTHING"#)
        .bind(&mapping).execute(&mut **conn));
    let mut stats = AcceptanceReconciliationStats::default();
    stats.created_outputs = query!(sqlx::query(
        r#"UPDATE covenant_utxos u SET created_block=decode(m.target,'hex')
        FROM jsonb_to_recordset($1::jsonb) m(old text,txid text,target text)
        WHERE u.created_block=decode(m.old,'hex') AND u.txid=decode(m.txid,'hex')"#
    )
    .bind(&mapping)
    .execute(&mut **conn))
    .rows_affected();
    stats.spent_inputs = query!(sqlx::query(
        // Materialize the affected old-block rows once. Otherwise Postgres can
        // scan the same spent-block index for every mapped transaction, even
        // when only two of hundreds of transactions have persisted inputs.
        r#"WITH affected AS MATERIALIZED (
            SELECT txid,vout,spent_by_txid,spent_block FROM covenant_utxos
            WHERE spent_block=ANY($2::bytea[])
        ), mapped AS MATERIALIZED (
            SELECT a.txid,a.vout,a.spent_by_txid,a.spent_block,decode(m.target,'hex') target
            FROM affected a JOIN jsonb_to_recordset($1::jsonb) m(old text,txid text,target text)
            ON a.spent_block=decode(m.old,'hex') AND a.spent_by_txid=decode(m.txid,'hex')
        )
        UPDATE covenant_utxos u SET spent_block=m.target FROM mapped m
        WHERE u.txid=m.txid AND u.vout=m.vout
          AND u.spent_block=m.spent_block AND u.spent_by_txid=m.spent_by_txid"#
    )
    .bind(&mapping)
    .bind(old)
    .execute(&mut **conn))
    .rows_affected();
    stats.actions = query!(sqlx::query(
        r#"WITH affected AS MATERIALIZED (
            SELECT id,txid,block_hash FROM covenant_actions WHERE block_hash=ANY($2::bytea[])
        ), mapped AS MATERIALIZED (
            SELECT a.id,a.txid,a.block_hash,decode(m.target,'hex') target,m.time
            FROM affected a JOIN jsonb_to_recordset($1::jsonb) m(old text,txid text,target text,time bigint)
            ON a.block_hash=decode(m.old,'hex') AND a.txid=decode(m.txid,'hex')
        )
        UPDATE covenant_actions a SET block_hash=m.target,block_time_ms=m.time FROM mapped m
        WHERE a.id=m.id AND a.block_hash=m.block_hash AND a.txid=m.txid"#
    )
    .bind(&mapping)
    .bind(old)
    .execute(&mut **conn))
    .rows_affected();
    stats.covenants = query!(sqlx::query(
        r#"WITH affected AS MATERIALIZED (
            SELECT covenant_id,genesis_txid,genesis_block FROM covenants
            WHERE genesis_block=ANY($2::bytea[])
        ), mapped AS MATERIALIZED (
            SELECT c.covenant_id,c.genesis_txid,c.genesis_block,decode(m.target,'hex') target,m.time
            FROM affected c JOIN jsonb_to_recordset($1::jsonb) m(old text,txid text,target text,time bigint)
            ON c.genesis_block=decode(m.old,'hex') AND c.genesis_txid=decode(m.txid,'hex')
        )
        UPDATE covenants c SET genesis_block=m.target,created_at_ms=m.time FROM mapped m
        WHERE c.covenant_id=m.covenant_id
          AND c.genesis_block=m.genesis_block AND c.genesis_txid=m.genesis_txid"#
    )
    .bind(&mapping)
    .bind(old)
    .execute(&mut **conn))
    .rows_affected();
    for (kind, count) in [
        ("created", stats.created_outputs),
        ("spent", stats.spent_inputs),
        ("action", stats.actions),
        ("genesis", stats.covenants),
    ] {
        ensure!(
            count
                == proof
                    .cohort
                    .references
                    .iter()
                    .filter(|r| r.kind == kind)
                    .count() as u64,
            "historical acceptance reference count changed for {kind}"
        );
    }
    let stale: bool = query!(sqlx::query_scalar(
        r#"SELECT EXISTS(SELECT 1 FROM covenant_utxos WHERE created_block=ANY($1::bytea[]))
        OR EXISTS(SELECT 1 FROM covenant_utxos WHERE spent_block=ANY($1::bytea[]))
        OR EXISTS(SELECT 1 FROM covenant_actions WHERE block_hash=ANY($1::bytea[]))
        OR EXISTS(SELECT 1 FROM covenants WHERE genesis_block=ANY($1::bytea[]))"#
    )
    .bind(old)
    .fetch_one(&mut **conn));
    ensure!(!stale, "historical acceptance left stale old references");
    query!(super::PgPersister::record_rest_removals(conn, old));
    query!(
        sqlx::query("UPDATE blocks SET is_chain_block=FALSE WHERE hash=ANY($1::bytea[])")
            .bind(old)
            .execute(&mut **conn)
    );
    // Ordinary genesis triggers only increase maxima. Recompute affected
    // template maxima once, after all per-transaction genesis times have moved.
    if stats.covenants > 0 {
        query!(sqlx::query(r#"WITH affected AS (SELECT DISTINCT COALESCE(c.template_name,c.claimed_template,'Unknown') template
            FROM covenants c WHERE c.genesis_txid=ANY($1::bytea[]))
            UPDATE covenant_template_summaries s SET latest_created_at_ms=(SELECT c.created_at_ms FROM covenants c
                WHERE COALESCE(c.template_name,c.claimed_template,'Unknown')=s.template ORDER BY c.created_at_ms DESC,c.covenant_id DESC LIMIT 1),
                updated_at_ms=(extract(epoch from now())*1000)::bigint FROM affected WHERE s.template=affected.template"#).bind(&ids).execute(&mut **conn));
    }
    query!(crate::repo::mark_kcc20_projection_dirty_txids_tx(
        conn,
        "historical_acceptance_map",
        &ids
    ));
    let window = proof.source.window();
    query!(sqlx::query("INSERT INTO historical_acceptance_map_sources(old_hash,proof_hash) SELECT h,$2 FROM unnest($1::bytea[]) h")
        .bind(old).bind(proof.proof_hash().as_slice()).execute(&mut **conn));
    query!(sqlx::query(r#"INSERT INTO historical_acceptance_map_entries(proof_hash,old_hash,txid,target_hash,target_score,target_time_ms)
        SELECT $2,decode(old,'hex'),decode(txid,'hex'),decode(target,'hex'),score,time FROM jsonb_to_recordset($1::jsonb) m(old text,txid text,target text,score bigint,time bigint)"#)
        .bind(&mapping).bind(proof.proof_hash().as_slice()).execute(&mut **conn));
    // Inserting the parent last seals the complete staged ledger.
    query!(sqlx::query(r#"INSERT INTO historical_acceptance_maps(proof_hash,source_tip,window_start,window_end,cohort_digest,window_digest,evidence,window_evidence,cohort_evidence)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)"#).bind(proof.proof_hash().as_slice()).bind(window.source_tip as i64)
        .bind(window.start_score as i64).bind(window.end_score as i64).bind(proof.cohort.digest().as_slice()).bind(proof.source.window_digest().as_slice()).bind(audit).bind(proof.source.normalized_window()).bind(proof.cohort.normalized_rows()).execute(&mut **conn));
    Ok(stats)
}

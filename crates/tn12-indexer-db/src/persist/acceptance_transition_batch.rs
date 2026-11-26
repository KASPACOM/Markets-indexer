//! Immutable staging outside the writer lock; one fixed guarded SQL batch inside.
use super::{AcceptanceReconciliationStats, HistoricalAcceptanceMapProof, PreparedTransition};
use anyhow::{ensure, Context, Result};
use sqlx::{Postgres, Row, Transaction};

const KERNEL: &str = concat!(
    include_str!("acceptance_transition_before_cohort.sql"),
    include_str!("acceptance_cohort_guard.sql"),
    include_str!("acceptance_transition_after_cohort.sql")
);

pub(super) async fn stage(
    conn: &mut Transaction<'_, Postgres>,
    proof: &HistoricalAcceptanceMapProof,
    prepared: &PreparedTransition,
) -> Result<()> {
    let comparison = proof
        .cohort
        .comparison_rows
        .as_ref()
        .context("historical cohort lacks exact comparison rows")?;
    ensure!(
        (1..=8192).contains(&proof.cohort.references.len())
            && comparison.len() <= 32 * 1024 * 1024
            && proof.cohort.normalized_rows().len() <= 16 * 1024 * 1024
            && proof.source.normalized_window().len() <= 64 * 1024 * 1024,
        "historical transition staging exceeds proof bounds"
    );
    for hashes in [
        &prepared.ids,
        &prepared.target_hashes,
        &prepared.acceptance_blocks,
    ] {
        ensure!(
            hashes.iter().all(|h| h.len() == 32),
            "historical transition has invalid hash length"
        );
    }
    ensure!(
        !prepared.ids.is_empty()
            && prepared.ids.len() <= 8192
            && proof.cohort.old_hashes().iter().all(|h| h.len() == 32),
        "historical transition has invalid source or transaction bounds"
    );
    ensure!(
        (1..=8192).contains(&proof.cohort.old_hashes().len())
            && prepared.target_hashes.len() == prepared.ids.len()
            && prepared
                .ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == prepared.ids.len()
            && proof
                .cohort
                .old_hashes()
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == proof.cohort.old_hashes().len(),
        "historical transition has duplicate identities or inconsistent cardinality"
    );
    let counts: Vec<i64> = ["created", "spent", "action", "genesis"]
        .iter()
        .map(|kind| {
            proof
                .cohort
                .references
                .iter()
                .filter(|r| r.kind == *kind)
                .count() as i64
        })
        .collect();
    ensure!(
        counts.iter().sum::<i64>() == proof.cohort.references.len() as i64,
        "historical transition has unknown reference kind"
    );
    sqlx::raw_sql(include_str!("acceptance_transition_stage.sql"))
        .execute(&mut **conn)
        .await?;
    let w = proof.source.window();
    sqlx::query("INSERT INTO pg_temp.historical_transition_input(mapping,block_evidence,inputs,comparison,old_hashes,target_hashes,ids,acceptance_blocks,proof,source_tip,window_start,window_end,cohort_digest,window_digest,audit,window_evidence,cohort_evidence,expected_created,expected_spent,expected_actions,expected_genesis) VALUES($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)")
        .bind(&prepared.mapping).bind(&prepared.block_evidence).bind(&prepared.inputs)
        .bind(comparison).bind(proof.cohort.old_hashes()).bind(&prepared.target_hashes)
        .bind(&prepared.ids).bind(&prepared.acceptance_blocks).bind(proof.proof_hash().as_slice())
        .bind(w.source_tip as i64).bind(w.start_score as i64).bind(w.end_score as i64)
        .bind(proof.cohort.digest().as_slice()).bind(proof.source.window_digest().as_slice())
        .bind(&prepared.audit).bind(proof.source.normalized_window()).bind(proof.cohort.normalized_rows())
        .bind(counts[0]).bind(counts[1]).bind(counts[2]).bind(counts[3])
        .execute(&mut **conn).await?;
    let inserted=sqlx::query("INSERT INTO pg_temp.historical_transition_mapping(old,txid,target,score,time) SELECT decode(m.old,'hex'),decode(m.txid,'hex'),decode(m.target,'hex'),m.score,m.time FROM pg_temp.historical_transition_input t CROSS JOIN LATERAL jsonb_to_recordset(t.mapping) m(old text,txid text,target text,score bigint,time bigint)")
        .execute(&mut **conn).await?.rows_affected();
    ensure!(
        inserted == prepared.ids.len() as u64,
        "historical transition mapping count differs"
    );
    sqlx::query("ANALYZE pg_temp.historical_transition_mapping")
        .execute(&mut **conn)
        .await?;
    Ok(())
}

pub(super) async fn execute(
    conn: &mut Transaction<'_, Postgres>,
    proof: &HistoricalAcceptanceMapProof,
) -> Result<AcceptanceReconciliationStats> {
    // Only the final bounded SELECT emits a row. Drain the entire fixed script.
    let rows = sqlx::raw_sql(KERNEL).fetch_all(&mut **conn).await;
    let rows = match rows {
        Ok(rows) => rows,
        Err(error) => {
            if let Some(db) = error.as_database_error() {
                if db.code().as_deref() == Some("P0H01") {
                    return Err(
                        super::super::acceptance_map_lifecycle::HistoricalAcceptanceMapGuard {
                            reason: db.message().to_owned(),
                        }
                        .into(),
                    );
                }
            }
            return Err(error.into());
        }
    };
    ensure!(
        rows.len() == 1,
        "historical transition returned unexpected stats rows"
    );
    let row = &rows[0];
    ensure!(
        row.try_get::<Vec<u8>, _>("proof")? == proof.proof_hash(),
        "historical transition staged proof differs"
    );
    Ok(AcceptanceReconciliationStats {
        created_outputs: u64::try_from(row.try_get::<i64, _>("created")?)?,
        spent_inputs: u64::try_from(row.try_get::<i64, _>("spent")?)?,
        actions: u64::try_from(row.try_get::<i64, _>("actions")?)?,
        covenants: u64::try_from(row.try_get::<i64, _>("genesis")?)?,
        already_reconciled: false,
    })
}

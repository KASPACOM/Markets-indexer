//! Replay and reorg guards for immutable historical acceptance maps.
use super::PgPersister;
use anyhow::{ensure, Result};
use sqlx::{Postgres, Transaction};

#[derive(Debug, thiserror::Error)]
#[error("historical acceptance map blocks replay: {reason}")]
pub struct HistoricalAcceptanceMapGuard {
    pub reason: String,
}
impl PgPersister {
    pub(super) async fn check_historical_acceptance_map_guards(
        conn: &mut Transaction<'_, Postgres>,
        txids: &[Vec<u8>],
        incoming_hashes: &[Vec<u8>],
    ) -> Result<()> {
        let reason: Option<String> = sqlx::query_scalar(
            r#"
            SELECT 'removed source block'::text FROM historical_acceptance_map_sources
                WHERE old_hash=ANY($1::bytea[])
            UNION ALL
            SELECT 'canonical target lost'::text FROM historical_acceptance_map_entries e
                JOIN historical_acceptance_maps m ON m.proof_hash=e.proof_hash
                WHERE e.txid=ANY($2::bytea[]) AND m.status='target_lost'
            LIMIT 1
        "#,
        )
        .bind(incoming_hashes)
        .bind(txids)
        .fetch_optional(&mut **conn)
        .await?;
        if let Some(reason) = reason {
            return Err(HistoricalAcceptanceMapGuard { reason }.into());
        }
        Ok(())
    }

    /// Called under the writer lock before real reorg deletion, while aliases
    /// are still available. Reorging an already removed alias is not target loss.
    pub(super) async fn invalidate_historical_acceptance_targets(
        conn: &mut Transaction<'_, Postgres>,
        removed: &[Vec<u8>],
    ) -> Result<()> {
        let lineage: Vec<(Vec<u8>, i32, bool)> = sqlx::query_as(
            r#"
            WITH RECURSIVE ancestors(hash,path,cycle) AS (
                SELECT h,ARRAY[h]::bytea[],FALSE FROM unnest($1::bytea[]) h
                WHERE NOT EXISTS (SELECT 1 FROM canonical_block_replacements r WHERE r.old_hash=h)
                UNION ALL
                SELECT r.old_hash,a.path || r.old_hash,r.old_hash=ANY(a.path)
                FROM canonical_block_replacements r JOIN ancestors a ON r.new_hash=a.hash
                WHERE NOT a.cycle AND cardinality(a.path)<=33
            ) SELECT hash,cardinality(path),cycle FROM ancestors LIMIT 4097
        "#,
        )
        .bind(removed)
        .fetch_all(&mut **conn)
        .await?;
        ensure!(
            lineage.len() <= 4096
                && lineage
                    .iter()
                    .all(|(_, depth, cycle)| *depth <= 33 && !cycle),
            "historical acceptance target lineage exceeds bound or contains a cycle"
        );
        let hashes: Vec<_> = lineage.into_iter().map(|r| r.0).collect();
        sqlx::query(
            r#"UPDATE historical_acceptance_maps m SET status='target_lost'
            WHERE m.status='applied' AND EXISTS(SELECT 1 FROM historical_acceptance_map_entries e
                WHERE e.proof_hash=m.proof_hash AND e.target_hash=ANY($1::bytea[]))"#,
        )
        .bind(hashes)
        .execute(&mut **conn)
        .await?;
        Ok(())
    }
}

//! Fence REST observations against removals committed by the live writer.
//! A revision proves only absence of a subsequent local removal. The caller
//! must separately obtain authoritative node evidence for removed hashes.
use super::PgPersister;
use anyhow::{ensure, Result};
use sqlx::{Postgres, Transaction};
use std::collections::BTreeMap;
use tn12_indexer_core::RestTransaction;

#[derive(Debug, thiserror::Error)]
#[error("REST acceptance observation invalidated by block removal; retain and refetch window")]
pub struct StaleRestAcceptance;

impl PgPersister {
    pub async fn rest_removal_revisions(
        &self,
        hashes: &[Vec<u8>],
    ) -> Result<BTreeMap<Vec<u8>, i64>> {
        ensure!(
            hashes.iter().all(|h| h.len() == 32),
            "invalid REST accepting hash"
        );
        let rows: Vec<(Vec<u8>,i64)> = sqlx::query_as(
            "SELECT h.hash,coalesce(r.revision,0) FROM unnest($1::bytea[]) h(hash) LEFT JOIN rest_replay_removed_blocks r ON r.block_hash=h.hash"
        ).bind(hashes).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().collect())
    }
    /// Preserve writer configuration and all existing ownership fences.
    pub fn with_rest_removal_guard(&self, revisions: BTreeMap<Vec<u8>, i64>) -> Self {
        let mut writer = self.clone();
        writer.rest_removal_guard = Some(revisions);
        writer
    }
    pub(super) fn require_rest_guard_hashes<'a>(
        &self,
        hashes: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<()> {
        if let Some(guard) = &self.rest_removal_guard {
            for hash in hashes {
                ensure!(guard.contains_key(hash), StaleRestAcceptance);
            }
        }
        Ok(())
    }
    pub(super) fn require_rest_guard_transactions(&self, txs: &[RestTransaction]) -> Result<()> {
        if self.rest_removal_guard.is_none() {
            return Ok(());
        }
        for tx in txs.iter().filter(|tx| tx.is_accepted) {
            let hash = hex::decode(
                tx.accepting_block_hash
                    .as_deref()
                    .ok_or(StaleRestAcceptance)?,
            )?;
            self.require_rest_guard_hashes([hash.as_slice()])?;
        }
        Ok(())
    }
    pub(super) async fn verify_rest_removal_guard(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<()> {
        let Some(guard) = &self.rest_removal_guard else {
            return Ok(());
        };
        let hashes: Vec<_> = guard.keys().cloned().collect();
        let revisions: Vec<_> = guard.values().copied().collect();
        let unchanged:bool=sqlx::query_scalar(
            "SELECT NOT EXISTS(SELECT 1 FROM unnest($1::bytea[],$2::bigint[]) e(hash,revision) LEFT JOIN rest_replay_removed_blocks r ON r.block_hash=e.hash WHERE coalesce(r.revision,0)<>e.revision)"
        ).bind(hashes).bind(revisions).fetch_one(&mut **tx).await?;
        ensure!(unchanged, StaleRestAcceptance);
        Ok(())
    }
    pub(super) async fn record_rest_removals(
        tx: &mut Transaction<'_, Postgres>,
        hashes: &[Vec<u8>],
    ) -> Result<()> {
        sqlx::query("INSERT INTO rest_replay_removed_blocks(block_hash,revision,removed_at_ms) SELECT h,nextval('rest_replay_removal_revision'),(extract(epoch from clock_timestamp())*1000)::bigint FROM (SELECT DISTINCT h FROM unnest($1::bytea[]) h) hashes ON CONFLICT(block_hash) DO UPDATE SET revision=EXCLUDED.revision,removed_at_ms=EXCLUDED.removed_at_ms")
            .bind(hashes).execute(&mut **tx).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Persister, PgPool};
    use tn12_indexer_core::{RestTxInput, RestTxOutput};
    fn body(id: u8, block: u8) -> RestTransaction {
        RestTransaction {
            transaction_id: hex::encode([id; 32]),
            is_accepted: true,
            accepting_block_hash: Some(hex::encode([block; 32])),
            accepting_block_blue_score: Some(100),
            accepting_block_time: Some(10000),
            inputs: vec![RestTxInput {
                previous_outpoint_hash: hex::encode([id ^ 0xff; 32]),
                previous_outpoint_index: "0".into(),
                previous_outpoint_amount: Some(2000),
                previous_outpoint_script: Some(format!("20{}ac", hex::encode([id ^ 0xff; 32]))),
                signature_script: "0151".into(),
                ..Default::default()
            }],
            outputs: vec![RestTxOutput {
                index: 0,
                amount: 1000,
                script_public_key: format!("aa20{}87", hex::encode([id; 32])),
                ..Default::default()
            }],
            ..Default::default()
        }
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn unguarded_rest_reinsert_reproduces_live_acceptance_conflict(pool: PgPool) {
        let writer = PgPersister::new(pool);
        let old = body(0xaa, 0x11);
        writer.persist_tx(&old).await.unwrap();
        writer.revert_block(&[0x11; 32]).await.unwrap();
        // This is the deployed path: REST prepared A before the removal and
        // writes it back while the watcher prepares replacement B.
        writer.persist_tx(&old).await.unwrap();
        let error = writer.persist_tx(&body(0xaa, 0x22)).await.unwrap_err();
        assert!(error.is::<super::super::AcceptanceConflict>(), "{error:#}");
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn stale_rest_cannot_reinsert_between_live_removal_and_replacement(pool: PgPool) {
        for bulk in [false, true] {
            let id = if bulk { 0xaa } else { 0xbb };
            let old = [body(id, 0x11), body(id - 1, 0x11)];
            let new = [body(id, 0x22), body(id - 1, 0x22)];
            let live = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait().with_generic_bulk_persist(bulk);
            let stats = live.persist_batch(&old).await.unwrap();
            assert_eq!(stats.utxos_inserted, 2);
            if bulk {
                assert!(super::super::generic_bulk::is_writer_candidate(
                    &old[0],
                    &live.decoders,
                    live.native_genesis_bulk
                ));
                assert!(old.len() >= super::super::generic_bulk::minimum_batch_len(&old[0]));
            }
            let observations = live
                .rest_removal_revisions(&[vec![0x11; 32]])
                .await
                .unwrap();
            let stale_rest = live.with_rest_removal_guard(observations);
            live.revert_block(&[0x11; 32]).await.unwrap();
            let error = stale_rest.persist_batch(&old).await.unwrap_err();
            assert!(error.is::<StaleRestAcceptance>(), "{error:#}");
            live.persist_batch(&new).await.unwrap();
            let actual: Vec<u8> =
                sqlx::query_scalar("SELECT created_block FROM covenant_utxos WHERE txid=$1")
                    .bind(vec![id; 32])
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(actual, vec![0x22; 32]);
            live.revert_block(&[0x22; 32]).await.unwrap();
        }
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn unknown_removal_invalidates_prepared_source_but_unrelated_removal_does_not(
        pool: PgPool,
    ) {
        let live = PgPersister::new(pool);
        let initial = live
            .rest_removal_revisions(&[vec![0x11; 32]])
            .await
            .unwrap();
        let guarded = live.with_rest_removal_guard(initial);
        live.revert_block(&[0x22; 32]).await.unwrap();
        guarded.persist_tx(&body(0xaa, 0x11)).await.unwrap();
        live.revert_block(&[0x11; 32]).await.unwrap();
        assert!(guarded
            .persist_tx(&body(0xaa, 0x11))
            .await
            .unwrap_err()
            .is::<StaleRestAcceptance>());
        let initial = live
            .rest_removal_revisions(&[vec![0x33; 32]])
            .await
            .unwrap();
        let guarded = live.with_rest_removal_guard(initial);
        live.revert_block(&[0x33; 32]).await.unwrap();
        assert!(guarded
            .persist_tx(&body(0xbb, 0x33))
            .await
            .unwrap_err()
            .is::<StaleRestAcceptance>());
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn renewed_observation_retains_revision_and_next_removal_revokes_it(pool: PgPool) {
        let live = PgPersister::new(pool);
        live.revert_block(&[0x11; 32]).await.unwrap();
        let fresh = live
            .rest_removal_revisions(&[vec![0x11; 32]])
            .await
            .unwrap();
        assert!(fresh[&vec![0x11; 32]] > 0);
        // Source-adapter tests separately require authoritative node proof.
        let writer = live.with_rest_removal_guard(fresh.clone());
        writer.persist_tx(&body(0xaa, 0x11)).await.unwrap();
        assert_eq!(
            live.rest_removal_revisions(&[vec![0x11; 32]])
                .await
                .unwrap(),
            fresh
        );
        assert!(writer
            .persist_tx(&body(0xbb, 0x22))
            .await
            .unwrap_err()
            .is::<StaleRestAcceptance>());
        live.revert_block(&[0x11; 32]).await.unwrap();
        assert!(writer
            .persist_tx(&body(0xaa, 0x11))
            .await
            .unwrap_err()
            .is::<StaleRestAcceptance>());
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn retired_legacy_alias_keeps_removal_evidence(pool: PgPool) {
        let live = PgPersister::new(pool.clone());
        live.persist_tx(&body(0xaa, 0x22)).await.unwrap();
        sqlx::query("INSERT INTO canonical_block_replacements(old_hash,new_hash,evidence,source_tip) VALUES($1,$2,'{}',2000)")
            .bind(vec![0x11u8;32]).bind(vec![0x22u8;32]).execute(&pool).await.unwrap();
        let before = live
            .rest_removal_revisions(&[vec![0x11; 32]])
            .await
            .unwrap();
        assert_eq!(before[&vec![0x11; 32]], 0);
        live.revert_block(&[0x22; 32]).await.unwrap();
        assert!(
            live.rest_removal_revisions(&[vec![0x11; 32]])
                .await
                .unwrap()[&vec![0x11; 32]]
                > 0
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM canonical_block_replacements")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        assert!(live
            .with_rest_removal_guard(before)
            .persist_tx(&body(0xbb, 0x11))
            .await
            .unwrap_err()
            .is::<StaleRestAcceptance>());
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn replay_entrypoint_rejects_missing_dependency_hash_coverage(pool: PgPool) {
        let live = PgPersister::new(pool);
        let guard = live
            .rest_removal_revisions(&[vec![0x22; 32]])
            .await
            .unwrap();
        let writer = live.with_rest_removal_guard(guard);
        assert!(writer
            .replay_deferred_tx(&body(0xaa, 0x11))
            .await
            .unwrap_err()
            .is::<StaleRestAcceptance>());
    }
}

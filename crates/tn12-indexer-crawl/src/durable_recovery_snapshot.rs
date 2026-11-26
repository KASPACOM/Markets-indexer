//! Capture the immutable evidence prefix before canonical repair. This module
//! cannot apply mutations, close intervals, or acknowledge receipts. The source
//! proof and final atomic commit remain recovery-controller responsibilities.
use super::{ChainAnchor, DurableInbox};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tn12_indexer_db::persist::DurableConsumerFence;

const MAX_RECEIPTS: i64 = 64;
const MAX_RECEIPT_BYTES: i64 = 8 * 1024 * 1024;
const MAX_INTERVALS: i64 = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ReceiptDigest {
    sequence: i64,
    received_at_ms: i64,
    bytes: i64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Interval {
    id: i64,
    opened_at_ms: i64,
    anchor: Option<ChainAnchor>,
    reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct EffectDigest {
    sequence: i64,
    bytes: i64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RecoverySnapshot {
    committed_sequence: i64,
    anchor: Option<ChainAnchor>,
    receipts: Vec<ReceiptDigest>,
    intervals: Vec<Interval>,
    effect: Option<EffectDigest>,
}

impl RecoverySnapshot {
    fn through_sequence(&self) -> i64 {
        self.receipts
            .last()
            .map_or(self.committed_sequence, |r| r.sequence)
    }
}

impl DurableInbox {
    /// Later appends and connection intervals remain outside this exact prefix.
    /// A replacement consumer reuses it after checking its generation and the
    /// unchanged checkpoint. It must reconcile later intervals separately.
    pub(crate) async fn capture_recovery_snapshot(
        &self,
        fence: &DurableConsumerFence,
    ) -> Result<RecoverySnapshot> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='350ms'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout='2s'")
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query("SELECT committed_sequence,next_sequence,anchor FROM wrpc_inbox_streams WHERE stream=$1 FOR UPDATE")
            .bind(&self.stream).fetch_one(&mut *tx).await?;
        fence.verify_locked(&mut tx, &self.stream).await?;
        let committed: i64 = row.try_get("committed_sequence")?;
        let next: i64 = row.try_get("next_sequence")?;
        let anchor: Option<serde_json::Value> = row.try_get("anchor")?;
        let anchor: Option<ChainAnchor> = anchor.map(serde_json::from_value).transpose()?;
        if let Some(anchor) = &anchor {
            anchor.validate()?;
        }
        ensure!(
            committed >= 0 && next > committed,
            "invalid recovery checkpoint"
        );
        let saved: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT snapshot FROM wrpc_recovery_snapshots WHERE stream=$1")
                .bind(&self.stream)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(saved) = saved {
            let saved: RecoverySnapshot = serde_json::from_value(saved)?;
            ensure!(
                saved.committed_sequence == committed && saved.anchor == anchor,
                "checkpoint changed while canonical recovery was pending"
            );
            tx.commit().await?;
            return Ok(saved);
        }

        // Read lengths before hashing so server and application work are bounded
        // by eight MiB, rather than sixty-four potentially full-sized frames.
        let lengths: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT sequence,octet_length(payload)::bigint FROM wrpc_inbox_entries WHERE stream=$1 AND sequence>$2 ORDER BY sequence LIMIT $3",
        ).bind(&self.stream).bind(committed).bind(MAX_RECEIPTS).fetch_all(&mut *tx).await?;
        let mut through = committed;
        let mut bytes = 0_i64;
        for (sequence, length) in lengths {
            ensure!(
                sequence
                    == through
                        .checked_add(1)
                        .context("receipt sequence overflow")?
                    && sequence < next
                    && (1..=MAX_RECEIPT_BYTES).contains(&length),
                "missing or invalid receipt in recovery prefix"
            );
            if bytes + length > MAX_RECEIPT_BYTES {
                break;
            }
            bytes += length;
            through = sequence;
        }
        ensure!(
            through > committed || next == committed + 1,
            "pending recovery receipt is missing"
        );
        let rows = sqlx::query("SELECT sequence,received_at_ms,octet_length(payload)::bigint AS bytes,encode(pg_catalog.sha256(payload),'hex') AS sha256 FROM wrpc_inbox_entries WHERE stream=$1 AND sequence>$2 AND sequence<=$3 ORDER BY sequence")
            .bind(&self.stream).bind(committed).bind(through).fetch_all(&mut *tx).await?;
        let receipts = rows
            .into_iter()
            .map(|r| {
                Ok(ReceiptDigest {
                    sequence: r.try_get("sequence")?,
                    received_at_ms: r.try_get("received_at_ms")?,
                    bytes: r.try_get("bytes")?,
                    sha256: r.try_get("sha256")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            receipts.len() as i64 == through - committed,
            "recovery prefix changed"
        );
        let rows = sqlx::query("SELECT id,opened_at_ms,anchor,reason FROM wrpc_recovery_intervals WHERE stream=$1 AND verified_at_ms IS NULL ORDER BY id LIMIT $2")
            .bind(&self.stream).bind(MAX_INTERVALS + 1).fetch_all(&mut *tx).await?;
        ensure!(
            rows.len() as i64 <= MAX_INTERVALS,
            "recovery interval bound exceeded"
        );
        let intervals = rows
            .into_iter()
            .map(|r| {
                let anchor: Option<serde_json::Value> = r.try_get("anchor")?;
                let anchor: Option<ChainAnchor> = anchor.map(serde_json::from_value).transpose()?;
                if let Some(anchor) = &anchor {
                    anchor.validate()?;
                }
                Ok(Interval {
                    id: r.try_get("id")?,
                    opened_at_ms: r.try_get("opened_at_ms")?,
                    anchor,
                    reason: r.try_get("reason")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let effect = sqlx::query("SELECT sequence,octet_length(payload)::bigint AS bytes,encode(pg_catalog.sha256(payload),'hex') AS sha256 FROM wrpc_inbox_effects WHERE stream=$1")
            .bind(&self.stream).fetch_optional(&mut *tx).await?
            .map(|r| Ok::<_, anyhow::Error>(EffectDigest { sequence: r.try_get("sequence")?,
                bytes: r.try_get("bytes")?, sha256: r.try_get("sha256")? })).transpose()?;
        if let Some(effect) = &effect {
            ensure!(
                effect.sequence == committed + 1 && effect.sequence <= through,
                "unfinished effect is outside recovery prefix"
            );
        }
        let snapshot = RecoverySnapshot {
            committed_sequence: committed,
            anchor,
            receipts,
            intervals,
            effect,
        };
        let value = serde_json::to_value(&snapshot)?;
        ensure!(
            serde_json::to_vec(&value)?.len() <= 65536,
            "recovery snapshot exceeds metadata bound"
        );
        sqlx::query(
            "INSERT INTO wrpc_recovery_snapshots(stream,snapshot,captured_at_ms) VALUES($1,$2,$3)",
        )
        .bind(&self.stream)
        .bind(value)
        .bind(chrono::Utc::now().timestamp_millis())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    async fn setup(pool: &PgPool) -> (DurableInbox, DurableConsumerFence) {
        let inbox =
            DurableInbox::open(pool.clone(), "testnet-10:recovery".into(), 32 * 1024 * 1024)
                .await
                .unwrap();
        let fence = DurableConsumerFence::claim(pool, "testnet-10:recovery")
            .await
            .unwrap();
        (inbox, fence)
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn durable_recovery_prefix_is_immutable_across_appends_and_takeover(pool: PgPool) {
        let (inbox, first) = setup(&pool).await;
        inbox.append(1, b"first", 1).await.unwrap();
        inbox.open_recovery_interval("disconnect").await.unwrap();
        let snapshot = inbox.capture_recovery_snapshot(&first).await.unwrap();
        assert_eq!(snapshot.through_sequence(), 1);
        assert_eq!(snapshot.intervals.len(), 1);
        assert_eq!(
            snapshot.receipts[0].sha256,
            "a7937b64b8caa58f03721bb6bacf5c78cb235febe0e70b1b84cd99541461a08e"
        );
        inbox.append(2, b"later", 2).await.unwrap();
        inbox.open_recovery_interval("reconnect").await.unwrap();
        let second = DurableConsumerFence::claim(&pool, "testnet-10:recovery")
            .await
            .unwrap();
        assert!(inbox.capture_recovery_snapshot(&first).await.is_err());
        assert_eq!(
            inbox.capture_recovery_snapshot(&second).await.unwrap(),
            snapshot
        );
        let checkpoint = inbox.checkpoint(&second).await.unwrap();
        assert_eq!(checkpoint.committed_sequence, 0);
        assert_eq!(checkpoint.next_sequence, 3);
        assert_eq!(checkpoint.open_recovery_intervals, 2);
        assert!(checkpoint.pending_recovery_snapshot);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn durable_recovery_capture_bounds_frame_count_without_skipping(pool: PgPool) {
        let (inbox, fence) = setup(&pool).await;
        for sequence in 1..=70 {
            inbox.append(sequence, b"small", sequence).await.unwrap();
        }
        let snapshot = inbox.capture_recovery_snapshot(&fence).await.unwrap();
        assert_eq!(snapshot.receipts.len(), 64);
        assert_eq!(snapshot.through_sequence(), 64);
        assert_eq!(
            inbox.checkpoint(&fence).await.unwrap().committed_sequence,
            0
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn durable_recovery_capture_bounds_bytes_before_hashing(pool: PgPool) {
        let (inbox, fence) = setup(&pool).await;
        let payload = vec![7; 4 * 1024 * 1024];
        for sequence in 1..=3 {
            inbox.append(sequence, &payload, sequence).await.unwrap();
        }
        let snapshot = inbox.capture_recovery_snapshot(&fence).await.unwrap();
        assert_eq!(snapshot.through_sequence(), 2);
        assert_eq!(
            snapshot.receipts.iter().map(|r| r.bytes).sum::<i64>(),
            MAX_RECEIPT_BYTES
        );
        assert_eq!(
            inbox.checkpoint(&fence).await.unwrap().pending_bytes,
            12 * 1024 * 1024
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn durable_recovery_snapshot_blocks_ordinary_consumer_and_anchor_ack(pool: PgPool) {
        use crate::durable_consumer::{ConsumerStep, DurableConsumer, RecoveryReason};
        use std::sync::Arc;
        let (inbox, fence) = setup(&pool).await;
        let anchor = ChainAnchor {
            network: "testnet-10".into(),
            block_hash: "11".repeat(32),
            blue_score: 10,
        };
        // This is only a seeded test fixture. Runtime bootstrap must establish
        // the anchor through canonical recovery and a proof commit.
        sqlx::query("UPDATE wrpc_inbox_streams SET anchor=$1")
            .bind(serde_json::to_value(&anchor).unwrap())
            .execute(&pool)
            .await
            .unwrap();
        inbox.append(1, b"pending", 1).await.unwrap();
        inbox.capture_recovery_snapshot(&fence).await.unwrap();
        assert!(inbox
            .acknowledge_contiguous(1, &anchor, &anchor, &fence)
            .await
            .is_err());
        assert!(inbox.acknowledge(1, Some(&anchor)).await.is_err());
        assert!(inbox
            .acknowledge_fenced(1, Some(&anchor), &fence)
            .await
            .is_err());
        let inbox = Arc::new(inbox);
        let mut consumer =
            DurableConsumer::new(inbox.clone(), fence.clone(), "testnet-10".into(), 8192).unwrap();
        assert!(matches!(
            consumer.step().await.unwrap(),
            ConsumerStep::RecoveryRequired {
                reason: RecoveryReason::PendingCanonicalSnapshot,
                ..
            }
        ));
        assert_eq!(
            inbox.checkpoint(&fence).await.unwrap().committed_sequence,
            0
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn durable_recovery_missing_receipt_or_too_many_intervals_never_saves_plan(pool: PgPool) {
        let (inbox, fence) = setup(&pool).await;
        inbox.append(1, b"head", 1).await.unwrap();
        sqlx::query("DELETE FROM wrpc_inbox_entries")
            .execute(&pool)
            .await
            .unwrap();
        assert!(inbox.capture_recovery_snapshot(&fence).await.is_err());
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM wrpc_recovery_snapshots")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        sqlx::query("UPDATE wrpc_inbox_streams SET next_sequence=1,pending_bytes=0")
            .execute(&pool)
            .await
            .unwrap();
        for _ in 0..=MAX_INTERVALS {
            inbox.open_recovery_interval("disconnect").await.unwrap();
        }
        assert!(inbox.capture_recovery_snapshot(&fence).await.is_err());
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM wrpc_recovery_snapshots")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn durable_recovery_gap_only_capture_never_fabricates_an_anchor(pool: PgPool) {
        let (inbox, fence) = setup(&pool).await;
        inbox.open_recovery_interval("connect").await.unwrap();
        let snapshot = inbox.capture_recovery_snapshot(&fence).await.unwrap();
        assert_eq!(snapshot.through_sequence(), 0);
        assert!(snapshot.anchor.is_none());
        assert!(snapshot.receipts.is_empty());
        assert_eq!(snapshot.intervals.len(), 1);
        assert!(
            inbox
                .checkpoint(&fence)
                .await
                .unwrap()
                .pending_recovery_snapshot
        );
    }
}

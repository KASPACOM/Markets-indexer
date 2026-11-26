//! Ordered persistence primitives for watcher intake. Transport integration must
//! also bound SDK queues and preserve recovery intervals before enabling intake.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::{Connection, PgConnection, PgPool, Row};

pub const APPLICATION_BUFFER_BYTES: usize = 128 * 1024 * 1024;
pub const NOTIFICATION_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const DURABLE_BACKLOG_BYTES: i64 = 20 * 1024 * 1024 * 1024;
#[path = "durable_effects.rs"]
mod effects;
pub use effects::{EffectStart, InboxEffectJournal};
#[path = "durable_apply.rs"]
mod apply;
pub use apply::{DurableCommitOutcome, DurableEventApplier};
#[path = "durable_recovery_snapshot.rs"]
mod recovery_snapshot;

const REPLAY_TAIL_BYTES: i64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainAnchor {
    pub network: String,
    pub block_hash: String,
    pub blue_score: u64,
}

impl ChainAnchor {
    fn validate(&self) -> Result<()> {
        ensure!(!self.network.is_empty(), "anchor network is missing");
        ensure!(
            hex::decode(&self.block_hash).is_ok_and(|bytes| bytes.len() == 32),
            "anchor block hash must be 32 bytes"
        );
        Ok(())
    }
}

#[derive(Debug)]
pub struct InboxEntry {
    pub sequence: i64,
    pub received_at_ms: i64,
    pub payload: Vec<u8>,
}

/// A single database snapshot for restart decisions. An anchor alone does not
/// establish coverage when a connection gap or uncertain effect remains open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxCheckpoint {
    pub committed_sequence: i64,
    pub next_sequence: i64,
    pub pending_bytes: i64,
    pub anchor: Option<ChainAnchor>,
    pub open_recovery_intervals: i64,
    pub uncertain_effect: bool,
    pub pending_recovery_snapshot: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AppendOutcome {
    Stored,
    AlreadyStored,
    AlreadyCommitted,
    CapacityReached,
}

pub struct IntakeLease {
    connection: PgConnection,
    stream: String,
}

impl IntakeLease {
    pub async fn close(self) -> Result<()> {
        self.close_with_deadline(std::time::Duration::from_secs(5))
            .await
    }

    async fn close_with_deadline(mut self, deadline: std::time::Duration) -> Result<()> {
        // Timeout only borrows the session. Ownership survives so physical
        // shutdown still runs if PostgreSQL cannot acknowledge the unlock.
        let unlocked = tokio::time::timeout(
            deadline,
            sqlx::query_scalar::<_, bool>(
                "SELECT pg_advisory_unlock(hashtextextended('wrpc-intake:' || $1, 0))",
            )
            .bind(&self.stream)
            .fetch_one(&mut self.connection),
        )
        .await;
        // This owning future drops the physical socket if its buffered flush
        // stalls. The server may retain its fence until TCP loss is observed;
        // replacement intake must keep failing closed while that fence exists.
        let closed = tokio::time::timeout(deadline, self.connection.close_hard())
            .await
            .context("intake physical close deadline exceeded");
        ensure!(
            unlocked.context("intake lease unlock deadline exceeded")??,
            "intake lease was not owned during close"
        );
        closed??;
        Ok(())
    }
}

/// Epoch-labelled monotonic clock for a single-process latency observer.
/// Share one instance between receipt and completion; never reuse it to time
/// records from another process. Normal durable ingestion keeps wall time.
#[derive(Clone)]
pub struct MonotonicReceiptClock {
    epoch_ms: i64,
    started: std::time::Instant,
}
impl MonotonicReceiptClock {
    pub fn new() -> Self {
        Self {
            epoch_ms: chrono::Utc::now().timestamp_millis(),
            started: std::time::Instant::now(),
        }
    }
    pub fn now_ms(&self) -> i64 {
        self.epoch_ms
            .saturating_add(self.started.elapsed().as_millis().min(i64::MAX as u128) as i64)
    }
}
impl Default for MonotonicReceiptClock {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DurableInbox {
    pool: PgPool,
    receipt_clock: Option<MonotonicReceiptClock>,
    stream: String,
    capacity_bytes: i64,
}

impl DurableInbox {
    pub(super) async fn require_anchor(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        expected: &ChainAnchor,
        fence: &tn12_indexer_db::persist::DurableConsumerFence,
    ) -> Result<()> {
        expected.validate()?;
        sqlx::query("SET LOCAL lock_timeout='350ms'")
            .execute(&mut **tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout='2s'")
            .execute(&mut **tx)
            .await?;
        let actual: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT anchor FROM wrpc_inbox_streams WHERE stream=$1 FOR UPDATE")
                .bind(&self.stream)
                .fetch_one(&mut **tx)
                .await?;
        fence.verify_locked(tx, &self.stream).await?;
        ensure!(
            actual == Some(serde_json::to_value(expected)?),
            "durable checkpoint anchor changed or missing"
        );
        let open: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM wrpc_recovery_intervals WHERE stream=$1 AND verified_at_ms IS NULL)",
        ).bind(&self.stream).fetch_one(&mut **tx).await?;
        ensure!(!open, "durable connection recovery remains unverified");
        let pending: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM wrpc_recovery_snapshots WHERE stream=$1)",
        ).bind(&self.stream).fetch_one(&mut **tx).await?;
        ensure!(!pending, "canonical recovery snapshot remains unverified");
        Ok(())
    }

    /// A replaced consumer cannot use this method to resume. Locking the stream
    /// also gives the metadata and recovery/effect checks one consistent view.
    pub async fn checkpoint(
        &self,
        fence: &tn12_indexer_db::persist::DurableConsumerFence,
    ) -> Result<InboxCheckpoint> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='350ms'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout='2s'")
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query("SELECT committed_sequence,next_sequence,pending_bytes,anchor FROM wrpc_inbox_streams WHERE stream=$1 FOR SHARE")
            .bind(&self.stream).fetch_one(&mut *tx).await?;
        fence.verify_locked(&mut tx, &self.stream).await?;
        let anchor: Option<serde_json::Value> = row.try_get("anchor")?;
        let anchor: Option<ChainAnchor> = anchor.map(serde_json::from_value).transpose()?;
        if let Some(anchor) = &anchor {
            anchor.validate()?;
        }
        let checkpoint = InboxCheckpoint {
            committed_sequence: row.try_get("committed_sequence")?,
            next_sequence: row.try_get("next_sequence")?,
            pending_bytes: row.try_get("pending_bytes")?,
            anchor,
            open_recovery_intervals: sqlx::query_scalar("SELECT count(*) FROM wrpc_recovery_intervals WHERE stream=$1 AND verified_at_ms IS NULL")
                .bind(&self.stream).fetch_one(&mut *tx).await?,
            uncertain_effect: sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM wrpc_inbox_effects WHERE stream=$1)")
                .bind(&self.stream).fetch_one(&mut *tx).await?,
            pending_recovery_snapshot: sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM wrpc_recovery_snapshots WHERE stream=$1)")
                .bind(&self.stream).fetch_one(&mut *tx).await?,
        };
        ensure!(
            checkpoint.next_sequence > checkpoint.committed_sequence,
            "invalid durable checkpoint sequence"
        );
        tx.commit().await?;
        Ok(checkpoint)
    }

    pub(crate) async fn acknowledge_contiguous(
        &self,
        sequence: i64,
        previous: &ChainAnchor,
        next: &ChainAnchor,
        fence: &tn12_indexer_db::persist::DurableConsumerFence,
    ) -> Result<()> {
        ensure!(
            previous.network == next.network,
            "checkpoint network changed"
        );
        let mut tx = self.pool.begin().await?;
        self.require_anchor(&mut tx, previous, fence).await?;
        self.acknowledge_in_transaction(&mut tx, sequence, Some(next), Some(fence))
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn open(pool: PgPool, stream: String, capacity_bytes: i64) -> Result<Self> {
        ensure!(
            !stream.is_empty() && stream.len() <= 256,
            "invalid inbox stream"
        );
        ensure!(
            (1..=DURABLE_BACKLOG_BYTES).contains(&capacity_bytes),
            "invalid inbox capacity"
        );
        sqlx::query("INSERT INTO wrpc_inbox_streams(stream,updated_at_ms) VALUES($1,$2) ON CONFLICT DO NOTHING")
            .bind(&stream).bind(chrono::Utc::now().timestamp_millis()).execute(&pool).await?;
        let inbox = Self {
            pool,
            receipt_clock: None,
            stream,
            capacity_bytes,
        };
        inbox.rebalance_replay_tail().await?;
        Ok(inbox)
    }

    pub fn with_monotonic_receipt_clock(mut self, clock: MonotonicReceiptClock) -> Self {
        self.receipt_clock = Some(clock);
        self
    }

    pub(crate) fn receipt_time_ms(&self) -> i64 {
        self.receipt_clock.as_ref().map_or_else(
            || chrono::Utc::now().timestamp_millis(),
            MonotonicReceiptClock::now_ms,
        )
    }

    async fn rebalance_replay_tail(&self) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let (committed, retained): (i64, i64) = sqlx::query_as(
            "SELECT committed_sequence,retained_bytes FROM wrpc_inbox_streams WHERE stream=$1 FOR UPDATE",
        ).bind(&self.stream).fetch_one(&mut *tx).await?;
        let trimmed = self.trim_replay_tail(&mut tx, committed, retained).await?;
        if trimmed != retained {
            sqlx::query("UPDATE wrpc_inbox_streams SET retained_bytes=$2 WHERE stream=$1")
                .bind(&self.stream)
                .bind(trimmed)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn trim_replay_tail(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        committed: i64,
        retained: i64,
    ) -> Result<i64> {
        let limit = REPLAY_TAIL_BYTES.min(self.capacity_bytes / 4);
        if retained <= limit {
            return Ok(retained);
        }
        // Trim only processed receipts, including when a smaller capacity is
        // selected on restart. Pending intake remains available for replay.
        let removed: i64 = sqlx::query_scalar(
            r#"
            WITH tail AS (
                SELECT sequence,sum(octet_length(payload)) OVER (ORDER BY sequence DESC) bytes
                FROM wrpc_inbox_entries WHERE stream=$1 AND sequence<=$2
            ), removed AS (
                DELETE FROM wrpc_inbox_entries WHERE stream=$1
                AND sequence IN (SELECT sequence FROM tail WHERE bytes>$3)
                RETURNING octet_length(payload) bytes
            ) SELECT coalesce(sum(bytes),0)::bigint FROM removed
        "#,
        )
        .bind(&self.stream)
        .bind(committed)
        .bind(limit * 3 / 4)
        .fetch_one(&mut **tx)
        .await?;
        retained
            .checked_sub(removed)
            .context("retained byte underflow")
    }

    /// A dedicated session owns intake until dropped. Returning a pooled session
    /// with an advisory lock would leave that lock attached to unrelated work.
    pub async fn acquire_intake_lease(&self) -> Result<IntakeLease> {
        let mut connection = PgConnection::connect_with(&self.pool.connect_options()).await?;
        let acquired: bool = sqlx::query_scalar(
            "SELECT pg_try_advisory_lock(hashtextextended('wrpc-intake:' || $1, 0))",
        )
        .bind(&self.stream)
        .fetch_one(&mut connection)
        .await?;
        ensure!(
            acquired,
            "durable intake stream already has an active producer"
        );
        Ok(IntakeLease {
            connection,
            stream: self.stream.clone(),
        })
    }

    pub async fn next_sequence(&self) -> Result<i64> {
        Ok(
            sqlx::query_scalar("SELECT next_sequence FROM wrpc_inbox_streams WHERE stream=$1")
                .bind(&self.stream)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    /// Receipt sequence must be retained across an uncertain append result.
    /// A capacity failure records an open recovery interval in the same commit.
    pub async fn append(
        &self,
        sequence: i64,
        payload: &[u8],
        received_at_ms: i64,
    ) -> Result<AppendOutcome> {
        self.append_transaction(self.pool.begin().await?, sequence, payload, received_at_ms)
            .await
    }

    /// Production intake uses the same connection that holds the session fence.
    /// Losing that connection prevents further appends by the former producer.
    pub async fn append_with_lease(
        &self,
        lease: &mut IntakeLease,
        sequence: i64,
        payload: &[u8],
        received_at_ms: i64,
    ) -> Result<AppendOutcome> {
        ensure!(
            lease.stream == self.stream,
            "intake lease belongs to a different stream"
        );
        self.append_transaction(
            lease.connection.begin().await?,
            sequence,
            payload,
            received_at_ms,
        )
        .await
    }

    async fn append_transaction(
        &self,
        mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
        sequence: i64,
        payload: &[u8],
        received_at_ms: i64,
    ) -> Result<AppendOutcome> {
        ensure!(sequence > 0, "invalid receipt sequence");
        ensure!(!payload.is_empty(), "empty inbox payload");
        ensure!(
            payload.len() <= NOTIFICATION_FRAME_BYTES,
            "notification exceeds frame limit"
        );
        let bytes = i64::try_from(payload.len())?;
        let row = sqlx::query("SELECT next_sequence,committed_sequence,pending_bytes,retained_bytes,effect_bytes,anchor FROM wrpc_inbox_streams WHERE stream=$1 FOR UPDATE")
            .bind(&self.stream).fetch_one(&mut *tx).await?;
        let committed: i64 = row.try_get("committed_sequence")?;
        let next: i64 = row.try_get("next_sequence")?;
        if sequence <= committed {
            return Ok(AppendOutcome::AlreadyCommitted);
        }
        if sequence < next {
            let existing: Vec<u8> = sqlx::query_scalar(
                "SELECT payload FROM wrpc_inbox_entries WHERE stream=$1 AND sequence=$2",
            )
            .bind(&self.stream)
            .bind(sequence)
            .fetch_one(&mut *tx)
            .await?;
            ensure!(
                existing == payload,
                "receipt reused with different notification payload"
            );
            return Ok(AppendOutcome::AlreadyStored);
        }
        ensure!(sequence == next, "inbox receipt sequence is not contiguous");
        let pending: i64 = row.try_get("pending_bytes")?;
        if pending
            .checked_add(bytes)
            .and_then(|total| total.checked_add(row.get::<i64, _>("retained_bytes")))
            .and_then(|total| total.checked_add(row.get::<i64, _>("effect_bytes")))
            .context("inbox capacity overflow")?
            > self.capacity_bytes
        {
            sqlx::query("INSERT INTO wrpc_recovery_intervals(stream,opened_at_ms,anchor,reason) SELECT $1,$2,$3,'durable_capacity' WHERE NOT EXISTS (SELECT 1 FROM wrpc_recovery_intervals WHERE stream=$1 AND verified_at_ms IS NULL AND reason='durable_capacity')")
                .bind(&self.stream).bind(received_at_ms).bind(row.try_get::<Option<serde_json::Value>,_>("anchor")?)
                .execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(AppendOutcome::CapacityReached);
        }
        let next = next.checked_add(1).context("inbox sequence exhausted")?;
        sqlx::query("INSERT INTO wrpc_inbox_entries(stream,sequence,received_at_ms,payload) VALUES($1,$2,$3,$4)")
            .bind(&self.stream).bind(sequence).bind(received_at_ms).bind(payload).execute(&mut *tx).await?;
        sqlx::query("UPDATE wrpc_inbox_streams SET next_sequence=$2,pending_bytes=pending_bytes+$3,updated_at_ms=$4 WHERE stream=$1")
            .bind(&self.stream).bind(next).bind(bytes).bind(received_at_ms).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(AppendOutcome::Stored)
    }

    pub async fn oldest(&self) -> Result<Option<InboxEntry>> {
        let row = sqlx::query("SELECT e.sequence,e.received_at_ms,e.payload FROM wrpc_inbox_entries e JOIN wrpc_inbox_streams s USING(stream) WHERE e.stream=$1 AND e.sequence>s.committed_sequence ORDER BY e.sequence LIMIT 1")
            .bind(&self.stream).fetch_optional(&self.pool).await?;
        row.map(|r| {
            Ok(InboxEntry {
                sequence: r.try_get("sequence")?,
                received_at_ms: r.try_get("received_at_ms")?,
                payload: r.try_get("payload")?,
            })
        })
        .transpose()
    }

    /// Hydration-only lookahead, bounded by the captured intake sequence.
    pub async fn peek_pending_after(
        &self,
        after: i64,
        through: i64,
        fence: &tn12_indexer_db::persist::DurableConsumerFence,
    ) -> Result<Option<InboxEntry>> {
        ensure!(after >= 0 && through >= after, "invalid lookahead range");
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='350ms'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout='2s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT stream FROM wrpc_inbox_streams WHERE stream=$1 FOR SHARE")
            .bind(&self.stream)
            .fetch_one(&mut *tx)
            .await?;
        fence.verify_locked(&mut tx, &self.stream).await?;
        let row = sqlx::query("SELECT e.sequence,e.received_at_ms,e.payload FROM wrpc_inbox_entries e JOIN wrpc_inbox_streams s USING(stream) WHERE e.stream=$1 AND e.sequence>$2 AND e.sequence<=$3 AND e.sequence>s.committed_sequence ORDER BY e.sequence LIMIT 1")
            .bind(&self.stream).bind(after).bind(through).fetch_optional(&mut *tx).await?;
        let result = row
            .map(|r| {
                Ok::<_, anyhow::Error>(InboxEntry {
                    sequence: r.try_get("sequence")?,
                    received_at_ms: r.try_get("received_at_ms")?,
                    payload: r.try_get("payload")?,
                })
            })
            .transpose()?;
        tx.commit().await?;
        Ok(result)
    }

    /// Read a bounded prefix once for hydration. Limits apply before transferring
    /// payloads, and a too-large next receipt stops the prefix without skipping it.
    pub async fn peek_pending_batch(
        &self,
        after: i64,
        through: i64,
        max_frames: usize,
        max_bytes: usize,
        fence: &tn12_indexer_db::persist::DurableConsumerFence,
    ) -> Result<Vec<InboxEntry>> {
        ensure!(after >= 0 && through >= after, "invalid lookahead range");
        ensure!((1..=64).contains(&max_frames), "invalid lookahead frame limit");
        ensure!((1..=8*1024*1024).contains(&max_bytes), "invalid lookahead byte limit");
        let mut tx=self.pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='350ms'").execute(&mut *tx).await?;
        sqlx::query("SET LOCAL statement_timeout='2s'").execute(&mut *tx).await?;
        sqlx::query("SELECT stream FROM wrpc_inbox_streams WHERE stream=$1 FOR SHARE")
            .bind(&self.stream).fetch_one(&mut *tx).await?;
        fence.verify_locked(&mut tx,&self.stream).await?;
        let rows=sqlx::query(
            "WITH candidates AS MATERIALIZED (
                SELECT e.sequence,octet_length(e.payload) AS bytes
                FROM wrpc_inbox_entries e JOIN wrpc_inbox_streams s USING(stream)
                WHERE e.stream=$1 AND e.sequence>$2 AND e.sequence<=$3 AND e.sequence>s.committed_sequence
                ORDER BY e.sequence LIMIT $4
            ), prefix AS (
                SELECT sequence,sum(bytes) OVER (ORDER BY sequence ROWS UNBOUNDED PRECEDING) AS total
                FROM candidates
            )
            SELECT e.sequence,e.received_at_ms,e.payload FROM prefix p
            JOIN wrpc_inbox_entries e ON e.stream=$1 AND e.sequence=p.sequence
            WHERE p.total<=$5 ORDER BY e.sequence"
        ).bind(&self.stream).bind(after).bind(through).bind(max_frames as i64).bind(max_bytes as i64)
            .fetch_all(&mut *tx).await?;
        let entries=rows.into_iter().map(|r| Ok(InboxEntry {
            sequence:r.try_get("sequence")?,received_at_ms:r.try_get("received_at_ms")?,payload:r.try_get("payload")?,
        })).collect::<Result<Vec<_>>>()?;
        tx.commit().await?;
        Ok(entries)
    }

    /// Read one processed receipt for cache reconstruction only. Reapplying its
    /// database writes could undo newer canonical acceptance after a reorg.
    pub async fn replay_tail_after(&self, after: i64) -> Result<Option<InboxEntry>> {
        let row = sqlx::query("SELECT e.sequence,e.received_at_ms,e.payload FROM wrpc_inbox_entries e JOIN wrpc_inbox_streams s USING(stream) WHERE e.stream=$1 AND e.sequence>$2 AND e.sequence<=s.committed_sequence ORDER BY e.sequence LIMIT 1")
            .bind(&self.stream).bind(after).fetch_optional(&self.pool).await?;
        row.map(|r| {
            Ok(InboxEntry {
                sequence: r.try_get("sequence")?,
                received_at_ms: r.try_get("received_at_ms")?,
                payload: r.try_get("payload")?,
            })
        })
        .transpose()
    }

    /// Call only after persistence succeeds. A crash before this commit leaves
    /// the same notification available for idempotent replay.
    pub async fn acknowledge(&self, sequence: i64, anchor: Option<&ChainAnchor>) -> Result<()> {
        self.acknowledge_inner(sequence, anchor, None).await
    }

    pub async fn acknowledge_fenced(
        &self,
        sequence: i64,
        anchor: Option<&ChainAnchor>,
        fence: &tn12_indexer_db::persist::DurableConsumerFence,
    ) -> Result<()> {
        self.acknowledge_inner(sequence, anchor, Some(fence)).await
    }

    async fn acknowledge_inner(
        &self,
        sequence: i64,
        anchor: Option<&ChainAnchor>,
        fence: Option<&tn12_indexer_db::persist::DurableConsumerFence>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        self.acknowledge_in_transaction(&mut tx, sequence, anchor, fence)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn acknowledge_in_transaction(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        sequence: i64,
        anchor: Option<&ChainAnchor>,
        fence: Option<&tn12_indexer_db::persist::DurableConsumerFence>,
    ) -> Result<()> {
        ensure!(sequence > 0, "invalid acknowledgement sequence");
        if let Some(anchor) = anchor {
            anchor.validate()?;
        }
        let (committed, retained): (i64, i64) = sqlx::query_as(
            "SELECT committed_sequence,retained_bytes FROM wrpc_inbox_streams WHERE stream=$1 FOR UPDATE",
        )
        .bind(&self.stream)
        .fetch_one(&mut **tx)
        .await?;
        if let Some(fence) = fence {
            fence.verify_locked(tx, &self.stream).await?;
        }
        if sequence <= committed {
            return Ok(());
        }
        let recovery_pending: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM wrpc_recovery_snapshots WHERE stream=$1)",
        ).bind(&self.stream).fetch_one(&mut **tx).await?;
        ensure!(
            !recovery_pending,
            "canonical recovery snapshot must be proved and completed atomically before acknowledgement"
        );
        ensure!(
            sequence
                == committed
                    .checked_add(1)
                    .context("inbox sequence exhausted")?,
            "out-of-order inbox acknowledgement"
        );
        let effect_pending: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM wrpc_inbox_effects WHERE stream=$1)")
                .bind(&self.stream)
                .fetch_one(&mut **tx)
                .await?;
        ensure!(
            !effect_pending,
            "pending effect must be completed atomically with acknowledgement"
        );
        let bytes: i32 = sqlx::query_scalar(
            "SELECT octet_length(payload) FROM wrpc_inbox_entries WHERE stream=$1 AND sequence=$2",
        )
        .bind(&self.stream)
        .bind(sequence)
        .fetch_one(&mut **tx)
        .await?;
        let retained = retained
            .checked_add(i64::from(bytes))
            .context("retained byte overflow")?;
        let retained = self.trim_replay_tail(tx, sequence, retained).await?;
        sqlx::query("UPDATE wrpc_inbox_streams SET committed_sequence=$2,pending_bytes=pending_bytes-$3,anchor=COALESCE($4,anchor),updated_at_ms=$5,retained_bytes=$6 WHERE stream=$1")
            .bind(&self.stream).bind(sequence).bind(i64::from(bytes))
            .bind(anchor.map(serde_json::to_value).transpose()?).bind(chrono::Utc::now().timestamp_millis())
            .bind(retained)
            .execute(&mut **tx).await?;
        Ok(())
    }

    /// Call before opening a connection, so an abrupt process/database failure
    /// leaves an interval to reconcile even when disconnect cannot be journaled.
    pub async fn open_recovery_interval(&self, reason: &str) -> Result<i64> {
        ensure!(
            !reason.is_empty() && reason.len() <= 128,
            "invalid recovery reason"
        );
        // Serialize with checkpoint reads and contiguous commits. Otherwise a
        // connection gap could appear between their final check and commit.
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='350ms'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout='2s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT stream FROM wrpc_inbox_streams WHERE stream=$1 FOR UPDATE")
            .bind(&self.stream)
            .fetch_one(&mut *tx)
            .await?;
        let id = sqlx::query_scalar("INSERT INTO wrpc_recovery_intervals(stream,opened_at_ms,anchor,reason) SELECT stream,$2,anchor,$3 FROM wrpc_inbox_streams WHERE stream=$1 RETURNING id")
            .bind(&self.stream).bind(chrono::Utc::now().timestamp_millis()).bind(reason)
            .fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_receipt_clock_uses_monotonic_elapsed_time() {
        let clock = MonotonicReceiptClock {
            epoch_ms: 123,
            started: std::time::Instant::now() - std::time::Duration::from_secs(2),
        };
        let copy = clock.clone();
        let first = copy.now_ms();
        assert!(first >= 2123);
        // The synthetic epoch is deliberately unrelated to current wall time.
        assert!(first < chrono::Utc::now().timestamp_millis() - 86_400_000);
        assert!(clock.now_ms() >= first);
    }

    async fn inbox(pool: PgPool, capacity: i64) -> DurableInbox {
        DurableInbox::open(pool, "testnet-10:watcher".into(), capacity)
            .await
            .unwrap()
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn bounded_batch_preserves_prefix_budget_and_consumer_fence(pool: PgPool) {
        use tn12_indexer_db::persist::DurableConsumerFence;
        let queue=inbox(pool.clone(),1024).await;
        let fence=DurableConsumerFence::claim(&pool,&queue.stream).await.unwrap();
        for (sequence,payload) in [(1,b"1234".as_slice()),(2,b"12345678".as_slice()),(3,b"1".as_slice())] {
            queue.append(sequence,payload,sequence).await.unwrap();
        }
        let prefix=queue.peek_pending_batch(0,3,64,7,&fence).await.unwrap();
        assert_eq!(prefix.iter().map(|e|e.sequence).collect::<Vec<_>>(),vec![1]);
        assert_eq!(prefix[0].payload,b"1234");
        // A smaller later receipt cannot jump past the oversized next receipt.
        assert!(queue.peek_pending_batch(1,3,64,7,&fence).await.unwrap().is_empty());
        let bounded=queue.peek_pending_batch(0,3,2,1024,&fence).await.unwrap();
        assert_eq!(bounded.iter().map(|e|e.sequence).collect::<Vec<_>>(),vec![1,2]);
        let bounded=queue.peek_pending_batch(0,2,64,1024,&fence).await.unwrap();
        assert_eq!(bounded.iter().map(|e|e.sequence).collect::<Vec<_>>(),vec![1,2]);
        assert_eq!(queue.checkpoint(&fence).await.unwrap().committed_sequence,0);
        for (frames,bytes) in [(0,1),(65,1),(1,0),(1,8*1024*1024+1)] {
            assert!(queue.peek_pending_batch(0,3,frames,bytes,&fence).await.is_err());
        }
        DurableConsumerFence::claim(&pool,&queue.stream).await.unwrap();
        assert!(queue.peek_pending_batch(0,3,64,1024,&fence).await.is_err());
        assert_eq!(queue.oldest().await.unwrap().unwrap().sequence,1);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn checkpoint_retains_gap_and_fences_replaced_reader(pool: PgPool) {
        use tn12_indexer_db::persist::DurableConsumerFence;
        let queue = inbox(pool.clone(), 1024).await;
        let fence = DurableConsumerFence::claim(&pool, &queue.stream)
            .await
            .unwrap();
        let empty = queue.checkpoint(&fence).await.unwrap();
        assert_eq!(empty.committed_sequence, 0);
        assert_eq!(empty.next_sequence, 1);
        assert_eq!(empty.anchor, None);
        assert!(!empty.uncertain_effect);
        queue.append(1, b"block", 1).await.unwrap();
        let anchor = ChainAnchor {
            network: "testnet-10".into(),
            block_hash: "11".repeat(32),
            blue_score: 10,
        };
        queue
            .acknowledge_fenced(1, Some(&anchor), &fence)
            .await
            .unwrap();
        queue.append(2, b"pending", 2).await.unwrap();
        queue.open_recovery_interval("reconnect").await.unwrap();
        let snapshot = queue.checkpoint(&fence).await.unwrap();
        assert_eq!(snapshot.committed_sequence, 1);
        assert_eq!(snapshot.next_sequence, 3);
        assert_eq!(snapshot.pending_bytes, 7);
        assert_eq!(snapshot.anchor, Some(anchor.clone()));
        assert_eq!(snapshot.open_recovery_intervals, 1);
        assert!(queue
            .acknowledge_contiguous(2, &anchor, &anchor, &fence)
            .await
            .is_err());
        assert_eq!(queue.oldest().await.unwrap().unwrap().sequence, 2);
        DurableConsumerFence::claim(&pool, &queue.stream)
            .await
            .unwrap();
        assert!(queue.checkpoint(&fence).await.is_err());
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn recovery_interval_serializes_with_checkpoint_commit(pool: PgPool) {
        use tn12_indexer_db::persist::DurableConsumerFence;
        let queue = std::sync::Arc::new(inbox(pool.clone(), 1024).await);
        let fence = DurableConsumerFence::claim(&pool, &queue.stream)
            .await
            .unwrap();
        queue.append(1, b"block", 1).await.unwrap();
        let anchor = ChainAnchor {
            network: "testnet-10".into(),
            block_hash: "11".repeat(32),
            blue_score: 10,
        };
        let mut tx = pool.begin().await.unwrap();
        queue
            .acknowledge_in_transaction(&mut tx, 1, Some(&anchor), Some(&fence))
            .await
            .unwrap();
        let other = queue.clone();
        let opening = tokio::spawn(async move { other.open_recovery_interval("reconnect").await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(!opening.is_finished());
        tx.commit().await.unwrap();
        let id = opening.await.unwrap().unwrap();
        let recorded: serde_json::Value =
            sqlx::query_scalar("SELECT anchor FROM wrpc_recovery_intervals WHERE id=$1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(recorded, serde_json::to_value(&anchor).unwrap());
        assert_eq!(
            queue
                .checkpoint(&fence)
                .await
                .unwrap()
                .open_recovery_intervals,
            1
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn replaced_consumer_cannot_acknowledge_pending_or_committed_receipts(pool: PgPool) {
        use tn12_indexer_db::persist::DurableConsumerFence;
        let queue = inbox(pool.clone(), 1024).await;
        queue.append(1, b"receipt", 1).await.unwrap();
        let old = DurableConsumerFence::claim(&pool, "testnet-10:watcher")
            .await
            .unwrap();
        let current = DurableConsumerFence::claim(&pool, "testnet-10:watcher")
            .await
            .unwrap();
        assert!(queue.acknowledge_fenced(1, None, &old).await.is_err());
        assert_eq!(queue.oldest().await.unwrap().unwrap().sequence, 1);
        queue.acknowledge_fenced(1, None, &current).await.unwrap();
        assert!(queue.acknowledge_fenced(1, None, &old).await.is_err());
        assert!(queue.oldest().await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn producer_lease_fences_concurrent_connections(pool: PgPool) {
        let queue = inbox(pool.clone(), 1024).await;
        let mut lease = queue.acquire_intake_lease().await.unwrap();
        let second = inbox(pool, 1024).await;
        assert!(second.acquire_intake_lease().await.is_err());
        let other = DurableInbox::open(queue.pool.clone(), "another-stream".into(), 1024)
            .await
            .unwrap();
        assert!(other
            .append_with_lease(&mut lease, 1, b"wrong stream", 10)
            .await
            .is_err());
        assert_eq!(
            queue
                .append_with_lease(&mut lease, 1, b"owned receipt", 10)
                .await
                .unwrap(),
            AppendOutcome::Stored
        );
        lease.close().await.unwrap();
        second
            .acquire_intake_lease()
            .await
            .unwrap()
            .close()
            .await
            .unwrap();
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn stalled_unlock_closes_session_and_preserves_failure(pool: PgPool) {
        let queue = inbox(pool, 1024).await;
        let mut lease = queue.acquire_intake_lease().await.unwrap();
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            sqlx::query("SELECT pg_sleep(0.2)").execute(&mut lease.connection)
        )
        .await
        .is_err());
        let error = lease
            .close_with_deadline(std::time::Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("unlock deadline"));
        // PostgreSQL may finish its already running statement before noticing
        // socket shutdown. Replacement intake remains fenced in that interval.
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Ok(next) = queue.acquire_intake_lease().await {
                    next.close().await.unwrap();
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn stalled_write_cannot_hold_cleanup_open(pool: PgPool) {
        use std::{sync::Arc, time::Duration};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let queue = inbox(pool.clone(), 1024).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let options = pool.connect_options();
        let upstream = (options.get_host().to_owned(), options.get_port());
        let (pause, mut paused) = tokio::sync::watch::channel(false);
        let ready = Arc::new(tokio::sync::Notify::new());
        let ready_proxy = ready.clone();
        let proxy = tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            let server = tokio::net::TcpStream::connect(upstream).await.unwrap();
            let (mut client_read, mut client_write) = client.into_split();
            let (mut server_read, mut server_write) = server.into_split();
            let forward = async {
                let mut bytes = [0; 8192];
                loop {
                    tokio::select! {
                        _ = paused.changed() => {
                            ready_proxy.notify_one();
                            std::future::pending::<()>().await;
                        },
                        n = client_read.read(&mut bytes) => {
                            let n = n.unwrap();
                            if n == 0 { break; }
                            server_write.write_all(&bytes[..n]).await.unwrap();
                        }
                    }
                }
            };
            let _ = tokio::join!(
                forward,
                tokio::io::copy(&mut server_read, &mut client_write)
            );
        });
        let mut connection = PgConnection::connect_with(
            &options
                .as_ref()
                .clone()
                .host("127.0.0.1")
                .port(port)
                .ssl_mode(sqlx::postgres::PgSslMode::Disable),
        )
        .await
        .unwrap();
        sqlx::query("SELECT pg_advisory_lock(hashtextextended('wrpc-intake:' || $1, 0))")
            .bind(&queue.stream)
            .execute(&mut connection)
            .await
            .unwrap();
        let mut lease = IntakeLease {
            connection,
            stream: queue.stream.clone(),
        };
        pause.send(true).unwrap();
        ready.notified().await;
        let payload = "x".repeat(32 * 1024 * 1024);
        assert!(tokio::time::timeout(
            Duration::from_millis(30),
            sqlx::query("SELECT length($1::text)")
                .bind(&payload)
                .execute(&mut lease.connection)
        )
        .await
        .is_err());
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            lease.close_with_deadline(Duration::from_millis(10)),
        )
        .await
        .expect("cleanup must terminate even when writes are partitioned");
        assert!(result.is_err());
        proxy.abort();
        let _ = proxy.await;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(next) = queue.acquire_intake_lease().await {
                    next.close().await.unwrap();
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn frame_limit_is_enforced_by_append_and_database(pool: PgPool) {
        let queue = inbox(pool.clone(), DURABLE_BACKLOG_BYTES).await;
        let oversized = vec![0_u8; NOTIFICATION_FRAME_BYTES + 1];
        assert!(queue.append(1, &oversized, 10).await.is_err());
        assert_eq!(queue.next_sequence().await.unwrap(), 1);
        let result = sqlx::query("INSERT INTO wrpc_inbox_entries(stream,sequence,received_at_ms,payload) VALUES($1,1,10,$2)")
            .bind(&queue.stream).bind(&oversized).execute(&pool).await;
        let error = result.unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().constraint(),
            Some("wrpc_inbox_payload_bound")
        );
        let empty = sqlx::query("INSERT INTO wrpc_inbox_entries(stream,sequence,received_at_ms,payload) VALUES($1,1,10,''::bytea)")
            .bind(&queue.stream).execute(&pool).await;
        assert!(empty.is_err());
        assert_eq!(
            queue
                .append(1, &oversized[..NOTIFICATION_FRAME_BYTES], 10)
                .await
                .unwrap(),
            AppendOutcome::Stored
        );
        assert_eq!(
            queue.oldest().await.unwrap().unwrap().payload.len(),
            NOTIFICATION_FRAME_BYTES
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn crash_and_duplicate_receipts_preserve_order(pool: PgPool) {
        let queue = inbox(pool.clone(), 1024).await;
        assert_eq!(
            queue.append(1, b"reorg payload", 10).await.unwrap(),
            AppendOutcome::Stored
        );
        let restarted = inbox(pool, 1024).await;
        assert_eq!(restarted.next_sequence().await.unwrap(), 2);
        assert_eq!(
            restarted.append(1, b"reorg payload", 11).await.unwrap(),
            AppendOutcome::AlreadyStored
        );
        assert!(restarted.append(1, b"different", 11).await.is_err());
        assert!(restarted.append(3, b"skipped", 11).await.is_err());
        restarted.append(2, b"next event", 12).await.unwrap();
        assert!(restarted.acknowledge(2, None).await.is_err());
        assert_eq!(
            restarted.oldest().await.unwrap().unwrap().payload,
            b"reorg payload"
        );
        restarted.acknowledge(1, None).await.unwrap();
        restarted.acknowledge(1, None).await.unwrap();
        assert_eq!(
            restarted.append(1, b"reorg payload", 13).await.unwrap(),
            AppendOutcome::AlreadyCommitted
        );
        assert_eq!(restarted.oldest().await.unwrap().unwrap().sequence, 2);
        restarted.acknowledge(2, None).await.unwrap();
        assert!(restarted.oldest().await.unwrap().is_none());
    }
    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn capacity_preserves_payload_and_recovery_anchor(pool: PgPool) {
        let queue = inbox(pool.clone(), 4).await;
        queue.append(1, b"aaaa", 10).await.unwrap();
        let anchor = ChainAnchor {
            network: "testnet-10".into(),
            block_hash: "ab".repeat(32),
            blue_score: 123,
        };
        queue.acknowledge(1, Some(&anchor)).await.unwrap();
        queue.append(2, b"bbbb", 11).await.unwrap();
        for _ in 0..2 {
            assert_eq!(
                queue.append(3, b"c", 12).await.unwrap(),
                AppendOutcome::CapacityReached
            );
        }
        assert_eq!(queue.next_sequence().await.unwrap(), 3);
        assert_eq!(queue.oldest().await.unwrap().unwrap().payload, b"bbbb");
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT anchor FROM wrpc_recovery_intervals WHERE verified_at_ms IS NULL",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(rows, vec![serde_json::to_value(&anchor).unwrap()]);
        queue.acknowledge(2, None).await.unwrap();
        assert_eq!(
            queue.append(3, b"c", 13).await.unwrap(),
            AppendOutcome::Stored
        );
        let pending: i64 = sqlx::query_scalar("SELECT pending_bytes FROM wrpc_inbox_streams")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(pending, 1);
    }
    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn connection_intent_survives_without_receiving_a_notification(pool: PgPool) {
        let queue = inbox(pool.clone(), 1024).await;
        queue.open_recovery_interval("connect").await.unwrap();
        drop(queue);
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM wrpc_recovery_intervals WHERE verified_at_ms IS NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn concurrent_append_retries_charge_capacity_once(pool: PgPool) {
        let first = inbox(pool.clone(), 4).await;
        let retry = inbox(pool.clone(), 4).await;
        let (a, b) = tokio::join!(first.append(1, b"body", 1), retry.append(1, b"body", 1));
        let outcomes = [a.unwrap(), b.unwrap()];
        assert!(outcomes.contains(&AppendOutcome::Stored));
        assert!(outcomes.contains(&AppendOutcome::AlreadyStored));
        let state: (i64, i64, i64) = sqlx::query_as(
            "SELECT next_sequence,committed_sequence,pending_bytes FROM wrpc_inbox_streams",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state, (2, 0, 4));
        let invalid = ChainAnchor {
            network: "testnet-10".into(),
            block_hash: "invalid".into(),
            blue_score: 2,
        };
        assert!(first.acknowledge(1, Some(&invalid)).await.is_err());
        assert_eq!(first.oldest().await.unwrap().unwrap().sequence, 1);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn processed_tail_survives_restart_without_reappearing_as_pending(pool: PgPool) {
        let queue = inbox(pool.clone(), 64).await;
        for sequence in 1..=6 {
            queue.append(sequence, b"body", sequence).await.unwrap();
        }
        for sequence in 1..=5 {
            queue.acknowledge(sequence, None).await.unwrap();
        }
        // Limit 16 bytes, trimmed to 12 after receipt five. Pending six survives.
        let restarted = inbox(pool.clone(), 64).await;
        assert_eq!(restarted.oldest().await.unwrap().unwrap().sequence, 6);
        assert_eq!(
            restarted
                .replay_tail_after(0)
                .await
                .unwrap()
                .unwrap()
                .sequence,
            3
        );
        assert_eq!(
            restarted
                .replay_tail_after(3)
                .await
                .unwrap()
                .unwrap()
                .sequence,
            4
        );
        assert_eq!(
            restarted
                .replay_tail_after(4)
                .await
                .unwrap()
                .unwrap()
                .sequence,
            5
        );
        assert!(restarted.replay_tail_after(5).await.unwrap().is_none());
        let bytes: (i64, i64) =
            sqlx::query_as("SELECT pending_bytes,retained_bytes FROM wrpc_inbox_streams")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(bytes, (4, 12));
        assert_eq!(
            restarted.append(7, &[0; 49], 7).await.unwrap(),
            AppendOutcome::CapacityReached
        );
        restarted.acknowledge(5, None).await.unwrap();
        let after: (i64, i64) =
            sqlx::query_as("SELECT pending_bytes,retained_bytes FROM wrpc_inbox_streams")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(after, bytes);
    }
    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn smaller_restart_capacity_trims_only_processed_cache_rows(pool: PgPool) {
        let queue = inbox(pool.clone(), 1024).await;
        queue.append(1, &[0; 128], 1).await.unwrap();
        queue.acknowledge(1, None).await.unwrap();
        queue.append(2, b"pending", 2).await.unwrap();
        let smaller = inbox(pool, 16).await;
        assert!(smaller.replay_tail_after(0).await.unwrap().is_none());
        assert_eq!(smaller.oldest().await.unwrap().unwrap().payload, b"pending");
        assert_eq!(
            smaller.append(3, b"next", 3).await.unwrap(),
            AppendOutcome::Stored
        );
    }
}

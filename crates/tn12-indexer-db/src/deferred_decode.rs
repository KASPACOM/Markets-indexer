//! Read-side visibility for retained, undecoded application transactions.
use anyhow::Result;
use serde::Serialize;
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeferredDecodeSummary {
    pub pending: i64,
    pub oldest_pending_at_ms: Option<i64>,
    pub retained_bytes: i64,
    pub byte_limit: i64,
    pub generation: i64,
}

pub async fn summary(pool: &PgPool) -> Result<DeferredDecodeSummary> {
    let (pending,oldest_pending_at_ms,retained_bytes,byte_limit,generation)=sqlx::query_as(
        "SELECT pending_count,(SELECT first_seen_at_ms FROM indexer_deferred_decodes WHERE status='pending' ORDER BY first_seen_at_ms LIMIT 1),retained_bytes,byte_limit,generation FROM indexer_deferred_decode_capacity WHERE singleton"
    ).fetch_one(pool).await?;
    Ok(DeferredDecodeSummary {
        pending,
        oldest_pending_at_ms,
        retained_bytes,
        byte_limit,
        generation,
    })
}

/// A read model must not present the last successfully decoded graph as current.
pub async fn ensure_family_complete(conn: &mut sqlx::PgConnection, id: &[u8]) -> Result<()> {
    let pending:bool=sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM indexer_deferred_decodes WHERE status='pending' AND covenant_ids @> ARRAY[$1]::bytea[])"
    ).bind(id).fetch_one(conn).await?;
    anyhow::ensure!(
        !pending,
        "covenant decoding incomplete: retained transactions await a supported decoder"
    );
    Ok(())
}

/// Stable chain content, excluding REST hydration and observation metadata.
pub fn evidence_identity(tx: &tn12_indexer_core::RestTransaction) -> serde_json::Value {
    serde_json::json!({
        "txid":tx.transaction_id.to_ascii_lowercase(),"version":tx.version,
        "payload":tx.payload.as_deref().unwrap_or(""),
        "inputs":tx.inputs.iter().map(|i|serde_json::json!([
            i.previous_outpoint_hash.to_ascii_lowercase(),i.previous_outpoint_index,
            i.signature_script.to_ascii_lowercase()
        ])).collect::<Vec<_>>(),
        "outputs":tx.outputs.iter().map(|o|serde_json::json!([
            o.index,o.amount,o.script_public_key.to_ascii_lowercase(),
            o.canonical_covenant_id(),o.covenant_authorizing_input()
        ])).collect::<Vec<_>>()
    })
}

/// Same-source transaction and accepting-block evidence. Construct only from a
/// fresh observation; headers and source identity are checked by the REST adapter.
pub struct CanonicalDecodeProof {
    txid: Vec<u8>,
    block_hash: Vec<u8>,
    observed_at_ms: i64,
    created: std::time::Instant,
}
impl CanonicalDecodeProof {
    pub fn verify(
        retained: &tn12_indexer_core::RestTransaction,
        source: &tn12_indexer_core::RestTransaction,
        block: &crate::persist::AcceptingBlockEvidence,
        source_tip: u64,
        observed_at_ms: i64,
    ) -> Result<Self> {
        anyhow::ensure!(
            source.is_accepted
                && retained.is_accepted
                && evidence_identity(retained) == evidence_identity(source),
            "source does not prove retained transaction content"
        );
        let hash = hex::decode(
            retained
                .accepting_block_hash
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("missing retained acceptance"))?,
        )?;
        anyhow::ensure!(
            block.is_chain_block
                && block.hash == hash
                && source.accepting_block_hash == retained.accepting_block_hash
                && source.accepting_block_blue_score == Some(block.blue_score)
                && retained.accepting_block_blue_score == Some(block.blue_score)
                && source_tip.saturating_sub(block.blue_score) >= 1000,
            "source acceptance is changed, unproven or immature"
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64;
        anyhow::ensure!(
            observed_at_ms <= now && now - observed_at_ms <= 15_000,
            "stale deferred acceptance observation"
        );
        Ok(Self {
            txid: hex::decode(&retained.transaction_id)?,
            block_hash: hash,
            observed_at_ms,
            created: std::time::Instant::now(),
        })
    }
    pub(crate) fn ensure_fresh(&self) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64;
        anyhow::ensure!(
            self.created.elapsed() <= std::time::Duration::from_secs(15)
                && now >= self.observed_at_ms
                && now - self.observed_at_ms <= 15_000,
            "deferred verification expired"
        );
        Ok(())
    }
    pub(crate) fn txid(&self) -> &[u8] {
        &self.txid
    }
    pub(crate) fn block_hash(&self) -> &[u8] {
        &self.block_hash
    }
    pub(crate) fn observed_at_ms(&self) -> i64 {
        self.observed_at_ms
    }
}


/// One retry at a time per settled worker. Reserve the next attempt before
/// contacting REST so process crashes cannot create a tight retry loop.
pub async fn claim_due(pool: &PgPool, now_ms: i64) -> Result<Option<(i64, serde_json::Value)>> {
    Ok(sqlx::query_as(
        "WITH candidate AS (SELECT sequence FROM indexer_deferred_decodes \
         WHERE status='pending' AND (next_retry_at_ms <= $1 OR last_attempt_revision IS DISTINCT FROM $2) \
         ORDER BY next_retry_at_ms,sequence LIMIT 1 FOR UPDATE SKIP LOCKED) \
         UPDATE indexer_deferred_decodes d SET attempts=d.attempts+1,last_attempt_revision=$2, \
         next_retry_at_ms=$1 + LEAST(3600000::bigint,60000::bigint * (1::bigint << LEAST(d.attempts,6)::int)) \
         FROM candidate c WHERE d.sequence=c.sequence RETURNING d.sequence,d.raw_transaction"
    ).bind(now_ms).bind(tn12_indexer_decoder::revision()).fetch_optional(pool).await?)
}

pub async fn record_retry_error(pool: &PgPool, sequence: i64, error: &str) -> Result<()> {
    sqlx::query("UPDATE indexer_deferred_decodes SET last_error=$2 WHERE sequence=$1 AND status='pending'")
        .bind(sequence).bind(error.chars().take(4000).collect::<String>()).execute(pool).await?;
    Ok(())
}


impl DeferredDecodeSummary {
    pub fn write_metrics(&self, output: &mut String, now_ms: i64) {
        use std::fmt::Write;
        output.push_str("# HELP tn10_indexer_decoding_pending Retained application transactions awaiting verified decoding.\n# TYPE tn10_indexer_decoding_pending gauge\n");
        let _=writeln!(output,"tn10_indexer_decoding_pending {}",self.pending);
        output.push_str("# HELP tn10_indexer_decoding_oldest_age_seconds Age from first retention, unchanged by retries.\n# TYPE tn10_indexer_decoding_oldest_age_seconds gauge\n");
        if let Some(first)=self.oldest_pending_at_ms {
            let _=writeln!(output,"tn10_indexer_decoding_oldest_age_seconds {}",now_ms.saturating_sub(first).max(0) / 1000);
        } else if self.pending == 0 {
            output.push_str("tn10_indexer_decoding_oldest_age_seconds 0\n");
        }
    }
}

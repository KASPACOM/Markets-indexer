//! Independent, sampled wRPC-receipt-to-public-API latency evidence.
//! Only the local disposable journal is written; node and API access is read-only.
//! This samples accepted transactions with a P2SH output, not every KCC20 path.
use anyhow::{ensure, Context, Result};
use kaspa_wrpc_client::prelude::Notification;
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tn12_indexer_crawl::{
    bounded_notification::decode_notification,
    bounded_wrpc_intake::journal_connection,
    durable_inbox::{DurableInbox, MonotonicReceiptClock},
};

const MAX_PROBES: usize = 4;
const BUCKETS_MS: [u64; 9] = [100, 250, 500, 1000, 1500, 2000, 5000, 10000, 15000];

fn emit(value: serde_json::Value) {
    println!("{value}");
}

async fn probe(
    client: reqwest::Client,
    clock: MonotonicReceiptClock,
    txid: String,
    accepting_hash: String,
    received_ms: i64,
    block_time_ms: Option<u64>,
) -> serde_json::Value {
    let started = std::time::Instant::now();
    let mut last_status = None;
    loop {
        let response = client
            .get(format!("https://tn10-indexer.kaspa.com/tx/{txid}"))
            .query(&[(
                "latency_probe",
                chrono::Utc::now().timestamp_millis().to_string(),
            )])
            .header("Cache-Control", "no-cache, no-store")
            .send()
            .await;
        let mut queryable = false;
        if let Ok(mut response) = response {
            last_status = Some(response.status().as_u16());
            if response.status().is_success() {
                queryable = read_actions_response(&mut response, &txid, &accepting_hash).await;
            }
        }
        let now = clock.now_ms();
        if queryable || started.elapsed() >= Duration::from_secs(15) {
            return json!({"event":"queryability_sample", "scope":"accepted_p2sh_output",
                "txid":txid,"accepting_block_hash":accepting_hash,
                "accepted_notification_received_at_ms":received_ms,
                "query_completed_at_ms":now,"queryable":queryable,"last_http_status":last_status,
                "notification_to_queryable_upper_bound_ms":queryable.then_some(now.saturating_sub(received_ms).saturating_add(1)),
                "accepting_block_age_ms":block_time_ms.map(|t| now.saturating_sub(t as i64)),
                "clock_regression":now<received_ms,"timing_clock":"shared_process_monotonic",
                "provisional_until_reorg_check":true});
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let database = std::env::var("TN10_CAPTURE_DATABASE_URL").context("local journal required")?;
    let url = reqwest::Url::parse(&database)?;
    ensure!(
        url.host_str() == Some("127.0.0.1")
            && url.port() == Some(55443)
            && url.path().starts_with("/tn10_wrpc_capture_"),
        "disposable local journal only"
    );
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&database)
        .await?;
    tn12_indexer_db::migrate(&pool).await?;
    let clock = MonotonicReceiptClock::new();
    let evidence = Evidence::open(pool.clone()).await?;
    let inbox = Arc::new(
        DurableInbox::open(pool, "testnet-10:queryability".into(), 128 * 1024 * 1024)
            .await?
            .with_monotonic_receipt_clock(clock.clone()),
    );
    // A restarted observer cannot reconstruct a continuous measurement from a
    // partially consumed stream. Retain that journal and use a fresh database.
    ensure!(
        inbox.next_sequence().await? == 1,
        "observer requires a fresh journal"
    );
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let wake = Arc::new(tokio::sync::Notify::new());
    let source = tokio::spawn(journal_connection(
        "wss://tn10-node.kaspa.com/testnet-10",
        "testnet-10",
        inbox.clone(),
        wake.clone(),
        stop_rx,
    ));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    let mut probes = tokio::task::JoinSet::<serde_json::Value>::new();
    let mut receipts = 0_u64;
    let mut notifications = 0_u64;
    let mut transaction_bodies = 0_u64;
    let mut accepted_ids = 0_u64;
    let mut last_histogram = std::time::Instant::now();
    let started = std::time::Instant::now();
    emit(
        json!({"event":"observer_started","at_ms":chrono::Utc::now().timestamp_millis(),
        "sample_modulus":64,"max_concurrent_probes":MAX_PROBES,
        "database_stop_threshold_bytes":512*1024*1024,"database_size_check_interval_seconds":60,
        "receipt_hard_limit":1_000_000,
        "note":"Measures from this observer's durable wRPC receipt, not consensus acceptance time; covers P2SH-output samples only."}),
    );
    loop {
        while let Some(result) = probes.try_join_next() {
            let mut record = result.context("queryability probe task failed")?;
            let valid = evidence.finish(&record).await?;
            record["reorg_invalidated"] = json!(!valid);
            emit(record);
        }
        if last_histogram.elapsed() >= Duration::from_secs(60) {
            let database_bytes: i64 =
                sqlx::query_scalar("SELECT pg_database_size(current_database())")
                    .fetch_one(&evidence.pool)
                    .await?;
            ensure!(
                database_bytes <= 512 * 1024 * 1024,
                "observer database capacity reached; measurement incomplete"
            );
            let totals = evidence.histogram().await?;
            emit(
                json!({"event":"queryability_histogram","at_ms":chrono::Utc::now().timestamp_millis(),
                "cumulative_buckets_ms":BUCKETS_MS,"totals":totals,"pending_probes":probes.len(),
                "notifications":notifications,"transaction_bodies":transaction_bodies,"accepted_ids":accepted_ids}),
            );
            last_histogram = std::time::Instant::now();
        }
        if source.is_finished() {
            source.await??;
            anyhow::bail!("observer source ended before measurement deadline");
        }
        if started.elapsed() >= Duration::from_secs(26 * 3600) {
            let _ = stop_tx.send(true);
            source.await??;
            while let Some(record) = probes.join_next().await {
                let mut record = record?;
                record["reorg_invalidated"] = json!(!evidence.finish(&record).await?);
                emit(record);
            }
            let totals = evidence.histogram().await?;
            let pending_intake = inbox.oldest().await?.is_some();
            let database_bytes: i64 =
                sqlx::query_scalar("SELECT pg_database_size(current_database())")
                    .fetch_one(&evidence.pool)
                    .await?;
            let complete = measurement_complete(&totals, pending_intake, database_bytes);
            emit(
                json!({"event":"observer_stopped","reason":"measurement_deadline",
                "sample_measurement_complete":complete,"totals":totals,
                "pending_intake":pending_intake,"database_bytes":database_bytes}),
            );
            ensure!(
                complete,
                "observer stopped with incomplete sample measurement"
            );
            return Ok(());
        }
        for sample in evidence.claim_ready(MAX_PROBES - probes.len()).await? {
            probes.spawn(probe(
                client.clone(),
                clock.clone(),
                sample.txid,
                sample.hash,
                sample.received_ms,
                None,
            ));
        }
        let Some(entry) = inbox.oldest().await? else {
            tokio::select! { _=wake.notified()=>{}, _=tokio::time::sleep(Duration::from_millis(50))=>{} }
            continue;
        };
        notifications += 1;
        match decode_notification(&entry.payload)? {
            Notification::BlockAdded(n) => {
                let block = n.block;
                transaction_bodies += block.transactions.len() as u64;
                for tx in &block.transactions {
                    // Node notifications may omit verbose data. Derive the
                    // consensus ID exactly as the live watcher does.
                    let id = match &tx.verbose_data {
                        Some(v) => v.transaction_id.to_string(),
                        None => {
                            let consensus: kaspa_consensus_core::tx::Transaction = tx
                                .clone()
                                .try_into()
                                .context("derive notification transaction ID")?;
                            consensus.id().to_string()
                        }
                    };
                    if !sampled(&id) {
                        continue;
                    }
                    let eligible = tx.outputs.iter().any(|o| {
                        let s = o.script_public_key.script();
                        s.len() == 35 && s[..2] == [0xaa, 0x20] && s[34] == 0x87
                    });
                    evidence.classify(&id, eligible).await?;
                }
            }
            Notification::VirtualChainChanged(n) => {
                if !n.removed_chain_block_hashes.is_empty() {
                    let removed: Vec<_> = n
                        .removed_chain_block_hashes
                        .iter()
                        .map(ToString::to_string)
                        .collect();
                    evidence.invalidate(&removed).await?;
                    emit(
                        json!({"event":"source_reorg","received_at_ms":entry.received_at_ms,
                        "removed_hashes":n.removed_chain_block_hashes.iter().map(ToString::to_string).collect::<Vec<_>>()}),
                    );
                }
                for group in n.accepted_transaction_ids.iter() {
                    let hash = group.accepting_block_hash.to_string();
                    accepted_ids += group.accepted_transaction_ids.len() as u64;
                    for id in &group.accepted_transaction_ids {
                        let id = id.to_string();
                        if !sampled(&id) {
                            continue;
                        }
                        ensure!(
                            receipts < 1_000_000,
                            "observer receipt capacity reached; measurement incomplete"
                        );
                        if !evidence
                            .receive(&id, &hash, entry.received_at_ms, None)
                            .await?
                        {
                            continue;
                        }
                        receipts += 1;
                    }
                }
            }
            _ => anyhow::bail!("unexpected observer notification"),
        }
        inbox.acknowledge(entry.sequence, None).await?;
        for sample in evidence.claim_ready(MAX_PROBES - probes.len()).await? {
            probes.spawn(probe(
                client.clone(),
                clock.clone(),
                sample.txid,
                sample.hash,
                sample.received_ms,
                None,
            ));
        }
    }
}

// Durable deduplication outlives the bounded body cache. Reorg invalidation
// remains effective even if a probe finishes after its removal notification.
struct Evidence {
    pool: sqlx::PgPool,
}
impl Evidence {
    async fn open(pool: sqlx::PgPool) -> Result<Self> {
        sqlx::raw_sql("CREATE TABLE IF NOT EXISTS observer_receipts(txid text NOT NULL, block_hash text NOT NULL, received_ms bigint NOT NULL, eligible boolean, scheduled boolean NOT NULL DEFAULT false, invalidated boolean NOT NULL DEFAULT false, completed boolean NOT NULL DEFAULT false, latency_ms bigint, PRIMARY KEY(txid,block_hash)); CREATE INDEX IF NOT EXISTS observer_receipts_block ON observer_receipts(block_hash); CREATE TABLE IF NOT EXISTS observer_removed_blocks(block_hash text PRIMARY KEY); CREATE TABLE IF NOT EXISTS observer_sampled_bodies(txid text PRIMARY KEY, eligible boolean NOT NULL); CREATE INDEX IF NOT EXISTS observer_receipts_pending ON observer_receipts(received_ms) WHERE eligible AND NOT scheduled AND NOT invalidated;").execute(&pool).await?;
        Ok(Self { pool })
    }
    async fn receive(&self, id: &str, hash: &str, at: i64, eligible: Option<bool>) -> Result<bool> {
        Ok(sqlx::query("INSERT INTO observer_receipts(txid,block_hash,received_ms,eligible) SELECT $1,$2,$3,COALESCE($4,(SELECT eligible FROM observer_sampled_bodies WHERE txid=$1)) WHERE NOT EXISTS(SELECT 1 FROM observer_removed_blocks WHERE block_hash=$2) ON CONFLICT DO NOTHING").bind(id).bind(hash).bind(at).bind(eligible).execute(&self.pool).await?.rows_affected()==1)
    }
    async fn classify(&self, id: &str, eligible: bool) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO observer_sampled_bodies VALUES($1,$2) ON CONFLICT DO NOTHING")
            .bind(id)
            .bind(eligible)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE observer_receipts SET eligible=$2 WHERE txid=$1 AND eligible IS NULL")
            .bind(id)
            .bind(eligible)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
    async fn claim_ready(&self, limit: usize) -> Result<Vec<Sample>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        ensure!(limit <= MAX_PROBES, "observer scheduling limit exceeded");
        let rows:Vec<(String,String,i64)>=sqlx::query_as("WITH ready AS (SELECT txid,block_hash FROM observer_receipts WHERE eligible AND NOT scheduled AND NOT invalidated ORDER BY received_ms LIMIT $1 FOR UPDATE SKIP LOCKED) UPDATE observer_receipts r SET scheduled=true FROM ready WHERE r.txid=ready.txid AND r.block_hash=ready.block_hash RETURNING r.txid,r.block_hash,r.received_ms")
            .bind(limit as i64).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|(txid, hash, received_ms)| Sample {
                txid,
                hash,
                received_ms,
            })
            .collect())
    }
    async fn invalidate(&self, hashes: &[String]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO observer_removed_blocks SELECT unnest($1::text[]) ON CONFLICT DO NOTHING",
        )
        .bind(hashes)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE observer_receipts SET invalidated=true WHERE block_hash=ANY($1::text[])",
        )
        .bind(hashes)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
    async fn finish(&self, r: &serde_json::Value) -> Result<bool> {
        let latency = if r["clock_regression"] == false {
            r["notification_to_queryable_upper_bound_ms"].as_i64()
        } else {
            None
        };
        Ok(sqlx::query("UPDATE observer_receipts SET completed=true,latency_ms=$3 WHERE txid=$1 AND block_hash=$2 AND NOT invalidated").bind(r["txid"].as_str().context("sample txid missing")?).bind(r["accepting_block_hash"].as_str().context("sample hash missing")?).bind(latency).execute(&self.pool).await?.rows_affected()==1)
    }
    async fn histogram(&self) -> Result<serde_json::Value> {
        Ok(sqlx::query_scalar("SELECT jsonb_build_object('counts',jsonb_build_array(count(*) FILTER(WHERE latency_ms<=100),count(*) FILTER(WHERE latency_ms<=250),count(*) FILTER(WHERE latency_ms<=500),count(*) FILTER(WHERE latency_ms<=1000),count(*) FILTER(WHERE latency_ms<=1500),count(*) FILTER(WHERE latency_ms<=2000),count(*) FILTER(WHERE latency_ms<=5000),count(*) FILTER(WHERE latency_ms<=10000),count(*) FILTER(WHERE latency_ms<=15000)),'successes',count(latency_ms),'failures',count(*) FILTER(WHERE completed AND latency_ms IS NULL),'eligible_pending',count(*) FILTER(WHERE eligible AND NOT completed),'unclassified',count(*) FILTER(WHERE eligible IS NULL)) FROM observer_receipts WHERE NOT invalidated").fetch_one(&self.pool).await?)
    }
}

struct Sample {
    txid: String,
    hash: String,
    received_ms: i64,
}
fn measurement_complete(
    totals: &serde_json::Value,
    pending_intake: bool,
    database_bytes: i64,
) -> bool {
    !pending_intake
        && totals["eligible_pending"] == 0
        && totals["unclassified"] == 0
        && totals["failures"] == 0
        && totals["successes"].as_u64().unwrap_or(0) > 0
        && database_bytes <= 512 * 1024 * 1024
}
async fn read_actions_response(response: &mut reqwest::Response, txid: &str, hash: &str) -> bool {
    let mut bytes = Vec::new();
    let complete = loop {
        match response.chunk().await {
            Ok(None) => break true,
            Ok(Some(chunk)) if bytes.len() + chunk.len() <= 2 * 1024 * 1024 => {
                bytes.extend_from_slice(&chunk)
            }
            _ => break false,
        }
    };
    complete
        && serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.as_array().map(|a| actions_match(a, txid, hash)))
            .unwrap_or(false)
}

fn actions_match(actions: &[serde_json::Value], txid: &str, hash: &str) -> bool {
    !actions.is_empty()
        && actions
            .iter()
            .all(|a| a["txidHex"] == txid && a["blockHashHex"] == hash)
}

fn sampled(txid: &str) -> bool {
    txid.len() == 64
        && txid.is_ascii()
        && u8::from_str_radix(&txid[..2], 16).is_ok_and(|b| b % 64 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn reorg_invalidates_completed_running_and_delayed_samples(pool: sqlx::PgPool) {
        let evidence = Evidence::open(pool).await.unwrap();
        assert!(evidence
            .receive("tx", "block", 100, Some(true))
            .await
            .unwrap());
        let record = json!({"txid":"tx","accepting_block_hash":"block","clock_regression":false,"notification_to_queryable_upper_bound_ms":250});
        assert!(evidence.finish(&record).await.unwrap());
        assert_eq!(evidence.histogram().await.unwrap()["successes"], 1);
        evidence
            .invalidate(&["block".into(), "removed-before-receipt".into()])
            .await
            .unwrap();
        assert!(!evidence.finish(&record).await.unwrap());
        assert_eq!(evidence.histogram().await.unwrap()["successes"], 0);
        assert!(!evidence
            .receive("late", "removed-before-receipt", 200, Some(true))
            .await
            .unwrap());
    }
    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn durable_join_survives_reordering_and_new_consumer_instance(pool: sqlx::PgPool) {
        let evidence = Evidence::open(pool.clone()).await.unwrap();
        assert!(evidence
            .receive("late-body", "block", 100, None)
            .await
            .unwrap());
        assert!(evidence.claim_ready(4).await.unwrap().is_empty());
        evidence.classify("late-body", true).await.unwrap();
        let resumed = Evidence::open(pool).await.unwrap();
        assert!(!resumed
            .receive("late-body", "block", 200, None)
            .await
            .unwrap());
        let ready = resumed.claim_ready(4).await.unwrap();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].received_ms, 100);
        assert!(resumed.claim_ready(4).await.unwrap().is_empty());
        resumed.classify("early-body", true).await.unwrap();
        assert!(resumed
            .receive("early-body", "second", 300, None)
            .await
            .unwrap());
        assert_eq!(resumed.claim_ready(4).await.unwrap()[0].received_ms, 300);
    }
    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn scheduling_caps_concurrency_without_dropping_receipts(pool: sqlx::PgPool) {
        let evidence = Evidence::open(pool).await.unwrap();
        for i in 0..10 {
            assert!(evidence
                .receive(&i.to_string(), "block", i, Some(true))
                .await
                .unwrap());
        }
        assert_eq!(evidence.claim_ready(4).await.unwrap().len(), 4);
        assert!(evidence.claim_ready(0).await.unwrap().is_empty());
        assert_eq!(evidence.claim_ready(4).await.unwrap().len(), 4);
        assert_eq!(evidence.claim_ready(4).await.unwrap().len(), 2);
        assert!(evidence.claim_ready(5).await.is_err());
        assert_eq!(evidence.histogram().await.unwrap()["eligible_pending"], 10);
    }
    #[test]
    fn stale_or_unrelated_actions_do_not_count_as_queryable() {
        assert!(actions_match(
            &[json!({"txidHex":"tx","blockHashHex":"block"})],
            "tx",
            "block"
        ));
        assert!(!actions_match(
            &[json!({"txidHex":"tx","blockHashHex":"old"})],
            "tx",
            "block"
        ));
        assert!(!actions_match(&[], "tx", "block"));
    }
    #[test]
    fn final_measurement_rejects_pending_missing_and_failed_evidence() {
        let good = json!({"eligible_pending":0,"unclassified":0,"failures":0,"successes":1});
        assert!(measurement_complete(&good, false, 1));
        assert!(!measurement_complete(&good, true, 1));
        assert!(!measurement_complete(&good, false, 512 * 1024 * 1024 + 1));
        for field in ["eligible_pending", "unclassified", "failures"] {
            let mut bad = good.clone();
            bad[field] = json!(1);
            assert!(!measurement_complete(&bad, false, 1));
        }
        let mut empty = good;
        empty["successes"] = json!(0);
        assert!(!measurement_complete(&empty, false, 1));
    }
    #[tokio::test]
    async fn truncated_http_body_cannot_count_complete_json_prefix_as_queryable() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await.unwrap();
            let body = json!([{"txidHex":"tx","blockHashHex":"block"}]).to_string();
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 9999\r\nConnection: close\r\n\r\n{body}").as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let mut response = reqwest::get(format!("http://{address}")).await.unwrap();
        assert!(!read_actions_response(&mut response, "tx", "block").await);
        server.await.unwrap();
    }
    #[test]
    fn sample_is_fixed_hash_subset() {
        assert!(sampled(&format!("40{}", "a".repeat(62))));
        assert!(!sampled(&format!("41{}", "a".repeat(62))));
        assert!(!sampled("bad"));
    }
}

//! Disposable local diagnostic. Never connects to a remote database.
use anyhow::{ensure, Result};
use blake2::{Blake2b512, Digest};
use serde_json::{json, Value};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};
use tn12_indexer_core::{RestTransaction, RestTxOutput};
use tn12_indexer_db::{Persister, PgPersister};

#[derive(Clone)]
struct TimingSubscriber(std::sync::Arc<std::sync::Mutex<Vec<Value>>>);
struct TimingFields(serde_json::Map<String, Value>);
impl tracing::field::Visit for TimingFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let text = format!("{value:?}");
        self.0.insert(
            field.name().into(),
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        );
    }
}
impl tracing::Subscriber for TimingSubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.level() <= &tracing::Level::INFO
            && metadata.target().starts_with("tn12_indexer_db")
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = TimingFields(serde_json::Map::new());
        event.record(&mut fields);
        if fields.0.contains_key("bulk_transactions") {
            self.0.lock().unwrap().push(Value::Object(fields.0));
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

async fn fingerprints(pool: &sqlx::PgPool) -> Result<Value> {
    let mut result = serde_json::Map::new();
    for (table, query) in [
        (
            "covenant_actions",
            r#"DECLARE benchmark_rows NO SCROLL CURSOR FOR SELECT (to_jsonb(t) - 'id')::text COLLATE "C" AS payload FROM covenant_actions t ORDER BY payload"#,
        ),
        (
            "covenant_utxos",
            r#"DECLARE benchmark_rows NO SCROLL CURSOR FOR SELECT (to_jsonb(t))::text COLLATE "C" AS payload FROM covenant_utxos t ORDER BY payload"#,
        ),
        (
            "covenant_summaries",
            r#"DECLARE benchmark_rows NO SCROLL CURSOR FOR SELECT (to_jsonb(t) - 'updated_at_ms')::text COLLATE "C" AS payload FROM covenant_summaries t ORDER BY payload"#,
        ),
        (
            "covenant_action_summaries",
            r#"DECLARE benchmark_rows NO SCROLL CURSOR FOR SELECT (to_jsonb(t) - 'updated_at_ms')::text COLLATE "C" AS payload FROM covenant_action_summaries t ORDER BY payload"#,
        ),
        (
            "covenant_template_summaries",
            r#"DECLARE benchmark_rows NO SCROLL CURSOR FOR SELECT (to_jsonb(t) - 'updated_at_ms')::text COLLATE "C" AS payload FROM covenant_template_summaries t ORDER BY payload"#,
        ),
    ] {
        let mut conn = pool.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *conn)
            .await?;
        sqlx::query("SET LOCAL work_mem='4MB'")
            .execute(&mut *conn)
            .await?;
        // Sort complete canonical row content, including ties. The server may
        // spill the sort; neither side aggregates the entire table in memory.
        sqlx::query(query).execute(&mut *conn).await?;
        let mut digest = Blake2b512::new();
        let mut rows = 0_u64;
        loop {
            let batch: Vec<String> = sqlx::query_scalar("FETCH FORWARD 256 FROM benchmark_rows")
                .fetch_all(&mut *conn)
                .await?;
            if batch.is_empty() {
                break;
            }
            for row in batch {
                digest.update((row.len() as u64).to_be_bytes());
                digest.update(row.as_bytes());
                rows += 1;
            }
        }
        conn.rollback().await?;
        result.insert(
            table.into(),
            json!({"rows":rows,"blake2b512":hex::encode(digest.finalize())}),
        );
    }
    Ok(Value::Object(result))
}

fn cgroup_io() -> Result<Option<String>> {
    match std::env::var("TN10_BENCH_IO_STAT_PATH") {
        Ok(path) => {
            ensure!(
                path.starts_with("/sys/fs/cgroup/system.slice/docker-")
                    && path.ends_with(".scope/io.stat"),
                "expected isolated Docker cgroup path"
            );
            Ok(Some(std::fs::read_to_string(path)?))
        }
        Err(_) => Ok(None),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let timings = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
    tracing::subscriber::set_global_default(TimingSubscriber(timings.clone()))?;
    let args: Vec<String> = std::env::args().collect();
    ensure!(
        args.len() == 4,
        "usage: benchmark <local-db> <seed|run> <source-json>"
    );
    let db = &args[1];
    ensure!(
        db.starts_with("tn10_fullwriter_budget_")
            && db.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'),
        "disposable local DB required"
    );
    let wal_compression =
        std::env::var("TN10_BENCH_WAL_COMPRESSION").unwrap_or_else(|_| "off".into());
    ensure!(
        matches!(wal_compression.as_str(), "off" | "lz4"),
        "unsupported diagnostic WAL compression"
    );
    let socket =
        std::env::var("TN10_BENCH_PG_SOCKET").unwrap_or_else(|_| "/var/run/postgresql".into());
    ensure!(
        matches!(socket.as_str(), "/var/run/postgresql" | "/dev/shm"),
        "local Unix socket required"
    );
    let port = std::env::var("TN10_BENCH_PG_PORT")
        .unwrap_or_else(|_| "5432".into())
        .parse::<u16>()?;
    let batch_size = std::env::var("TN10_BENCH_BATCH_SIZE")
        .unwrap_or_else(|_| "16".into())
        .parse::<usize>()?;
    ensure!(
        matches!(batch_size, 16 | 32 | 64),
        "benchmark batch must be 16, 32, or 64"
    );
    // This diagnostic runs as the local postgres account over its Unix socket.
    let options = PgConnectOptions::new()
        .host(&socket)
        .port(port)
        .username("postgres")
        .database(db)
        .options([("wal_compression", wal_compression.as_str())]);
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect_with(options)
        .await?;
    tn12_indexer_db::migrate(&pool).await?;
    let actual_wal_compression: String = sqlx::query_scalar("SHOW wal_compression")
        .fetch_one(&pool)
        .await?;
    ensure!(
        actual_wal_compression == wal_compression,
        "WAL compression setting mismatch"
    );
    let blocks: Vec<Value> = serde_json::from_slice(&std::fs::read(&args[3])?)?;
    let mut txs = Vec::new();
    for block in &blocks {
        for value in block["transactions"].as_array().unwrap() {
            let mut tx: RestTransaction = serde_json::from_value(value.clone())?;
            ensure!(tx.is_accepted, "unaccepted fixture transaction");
            tx.normalize_missing_output_indexes();
            tx.accepting_block_hash = Some(block["hash"].as_str().unwrap().into());
            tx.accepting_block_blue_score = block["blue_score"].as_u64();
            tx.accepting_block_time = block["timestamp"].as_u64();
            tx.block_time = tx.accepting_block_time.unwrap();
            txs.push(tx);
        }
    }
    // Mirror scan.rs candidate selection, including spend-only input/address matches.
    // Keep all source transactions for parent seeding and explicit diagnostic comparison.
    let source_transactions = txs.len();
    let is_p2sh = |script: &str| {
        hex::decode(script).is_ok_and(|bytes| tn12_indexer_core::is_p2sh_script_pubkey(&bytes))
    };
    let candidate = |tx: &RestTransaction| {
        tx.outputs.iter().any(|out| {
            out.script_public_key_type
                .as_deref()
                .is_some_and(|kind| kind.eq_ignore_ascii_case("scripthash"))
                || is_p2sh(&out.script_public_key)
        }) || tx.inputs.iter().any(|input| {
            input
                .previous_outpoint_script
                .as_deref()
                .is_some_and(&is_p2sh)
                || input
                    .previous_outpoint_address
                    .as_deref()
                    .is_some_and(|address| {
                        address
                            .split_once(':')
                            .is_some_and(|(_, payload)| payload.starts_with('p'))
                    })
        })
    };
    let scanner_candidates = txs.iter().filter(|tx| candidate(tx)).count();
    let include_non_candidates =
        std::env::var("TN10_BENCH_INCLUDE_NON_CANDIDATES").as_deref() == Ok("1");
    if args[2] == "run" && !include_non_candidates {
        txs.retain(candidate);
    }
    let native_genesis = match std::env::var("TN10_BENCH_NATIVE_GENESIS").ok().as_deref() {
        None | Some("0") => false,
        Some("1") => true,
        _ => anyhow::bail!("TN10_BENCH_NATIVE_GENESIS must be 0 or 1"),
    };
    let writer = PgPersister::new(pool.clone())
        .with_native_genesis_bulk(native_genesis)
        .with_generic_bulk_persist(true)
        .with_generic_bulk_max_txs(batch_size)
        .with_generic_writer_budget(
            std::env::var("TN10_BENCH_WRITER_BUDGET").as_deref() == Ok("1"),
        );
    match args[2].as_str() {
        "seed" => {
            tn12_indexer_db::migrate(&pool).await?;
            let ids: BTreeSet<_> = txs.iter().map(|t| t.transaction_id.as_str()).collect();
            let mut parents: BTreeMap<String, RestTransaction> = BTreeMap::new();
            for tx in &txs {
                for input in &tx.inputs {
                    if ids.contains(input.previous_outpoint_hash.as_str()) {
                        continue;
                    }
                    let id = &input.previous_outpoint_hash;
                    let parent = parents
                        .entry(id.clone())
                        .or_insert_with(|| RestTransaction {
                            transaction_id: id.clone(),
                            is_accepted: true,
                            accepting_block_hash: Some(id.clone()),
                            accepting_block_blue_score: Some(
                                blocks[0]["blue_score"].as_u64().unwrap() - 1,
                            ),
                            accepting_block_time: Some(
                                blocks[0]["timestamp"].as_u64().unwrap() - 1,
                            ),
                            block_time: blocks[0]["timestamp"].as_u64().unwrap() - 1,
                            ..Default::default()
                        });
                    let index = input.previous_outpoint_index.parse()?;
                    let output = RestTxOutput {
                        transaction_id: id.clone(),
                        index,
                        amount: input
                            .previous_outpoint_amount
                            .ok_or_else(|| anyhow::anyhow!("unresolved amount"))?,
                        script_public_key: input
                            .previous_outpoint_script
                            .clone()
                            .ok_or_else(|| anyhow::anyhow!("unresolved script"))?,
                        script_public_key_address: input.previous_outpoint_address.clone(),
                        ..Default::default()
                    };
                    if let Some(old) = parent.outputs.iter().find(|o| o.index == index) {
                        ensure!(
                            old.amount == output.amount
                                && old.script_public_key == output.script_public_key,
                            "inconsistent parent"
                        );
                    } else {
                        parent.outputs.push(output);
                    }
                }
            }
            let parents: Vec<_> = parents.into_values().collect();
            writer.persist_batch(&parents).await?;
            sqlx::raw_sql("ANALYZE").execute(&pool).await?;
            println!(
                "{}",
                json!({"phase":"seed", "parents":parents.len(), "transactions":txs.len()})
            );
        }
        "seed-context" => {
            ensure!(txs.len() <= 4096, "bounded prior context required");
            let stats = writer.persist_batch(&txs).await?;
            sqlx::raw_sql("ANALYZE").execute(&pool).await?;
            println!(
                "{}",
                json!({"phase":"seed-context","transactions":txs.len(),"actions_inserted":stats.actions_inserted})
            );
        }
        "run" => {
            let initial_state = fingerprints(&pool).await?;
            let checkpoint = std::env::var("TN10_BENCH_CHECKPOINT").as_deref() == Ok("1");
            if checkpoint {
                sqlx::query("CHECKPOINT").execute(&pool).await?;
            }
            let database_oid: i64 = sqlx::query_scalar(
                "SELECT oid::bigint FROM pg_database WHERE datname=current_database()",
            )
            .fetch_one(&pool)
            .await?;
            let before: String = sqlx::query_scalar("SELECT pg_current_wal_insert_lsn()::text")
                .fetch_one(&pool)
                .await?;
            let io_before = cgroup_io()?;
            let start = Instant::now();
            let stats = writer.persist_batch(&txs).await?;
            let elapsed = start.elapsed().as_secs_f64();
            let io_after = cgroup_io()?;
            let first_persist_timing = timings.lock().unwrap().first().cloned();
            let after: String = sqlx::query_scalar("SELECT pg_current_wal_insert_lsn()::text")
                .fetch_one(&pool)
                .await?;
            let wal: String =
                sqlx::query_scalar("SELECT pg_wal_lsn_diff($2::pg_lsn, $1::pg_lsn)::text")
                    .bind(&before)
                    .bind(&after)
                    .fetch_one(&pool)
                    .await?;
            let fingerprint: Value = sqlx::query_scalar("SELECT jsonb_build_object('actions', (SELECT count(*) FROM covenant_actions), 'utxos',(SELECT count(*) FROM covenant_utxos), 'spent',(SELECT count(*) FROM covenant_utxos WHERE spent_by_txid IS NOT NULL), 'indexes_bytes',pg_indexes_size('covenant_actions'))").fetch_one(&pool).await?;
            let persisted_state = fingerprints(&pool).await?;
            let replay = writer.persist_batch(&txs).await?;
            let duplicate_state = fingerprints(&pool).await?;
            ensure!(
                duplicate_state == persisted_state,
                "duplicate replay changed full state"
            );
            ensure!(
                replay.actions_inserted == 0 && replay.utxos_inserted == 0,
                "duplicate replay changed row counts"
            );
            let mut reverted = BTreeSet::new();
            for tx in txs.iter().rev() {
                let hash = tx.accepting_block_hash.as_ref().unwrap();
                if reverted.insert(hash) {
                    writer.revert_block(&hex::decode(hash)?).await?;
                }
            }
            let reverted_state = fingerprints(&pool).await?;
            ensure!(
                reverted_state == initial_state,
                "reorg did not restore initial state"
            );
            let replay_after_reorg = writer.persist_batch(&txs).await?;
            let restored_state = fingerprints(&pool).await?;
            ensure!(
                restored_state == persisted_state,
                "reorg replay changed full state"
            );
            ensure!(
                replay_after_reorg.actions_inserted == stats.actions_inserted,
                "reorg replay action mismatch"
            );
            println!(
                "{}",
                json!({"phase":"run","database":db,"cgroup_io_before":io_before,"cgroup_io_after":io_after,"first_persist_timing":first_persist_timing,"wal_compression":actual_wal_compression,"checkpoint_before_persist":checkpoint,"wal_start_lsn":before,"wal_end_lsn":after,"database_oid":database_oid,"source_transactions":source_transactions,"scanner_candidates":scanner_candidates,"include_non_candidates":include_non_candidates,"elapsed_s":elapsed,"transactions":txs.len(),"tps":txs.len() as f64/elapsed,"actions_inserted":stats.actions_inserted,"utxos_inserted":stats.utxos_inserted,"utxos_spent":stats.utxos_spent,"wal_bytes_cluster_wide":wal,"fingerprint":fingerprint,"duplicate_replay_ok":true,"reorg_replay_actions_ok":true,"phase_hashes":{"initial":initial_state,"persisted":persisted_state,"duplicate":duplicate_state,"reverted":reverted_state,"restored":restored_state}})
            );
        }
        _ => anyhow::bail!("unsupported mode"),
    }
    pool.close().await;
    Ok(())
}

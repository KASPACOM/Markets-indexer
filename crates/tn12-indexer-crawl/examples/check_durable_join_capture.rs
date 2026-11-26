//! Read-only replay of locally captured frames. This checks cache capacity and
//! join availability; it does not persist transactions or prove pipeline SLOs.
use anyhow::{ensure, Context, Result};
use kaspa_addresses::Prefix;
use kaspa_wrpc_client::prelude::Notification;
use sqlx::Row;
use std::time::Instant;
use tn12_indexer_crawl::{
    bounded_notification::decode_notification,
    durable_join::{DurableJoin, JOIN_CACHE_BYTES},
};

#[tokio::main]
async fn main() -> Result<()> {
    let url = std::env::var("DATABASE_URL").context("local capture DATABASE_URL required")?;
    let parsed = reqwest::Url::parse(&url)?;
    ensure!(
        parsed.host_str() == Some("127.0.0.1") && parsed.port() == Some(55443),
        "probe accepts only the isolated local capture database"
    );
    let stream = std::env::var("CAPTURE_STREAM")?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await?;
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    let end: i64 =
        sqlx::query_scalar("SELECT committed_sequence FROM wrpc_inbox_streams WHERE stream=$1")
            .bind(&stream)
            .fetch_one(&mut *tx)
            .await?;
    let mut cache = DurableJoin::new(JOIN_CACHE_BYTES)?;
    let mut previous = 0i64;
    let mut frames = 0usize;
    let mut vcc = 0usize;
    let mut ready = 0usize;
    let mut warm_vcc = 0usize;
    let mut warm_ready = 0usize;
    let mut work_us = 0u128;
    let mut high_water = 0usize;
    for _ in 0..10_000 {
        let row = sqlx::query("SELECT sequence,payload FROM wrpc_inbox_entries WHERE stream=$1 AND sequence>$2 AND sequence<=$3 ORDER BY sequence LIMIT 1")
            .bind(&stream).bind(previous).bind(end).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            break;
        };
        let sequence: i64 = row.try_get("sequence")?;
        ensure!(
            previous == 0 || sequence == previous + 1,
            "capture has a missing receipt"
        );
        let payload: Vec<u8> = row.try_get("payload")?;
        let started = Instant::now();
        let event = decode_notification(&payload)?;
        // Reprocess every event twice to exercise duplicate traffic. There are
        // no database effects in this probe and no durable acknowledgements.
        for repeat in 0..2 {
            match &event {
                Notification::BlockAdded(n) => cache.remember_block(&n.block, Prefix::Testnet)?,
                Notification::VirtualChainChanged(n) => {
                    let complete = cache.resolve(&n.accepted_transaction_ids)?.is_some();
                    if repeat == 0 {
                        vcc += 1;
                        ready += usize::from(complete);
                        if frames >= 500 {
                            warm_vcc += 1;
                            warm_ready += usize::from(complete);
                        }
                    }
                }
                _ => anyhow::bail!("unexpected captured notification"),
            }
        }
        work_us += started.elapsed().as_micros();
        high_water = high_water.max(cache.charged_bytes());
        previous = sequence;
        frames += 1;
    }
    tx.rollback().await?;
    println!(
        "{}",
        serde_json::json!({"frames":frames,"double_processing_us":work_us,
        "vcc":vcc,"joined":ready,"warm_vcc":warm_vcc,"warm_joined":warm_ready,
        "cache_high_water_bytes":high_water,"limit_bytes":JOIN_CACHE_BYTES,
        "last_sequence":previous,"scope":"cache only; no writer or pipeline SLO claim"})
    );
    Ok(())
}

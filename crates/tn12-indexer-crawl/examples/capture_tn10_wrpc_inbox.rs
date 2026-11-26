//! Read-only TN10 notification capture into a disposable local PostgreSQL DB.
//! Does not start an indexer consumer or touch the canonical DEV database.
use anyhow::{ensure, Context, Result};
use std::{sync::Arc, time::Duration};
use tn12_indexer_crawl::{bounded_wrpc_intake::journal_connection, durable_inbox::DurableInbox};

#[tokio::main]
async fn main() -> Result<()> {
    let database =
        std::env::var("TN10_CAPTURE_DATABASE_URL").context("local capture database required")?;
    let parsed = reqwest::Url::parse(&database)?;
    ensure!(
        parsed.host_str() == Some("127.0.0.1")
            && parsed.port() == Some(55443)
            && parsed.path().starts_with("/tn10_wrpc_capture_"),
        "capture only permits disposable local databases"
    );
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .connect(&database)
        .await?;
    tn12_indexer_db::migrate(&pool).await?;
    if std::env::args().any(|arg| arg == "--decode") {
        use futures::TryStreamExt;
        let mut entries = sqlx::query_as::<_, (i64, Vec<u8>)>(
            "SELECT sequence,payload FROM wrpc_inbox_entries ORDER BY sequence",
        )
        .fetch(&pool);
        let mut decoded = 0_u64;
        while let Some((sequence, bytes)) = entries.try_next().await? {
            tn12_indexer_crawl::bounded_notification::decode_notification(&bytes)
                .with_context(|| format!("decode captured sequence {sequence}"))?;
            decoded += 1;
        }
        println!("decoded_notifications={decoded}");
        return Ok(());
    }
    let inbox = Arc::new(
        DurableInbox::open(pool.clone(), "testnet-10:capture".into(), 256 * 1024 * 1024).await?,
    );
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let deadline = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(600)).await;
        let _ = stop_tx.send(true);
    });
    let result = journal_connection(
        "wss://tn10-node.kaspa.com/testnet-10",
        "testnet-10",
        inbox,
        Arc::new(tokio::sync::Notify::new()),
        stop_rx,
    )
    .await;
    deadline.abort();
    let (count, bytes): (i64, i64) = sqlx::query_as(
        "SELECT count(*),coalesce(sum(octet_length(payload)),0)::bigint FROM wrpc_inbox_entries",
    )
    .fetch_one(&pool)
    .await?;
    println!(
        "captured_notifications={count} captured_bytes={bytes} stopped={:?}",
        result.as_ref().err().map(|e| format!("{e:#}"))
    );
    result
}

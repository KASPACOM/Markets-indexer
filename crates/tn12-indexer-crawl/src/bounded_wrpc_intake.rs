//! Direct wRPC intake avoids the SDK's unbounded notification relay/notifier.
//! This transport only journals; covenant persistence belongs to the consumer.
use crate::durable_inbox::{AppendOutcome, DurableInbox};
use anyhow::{ensure, Context, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use futures::{SinkExt, StreamExt};
use kaspa_rpc_core::api::ops::RpcApiOps;
use kaspa_wrpc_client::prelude::*;
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::{
    tungstenite::{protocol::WebSocketConfig, Message},
    MaybeTlsStream, WebSocketStream,
};
use workflow_rpc::messages::borsh::{BorshReqHeader, BorshServerMessage, ServerMessageKind};
use workflow_serializer::prelude::Serializable;

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

const MAX_WIRE_BYTES: usize = crate::durable_inbox::NOTIFICATION_FRAME_BYTES;
/// One socket per invocation. Dropping it cannot trigger a reconnect. Header
/// errors leave recovery open; transaction payload decoding belongs to the consumer.
pub async fn journal_connection(
    endpoint: &str,
    network: &str,
    inbox: Arc<DurableInbox>,
    wake_consumer: Arc<tokio::sync::Notify>,
    stop: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut producer_lease =
        tokio::time::timeout(Duration::from_secs(5), inbox.acquire_intake_lease())
            .await
            .context("durable intake producer lease deadline")??;
    let result = journal_with_lease(
        endpoint,
        network,
        inbox,
        wake_consumer,
        stop,
        &mut producer_lease,
    )
    .await;
    let closed = producer_lease.close().await;
    match result {
        Err(error) => {
            if let Err(close_error) = closed {
                tracing::warn!(%close_error, "intake lease close failed after operation error");
            }
            Err(error)
        }
        Ok(()) => closed,
    }
}

async fn journal_with_lease(
    endpoint: &str,
    network: &str,
    inbox: Arc<DurableInbox>,
    wake_consumer: Arc<tokio::sync::Notify>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    producer_lease: &mut crate::durable_inbox::IntakeLease,
) -> Result<()> {
    inbox.open_recovery_interval("connection_started").await?;
    let mut next = inbox.next_sequence().await?;
    let (mut socket, _) = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_tungstenite::connect_async_with_config(
            endpoint,
            Some(WebSocketConfig {
                max_message_size: Some(MAX_WIRE_BYTES),
                max_frame_size: Some(MAX_WIRE_BYTES),
                max_write_buffer_size: 1024 * 1024,
                ..Default::default()
            }),
            true,
        ),
    )
    .await
    .context("intake connect deadline exceeded")??;
    let operation = async {
        let info: Serializable<GetServerInfoResponse> = call(
            &mut socket,
            1,
            RpcApiOps::GetServerInfo,
            Serializable(GetServerInfoRequest {}),
            &inbox,
            producer_lease,
            &mut next,
            &wake_consumer,
        )
        .await?;
        ensure!(
            info.0.network_id.to_string() == network && info.0.is_synced,
            "intake node network mismatch or unsynced"
        );
        let _: Serializable<SubscribeResponse> = call(
            &mut socket,
            2,
            RpcApiOps::Subscribe,
            Serializable(Scope::BlockAdded(BlockAddedScope {})),
            &inbox,
            producer_lease,
            &mut next,
            &wake_consumer,
        )
        .await?;
        let _: Serializable<SubscribeResponse> = call(
            &mut socket,
            3,
            RpcApiOps::Subscribe,
            Serializable(Scope::VirtualChainChanged(VirtualChainChangedScope {
                include_accepted_transaction_ids: true,
            })),
            &inbox,
            producer_lease,
            &mut next,
            &wake_consumer,
        )
        .await?;
        loop {
            let bytes = receive(&mut socket).await?;
            let response =
                route_and_journal(&bytes, &inbox, producer_lease, &mut next, &wake_consumer)
                    .await?;
            ensure!(response.is_none(), "unexpected intake RPC response");
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let result = if *stop.borrow() {
        Ok(())
    } else {
        tokio::select! {
            result = operation => result,
            _ = stop.changed() => Ok(()),
        }
    };
    // Drop closes the only transport; no SDK queues, relay tasks or reconnect loop.
    result
}

async fn receive(socket: &mut Socket) -> Result<Vec<u8>> {
    loop {
        match socket
            .next()
            .await
            .context("intake disconnected; continuity verification required")??
        {
            Message::Binary(bytes) => return Ok(bytes),
            Message::Ping(_) => socket.flush().await?,
            Message::Pong(_) => {}
            _ => anyhow::bail!(
                "unexpected intake frame or disconnect; continuity verification required"
            ),
        }
    }
}

async fn route_and_journal(
    bytes: &[u8],
    inbox: &DurableInbox,
    lease: &mut crate::durable_inbox::IntakeLease,
    next: &mut i64,
    wake: &tokio::sync::Notify,
) -> Result<Option<(u64, Vec<u8>)>> {
    ensure!(
        bytes.len() <= MAX_WIRE_BYTES,
        "intake frame exceeds wire limit"
    );
    let message: BorshServerMessage<RpcApiOps, u64> =
        bytes.try_into().context("invalid intake frame")?;
    match message.header.kind {
        ServerMessageKind::Notification => {
            ensure!(
                message.header.id.is_none(),
                "notification contains response ID"
            );
            let op = message
                .header
                .op
                .context("notification missing operation")?;
            ensure!(
                matches!(
                    op,
                    RpcApiOps::BlockAddedNotification | RpcApiOps::VirtualChainChangedNotification
                ),
                "unexpected intake notification operation"
            );
            // Preserve the exact encoded frame before decoding transaction vectors.
            // The SDK decoder allocates from wire lengths; the consumer must apply
            // a bounded decoder and validate operation/body agreement before ack.
            let outcome = tokio::time::timeout(
                Duration::from_secs(2),
                inbox.append_with_lease(lease, *next, bytes, inbox.receipt_time_ms()),
            )
            .await
            .context("durable intake database deadline exceeded")??;
            ensure!(
                outcome != AppendOutcome::CapacityReached,
                "durable intake capacity reached"
            );
            *next = next.checked_add(1).context("intake sequence exhausted")?;
            wake.notify_one();
            Ok(None)
        }
        ServerMessageKind::Success => Ok(Some((
            message.header.id.context("response missing ID")?,
            message.payload.to_vec(),
        ))),
        ServerMessageKind::Error => anyhow::bail!("intake RPC returned an error"),
    }
}

async fn call<Req: BorshSerialize, Resp: BorshDeserialize>(
    socket: &mut Socket,
    id: u64,
    op: RpcApiOps,
    request: Req,
    inbox: &DurableInbox,
    lease: &mut crate::durable_inbox::IntakeLease,
    next: &mut i64,
    wake: &tokio::sync::Notify,
) -> Result<Resp> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut bytes = borsh::to_vec(&BorshReqHeader::new(Some(id), op))?;
        bytes.extend_from_slice(&borsh::to_vec(&request)?);
        socket.send(Message::Binary(bytes)).await?;
        loop {
            let bytes = receive(socket).await?;
            if let Some((response_id, payload)) =
                route_and_journal(&bytes, inbox, lease, next, wake).await?
            {
                ensure!(response_id == id, "unexpected intake response ID");
                let response =
                    std::result::Result::<Resp, workflow_rpc::error::ServerError>::try_from_slice(
                        &payload,
                    )
                    .context("invalid intake RPC response")??;
                return Ok(response);
            }
        }
    })
    .await
    .context("intake RPC deadline exceeded")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn invalid_headers_stop_and_opaque_payloads_are_preserved(pool: sqlx::PgPool) {
        use workflow_rpc::messages::borsh::BorshServerMessageHeader;
        let inbox = DurableInbox::open(pool.clone(), "malformed".into(), 1_000_000)
            .await
            .unwrap();
        inbox
            .open_recovery_interval("connection_started")
            .await
            .unwrap();
        let mut lease = inbox.acquire_intake_lease().await.unwrap();
        let mut next = 1;
        let wake = tokio::sync::Notify::new();
        for bytes in [vec![255], vec![0; MAX_WIRE_BYTES + 1]] {
            assert!(
                route_and_journal(&bytes, &inbox, &mut lease, &mut next, &wake)
                    .await
                    .is_err()
            );
            assert_eq!(next, 1);
            assert!(inbox.oldest().await.unwrap().is_none());
        }
        let header = BorshServerMessageHeader::<RpcApiOps, u64>::new(
            None,
            ServerMessageKind::Notification,
            Some(RpcApiOps::BlockAddedNotification),
        );
        let mut wire_frame = borsh::to_vec(&header).unwrap();
        wire_frame.extend_from_slice(&[255; 8]);
        assert!(
            route_and_journal(&wire_frame, &inbox, &mut lease, &mut next, &wake)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(inbox.oldest().await.unwrap().unwrap().payload, wire_frame);
        assert_eq!(next, 2);
        let committed: i64 = sqlx::query_scalar(
            "SELECT committed_sequence FROM wrpc_inbox_streams WHERE stream='malformed'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            committed, 0,
            "receipt must not acknowledge consumer processing"
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn disconnect_does_not_reconnect(pool: sqlx::PgPool) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_async(socket).await.unwrap();
            let _ = websocket.next().await;
            websocket.close(None).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(500), listener.accept())
                    .await
                    .is_err()
            );
        });
        let inbox = Arc::new(
            DurableInbox::open(pool, "disconnect".into(), 1_000_000)
                .await
                .unwrap(),
        );
        let (_stop, stop) = tokio::sync::watch::channel(false);
        assert!(journal_connection(
            &endpoint,
            "testnet-10",
            inbox.clone(),
            Arc::new(tokio::sync::Notify::new()),
            stop
        )
        .await
        .is_err());
        assert!(inbox.oldest().await.unwrap().is_none());
        inbox
            .acquire_intake_lease()
            .await
            .unwrap()
            .close()
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    #[ignore = "read-only TN10 subscription smoke; requires TN10_WRPC_TEST_URL"]
    async fn full_durable_inbox_stops_intake_and_preserves_interval(pool: sqlx::PgPool) {
        let endpoint = std::env::var("TN10_WRPC_TEST_URL").unwrap();
        let queue = Arc::new(
            DurableInbox::open(pool.clone(), "testnet-10:full".into(), 1)
                .await
                .unwrap(),
        );
        let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            journal_connection(
                &endpoint,
                "testnet-10",
                queue.clone(),
                Arc::new(tokio::sync::Notify::new()),
                stop_rx,
            ),
        )
        .await
        .unwrap();
        assert!(format!("{:#}", result.unwrap_err()).contains("capacity reached"));
        assert!(queue.oldest().await.unwrap().is_none());
        assert_eq!(queue.next_sequence().await.unwrap(), 1);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM wrpc_recovery_intervals WHERE stream='testnet-10:full' AND verified_at_ms IS NULL")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(count, 2);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    #[ignore = "read-only TN10 subscription smoke; requires TN10_WRPC_TEST_URL"]
    async fn live_notifications_are_journaled_before_delivery(pool: sqlx::PgPool) {
        let endpoint = std::env::var("TN10_WRPC_TEST_URL").unwrap();
        let queue = Arc::new(
            DurableInbox::open(pool, "testnet-10:smoke".into(), 1024 * 1024)
                .await
                .unwrap(),
        );
        let wake = Arc::new(tokio::sync::Notify::new());
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn({
            let queue = queue.clone();
            let wake = wake.clone();
            async move { journal_connection(&endpoint, "testnet-10", queue, wake, stop_rx).await }
        });
        let received = tokio::time::timeout(Duration::from_secs(15), wake.notified()).await;
        let _ = stop_tx.send(true);
        let stopped = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert!(received.is_ok(), "no durable notification: {stopped:?}");
        stopped.unwrap();
        queue
            .acquire_intake_lease()
            .await
            .unwrap()
            .close()
            .await
            .unwrap();
        let entry = queue.oldest().await.unwrap().unwrap();
        let frame: BorshServerMessage<RpcApiOps, u64> =
            entry.payload.as_slice().try_into().unwrap();
        assert!(matches!(frame.header.kind, ServerMessageKind::Notification));
        assert!(!frame.payload.is_empty());
        assert_eq!(entry.sequence, 1);
    }
}

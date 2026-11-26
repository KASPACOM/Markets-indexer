use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn paged_fetch_is_parallel_ordered_and_rejects_incomplete_pages(pool: sqlx::PgPool) {
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES('fetch-ready','{}',1)")
        .execute(&pool)
        .await
        .unwrap();
    let owner = PagedRecoveryOwner::claim(&pool, "fetch-ready", &[])
        .await
        .unwrap();
    let originals: Vec<_> = (1..=4)
        .map(|id| RestTransaction {
            transaction_id: format!("{id:064x}"),
            ..Default::default()
        })
        .collect();
    for failure in ["none", "identity", "missing_acceptance", "stale"] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(4));
        let expected = originals.clone();
        let server = tokio::spawn(async move {
            let mut handlers = Vec::new();
            for _ in 0..4 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let expected = expected.clone();
                let barrier = barrier.clone();
                handlers.push(tokio::spawn(async move {
                    let mut request=[0;8192];
                    let n=socket.read(&mut request).await.unwrap();
                    let request=String::from_utf8_lossy(&request[..n]);
                    let index=expected.iter().position(|body|request.contains(&body.transaction_id)).unwrap();
                    barrier.wait().await; // sequential fetch deadlocks the test
                    if index==0 { tokio::time::sleep(Duration::from_millis(100)).await; }
                    let mut body=serde_json::to_value(&expected[index]).unwrap();
                    if index==2 {
                        match failure {
                            "identity"=>body["transaction_id"]=serde_json::json!("ff".repeat(32)),
                            "missing_acceptance"=>{body.as_object_mut().unwrap().remove("is_accepted");},
                            _=>{}
                        }
                    }
                    let body=body.to_string();
                    let response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
                    let response=if failure=="stale" && index==2 {
                        response.replacen("HTTP/1.1 200 OK\r\n","HTTP/1.1 200 OK\r\nDate: Sat, 01 Jan 2000 00:00:00 GMT\r\nAge: 600\r\n",1)
                    } else {crate::source_observation::fresh_test_response(response)};
                    let _=socket.write_all(response.as_bytes()).await;
                }));
            }
            for handler in handlers {
                handler.await.unwrap();
            }
        });
        let follower = ChainTipFollower::new(
            RestClient::new(format!("http://{address}")).unwrap(),
            Arc::new(PgPersister::new(pool.clone())),
            pool.clone(),
            "fetch-cursor",
            TipFollowerConfig {
                hydrate_concurrency: 16,
                ..Default::default()
            },
        )
        .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            follower.fetch_paged_recovery_acceptances(&owner, &originals),
        )
        .await
        .unwrap();
        if failure == "none" {
            assert_eq!(
                result
                    .unwrap()
                    .iter()
                    .map(|body| &body.transaction_id)
                    .collect::<Vec<_>>(),
                originals
                    .iter()
                    .map(|body| &body.transaction_id)
                    .collect::<Vec<_>>()
            );
        } else {
            assert!(result.is_err(), "accepted {failure}");
        }
        server.await.unwrap();
        let mut oversized = originals.clone();
        oversized.push(originals[0].clone());
        assert!(follower
            .fetch_paged_recovery_acceptances(&owner, &oversized)
            .await
            .is_err());
    }
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT replayed_transactions FROM tn10_live_recovery_plans WHERE intent_key='fetch-ready'")
        .fetch_one(&pool).await.unwrap(),0);
}

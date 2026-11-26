use super::*;
use axum::{body::to_bytes, http::Request};
use tower::ServiceExt;

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn shadow_current_read_contracts_match_and_recovery_rejects_reads(pool: PgPool) {
    let fixture: Vec<RestTransaction> = serde_json::from_str(include_str!(
        "../../tn12-indexer-db/tests/fixtures/tn10-dense-generic-32.json"
    ))
    .unwrap();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    let mut tx = fixture[0].clone();
    tx.inputs.clear();
    tx.outputs.truncate(1);
    writer.persist_tx(&tx).await.unwrap();
    let state = test_state(
        Some(pool.clone()),
        api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 0),
    );
    let app = Router::new()
        .route("/covenants", get(list_covenants))
        .route("/utxos", get(list_active_utxos))
        .with_state(state);
    let routes = ["/utxos?limit=1", "/utxos?limit=2&offset=0"];
    let mut before = Vec::new();
    for route in routes {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(route).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        before.push(to_bytes(response.into_body(), 1024 * 1024).await.unwrap());
    }
    sqlx::raw_sql(tn12_indexer_db::shadow::MIGRATION)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE shadow_v2.control SET ready=true,source_validated=true,checkpoint_hash=$1,checkpoint_score=10,history_start_score=10,history_start_ms=1000")
        .bind(vec![0u8;32]).execute(&pool).await.unwrap();
    sqlx::query("SELECT shadow_v2.install_guards()")
        .execute(&pool)
        .await
        .unwrap();
    let app = app.layer(middleware::from_fn_with_state(
        shadow::ShadowApi::new(pool.clone()).unwrap(),
        shadow::fence,
    ));
    for (route, expected) in routes.into_iter().zip(before) {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(route).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-shadow-generation"], "0");
        assert_eq!(
            to_bytes(response.into_body(), 1024 * 1024).await.unwrap(),
            expected
        );
    }
    for route in [
        "/covenants?from=1",
        "/covenants?%66rom=1",
        "/covenants",
        "/events",
        "/addresses/test/events",
        "/covenants/test/actions",
        "/kcc20/test/activity",
        "/events?from=1001",
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(route).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/utxos")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let epoch: i64 = sqlx::query_scalar("SELECT shadow_v2.acquire('test')")
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query("SELECT shadow_v2.begin_plan($1,$2,$3,20,ARRAY['ingestor','projection'],'[]')")
        .bind(epoch)
        .bind(vec![0u8; 32])
        .bind(vec![1u8; 32])
        .execute(&pool)
        .await
        .unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/utxos")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn shadow_current_read_contracts_bound_admission_and_release_timed_out_fences(pool: PgPool) {
    sqlx::raw_sql(tn12_indexer_db::shadow::MIGRATION)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE shadow_v2.control SET ready=true,source_validated=true,checkpoint_hash=$1,checkpoint_score=10,history_start_score=10,history_start_ms=1000")
        .bind(vec![0u8;32]).execute(&pool).await.unwrap();
    let small = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    let (started, mut receiver) = tokio::sync::mpsc::channel(1);
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let handler_pool = small.clone();
    let handler_release = release.clone();
    let app = Router::new()
        .route(
            "/utxos",
            get(move || {
                let pool = handler_pool.clone();
                let started = started.clone();
                let release = handler_release.clone();
                async move {
                    // The handler must still get a connection while its read fence is held.
                    sqlx::query("SELECT 1").execute(&pool).await.unwrap();
                    started.send(()).await.unwrap();
                    let _permit = release.acquire_owned().await.unwrap();
                    "ok"
                }
            }),
        )
        .layer(middleware::from_fn_with_state(
            shadow::ShadowApi::new(small.clone()).unwrap(),
            shadow::fence,
        ));
    let first = tokio::spawn(
        app.clone().oneshot(
            Request::builder()
                .uri("/utxos")
                .body(Body::empty())
                .unwrap(),
        ),
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/utxos")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    assert!(std::str::from_utf8(&body)
        .unwrap()
        .contains("shadow_api_busy"));
    release.add_permits(1);
    assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);

    let stalled = Router::new()
        .route(
            "/utxos",
            get(|| async { std::future::pending::<&'static str>().await }),
        )
        .layer(middleware::from_fn_with_state(
            shadow::ShadowApi::new(small.clone())
                .unwrap()
                .with_test_deadline(std::time::Duration::from_millis(100)),
            shadow::fence,
        ));
    let response = stalled
        .oneshot(
            Request::builder()
                .uri("/utxos")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    // A timeout must drop the SHARE lock, otherwise recovery cannot acquire it.
    let mut transaction = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query("SELECT * FROM shadow_v2.control FOR UPDATE")
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
    transaction.rollback().await.unwrap();
    small.close().await;
}

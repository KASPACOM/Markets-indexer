//! Execute the shipped binary against a real isolated SQLx database, with no node.
use serde_json::json;
use sqlx::{ConnectOptions, PgPool};
use tn12_indexer_core::RestTransaction;

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn offline_shadow_replay_publishes_and_is_receipt_idempotent(pool: PgPool) {
    sqlx::raw_sql(tn12_indexer_db::shadow::MIGRATION)
        .execute(&pool)
        .await
        .unwrap();
    let instance = "00000000-0000-0000-0000-000000000007";
    sqlx::query(
        "INSERT INTO shadow_v2.identity(network,instance_id) VALUES('testnet-10',$1::text::uuid)",
    )
    .bind(instance)
    .execute(&pool)
    .await
    .unwrap();
    let revision = option_env!("SHADOW_DECODER_REVISION");
    let seed_manifest = json!({"decoder_revision":revision.unwrap_or("unpinned"),
        "source_identity":{"decoder_revision":revision.unwrap_or("unpinned"),
        "genesis_hash":"f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370"}});
    let seed = vec![0u8; 32];
    sqlx::query("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) VALUES($1,0,0,'{}',0,true,0)")
        .bind(&seed).execute(&pool).await.unwrap();
    sqlx::query("UPDATE shadow_v2.control SET checkpoint_hash=$1,checkpoint_score=0,history_start_hash=$1,history_start_score=0,history_start_ms=0,seed_manifest=$2,ready=false")
        .bind(&seed).bind(&seed_manifest).execute(&pool).await.unwrap();
    sqlx::query("SELECT shadow_v2.install_guards()")
        .execute(&pool)
        .await
        .unwrap();
    let fixture: Vec<RestTransaction> = serde_json::from_str(include_str!(
        "../../tn12-indexer-db/tests/fixtures/tn10-dense-generic-32.json"
    ))
    .unwrap();
    let mut body = fixture[0].clone();
    body.inputs.clear();
    body.outputs.truncate(1);
    body.outputs[0].script_public_key = format!("aa20{}87", "72".repeat(32));
    body.outputs[0].script_public_key_address = None;
    let hash = body.accepting_block_hash.clone().unwrap();
    let target = hex::decode(&hash).unwrap();
    let plan = json!({"format":"tn10-shadow-plan/1","network":"testnet-10","decoder_revision":revision.unwrap_or("unpinned"),
        "instance_id":instance,"base_hash":hex::encode(seed),"target_hash":hash,"target_score":body.accepting_block_blue_score,
        "steps":[{"kind":"apply","evidence":body}]});
    let directory = std::env::temp_dir().join(format!(
        "shadow-replay-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let file = directory.join("plan.json");
    std::fs::write(&file, serde_json::to_vec(&plan).unwrap()).unwrap();
    let url = pool.connect_options().to_url_lossy().to_string();
    let invoke = || {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_tn10-shadow-indexer"));
        command
            .env("SHADOW_DATABASE_URL", &url)
            .env("SHADOW_INSTANCE_ID", instance)
            .arg("replay")
            .arg("--plan")
            .arg(&file);
        command
    };
    let output = invoke().output().await.unwrap();
    assert!(!output.status.success());
    if revision.is_none() {
        assert!(String::from_utf8_lossy(&output.stderr).contains("SHADOW_DECODER_REVISION"));
        std::fs::remove_dir_all(&directory).unwrap();
        return;
    }
    assert!(String::from_utf8_lossy(&output.stderr).contains("live source validation"));
    let unready: (bool, i64) = sqlx::query_as("SELECT ready,generation FROM shadow_v2.control")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(unready, (false, 0));
    // Model restoration of a previously activated snapshot, then reject a
    // decoder mismatch before either offline effects or a live node connection.
    sqlx::query("UPDATE shadow_v2.control SET source_validated=true,seed_manifest=jsonb_set(seed_manifest,'{decoder_revision}','\"another-decoder\"')")
        .execute(&pool).await.unwrap();
    let output = invoke().output().await.unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("seed decoder revision"));
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_tn10-shadow-indexer"))
        .env("SHADOW_DATABASE_URL", &url)
        .env("SHADOW_INSTANCE_ID", instance)
        .args(["run", "--once", "--wrpc-url", "ws://127.0.0.1:1"])
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("seed decoder revision"));
    sqlx::query("UPDATE shadow_v2.control SET seed_manifest=$1")
        .bind(&seed_manifest)
        .execute(&pool)
        .await
        .unwrap();
    for _ in 0..2 {
        let output = invoke().output().await.unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let state: (bool, i64, Vec<u8>) =
        sqlx::query_as("SELECT ready,generation,checkpoint_hash FROM shadow_v2.control")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(state, (true, 1, target));
    let outputs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE status='active'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(outputs > 0);
    let receipts:i64=sqlx::query_scalar("SELECT count(*) FROM shadow_v2.plans WHERE archive_digest IS NOT NULL AND status='completed'").fetch_one(&pool).await.unwrap();
    assert_eq!(receipts, 1);
    std::fs::remove_dir_all(directory).unwrap();
}

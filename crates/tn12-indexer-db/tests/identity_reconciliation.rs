use sqlx::PgPool;
use tn12_indexer_core::RestTransaction;
use tn12_indexer_db::{Persister, PgPersister};

fn child() -> RestTransaction {
    serde_json::from_str(include_str!("fixtures/tn10-identity-child.json")).unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_parent_must_not_create_a_false_genesis(pool: PgPool) {
    let writer = PgPersister::new(pool.clone());
    let result = writer.persist_tx(&child()).await;
    assert!(
        result.is_err(),
        "accepted child with unresolved P2SH parent became a false deploy"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM covenants")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count, 0,
        "failed identity resolution must roll back the transaction"
    );
}

const OLD: &str = "11f6ea263dea9104ff409e0b6eb575282c1c658599910cf652861f3226193d4e";
const OWNER: &str = "3613f72061dc5f0f46b488686017b11feeb50cf4787f0b8bc3e4004cc40f1b93";

fn proof() -> Vec<RestTransaction> {
    vec![
        serde_json::from_str(include_str!("fixtures/tn10-identity-parent.json")).unwrap(),
        serde_json::from_str(include_str!("fixtures/tn10-identity-genesis.json")).unwrap(),
    ]
}
async fn parent(pool: &PgPool) {
    let source = proof().remove(1);
    let output = &source.outputs[0];
    let block = hex::decode(source.accepting_block_hash.as_ref().unwrap()).unwrap();
    let tid = hex::decode(&source.transaction_id).unwrap();
    assert_eq!(
        tn12_indexer_core::compute_genesis_covenant_id_for_output(&source, 0).unwrap(),
        OWNER
    );
    sqlx::query("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) VALUES($1,$2,0,ARRAY[]::bytea[],$3,true,$3)")
        .bind(&block).bind(source.accepting_block_blue_score.unwrap() as i64).bind(source.accepting_block_time.unwrap() as i64).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO covenants(covenant_id,address,script_version,script_hash,genesis_txid,genesis_vout,genesis_block,created_at_ms) VALUES(decode($1,'hex'),$4,0,decode($1,'hex'),$2,0,$3,1)")
        .bind(OWNER).bind(&tid).bind(&block).bind(output.script_public_key_address.as_deref().unwrap()).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,created_block,status) VALUES($1,0,decode($2,'hex'),$3,$4,$5,$6,'active')")
        .bind(&tid).bind(OWNER).bind(output.script_public_key_address.as_deref().unwrap()).bind(output.amount as i64).bind(hex::decode(&output.script_public_key).unwrap()).bind(&block).execute(pool).await.unwrap();
    PgPersister::new(pool.clone())
        .persist_tx(&proof()[0])
        .await
        .unwrap();
}
async fn ghost(pool: &PgPool) {
    let source = child();
    let tid = hex::decode(&source.transaction_id).unwrap();
    sqlx::query("INSERT INTO covenants(covenant_id,address,script_version,script_hash,genesis_txid,genesis_vout,genesis_block,created_at_ms) SELECT decode($1,'hex'),u.address,0,substring(u.script_pubkey from 3 for 32),u.txid,u.vout,u.created_block,1 FROM covenant_utxos u WHERE u.txid=$2 AND u.vout=0")
        .bind(OLD).bind(&tid).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action,outputs) SELECT decode($1,'hex'),txid,block_hash,block_time_ms,'deploy',outputs FROM covenant_actions WHERE txid=$2 AND action='continuation'")
        .bind(OLD).bind(&tid).execute(pool).await.unwrap();
}
async fn canonical(pool: &PgPool) -> PgPersister {
    parent(pool).await;
    let writer = PgPersister::new(pool.clone());
    writer.persist_tx(&child()).await.unwrap();
    writer
}
async fn old_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM covenants WHERE covenant_id=decode($1,'hex')")
        .bind(OLD)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn captured_relocation_preview_apply_restart_and_alias(pool: PgPool) {
    let writer = canonical(&pool).await;
    ghost(&pool).await;
    let preview = writer
        .repair_output_identities(&child(), &proof(), false)
        .await
        .unwrap();
    assert_eq!(preview.len(), 1);
    assert_eq!(preview[0].old_covenant_id, OLD);
    assert_eq!(preview[0].new_covenant_id, OWNER);
    assert!(preview[0].retired_family);
    assert_eq!(old_count(&pool).await, 1);
    let audit: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_identity_corrections")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(audit, 0);
    writer
        .repair_output_identities(&child(), &proof(), true)
        .await
        .unwrap();
    assert_eq!(old_count(&pool).await, 0);
    let again = PgPersister::new(pool.clone())
        .repair_output_identities(&child(), &proof(), true)
        .await
        .unwrap();
    assert!(again.is_empty());
    let alias = tn12_indexer_db::repo::covenant_by_script_hash(&pool, OLD)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alias.covenant_id_hex, OWNER);
    let dirty: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kcc20_projection_dirty WHERE reason='identity_reconciliation')").fetch_one(&pool).await.unwrap();
    assert!(dirty);
    sqlx::query("UPDATE blocks SET is_chain_block=false WHERE hash=$1")
        .bind(hex::decode(child().accepting_block_hash.unwrap()).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    assert!(tn12_indexer_db::repo::covenant_by_script_hash(&pool, OLD)
        .await
        .unwrap()
        .is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn normal_replay_reconciles_stale_actions_atomically(pool: PgPool) {
    let writer = canonical(&pool).await;
    ghost(&pool).await;
    for _ in 0..2 {
        writer.persist_tx(&child()).await.unwrap();
    }
    assert_eq!(old_count(&pool).await, 0);
    let actions: i64=sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE txid=$1 AND action IN ('deploy','continuation')").bind(hex::decode(child().transaction_id).unwrap()).fetch_one(&pool).await.unwrap();
    assert_eq!(actions, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn source_disagreement_and_classified_family_cannot_be_deleted(pool: PgPool) {
    let writer = canonical(&pool).await;
    ghost(&pool).await;
    let mut wrong = child();
    wrong.outputs[0].amount += 1;
    assert!(writer
        .repair_output_identities(&wrong, &proof(), true)
        .await
        .is_err());
    wrong = child();
    wrong.accepting_block_hash = Some("ff".repeat(32));
    assert!(writer
        .repair_output_identities(&wrong, &proof(), true)
        .await
        .is_err());
    sqlx::query("UPDATE covenants SET template_name='KCC20' WHERE covenant_id=decode($1,'hex')")
        .bind(OLD)
        .execute(&pool)
        .await
        .unwrap();
    assert!(writer
        .repair_output_identities(&child(), &proof(), true)
        .await
        .is_err());
    assert_eq!(old_count(&pool).await, 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM covenant_identity_corrections")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn shared_family_keeps_unrelated_outputs(pool: PgPool) {
    let writer = canonical(&pool).await;
    ghost(&pool).await;
    sqlx::query("INSERT INTO covenant_utxos SELECT decode(repeat('ff',32),'hex'),vout,decode($1,'hex'),address,amount_sompi,script_pubkey,state,created_block,spent_block,spent_by_txid,status FROM covenant_utxos WHERE txid=$2 AND vout=0")
        .bind(OLD).bind(hex::decode(child().transaction_id).unwrap()).execute(&pool).await.unwrap();
    let result = writer
        .repair_output_identities(&child(), &proof(), true)
        .await
        .unwrap();
    assert!(!result[0].retired_family);
    assert_eq!(old_count(&pool).await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn blocked_family_does_not_starve_peers_or_advance_cursor(pool: PgPool) {
    let writer = canonical(&pool).await;
    ghost(&pool).await;
    let job = writer
        .prepare_settled_repair("identity_test", 588911100, 100)
        .await
        .unwrap();
    assert!(writer
        .acknowledge_settled_replay("identity_test", job.epoch)
        .await
        .unwrap());
    while !writer
        .discover_settled_members("identity_test")
        .await
        .unwrap()
    {}
    let error = writer
        .step_settled_repair("identity_test", 588911200, 588912000)
        .await
        .unwrap_err();
    writer
        .retain_settled_error("identity_test", &error)
        .await
        .unwrap();
    let blocked = tn12_indexer_db::persist::genesis::read_job(&pool, "identity_test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(blocked.blocker.unwrap()["reason"], "inconsistent_identity");
    assert!(!writer
        .step_settled_repair("identity_test", 588911200, 588912000)
        .await
        .unwrap());
    assert!(!writer
        .step_settled_repair("identity_test", 588911200, 588912000)
        .await
        .unwrap());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM indexer_state WHERE key='identity_test:settled_recheck'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    writer
        .repair_output_identities(&child(), &proof(), true)
        .await
        .unwrap();
    let mut completed = false;
    for _ in 0..10 {
        if writer
            .step_settled_repair("identity_test", 588911200, 588912000)
            .await
            .unwrap()
        {
            completed = true;
            break;
        }
    }
    assert!(
        completed,
        "the captured window must complete after correction"
    );
    let actions = tn12_indexer_db::repo::actions_for_covenant(&pool, OLD, 100, 0, false, None, &[])
        .await
        .unwrap();
    assert!(
        !actions.is_empty(),
        "old ID must resolve action lookups as well as detail"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn failure_after_audit_insert_rolls_back_every_change(pool: PgPool) {
    let writer = canonical(&pool).await;
    ghost(&pool).await;
    sqlx::raw_sql("CREATE FUNCTION fail_identity_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected failure'; END $$; CREATE TRIGGER fail_identity_delete BEFORE DELETE ON covenant_actions FOR EACH ROW EXECUTE FUNCTION fail_identity_delete();").execute(&pool).await.unwrap();
    assert!(writer
        .repair_output_identities(&child(), &proof(), true)
        .await
        .is_err());
    assert_eq!(old_count(&pool).await, 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM covenant_identity_corrections")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_native_input_is_not_proof_of_funding(pool: PgPool) {
    let mut source = child();
    source.inputs[0].previous_outpoint_address = None;
    source.inputs[0].previous_outpoint_script = None;
    assert!(PgPersister::new(pool).persist_tx(&source).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn inventory_pages_clean_rows_and_reports_conflicting_owner(pool: PgPool) {
    canonical(&pool).await;
    ghost(&pool).await;
    let page = tn12_indexer_db::persist::identity::inventory(&pool, None, 1)
        .await
        .unwrap();
    assert_eq!(page["candidates"][0]["familyId"], OLD);
    assert_eq!(page["candidates"][0]["outputOwner"], OWNER);
    assert_eq!(page["complete"], false);
    let next = tn12_indexer_db::persist::identity::inventory(&pool, page["nextAfter"].as_str(), 2)
        .await
        .unwrap();
    assert_eq!(next["scannedFamilies"], 1);
    assert_eq!(next["complete"], true);
    assert_eq!(next["candidates"], serde_json::json!([]));
}

#[sqlx::test(migrations = "./migrations")]
async fn repair_rejects_missing_or_conflicting_ancestor_evidence(pool: PgPool) {
    let writer = canonical(&pool).await;
    ghost(&pool).await;
    assert!(writer
        .repair_output_identities(&child(), &[], true)
        .await
        .is_err());
    let mut ancestors = proof();
    ancestors[0].outputs[0].amount += 1;
    assert!(writer
        .repair_output_identities(&child(), &ancestors, true)
        .await
        .is_err());
    sqlx::query(
        "UPDATE covenant_utxos SET covenant_id=decode($1,'hex') WHERE txid=decode($2,'hex')",
    )
    .bind(OLD)
    .bind(&proof()[0].transaction_id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(writer
        .repair_output_identities(&child(), &proof(), true)
        .await
        .is_err());
    assert_eq!(old_count(&pool).await, 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM covenant_identity_corrections")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn retained_protocol_state_prevents_family_retirement(pool: PgPool) {
    let writer = canonical(&pool).await;
    ghost(&pool).await;
    sqlx::query("INSERT INTO kcc20_holders(covenant_id,owner_identifier,identifier_type,amount_total,utxo_count,is_minter,last_change_ms) VALUES(decode($1,'hex'),decode(repeat('01',32),'hex'),0,1,1,false,1)")
        .bind(OLD).execute(&pool).await.unwrap();
    assert!(writer
        .repair_output_identities(&child(), &proof(), true)
        .await
        .is_err());
    assert_eq!(old_count(&pool).await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn conflicting_existing_audit_is_not_overwritten(pool: PgPool) {
    let writer = canonical(&pool).await;
    ghost(&pool).await;
    sqlx::query("INSERT INTO covenant_identity_corrections(old_covenant_id,new_covenant_id,txid,vout,accepting_block,old_action,old_family,corrected_at_ms) VALUES(decode($1,'hex'),decode(repeat('ff',32),'hex'),decode($2,'hex'),0,decode($3,'hex'),'{}','{}',1)")
        .bind(OLD).bind(child().transaction_id).bind(child().accepting_block_hash.unwrap()).execute(&pool).await.unwrap();
    assert!(writer
        .repair_output_identities(&child(), &proof(), true)
        .await
        .is_err());
    assert_eq!(old_count(&pool).await, 1);
}

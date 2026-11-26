use sqlx::PgPool;
use tn12_indexer_db::{
    persist::{PersistTransientKind, TransientPersistError},
    repo,
};

#[sqlx::test(migrations = "./migrations")]
async fn repository_repairs_respect_ingestion_writer_lock(pool: PgPool) {
    let mut ingestion = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(6074847039450202930::bigint)")
        .execute(&mut *ingestion)
        .await
        .unwrap();
    let rekey = repo::rekey_covenant_id(&pool, &[1; 32], &[2; 32])
        .await
        .unwrap_err();
    assert_eq!(
        rekey.downcast_ref::<TransientPersistError>().unwrap().kind,
        PersistTransientKind::WriterLockBusy
    );
    let cleanup = repo::delete_misclassified_continuation_deploy_actions(&pool)
        .await
        .unwrap_err();
    assert_eq!(
        cleanup
            .downcast_ref::<TransientPersistError>()
            .unwrap()
            .kind,
        PersistTransientKind::WriterLockBusy
    );
    ingestion.rollback().await.unwrap();
    assert!(!repo::rekey_covenant_id(&pool, &[1; 32], &[2; 32])
        .await
        .unwrap());
    assert_eq!(
        repo::delete_misclassified_continuation_deploy_actions(&pool)
            .await
            .unwrap(),
        0
    );
}

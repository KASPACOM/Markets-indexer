use sqlx::PgPool;

async fn rerun_snapshot_genesis_repair(pool: &PgPool) {
    sqlx::raw_sql(include_str!(
        "../migrations/20261109120002_repair_snapshot_genesis_deploy_outputs.sql"
    ))
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn future_deploy_actions_are_unique_by_output_vout(pool: PgPool) {
    let indexes: (bool, bool) = sqlx::query_as(
        r#"
        SELECT
            to_regclass('covenant_actions_deploy_uniq') IS NULL,
            to_regclass('covenant_actions_deploy_vout_uniq') IS NOT NULL
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(indexes, (true, true));

    sqlx::raw_sql(
        r#"
        INSERT INTO blocks(
            hash, blue_score, daa_score, parent_hashes, timestamp_ms,
            is_chain_block, indexed_at_ms
        ) VALUES (decode(repeat('aa', 32), 'hex'), 1, 1, ARRAY[]::bytea[], 1, TRUE, 1);

        INSERT INTO covenants(
            covenant_id, address, script_version, script_hash, genesis_txid,
            genesis_vout, genesis_block, created_at_ms
        ) VALUES (
            decode(repeat('bb', 32), 'hex'), 'kaspatest:reserve', 0,
            decode(repeat('dd', 32), 'hex'), decode(repeat('cc', 32), 'hex'),
            0, decode(repeat('aa', 32), 'hex'), 1
        );

        INSERT INTO covenant_actions(
            covenant_id, txid, block_hash, block_time_ms, action, outputs
        ) VALUES
        (
            decode(repeat('bb', 32), 'hex'), decode(repeat('cc', 32), 'hex'),
            decode(repeat('aa', 32), 'hex'), 1, 'deploy',
            jsonb_build_object('vout', 0)
        ),
        (
            decode(repeat('bb', 32), 'hex'), decode(repeat('cc', 32), 'hex'),
            decode(repeat('aa', 32), 'hex'), 1, 'deploy',
            jsonb_build_object('vout', 1)
        );
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let vouts: Vec<String> = sqlx::query_scalar(
        "SELECT outputs->>'vout' FROM covenant_actions WHERE action='deploy' ORDER BY outputs->>'vout'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(vouts, vec!["0", "1"]);

    let duplicate = sqlx::query(
        r#"
        INSERT INTO covenant_actions(
            covenant_id, txid, block_hash, block_time_ms, action, outputs
        ) VALUES (
            decode(repeat('bb', 32), 'hex'), decode(repeat('cc', 32), 'hex'),
            decode(repeat('aa', 32), 'hex'), 1, 'deploy',
            jsonb_build_object('vout', 1)
        )
        "#,
    )
    .execute(&pool)
    .await;
    assert!(duplicate.is_err(), "duplicate deploy vout was accepted");
}

#[sqlx::test(migrations = "./migrations")]
async fn repair_backfills_each_current_snapshot_genesis_vout_idempotently(pool: PgPool) {
    sqlx::raw_sql(
        r#"
        INSERT INTO blocks(
            hash, blue_score, daa_score, parent_hashes, timestamp_ms,
            is_chain_block, indexed_at_ms
        ) VALUES (decode(repeat('11', 32), 'hex'), 1, 1, ARRAY[]::bytea[], 1, TRUE, 1);

        INSERT INTO covenants(
            covenant_id, address, script_version, script_hash, genesis_txid,
            genesis_vout, genesis_block, created_at_ms
        ) VALUES (
            decode(repeat('22', 32), 'hex'), 'kaspatest:snapshot', 0,
            decode(repeat('33', 32), 'hex'), decode(repeat('44', 32), 'hex'),
            0, decode(repeat('11', 32), 'hex'), 1
        );

        INSERT INTO covenant_utxos(
            txid, vout, covenant_id, address, amount_sompi, script_pubkey,
            state, created_block, status
        )
        SELECT
            decode(repeat('44', 32), 'hex'), vout,
            decode(repeat('22', 32), 'hex'), 'kaspatest:snapshot', 100 + vout,
            decode('aa20' || repeat('33', 32) || '87', 'hex'),
            jsonb_build_object('shard', vout),
            decode(repeat('11', 32), 'hex'), 'active'
        FROM generate_series(0, 1) AS shard(vout);

        INSERT INTO covenant_actions(
            covenant_id, txid, block_hash, block_time_ms, action, outputs,
            decoded_args
        ) VALUES (
            decode(repeat('22', 32), 'hex'), decode(repeat('44', 32), 'hex'),
            decode(repeat('11', 32), 'hex'), 1, 'deploy',
            jsonb_build_object('vout', 0),
            jsonb_build_object(
                'projectionSchema', 'kcc20-snapshot-token-genesis/v1'
            )
        );
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    rerun_snapshot_genesis_repair(&pool).await;
    rerun_snapshot_genesis_repair(&pool).await;

    let vouts: Vec<String> = sqlx::query_scalar(
        "SELECT outputs->>'vout' FROM covenant_actions WHERE action='deploy' ORDER BY outputs->>'vout'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(vouts, vec!["0", "1"]);
}

#[sqlx::test(migrations = "./migrations")]
async fn repair_does_not_turn_stale_deploy_continuation_utxos_into_deploys(pool: PgPool) {
    sqlx::raw_sql(
        r#"
        INSERT INTO blocks(
            hash, blue_score, daa_score, parent_hashes, timestamp_ms,
            is_chain_block, indexed_at_ms
        ) VALUES (decode(repeat('55', 32), 'hex'), 1, 1, ARRAY[]::bytea[], 1, TRUE, 1);

        INSERT INTO covenants(
            covenant_id, address, script_version, script_hash, genesis_txid,
            genesis_vout, genesis_block, created_at_ms
        ) VALUES (
            decode(repeat('66', 32), 'hex'), 'kaspatest:continuation', 0,
            decode(repeat('77', 32), 'hex'), decode(repeat('88', 32), 'hex'),
            0, decode(repeat('55', 32), 'hex'), 1
        );

        INSERT INTO covenant_utxos(
            txid, vout, covenant_id, address, amount_sompi, script_pubkey,
            state, created_block, status
        ) VALUES (
            decode(repeat('99', 32), 'hex'), 0,
            decode(repeat('66', 32), 'hex'), 'kaspatest:continuation', 100,
            decode('aa20' || repeat('77', 32) || '87', 'hex'),
            jsonb_build_object('mode', 'continuation'),
            decode(repeat('55', 32), 'hex'), 'active'
        );

        INSERT INTO covenant_actions(
            covenant_id, txid, block_hash, block_time_ms, action, outputs,
            decoded_args
        ) VALUES
        (
            decode(repeat('66', 32), 'hex'), decode(repeat('99', 32), 'hex'),
            decode(repeat('55', 32), 'hex'), 1, 'deploy', NULL,
            jsonb_build_object(
                'projectionSchema', 'kcc20-snapshot-token-genesis/v1'
            )
        ),
        (
            decode(repeat('66', 32), 'hex'), decode(repeat('99', 32), 'hex'),
            decode(repeat('55', 32), 'hex'), 1, 'continuation',
            jsonb_build_object('vout', 0), NULL
        );
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    rerun_snapshot_genesis_repair(&pool).await;

    let deploy_vouts: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT outputs->>'vout' FROM covenant_actions WHERE action='deploy' ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(deploy_vouts, vec![None]);

    let continuation_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM covenant_actions WHERE action='continuation'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(continuation_count, 1);
}

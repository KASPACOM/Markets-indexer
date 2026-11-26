-- Keep an exact, migration-scoped content identity beside the canonical
-- snapshot claim rows. Reads use this materialized value instead of hashing
-- the complete claim history on every eligibility request.

CREATE TABLE snapshot_claim_history_commitments (
    controller_id BYTEA NOT NULL CHECK (octet_length(controller_id) = 32),
    token_id BYTEA NOT NULL CHECK (octet_length(token_id) = 32),
    total BIGINT NOT NULL CHECK (total >= 0),
    content_commitment BYTEA NOT NULL
        CHECK (octet_length(content_commitment) = 32),
    PRIMARY KEY (controller_id, token_id)
);

CREATE FUNCTION snapshot_claim_token_id(args JSONB)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT CASE
        WHEN lower(args->>'tokenId') ~ '^[a-f0-9]{64}$'
        THEN decode(lower(args->>'tokenId'), 'hex')
        ELSE NULL
    END;
$$;

CREATE FUNCTION snapshot_claim_history_seed(
    requested_controller_id BYTEA,
    requested_token_id BYTEA
)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT pg_catalog.sha256(
        convert_to('kcc20-snapshot-claim-history-content/v1', 'UTF8') ||
        requested_controller_id ||
        requested_token_id
    );
$$;

CREATE FUNCTION snapshot_claim_history_empty_commitment(
    requested_controller_id BYTEA,
    requested_token_id BYTEA
)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT pg_catalog.sha256(
        snapshot_claim_history_seed(
            requested_controller_id,
            requested_token_id
        ) ||
        int8send(0)
    );
$$;

CREATE FUNCTION refresh_snapshot_claim_history_commitment(
    requested_controller_id BYTEA,
    requested_token_id BYTEA
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    running_commitment BYTEA;
    claim_row RECORD;
    claim_total BIGINT := 0;
BEGIN
    IF octet_length(requested_controller_id) <> 32 OR
       octet_length(requested_token_id) <> 32 THEN
        RAISE EXCEPTION 'snapshot claim scope IDs must be exactly 32 bytes';
    END IF;

    -- Serialize writers for one scope. The row scan starts after this lock, so
    -- a waiting READ COMMITTED transaction sees the preceding writer's commit.
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            encode(requested_controller_id, 'hex') || ':' ||
            encode(requested_token_id, 'hex'),
            0
        )
    );

    running_commitment := snapshot_claim_history_seed(
        requested_controller_id,
        requested_token_id
    );

    FOR claim_row IN
        WITH claim_rows AS (
            SELECT
                claim.block_time_ms,
                claim.id,
                jsonb_build_object(
                    'controllerIdHex', encode(controller.covenant_id, 'hex'),
                    'txidHex', encode(claim.txid, 'hex'),
                    'blockHashHex', encode(claim.block_hash, 'hex'),
                    'blockTimeMs', claim.block_time_ms,
                    'inputs', claim.inputs,
                    'decodedArgs', claim.decoded_args,
                    'classificationKind', controller.classification_kind,
                    'classificationStatus', controller.classification_status,
                    'controllerTemplateName', controller.template_name,
                    'tokenActionCount', token_match.action_count,
                    'tokenInputs', token_match.inputs,
                    'tokenTemplateName', token_match.template_name,
                    'tokenClassificationKind', token_match.classification_kind,
                    'tokenClassificationStatus', token_match.classification_status
                ) AS payload
            FROM covenant_actions claim
            JOIN covenants controller
              ON controller.covenant_id = claim.covenant_id
            LEFT JOIN LATERAL (
                SELECT
                    COUNT(*)::BIGINT AS action_count,
                    CASE WHEN COUNT(*) = 1
                        THEN (ARRAY_AGG(token_action.inputs ORDER BY token_action.id))[1]
                    END AS inputs,
                    CASE WHEN COUNT(*) = 1
                        THEN (ARRAY_AGG(token_covenant.classification_kind ORDER BY token_action.id))[1]
                    END AS classification_kind,
                    CASE WHEN COUNT(*) = 1
                        THEN (ARRAY_AGG(token_covenant.classification_status ORDER BY token_action.id))[1]
                    END AS classification_status,
                    CASE WHEN COUNT(*) = 1
                        THEN (ARRAY_AGG(token_covenant.template_name ORDER BY token_action.id))[1]
                    END AS template_name
                FROM covenant_actions token_action
                JOIN covenants token_covenant
                  ON token_covenant.covenant_id = token_action.covenant_id
                WHERE token_action.txid = claim.txid
                  AND token_action.action = 'spend'
                  AND token_action.entrypoint = 'transfer'
                  AND (
                      token_action.canonical_token_id = requested_token_id
                      OR (
                          token_action.canonical_token_id IS NULL
                          AND token_action.covenant_id = requested_token_id
                      )
                  )
            ) token_match ON TRUE
            WHERE claim.covenant_id = requested_controller_id
              AND claim.action = 'spend'
              AND claim.entrypoint = 'claim'
              AND claim.decoded_args->>'projectionSchema' =
                  'kcc20-snapshot-claim/v1'
              AND snapshot_claim_token_id(claim.decoded_args) =
                  requested_token_id
        )
        SELECT payload
        FROM claim_rows
        ORDER BY block_time_ms ASC, id ASC
    LOOP
        running_commitment := pg_catalog.sha256(
            running_commitment ||
            pg_catalog.sha256(convert_to(claim_row.payload::TEXT, 'UTF8'))
        );
        claim_total := claim_total + 1;
    END LOOP;

    running_commitment := pg_catalog.sha256(
        running_commitment || int8send(claim_total)
    );

    INSERT INTO snapshot_claim_history_commitments (
        controller_id,
        token_id,
        total,
        content_commitment
    ) VALUES (
        requested_controller_id,
        requested_token_id,
        claim_total,
        running_commitment
    )
    ON CONFLICT (controller_id, token_id) DO UPDATE
    SET total = EXCLUDED.total,
        content_commitment = EXCLUDED.content_commitment;
END;
$$;

CREATE FUNCTION refresh_snapshot_claim_commitments_after_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    scope RECORD;
BEGIN
    FOR scope IN
        SELECT DISTINCT controller_id, token_id
        FROM (
            SELECT
                changed.covenant_id AS controller_id,
                snapshot_claim_token_id(changed.decoded_args) AS token_id
            FROM inserted_snapshot_actions changed
            WHERE changed.action = 'spend'
              AND changed.entrypoint = 'claim'
              AND changed.decoded_args->>'projectionSchema' =
                  'kcc20-snapshot-claim/v1'
            UNION
            SELECT
                claim.covenant_id AS controller_id,
                snapshot_claim_token_id(claim.decoded_args) AS token_id
            FROM inserted_snapshot_actions changed
            JOIN covenant_actions claim ON claim.txid = changed.txid
            WHERE changed.action = 'spend'
              AND changed.entrypoint = 'transfer'
              AND claim.action = 'spend'
              AND claim.entrypoint = 'claim'
              AND claim.decoded_args->>'projectionSchema' =
                  'kcc20-snapshot-claim/v1'
        ) affected
        WHERE token_id IS NOT NULL
        ORDER BY controller_id, token_id
    LOOP
        PERFORM refresh_snapshot_claim_history_commitment(
            scope.controller_id,
            scope.token_id
        );
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE FUNCTION refresh_snapshot_claim_commitments_after_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    scope RECORD;
BEGIN
    FOR scope IN
        SELECT DISTINCT controller_id, token_id
        FROM (
            SELECT
                changed.covenant_id AS controller_id,
                snapshot_claim_token_id(changed.decoded_args) AS token_id
            FROM deleted_snapshot_actions changed
            WHERE changed.action = 'spend'
              AND changed.entrypoint = 'claim'
              AND changed.decoded_args->>'projectionSchema' =
                  'kcc20-snapshot-claim/v1'
            UNION
            SELECT
                claim.covenant_id AS controller_id,
                snapshot_claim_token_id(claim.decoded_args) AS token_id
            FROM deleted_snapshot_actions changed
            JOIN covenant_actions claim ON claim.txid = changed.txid
            WHERE changed.action = 'spend'
              AND changed.entrypoint = 'transfer'
              AND claim.action = 'spend'
              AND claim.entrypoint = 'claim'
              AND claim.decoded_args->>'projectionSchema' =
                  'kcc20-snapshot-claim/v1'
            UNION
            SELECT
                claim.covenant_id AS controller_id,
                snapshot_claim_token_id(claim.decoded_args) AS token_id
            FROM deleted_snapshot_actions changed
            JOIN deleted_snapshot_actions claim ON claim.txid = changed.txid
            WHERE changed.action = 'spend'
              AND changed.entrypoint = 'transfer'
              AND claim.action = 'spend'
              AND claim.entrypoint = 'claim'
              AND claim.decoded_args->>'projectionSchema' =
                  'kcc20-snapshot-claim/v1'
        ) affected
        WHERE token_id IS NOT NULL
        ORDER BY controller_id, token_id
    LOOP
        PERFORM refresh_snapshot_claim_history_commitment(
            scope.controller_id,
            scope.token_id
        );
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE FUNCTION refresh_snapshot_claim_commitments_after_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    scope RECORD;
BEGIN
    FOR scope IN
        WITH changed AS (
            SELECT * FROM updated_old_snapshot_actions
            UNION ALL
            SELECT * FROM updated_new_snapshot_actions
        ), claims AS (
            SELECT *
            FROM covenant_actions
            WHERE action = 'spend'
              AND entrypoint = 'claim'
              AND decoded_args->>'projectionSchema' =
                  'kcc20-snapshot-claim/v1'
            UNION ALL
            SELECT *
            FROM updated_old_snapshot_actions
            WHERE action = 'spend'
              AND entrypoint = 'claim'
              AND decoded_args->>'projectionSchema' =
                  'kcc20-snapshot-claim/v1'
        )
        SELECT DISTINCT controller_id, token_id
        FROM (
            SELECT
                changed.covenant_id AS controller_id,
                snapshot_claim_token_id(changed.decoded_args) AS token_id
            FROM changed
            WHERE changed.action = 'spend'
              AND changed.entrypoint = 'claim'
              AND changed.decoded_args->>'projectionSchema' =
                  'kcc20-snapshot-claim/v1'
            UNION
            SELECT
                claim.covenant_id AS controller_id,
                snapshot_claim_token_id(claim.decoded_args) AS token_id
            FROM changed
            JOIN claims claim ON claim.txid = changed.txid
            WHERE changed.action = 'spend'
              AND changed.entrypoint = 'transfer'
        ) affected
        WHERE token_id IS NOT NULL
        ORDER BY controller_id, token_id
    LOOP
        PERFORM refresh_snapshot_claim_history_commitment(
            scope.controller_id,
            scope.token_id
        );
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE FUNCTION clear_snapshot_claim_history_commitments_after_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- Transition tables are unavailable for TRUNCATE. Every materialized
    -- scope is stale after canonical action history is cleared, while reads
    -- deterministically derive a missing scope's empty commitment.
    DELETE FROM snapshot_claim_history_commitments;
    RETURN NULL;
END;
$$;

CREATE FUNCTION refresh_snapshot_claim_commitments_after_covenant_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    scope RECORD;
BEGIN
    FOR scope IN
        SELECT DISTINCT controller_id, token_id
        FROM (
            SELECT
                claim.covenant_id AS controller_id,
                snapshot_claim_token_id(claim.decoded_args) AS token_id
            FROM covenant_actions claim
            WHERE claim.covenant_id = NEW.covenant_id
              AND claim.action = 'spend'
              AND claim.entrypoint = 'claim'
              AND claim.decoded_args->>'projectionSchema' =
                  'kcc20-snapshot-claim/v1'
            UNION
            SELECT
                claim.covenant_id AS controller_id,
                snapshot_claim_token_id(claim.decoded_args) AS token_id
            FROM covenant_actions token_action
            JOIN covenant_actions claim ON claim.txid = token_action.txid
            WHERE token_action.covenant_id = NEW.covenant_id
              AND token_action.action = 'spend'
              AND token_action.entrypoint = 'transfer'
              AND claim.action = 'spend'
              AND claim.entrypoint = 'claim'
              AND claim.decoded_args->>'projectionSchema' =
                  'kcc20-snapshot-claim/v1'
        ) affected
        WHERE token_id IS NOT NULL
        ORDER BY controller_id, token_id
    LOOP
        PERFORM refresh_snapshot_claim_history_commitment(
            scope.controller_id,
            scope.token_id
        );
    END LOOP;
    RETURN NULL;
END;
$$;

DO $$
DECLARE
    scope RECORD;
BEGIN
    FOR scope IN
        SELECT DISTINCT
            covenant_id AS controller_id,
            snapshot_claim_token_id(decoded_args) AS token_id
        FROM covenant_actions
        WHERE action = 'spend'
          AND entrypoint = 'claim'
          AND decoded_args->>'projectionSchema' =
              'kcc20-snapshot-claim/v1'
          AND snapshot_claim_token_id(decoded_args) IS NOT NULL
        ORDER BY controller_id, token_id
    LOOP
        PERFORM refresh_snapshot_claim_history_commitment(
            scope.controller_id,
            scope.token_id
        );
    END LOOP;
END;
$$;

CREATE TRIGGER covenant_actions_snapshot_commitment_insert
AFTER INSERT ON covenant_actions
REFERENCING NEW TABLE AS inserted_snapshot_actions
FOR EACH STATEMENT
EXECUTE FUNCTION refresh_snapshot_claim_commitments_after_insert();

CREATE TRIGGER covenant_actions_snapshot_commitment_delete
AFTER DELETE ON covenant_actions
REFERENCING OLD TABLE AS deleted_snapshot_actions
FOR EACH STATEMENT
EXECUTE FUNCTION refresh_snapshot_claim_commitments_after_delete();

CREATE TRIGGER covenant_actions_snapshot_commitment_update
AFTER UPDATE ON covenant_actions
REFERENCING OLD TABLE AS updated_old_snapshot_actions
            NEW TABLE AS updated_new_snapshot_actions
FOR EACH STATEMENT
EXECUTE FUNCTION refresh_snapshot_claim_commitments_after_update();

CREATE TRIGGER covenant_actions_snapshot_commitment_truncate
AFTER TRUNCATE ON covenant_actions
FOR EACH STATEMENT
EXECUTE FUNCTION clear_snapshot_claim_history_commitments_after_truncate();

CREATE TRIGGER covenants_snapshot_commitment_update
AFTER UPDATE OF classification_kind, classification_status, template_name
ON covenants
FOR EACH ROW
WHEN (
    (OLD.classification_kind, OLD.classification_status, OLD.template_name)
        IS DISTINCT FROM
    (NEW.classification_kind, NEW.classification_status, NEW.template_name)
)
EXECUTE FUNCTION refresh_snapshot_claim_commitments_after_covenant_update();

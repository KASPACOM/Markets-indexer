CREATE TABLE snapshot_claim_history_revision (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    epoch TEXT NOT NULL CHECK (epoch ~ '^[a-f0-9]{64}$'),
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0)
);

INSERT INTO snapshot_claim_history_revision (singleton, epoch, revision)
VALUES (
    TRUE,
    md5(random()::TEXT || clock_timestamp()::TEXT) ||
        md5(random()::TEXT || clock_timestamp()::TEXT),
    0
);

CREATE FUNCTION bump_snapshot_claim_history_revision()
RETURNS VOID
LANGUAGE SQL
AS $$
    UPDATE snapshot_claim_history_revision
    SET epoch = md5(random()::TEXT || clock_timestamp()::TEXT) ||
            md5(random()::TEXT || clock_timestamp()::TEXT),
        revision = revision + 1
    WHERE singleton = TRUE;
$$;

CREATE FUNCTION bump_snapshot_claim_history_revision_after_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM inserted_actions
        WHERE decoded_args->>'projectionSchema' = 'kcc20-snapshot-claim/v1'
    ) OR EXISTS (
        SELECT 1
        FROM inserted_actions changed
        JOIN covenant_actions claim ON claim.txid = changed.txid
        WHERE changed.action = 'spend'
          AND changed.entrypoint = 'transfer'
          AND claim.decoded_args->>'projectionSchema' = 'kcc20-snapshot-claim/v1'
    ) THEN
        PERFORM bump_snapshot_claim_history_revision();
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION bump_snapshot_claim_history_revision_after_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM deleted_actions
        WHERE decoded_args->>'projectionSchema' = 'kcc20-snapshot-claim/v1'
    ) OR EXISTS (
        SELECT 1
        FROM deleted_actions changed
        JOIN covenant_actions claim ON claim.txid = changed.txid
        WHERE changed.action = 'spend'
          AND changed.entrypoint = 'transfer'
          AND claim.decoded_args->>'projectionSchema' = 'kcc20-snapshot-claim/v1'
    ) THEN
        PERFORM bump_snapshot_claim_history_revision();
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION bump_snapshot_claim_history_revision_after_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM updated_old_actions
        WHERE decoded_args->>'projectionSchema' = 'kcc20-snapshot-claim/v1'
    ) OR EXISTS (
        SELECT 1 FROM updated_new_actions
        WHERE decoded_args->>'projectionSchema' = 'kcc20-snapshot-claim/v1'
    ) OR EXISTS (
        SELECT 1
        FROM updated_old_actions changed
        JOIN covenant_actions claim ON claim.txid = changed.txid
        WHERE changed.action = 'spend'
          AND changed.entrypoint = 'transfer'
          AND claim.decoded_args->>'projectionSchema' = 'kcc20-snapshot-claim/v1'
    ) OR EXISTS (
        SELECT 1
        FROM updated_new_actions changed
        JOIN covenant_actions claim ON claim.txid = changed.txid
        WHERE changed.action = 'spend'
          AND changed.entrypoint = 'transfer'
          AND claim.decoded_args->>'projectionSchema' = 'kcc20-snapshot-claim/v1'
    ) THEN
        PERFORM bump_snapshot_claim_history_revision();
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION bump_snapshot_claim_history_revision_after_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM bump_snapshot_claim_history_revision();
    RETURN NULL;
END;
$$;

CREATE TRIGGER covenant_actions_snapshot_history_insert_revision
AFTER INSERT ON covenant_actions
REFERENCING NEW TABLE AS inserted_actions
FOR EACH STATEMENT EXECUTE FUNCTION bump_snapshot_claim_history_revision_after_insert();

CREATE TRIGGER covenant_actions_snapshot_history_delete_revision
AFTER DELETE ON covenant_actions
REFERENCING OLD TABLE AS deleted_actions
FOR EACH STATEMENT EXECUTE FUNCTION bump_snapshot_claim_history_revision_after_delete();

CREATE TRIGGER covenant_actions_snapshot_history_update_revision
AFTER UPDATE ON covenant_actions
REFERENCING OLD TABLE AS updated_old_actions NEW TABLE AS updated_new_actions
FOR EACH STATEMENT EXECUTE FUNCTION bump_snapshot_claim_history_revision_after_update();

CREATE TRIGGER covenant_actions_snapshot_history_truncate_revision
AFTER TRUNCATE ON covenant_actions
FOR EACH STATEMENT EXECUTE FUNCTION bump_snapshot_claim_history_revision_after_truncate();

CREATE FUNCTION bump_snapshot_claim_history_revision_after_covenant_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM bump_snapshot_claim_history_revision();
    RETURN NULL;
END;
$$;

CREATE TRIGGER covenants_snapshot_history_update_revision
AFTER UPDATE ON covenants
FOR EACH STATEMENT EXECUTE FUNCTION bump_snapshot_claim_history_revision_after_covenant_mutation();

CREATE TRIGGER covenants_snapshot_history_delete_revision
AFTER DELETE ON covenants
FOR EACH STATEMENT EXECUTE FUNCTION bump_snapshot_claim_history_revision_after_covenant_mutation();

CREATE TRIGGER covenants_snapshot_history_truncate_revision
AFTER TRUNCATE ON covenants
FOR EACH STATEMENT EXECUTE FUNCTION bump_snapshot_claim_history_revision_after_covenant_mutation();

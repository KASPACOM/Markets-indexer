-- The claim-history endpoint joins classification fields from the controller
-- and token covenant rows, so changes to those fields must invalidate a
-- replay. The original trigger invalidated the global claim-history revision
-- after *every* covenants update, including routine indexing maintenance on
-- unrelated contracts. On an active indexer that made a stable paginated
-- replay practically impossible.

DROP TRIGGER IF EXISTS covenants_snapshot_history_update_revision ON covenants;

CREATE FUNCTION bump_snapshot_history_after_relevant_covenant_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM covenant_actions claim
        WHERE claim.covenant_id = NEW.covenant_id
          AND claim.action = 'spend'
          AND claim.entrypoint = 'claim'
          AND claim.decoded_args->>'projectionSchema' = 'kcc20-snapshot-claim/v1'
    ) OR EXISTS (
        SELECT 1
        FROM covenant_actions token_action
        JOIN covenant_actions claim ON claim.txid = token_action.txid
        WHERE token_action.covenant_id = NEW.covenant_id
          AND token_action.action = 'spend'
          AND token_action.entrypoint = 'transfer'
          AND claim.action = 'spend'
          AND claim.entrypoint = 'claim'
          AND claim.decoded_args->>'projectionSchema' = 'kcc20-snapshot-claim/v1'
          AND (
              encode(token_action.canonical_token_id, 'hex') =
                  lower(claim.decoded_args->>'tokenId')
              OR (
                  token_action.canonical_token_id IS NULL
                  AND encode(token_action.covenant_id, 'hex') =
                      lower(claim.decoded_args->>'tokenId')
              )
          )
    ) THEN
        PERFORM bump_snapshot_claim_history_revision();
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER covenants_snapshot_history_update_revision
AFTER UPDATE OF classification_kind, classification_status, template_name ON covenants
FOR EACH ROW
WHEN (
    (OLD.classification_kind, OLD.classification_status, OLD.template_name)
        IS DISTINCT FROM
    (NEW.classification_kind, NEW.classification_status, NEW.template_name)
)
EXECUTE FUNCTION bump_snapshot_history_after_relevant_covenant_update();

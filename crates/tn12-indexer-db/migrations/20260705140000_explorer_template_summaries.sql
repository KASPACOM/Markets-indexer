CREATE TABLE covenant_template_summaries (
    template                 TEXT PRIMARY KEY,
    covenant_count           BIGINT NOT NULL DEFAULT 0,
    verified_count           BIGINT NOT NULL DEFAULT 0,
    claimed_only_count       BIGINT NOT NULL DEFAULT 0,
    active_covenants         BIGINT NOT NULL DEFAULT 0,
    active_utxos             BIGINT NOT NULL DEFAULT 0,
    total_amount_sompi       NUMERIC NOT NULL DEFAULT 0,
    action_count             BIGINT NOT NULL DEFAULT 0,
    matched_count            BIGINT NOT NULL DEFAULT 0,
    unrevealed_count         BIGINT NOT NULL DEFAULT 0,
    unmatched_count          BIGINT NOT NULL DEFAULT 0,
    latest_created_at_ms     BIGINT,
    latest_action_time_ms    BIGINT,
    updated_at_ms            BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

CREATE INDEX covenant_template_summaries_activity_idx
    ON covenant_template_summaries (action_count DESC, template ASC);

CREATE INDEX covenant_template_summaries_covenants_idx
    ON covenant_template_summaries (covenant_count DESC, template ASC);

CREATE OR REPLACE FUNCTION refresh_covenant_template_summary(target_template TEXT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF target_template IS NULL OR target_template = '' THEN
        RETURN;
    END IF;

    INSERT INTO covenant_template_summaries (
        template,
        covenant_count,
        verified_count,
        claimed_only_count,
        active_covenants,
        active_utxos,
        total_amount_sompi,
        action_count,
        matched_count,
        unrevealed_count,
        unmatched_count,
        latest_created_at_ms,
        latest_action_time_ms,
        updated_at_ms
    )
    SELECT
        grouped.template,
        COUNT(*)::BIGINT AS covenant_count,
        COUNT(*) FILTER (WHERE c.template_name IS NOT NULL)::BIGINT AS verified_count,
        COUNT(*) FILTER (WHERE c.template_name IS NULL AND c.claimed_template IS NOT NULL)::BIGINT AS claimed_only_count,
        COUNT(*) FILTER (WHERE COALESCE(s.active_utxos, 0) > 0)::BIGINT AS active_covenants,
        COALESCE(SUM(s.active_utxos), 0)::BIGINT AS active_utxos,
        COALESCE(SUM(s.total_amount_sompi), 0)::NUMERIC AS total_amount_sompi,
        COALESCE(SUM(a.action_count), 0)::BIGINT AS action_count,
        COUNT(*) FILTER (WHERE c.classification_status = 'matched')::BIGINT AS matched_count,
        COUNT(*) FILTER (WHERE c.classification_status = 'unrevealed')::BIGINT AS unrevealed_count,
        COUNT(*) FILTER (WHERE c.classification_status = 'unmatched')::BIGINT AS unmatched_count,
        MAX(c.created_at_ms) AS latest_created_at_ms,
        MAX(a.latest_action_time_ms) AS latest_action_time_ms,
        EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 AS updated_at_ms
    FROM covenants c
    CROSS JOIN LATERAL (
        SELECT COALESCE(c.template_name, c.claimed_template, 'Unknown') AS template
    ) grouped
    LEFT JOIN covenant_summaries s ON s.covenant_id = c.covenant_id
    LEFT JOIN LATERAL (
        SELECT
            COUNT(*)::BIGINT AS action_count,
            MAX(block_time_ms) AS latest_action_time_ms
        FROM covenant_actions action
        WHERE action.covenant_id = c.covenant_id
    ) a ON TRUE
    WHERE grouped.template = target_template
    GROUP BY grouped.template
    ON CONFLICT (template) DO UPDATE SET
        covenant_count = EXCLUDED.covenant_count,
        verified_count = EXCLUDED.verified_count,
        claimed_only_count = EXCLUDED.claimed_only_count,
        active_covenants = EXCLUDED.active_covenants,
        active_utxos = EXCLUDED.active_utxos,
        total_amount_sompi = EXCLUDED.total_amount_sompi,
        action_count = EXCLUDED.action_count,
        matched_count = EXCLUDED.matched_count,
        unrevealed_count = EXCLUDED.unrevealed_count,
        unmatched_count = EXCLUDED.unmatched_count,
        latest_created_at_ms = EXCLUDED.latest_created_at_ms,
        latest_action_time_ms = EXCLUDED.latest_action_time_ms,
        updated_at_ms = EXCLUDED.updated_at_ms;

    IF NOT FOUND THEN
        DELETE FROM covenant_template_summaries WHERE template = target_template;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION refresh_covenant_template_summary_for_covenant(target_covenant_id BYTEA)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    target_template TEXT;
BEGIN
    IF target_covenant_id IS NULL THEN
        RETURN;
    END IF;

    SELECT COALESCE(template_name, claimed_template, 'Unknown')
      INTO target_template
      FROM covenants
     WHERE covenant_id = target_covenant_id;

    PERFORM refresh_covenant_template_summary(target_template);
END;
$$;

INSERT INTO covenant_template_summaries (
    template,
    covenant_count,
    verified_count,
    claimed_only_count,
    active_covenants,
    active_utxos,
    total_amount_sompi,
    action_count,
    matched_count,
    unrevealed_count,
    unmatched_count,
    latest_created_at_ms,
    latest_action_time_ms,
    updated_at_ms
)
WITH action_totals AS (
    SELECT covenant_id,
           COUNT(*)::BIGINT AS action_count,
           MAX(block_time_ms) AS latest_action_time_ms
    FROM covenant_actions
    GROUP BY covenant_id
)
SELECT
    COALESCE(c.template_name, c.claimed_template, 'Unknown') AS template,
    COUNT(*)::BIGINT AS covenant_count,
    COUNT(*) FILTER (WHERE c.template_name IS NOT NULL)::BIGINT AS verified_count,
    COUNT(*) FILTER (WHERE c.template_name IS NULL AND c.claimed_template IS NOT NULL)::BIGINT AS claimed_only_count,
    COUNT(*) FILTER (WHERE COALESCE(s.active_utxos, 0) > 0)::BIGINT AS active_covenants,
    COALESCE(SUM(s.active_utxos), 0)::BIGINT AS active_utxos,
    COALESCE(SUM(s.total_amount_sompi), 0)::NUMERIC AS total_amount_sompi,
    COALESCE(SUM(a.action_count), 0)::BIGINT AS action_count,
    COUNT(*) FILTER (WHERE c.classification_status = 'matched')::BIGINT AS matched_count,
    COUNT(*) FILTER (WHERE c.classification_status = 'unrevealed')::BIGINT AS unrevealed_count,
    COUNT(*) FILTER (WHERE c.classification_status = 'unmatched')::BIGINT AS unmatched_count,
    MAX(c.created_at_ms) AS latest_created_at_ms,
    MAX(a.latest_action_time_ms) AS latest_action_time_ms,
    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 AS updated_at_ms
FROM covenants c
LEFT JOIN covenant_summaries s ON s.covenant_id = c.covenant_id
LEFT JOIN action_totals a ON a.covenant_id = c.covenant_id
GROUP BY COALESCE(c.template_name, c.claimed_template, 'Unknown');

CREATE OR REPLACE FUNCTION apply_covenant_template_summary_delta(
    target_template TEXT,
    covenant_delta BIGINT DEFAULT 0,
    verified_delta BIGINT DEFAULT 0,
    claimed_only_delta BIGINT DEFAULT 0,
    active_covenants_delta BIGINT DEFAULT 0,
    active_utxos_delta BIGINT DEFAULT 0,
    total_amount_sompi_delta NUMERIC DEFAULT 0,
    action_delta BIGINT DEFAULT 0,
    matched_delta BIGINT DEFAULT 0,
    unrevealed_delta BIGINT DEFAULT 0,
    unmatched_delta BIGINT DEFAULT 0,
    latest_created_candidate BIGINT DEFAULT NULL,
    latest_action_candidate BIGINT DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF target_template IS NULL OR target_template = '' THEN
        RETURN;
    END IF;

    INSERT INTO covenant_template_summaries (
        template,
        covenant_count,
        verified_count,
        claimed_only_count,
        active_covenants,
        active_utxos,
        total_amount_sompi,
        action_count,
        matched_count,
        unrevealed_count,
        unmatched_count,
        latest_created_at_ms,
        latest_action_time_ms,
        updated_at_ms
    )
    VALUES (
        target_template,
        GREATEST(covenant_delta, 0),
        GREATEST(verified_delta, 0),
        GREATEST(claimed_only_delta, 0),
        GREATEST(active_covenants_delta, 0),
        GREATEST(active_utxos_delta, 0),
        GREATEST(total_amount_sompi_delta, 0),
        GREATEST(action_delta, 0),
        GREATEST(matched_delta, 0),
        GREATEST(unrevealed_delta, 0),
        GREATEST(unmatched_delta, 0),
        latest_created_candidate,
        latest_action_candidate,
        EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
    )
    ON CONFLICT (template) DO UPDATE SET
        covenant_count = GREATEST(covenant_template_summaries.covenant_count + covenant_delta, 0),
        verified_count = GREATEST(covenant_template_summaries.verified_count + verified_delta, 0),
        claimed_only_count = GREATEST(covenant_template_summaries.claimed_only_count + claimed_only_delta, 0),
        active_covenants = GREATEST(covenant_template_summaries.active_covenants + active_covenants_delta, 0),
        active_utxos = GREATEST(covenant_template_summaries.active_utxos + active_utxos_delta, 0),
        total_amount_sompi = GREATEST(covenant_template_summaries.total_amount_sompi + total_amount_sompi_delta, 0),
        action_count = GREATEST(covenant_template_summaries.action_count + action_delta, 0),
        matched_count = GREATEST(covenant_template_summaries.matched_count + matched_delta, 0),
        unrevealed_count = GREATEST(covenant_template_summaries.unrevealed_count + unrevealed_delta, 0),
        unmatched_count = GREATEST(covenant_template_summaries.unmatched_count + unmatched_delta, 0),
        latest_created_at_ms = GREATEST(
            COALESCE(covenant_template_summaries.latest_created_at_ms, 0),
            COALESCE(latest_created_candidate, 0)
        ),
        latest_action_time_ms = GREATEST(
            COALESCE(covenant_template_summaries.latest_action_time_ms, 0),
            COALESCE(latest_action_candidate, 0)
        ),
        updated_at_ms = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000;

    DELETE FROM covenant_template_summaries
     WHERE template = target_template
       AND covenant_count = 0
       AND verified_count = 0
       AND claimed_only_count = 0
       AND active_covenants = 0
       AND active_utxos = 0
       AND total_amount_sompi = 0
       AND action_count = 0
       AND matched_count = 0
       AND unrevealed_count = 0
       AND unmatched_count = 0;
END;
$$;

CREATE OR REPLACE FUNCTION refresh_covenant_template_summary_from_covenant_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    old_template TEXT;
    new_template TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Deletes are rare reorg/repair paths; rebuild to avoid stale maxima.
        old_template := COALESCE(OLD.template_name, OLD.claimed_template, 'Unknown');
        PERFORM refresh_covenant_template_summary(old_template);
        RETURN OLD;
    END IF;

    new_template := COALESCE(NEW.template_name, NEW.claimed_template, 'Unknown');

    IF TG_OP = 'UPDATE' THEN
        old_template := COALESCE(OLD.template_name, OLD.claimed_template, 'Unknown');
        IF old_template IS DISTINCT FROM new_template THEN
            -- Template moves are repair/reclassification paths; rebuild both sides once.
            PERFORM refresh_covenant_template_summary(old_template);
            PERFORM refresh_covenant_template_summary(new_template);
            RETURN NEW;
        END IF;

        PERFORM apply_covenant_template_summary_delta(
            new_template,
            0,
            CASE WHEN NEW.template_name IS NOT NULL THEN 1 ELSE 0 END -
                CASE WHEN OLD.template_name IS NOT NULL THEN 1 ELSE 0 END,
            CASE WHEN NEW.template_name IS NULL AND NEW.claimed_template IS NOT NULL THEN 1 ELSE 0 END -
                CASE WHEN OLD.template_name IS NULL AND OLD.claimed_template IS NOT NULL THEN 1 ELSE 0 END,
            0,
            0,
            0,
            0,
            CASE WHEN NEW.classification_status = 'matched' THEN 1 ELSE 0 END -
                CASE WHEN OLD.classification_status = 'matched' THEN 1 ELSE 0 END,
            CASE WHEN NEW.classification_status = 'unrevealed' THEN 1 ELSE 0 END -
                CASE WHEN OLD.classification_status = 'unrevealed' THEN 1 ELSE 0 END,
            CASE WHEN NEW.classification_status = 'unmatched' THEN 1 ELSE 0 END -
                CASE WHEN OLD.classification_status = 'unmatched' THEN 1 ELSE 0 END,
            NEW.created_at_ms,
            NULL
        );
    ELSE
        PERFORM apply_covenant_template_summary_delta(
            new_template,
            1,
            CASE WHEN NEW.template_name IS NOT NULL THEN 1 ELSE 0 END,
            CASE WHEN NEW.template_name IS NULL AND NEW.claimed_template IS NOT NULL THEN 1 ELSE 0 END,
            0,
            0,
            0,
            0,
            CASE WHEN NEW.classification_status = 'matched' THEN 1 ELSE 0 END,
            CASE WHEN NEW.classification_status = 'unrevealed' THEN 1 ELSE 0 END,
            CASE WHEN NEW.classification_status = 'unmatched' THEN 1 ELSE 0 END,
            NEW.created_at_ms,
            NULL
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER covenants_refresh_template_summary
AFTER INSERT OR UPDATE OF template_name, claimed_template, classification_status, classification_kind, created_at_ms OR DELETE ON covenants
FOR EACH ROW
EXECUTE FUNCTION refresh_covenant_template_summary_from_covenant_trigger();

CREATE OR REPLACE FUNCTION refresh_covenant_template_summary_from_summary_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_template TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Deletes are rare reorg/repair paths; rebuild to avoid stale maxima.
        PERFORM refresh_covenant_template_summary_for_covenant(OLD.covenant_id);
        RETURN OLD;
    END IF;

    IF TG_OP = 'UPDATE' AND OLD.covenant_id IS DISTINCT FROM NEW.covenant_id THEN
        PERFORM refresh_covenant_template_summary_for_covenant(OLD.covenant_id);
        PERFORM refresh_covenant_template_summary_for_covenant(NEW.covenant_id);
        RETURN NEW;
    END IF;

    SELECT COALESCE(template_name, claimed_template, 'Unknown')
      INTO target_template
      FROM covenants
     WHERE covenant_id = NEW.covenant_id;

    IF target_template IS NULL THEN
        RETURN NEW;
    END IF;

    IF TG_OP = 'INSERT' THEN
        PERFORM apply_covenant_template_summary_delta(
            target_template,
            0,
            0,
            0,
            CASE WHEN NEW.active_utxos > 0 THEN 1 ELSE 0 END,
            NEW.active_utxos,
            NEW.total_amount_sompi,
            0,
            0,
            0,
            0,
            NULL,
            NULL
        );
    ELSE
        PERFORM apply_covenant_template_summary_delta(
            target_template,
            0,
            0,
            0,
            CASE WHEN NEW.active_utxos > 0 THEN 1 ELSE 0 END -
                CASE WHEN OLD.active_utxos > 0 THEN 1 ELSE 0 END,
            NEW.active_utxos - OLD.active_utxos,
            NEW.total_amount_sompi - OLD.total_amount_sompi,
            0,
            0,
            0,
            0,
            NULL,
            NULL
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER covenant_summaries_refresh_template_summary
AFTER INSERT OR UPDATE OR DELETE ON covenant_summaries
FOR EACH ROW
EXECUTE FUNCTION refresh_covenant_template_summary_from_summary_trigger();

CREATE OR REPLACE FUNCTION refresh_covenant_template_summary_from_action_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_template TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Deletes are rare reorg/repair paths; rebuild to avoid stale latest_action_time_ms.
        PERFORM refresh_covenant_template_summary_for_covenant(OLD.covenant_id);
        RETURN OLD;
    END IF;

    IF TG_OP = 'UPDATE' AND OLD.covenant_id IS DISTINCT FROM NEW.covenant_id THEN
        -- Moving an action between covenants is also a repair path; rebuild both sides.
        PERFORM refresh_covenant_template_summary_for_covenant(OLD.covenant_id);
        PERFORM refresh_covenant_template_summary_for_covenant(NEW.covenant_id);
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' AND OLD.block_time_ms IS DISTINCT FROM NEW.block_time_ms AND OLD.block_time_ms >= NEW.block_time_ms THEN
        -- If a latest timestamp may have moved backward, rebuild once for correctness.
        PERFORM refresh_covenant_template_summary_for_covenant(NEW.covenant_id);
        RETURN NEW;
    END IF;

    SELECT COALESCE(template_name, claimed_template, 'Unknown')
      INTO target_template
      FROM covenants
     WHERE covenant_id = NEW.covenant_id;

    IF target_template IS NULL THEN
        RETURN NEW;
    END IF;

    PERFORM apply_covenant_template_summary_delta(
        target_template,
        0,
        0,
        0,
        0,
        0,
        0,
        CASE WHEN TG_OP = 'INSERT' THEN 1 ELSE 0 END,
        0,
        0,
        0,
        NULL,
        NEW.block_time_ms
    );

    RETURN NEW;
END;
$$;

CREATE TRIGGER covenant_actions_refresh_template_summary
AFTER INSERT OR UPDATE OF covenant_id, block_time_ms OR DELETE ON covenant_actions
FOR EACH ROW
EXECUTE FUNCTION refresh_covenant_template_summary_from_action_trigger();

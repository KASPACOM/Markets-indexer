-- Repair each affected template once after backward action timestamp updates.
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
        -- The statement trigger repairs backward timestamps after all row summaries update.
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

CREATE FUNCTION refresh_covenant_template_summary_from_action_timestamp_statement()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM 1
    FROM covenant_template_summaries summary
    JOIN (
        SELECT DISTINCT COALESCE(c.template_name, c.claimed_template, 'Unknown') AS template
        FROM previous_actions old_action
        JOIN updated_actions new_action USING (id)
        JOIN covenants c ON c.covenant_id = new_action.covenant_id
        WHERE old_action.covenant_id = new_action.covenant_id
          AND old_action.block_time_ms > new_action.block_time_ms
    ) affected ON affected.template = summary.template
    ORDER BY summary.template
    FOR UPDATE OF summary;

    WITH affected AS (
        SELECT COALESCE(c.template_name, c.claimed_template, 'Unknown') AS template,
               MAX(old_action.block_time_ms) AS previous_latest_time_ms
        FROM previous_actions old_action
        JOIN updated_actions new_action USING (id)
        JOIN covenants c ON c.covenant_id = new_action.covenant_id
        WHERE old_action.covenant_id = new_action.covenant_id
          AND old_action.block_time_ms > new_action.block_time_ms
        GROUP BY COALESCE(c.template_name, c.claimed_template, 'Unknown')
    )
    UPDATE covenant_template_summaries summary
       SET latest_action_time_ms = (
               SELECT action_summary.latest_action_time_ms
               FROM covenant_action_summaries action_summary
               JOIN covenants c ON c.covenant_id = action_summary.covenant_id
               WHERE COALESCE(c.template_name, c.claimed_template, 'Unknown') = affected.template
                 AND action_summary.latest_action_time_ms IS NOT NULL
               ORDER BY action_summary.latest_action_time_ms DESC NULLS LAST
               LIMIT 1
           ),
           updated_at_ms = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
      FROM affected
     WHERE summary.template = affected.template
       AND summary.latest_action_time_ms <= affected.previous_latest_time_ms;
    RETURN NULL;
END;
$$;

CREATE TRIGGER covenant_actions_refresh_template_timestamp_statement
AFTER UPDATE ON covenant_actions
REFERENCING OLD TABLE AS previous_actions NEW TABLE AS updated_actions
FOR EACH STATEMENT
EXECUTE FUNCTION refresh_covenant_template_summary_from_action_timestamp_statement();

-- A dense REST window can insert thousands of generic actions in one statement.
-- Apply insert deltas once per covenant and template using only rows that were
-- actually inserted. UPDATE and DELETE retain their existing repair triggers.
CREATE OR REPLACE FUNCTION refresh_covenant_action_summary_from_insert_statement()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO covenant_action_summaries (
        covenant_id, action_count, latest_action_time_ms, updated_at_ms
    )
    SELECT covenant_id, COUNT(*), MAX(block_time_ms),
           EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
    FROM inserted_actions
    WHERE covenant_id IS NOT NULL
    GROUP BY covenant_id
    ORDER BY covenant_id
    ON CONFLICT (covenant_id) DO UPDATE SET
        action_count = covenant_action_summaries.action_count + EXCLUDED.action_count,
        latest_action_time_ms = CASE
            WHEN covenant_action_summaries.latest_action_time_ms IS NULL
                THEN EXCLUDED.latest_action_time_ms
            WHEN EXCLUDED.latest_action_time_ms IS NULL
                THEN covenant_action_summaries.latest_action_time_ms
            ELSE GREATEST(
                covenant_action_summaries.latest_action_time_ms,
                EXCLUDED.latest_action_time_ms
            )
        END,
        updated_at_ms = EXCLUDED.updated_at_ms;
    RETURN NULL;
END;
$$;

DROP TRIGGER covenant_actions_refresh_summary ON covenant_actions;
DROP TRIGGER IF EXISTS covenant_actions_refresh_summary_insert ON covenant_actions;
CREATE TRIGGER covenant_actions_refresh_summary
AFTER UPDATE OR DELETE ON covenant_actions
FOR EACH ROW EXECUTE FUNCTION refresh_covenant_action_summary_from_action_trigger();
CREATE TRIGGER covenant_actions_refresh_summary_insert
AFTER INSERT ON covenant_actions
REFERENCING NEW TABLE AS inserted_actions
FOR EACH STATEMENT EXECUTE FUNCTION refresh_covenant_action_summary_from_insert_statement();

CREATE OR REPLACE FUNCTION refresh_covenant_template_summary_from_insert_statement()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    item RECORD;
BEGIN
    FOR item IN
        SELECT COALESCE(c.template_name, c.claimed_template, 'Unknown') AS template,
               COUNT(*) AS action_count, MAX(a.block_time_ms) AS latest_action_time_ms
        FROM inserted_actions a
        JOIN covenants c USING (covenant_id)
        GROUP BY 1
        ORDER BY 1
    LOOP
        PERFORM apply_covenant_template_summary_delta(
            item.template, 0, 0, 0, 0, 0, 0,
            item.action_count, 0, 0, 0, NULL, item.latest_action_time_ms
        );
    END LOOP;
    RETURN NULL;
END;
$$;

DROP TRIGGER covenant_actions_refresh_template_summary ON covenant_actions;
DROP TRIGGER IF EXISTS covenant_actions_refresh_template_summary_insert ON covenant_actions;
CREATE TRIGGER covenant_actions_refresh_template_summary
AFTER UPDATE OF covenant_id, block_time_ms ON covenant_actions
FOR EACH ROW EXECUTE FUNCTION refresh_covenant_template_summary_from_action_trigger();
CREATE TRIGGER covenant_actions_refresh_template_summary_insert
AFTER INSERT ON covenant_actions
REFERENCING NEW TABLE AS inserted_actions
FOR EACH STATEMENT EXECUTE FUNCTION refresh_covenant_template_summary_from_insert_statement();

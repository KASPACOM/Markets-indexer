-- The existing latest-action index stores descending values with NULLS LAST.
-- Match that order in reorg fallback lookups so PostgreSQL can stop after the
-- first matching covenant instead of scanning and sorting every summary row.
CREATE OR REPLACE FUNCTION refresh_covenant_template_summary_from_action_delete_statement()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM 1
    FROM covenant_template_summaries summary
    JOIN (
        SELECT DISTINCT
            COALESCE(c.template_name, c.claimed_template, 'Unknown') AS template
        FROM deleted_actions deleted
        JOIN covenants c ON c.covenant_id = deleted.covenant_id
    ) affected ON affected.template = summary.template
    ORDER BY summary.template
    FOR UPDATE OF summary;

    WITH deleted_by_template AS (
        SELECT
            COALESCE(c.template_name, c.claimed_template, 'Unknown') AS template,
            COUNT(*)::BIGINT AS deleted_count,
            MAX(deleted.block_time_ms) AS deleted_latest_time_ms
        FROM deleted_actions deleted
        JOIN covenants c ON c.covenant_id = deleted.covenant_id
        GROUP BY COALESCE(c.template_name, c.claimed_template, 'Unknown')
    )
    UPDATE covenant_template_summaries summary
       SET action_count = GREATEST(summary.action_count - deleted.deleted_count, 0),
           latest_action_time_ms = CASE
               WHEN summary.latest_action_time_ms IS NULL THEN NULL
               WHEN summary.latest_action_time_ms > deleted.deleted_latest_time_ms
                   THEN summary.latest_action_time_ms
               ELSE (
                   SELECT action_summary.latest_action_time_ms
                   FROM covenant_action_summaries action_summary
                   JOIN covenants action_covenant
                     ON action_covenant.covenant_id = action_summary.covenant_id
                   WHERE COALESCE(
                             action_covenant.template_name,
                             action_covenant.claimed_template,
                             'Unknown'
                         ) = deleted.template
                     AND action_summary.latest_action_time_ms IS NOT NULL
                   ORDER BY action_summary.latest_action_time_ms DESC NULLS LAST
                   LIMIT 1
               )
           END,
           updated_at_ms = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
      FROM deleted_by_template deleted
     WHERE summary.template = deleted.template;

    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION apply_covenant_template_summary_covenant_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    old_template TEXT;
    active_utxos_value BIGINT;
    total_amount_sompi_value NUMERIC;
    action_count_value BIGINT;
    covenant_latest_action_time_ms BIGINT;
    template_latest_created_at_ms BIGINT;
    template_latest_action_time_ms BIGINT;
BEGIN
    old_template := COALESCE(OLD.template_name, OLD.claimed_template, 'Unknown');

    SELECT latest_created_at_ms, latest_action_time_ms
      INTO template_latest_created_at_ms, template_latest_action_time_ms
      FROM covenant_template_summaries
     WHERE template = old_template
     FOR UPDATE;

    SELECT
        COALESCE(summary.active_utxos, 0)::BIGINT,
        COALESCE(summary.total_amount_sompi, 0)::NUMERIC,
        COALESCE(action_summary.action_count, 0)::BIGINT,
        action_summary.latest_action_time_ms
      INTO active_utxos_value,
           total_amount_sompi_value,
           action_count_value,
           covenant_latest_action_time_ms
      FROM (SELECT 1) seed
      LEFT JOIN covenant_summaries summary
        ON summary.covenant_id = OLD.covenant_id
      LEFT JOIN covenant_action_summaries action_summary
        ON action_summary.covenant_id = OLD.covenant_id;

    PERFORM apply_covenant_template_summary_delta(
        old_template,
        -1,
        -(CASE WHEN OLD.template_name IS NOT NULL THEN 1 ELSE 0 END),
        -(CASE WHEN OLD.template_name IS NULL AND OLD.claimed_template IS NOT NULL THEN 1 ELSE 0 END),
        -(CASE WHEN active_utxos_value > 0 THEN 1 ELSE 0 END),
        -active_utxos_value,
        -total_amount_sompi_value,
        -action_count_value,
        -(CASE WHEN OLD.classification_status = 'matched' THEN 1 ELSE 0 END),
        -(CASE WHEN OLD.classification_status = 'unrevealed' THEN 1 ELSE 0 END),
        -(CASE WHEN OLD.classification_status = 'unmatched' THEN 1 ELSE 0 END),
        NULL,
        NULL
    );

    IF template_latest_created_at_ms IS NOT DISTINCT FROM OLD.created_at_ms THEN
        UPDATE covenant_template_summaries summary
           SET latest_created_at_ms = (
                   SELECT covenant.created_at_ms
                   FROM covenants covenant
                   WHERE COALESCE(
                             covenant.template_name,
                             covenant.claimed_template,
                             'Unknown'
                         ) = old_template
                     AND covenant.covenant_id <> OLD.covenant_id
                   ORDER BY covenant.created_at_ms DESC, covenant.covenant_id DESC
                   LIMIT 1
               ),
               updated_at_ms = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
         WHERE summary.template = old_template;
    END IF;

    IF covenant_latest_action_time_ms IS NOT NULL
       AND template_latest_action_time_ms IS NOT DISTINCT FROM covenant_latest_action_time_ms
    THEN
        UPDATE covenant_template_summaries summary
           SET latest_action_time_ms = CASE
                   WHEN summary.action_count = 0 THEN NULL
                   ELSE (
                       SELECT action_summary.latest_action_time_ms
                       FROM covenant_action_summaries action_summary
                       JOIN covenants covenant
                         ON covenant.covenant_id = action_summary.covenant_id
                       WHERE covenant.covenant_id <> OLD.covenant_id
                         AND COALESCE(
                                 covenant.template_name,
                                 covenant.claimed_template,
                                 'Unknown'
                             ) = old_template
                         AND action_summary.latest_action_time_ms IS NOT NULL
                       ORDER BY action_summary.latest_action_time_ms DESC NULLS LAST
                       LIMIT 1
                   )
               END,
               updated_at_ms = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
         WHERE summary.template = old_template;
    END IF;

    RETURN OLD;
END;
$$;

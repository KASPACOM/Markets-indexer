-- Batch forward and backward timestamp-only updates without changing action counts.
CREATE OR REPLACE FUNCTION refresh_covenant_action_summary_from_action_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM add_covenant_action_summary(NEW.covenant_id, NEW.block_time_ms);
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        PERFORM remove_covenant_action_summary(OLD.covenant_id, OLD.block_time_ms);
        RETURN OLD;
    END IF;

    IF OLD.covenant_id IS DISTINCT FROM NEW.covenant_id THEN
        -- Covenant ID changes are repair/canonicalization operations. Rebuild both
        -- sides because ON UPDATE CASCADE may move many actions in one statement.
        PERFORM refresh_covenant_action_summary(OLD.covenant_id);
        PERFORM refresh_covenant_action_summary(NEW.covenant_id);
        RETURN NEW;
    END IF;

    -- Same-covenant timestamp updates are repaired after the entire statement.
    RETURN NEW;
END;
$$;

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

    IF TG_OP = 'UPDATE' THEN
        -- Action summaries and template timestamps settle together after the statement.
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


-- The existing AFTER UPDATE transition-table trigger invokes this function.
-- Repair covenant summaries first, then template summaries, from final rows.
CREATE OR REPLACE FUNCTION refresh_covenant_template_summary_from_action_timestamp_statement()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    missing_covenant BYTEA;
    missing_template TEXT;
BEGIN
    FOR missing_covenant IN
        WITH affected AS (SELECT DISTINCT n.covenant_id
        FROM previous_actions o JOIN updated_actions n USING(id)
        WHERE o.covenant_id=n.covenant_id
          AND o.block_time_ms IS DISTINCT FROM n.block_time_ms)
        SELECT a.covenant_id FROM affected a
        LEFT JOIN covenant_action_summaries s USING(covenant_id)
        WHERE s.covenant_id IS NULL ORDER BY a.covenant_id
    LOOP
        PERFORM refresh_covenant_action_summary(missing_covenant);
    END LOOP;

    PERFORM 1 FROM covenant_action_summaries s
    JOIN (SELECT DISTINCT n.covenant_id
        FROM previous_actions o JOIN updated_actions n USING(id)
        WHERE o.covenant_id=n.covenant_id
          AND o.block_time_ms IS DISTINCT FROM n.block_time_ms) a USING(covenant_id)
    ORDER BY s.covenant_id FOR UPDATE OF s;

    -- Counts are unchanged by same-covenant timestamp edits. The established
    -- summary invariant lets unaffected maxima survive without random index I/O.
    -- A batch containing every action supplies its exact new maximum directly.
    -- Detectable invalidation uses the exact indexed fallback. This preserves
    -- valid summaries; it cannot detect arbitrary pre-existing cache corruption.
    WITH affected AS (
        SELECT n.covenant_id,COUNT(*) AS changed_count,
               MAX(o.block_time_ms) AS old_max,MAX(n.block_time_ms) AS new_max
        FROM previous_actions o JOIN updated_actions n USING(id)
        WHERE o.covenant_id=n.covenant_id
          AND o.block_time_ms IS DISTINCT FROM n.block_time_ms
        GROUP BY n.covenant_id
    ), expected AS MATERIALIZED (
        SELECT a.covenant_id, CASE
            WHEN s.action_count=a.changed_count THEN a.new_max
            WHEN s.action_count>a.changed_count
                 AND s.latest_action_time_ms>=a.old_max
                 AND (s.latest_action_time_ms>a.old_max OR a.new_max>=s.latest_action_time_ms)
                THEN GREATEST(s.latest_action_time_ms,a.new_max)
            ELSE (
                SELECT block_time_ms FROM covenant_actions source
                WHERE source.covenant_id=a.covenant_id
                ORDER BY block_time_ms DESC,id DESC LIMIT 1
            ) END AS latest_time
        FROM affected a JOIN covenant_action_summaries s USING(covenant_id)
    )
    UPDATE covenant_action_summaries s
    SET latest_action_time_ms=e.latest_time,
        updated_at_ms=EXTRACT(EPOCH FROM NOW())::BIGINT*1000
    FROM expected e WHERE s.covenant_id=e.covenant_id
      AND s.latest_action_time_ms IS DISTINCT FROM e.latest_time;

    FOR missing_template IN
        WITH affected AS (SELECT DISTINCT COALESCE(c.template_name,c.claimed_template,'Unknown') AS template
        FROM previous_actions o JOIN updated_actions n USING(id)
        JOIN covenants c ON c.covenant_id=n.covenant_id
        WHERE o.covenant_id=n.covenant_id
          AND o.block_time_ms IS DISTINCT FROM n.block_time_ms)
        SELECT a.template FROM affected a
        LEFT JOIN covenant_template_summaries s USING(template)
        WHERE s.template IS NULL ORDER BY a.template
    LOOP
        PERFORM refresh_covenant_template_summary(missing_template);
    END LOOP;

    PERFORM 1 FROM covenant_template_summaries s
    JOIN (SELECT DISTINCT COALESCE(c.template_name,c.claimed_template,'Unknown') AS template
        FROM previous_actions o JOIN updated_actions n USING(id)
        JOIN covenants c ON c.covenant_id=n.covenant_id
        WHERE o.covenant_id=n.covenant_id
          AND o.block_time_ms IS DISTINCT FROM n.block_time_ms) a USING(template)
    ORDER BY s.template FOR UPDATE OF s;

    WITH affected AS (SELECT DISTINCT COALESCE(c.template_name,c.claimed_template,'Unknown') AS template
        FROM previous_actions o JOIN updated_actions n USING(id)
        JOIN covenants c ON c.covenant_id=n.covenant_id
        WHERE o.covenant_id=n.covenant_id
          AND o.block_time_ms IS DISTINCT FROM n.block_time_ms), expected AS MATERIALIZED (
        SELECT a.template, (
            SELECT summary.latest_action_time_ms
            FROM covenant_action_summaries summary
            JOIN covenants c ON c.covenant_id=summary.covenant_id
            WHERE COALESCE(c.template_name,c.claimed_template,'Unknown')=a.template
              AND summary.latest_action_time_ms IS NOT NULL
            ORDER BY summary.latest_action_time_ms DESC NULLS LAST LIMIT 1
        ) AS latest_time FROM affected a
    )
    UPDATE covenant_template_summaries s
    SET latest_action_time_ms=e.latest_time,
        updated_at_ms=EXTRACT(EPOCH FROM NOW())::BIGINT*1000
    FROM expected e WHERE s.template=e.template
      AND s.latest_action_time_ms IS DISTINCT FROM e.latest_time;
    RETURN NULL;
END;
$$;

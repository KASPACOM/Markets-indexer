CREATE OR REPLACE FUNCTION add_covenant_action_summary(
    target_covenant_id BYTEA,
    action_time_ms BIGINT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF target_covenant_id IS NULL THEN
        RETURN;
    END IF;

    INSERT INTO covenant_action_summaries (
        covenant_id,
        action_count,
        latest_action_time_ms,
        updated_at_ms
    )
    VALUES (
        target_covenant_id,
        1,
        action_time_ms,
        EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
    )
    ON CONFLICT (covenant_id) DO UPDATE SET
        action_count = covenant_action_summaries.action_count + 1,
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
END;
$$;

CREATE OR REPLACE FUNCTION remove_covenant_action_summary(
    target_covenant_id BYTEA,
    removed_action_time_ms BIGINT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF target_covenant_id IS NULL THEN
        RETURN;
    END IF;

    UPDATE covenant_action_summaries summary
    SET action_count = GREATEST(summary.action_count - 1, 0),
        latest_action_time_ms = CASE
            WHEN summary.action_count <= 1 THEN NULL
            WHEN summary.latest_action_time_ms IS NOT DISTINCT FROM removed_action_time_ms THEN (
                SELECT action.block_time_ms
                FROM covenant_actions action
                WHERE action.covenant_id = target_covenant_id
                ORDER BY action.block_time_ms DESC, action.id DESC
                LIMIT 1
            )
            ELSE summary.latest_action_time_ms
        END,
        updated_at_ms = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
    WHERE summary.covenant_id = target_covenant_id;

    IF NOT FOUND THEN
        PERFORM refresh_covenant_action_summary(target_covenant_id);
    END IF;
END;
$$;

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

    IF OLD.block_time_ms IS NOT DISTINCT FROM NEW.block_time_ms THEN
        RETURN NEW;
    END IF;

    UPDATE covenant_action_summaries summary
    SET latest_action_time_ms = CASE
            WHEN NEW.block_time_ms > OLD.block_time_ms THEN
                GREATEST(summary.latest_action_time_ms, NEW.block_time_ms)
            WHEN summary.latest_action_time_ms IS NOT DISTINCT FROM OLD.block_time_ms THEN (
                SELECT action.block_time_ms
                FROM covenant_actions action
                WHERE action.covenant_id = NEW.covenant_id
                ORDER BY action.block_time_ms DESC, action.id DESC
                LIMIT 1
            )
            ELSE summary.latest_action_time_ms
        END,
        updated_at_ms = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
    WHERE summary.covenant_id = NEW.covenant_id;

    IF NOT FOUND THEN
        PERFORM refresh_covenant_action_summary(NEW.covenant_id);
    END IF;

    RETURN NEW;
END;
$$;

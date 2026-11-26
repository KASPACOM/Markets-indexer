CREATE TABLE covenant_action_summaries (
    covenant_id           BYTEA PRIMARY KEY REFERENCES covenants(covenant_id) ON UPDATE CASCADE ON DELETE CASCADE,
    action_count          BIGINT NOT NULL DEFAULT 0,
    latest_action_time_ms BIGINT,
    updated_at_ms         BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

CREATE INDEX covenant_action_summaries_latest_idx
    ON covenant_action_summaries (latest_action_time_ms DESC NULLS LAST, covenant_id);

CREATE OR REPLACE FUNCTION refresh_covenant_action_summary(target_covenant_id BYTEA)
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
    SELECT
        c.covenant_id,
        COALESCE(a.action_count, 0)::BIGINT AS action_count,
        a.latest_action_time_ms,
        EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 AS updated_at_ms
    FROM covenants c
    LEFT JOIN LATERAL (
        SELECT
            COUNT(*)::BIGINT AS action_count,
            MAX(block_time_ms) AS latest_action_time_ms
        FROM covenant_actions
        WHERE covenant_id = c.covenant_id
    ) a ON TRUE
    WHERE c.covenant_id = target_covenant_id
    ON CONFLICT (covenant_id) DO UPDATE SET
        action_count = EXCLUDED.action_count,
        latest_action_time_ms = EXCLUDED.latest_action_time_ms,
        updated_at_ms = EXCLUDED.updated_at_ms;

    IF NOT FOUND THEN
        DELETE FROM covenant_action_summaries WHERE covenant_id = target_covenant_id;
    END IF;
END;
$$;

INSERT INTO covenant_action_summaries (
    covenant_id,
    action_count,
    latest_action_time_ms,
    updated_at_ms
)
SELECT
    c.covenant_id,
    COALESCE(a.action_count, 0)::BIGINT AS action_count,
    a.latest_action_time_ms,
    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 AS updated_at_ms
FROM covenants c
LEFT JOIN (
    SELECT
        covenant_id,
        COUNT(*)::BIGINT AS action_count,
        MAX(block_time_ms) AS latest_action_time_ms
    FROM covenant_actions
    GROUP BY covenant_id
) a ON a.covenant_id = c.covenant_id;

CREATE OR REPLACE FUNCTION refresh_covenant_action_summary_from_action_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM refresh_covenant_action_summary(OLD.covenant_id);
        RETURN OLD;
    END IF;

    PERFORM refresh_covenant_action_summary(NEW.covenant_id);

    IF TG_OP = 'UPDATE' AND OLD.covenant_id IS DISTINCT FROM NEW.covenant_id THEN
        PERFORM refresh_covenant_action_summary(OLD.covenant_id);
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER covenant_actions_refresh_summary
AFTER INSERT OR UPDATE OR DELETE ON covenant_actions
FOR EACH ROW
EXECUTE FUNCTION refresh_covenant_action_summary_from_action_trigger();

CREATE OR REPLACE FUNCTION refresh_covenant_action_summary_from_covenant_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM refresh_covenant_action_summary(NEW.covenant_id);
    RETURN NEW;
END;
$$;

CREATE TRIGGER covenants_refresh_action_summary
AFTER INSERT OR UPDATE OF covenant_id ON covenants
FOR EACH ROW
EXECUTE FUNCTION refresh_covenant_action_summary_from_covenant_trigger();

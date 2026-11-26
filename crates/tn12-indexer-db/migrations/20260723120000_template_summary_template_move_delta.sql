CREATE OR REPLACE FUNCTION refresh_covenant_template_summary_from_covenant_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    old_template TEXT;
    new_template TEXT;
    active_utxos_value BIGINT;
    total_amount_sompi_value NUMERIC;
    action_count_value BIGINT;
    latest_action_time_ms_value BIGINT;
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
            SELECT
                COALESCE(s.active_utxos, 0)::BIGINT,
                COALESCE(s.total_amount_sompi, 0)::NUMERIC,
                COALESCE(a.action_count, 0)::BIGINT,
                a.latest_action_time_ms
              INTO active_utxos_value,
                   total_amount_sompi_value,
                   action_count_value,
                   latest_action_time_ms_value
              FROM (SELECT 1) seed
              LEFT JOIN covenant_summaries s
                ON s.covenant_id = NEW.covenant_id
              LEFT JOIN covenant_action_summaries a
                ON a.covenant_id = NEW.covenant_id;

            -- A single covenant classification must not rebuild the whole
            -- previous template bucket inside the scanner transaction.
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

            PERFORM apply_covenant_template_summary_delta(
                new_template,
                1,
                CASE WHEN NEW.template_name IS NOT NULL THEN 1 ELSE 0 END,
                CASE WHEN NEW.template_name IS NULL AND NEW.claimed_template IS NOT NULL THEN 1 ELSE 0 END,
                CASE WHEN active_utxos_value > 0 THEN 1 ELSE 0 END,
                active_utxos_value,
                total_amount_sompi_value,
                action_count_value,
                CASE WHEN NEW.classification_status = 'matched' THEN 1 ELSE 0 END,
                CASE WHEN NEW.classification_status = 'unrevealed' THEN 1 ELSE 0 END,
                CASE WHEN NEW.classification_status = 'unmatched' THEN 1 ELSE 0 END,
                NEW.created_at_ms,
                latest_action_time_ms_value
            );
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

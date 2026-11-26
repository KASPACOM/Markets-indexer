CREATE OR REPLACE FUNCTION upsert_covenant_summary_active_utxo(
    target_covenant_id BYTEA,
    target_txid BYTEA,
    target_vout INT,
    target_address TEXT,
    target_amount_sompi BIGINT,
    target_created_block BYTEA
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    target_blue_score BIGINT;
BEGIN
    SELECT COALESCE(blue_score, 0)::BIGINT
      INTO target_blue_score
      FROM blocks
     WHERE hash = target_created_block;

    target_blue_score := COALESCE(target_blue_score, 0);

    INSERT INTO covenant_summaries (
        covenant_id,
        current_address,
        active_utxos,
        total_amount_sompi,
        latest_active_txid,
        latest_active_vout,
        latest_active_block,
        latest_active_blue_score,
        updated_at_ms
    )
    SELECT
        c.covenant_id,
        target_address,
        1,
        target_amount_sompi,
        target_txid,
        target_vout,
        target_created_block,
        target_blue_score,
        EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
    FROM covenants c
    WHERE c.covenant_id = target_covenant_id
    ON CONFLICT (covenant_id) DO UPDATE SET
        current_address = CASE
            WHEN ROW(
                target_blue_score,
                target_txid,
                target_vout
            ) > ROW(
                COALESCE(covenant_summaries.latest_active_blue_score, -1),
                COALESCE(covenant_summaries.latest_active_txid, '\x'::BYTEA),
                COALESCE(covenant_summaries.latest_active_vout, -1)
            ) THEN target_address
            ELSE covenant_summaries.current_address
        END,
        active_utxos = covenant_summaries.active_utxos + 1,
        total_amount_sompi = covenant_summaries.total_amount_sompi + target_amount_sompi,
        latest_active_txid = CASE
            WHEN ROW(
                target_blue_score,
                target_txid,
                target_vout
            ) > ROW(
                COALESCE(covenant_summaries.latest_active_blue_score, -1),
                COALESCE(covenant_summaries.latest_active_txid, '\x'::BYTEA),
                COALESCE(covenant_summaries.latest_active_vout, -1)
            ) THEN target_txid
            ELSE covenant_summaries.latest_active_txid
        END,
        latest_active_vout = CASE
            WHEN ROW(
                target_blue_score,
                target_txid,
                target_vout
            ) > ROW(
                COALESCE(covenant_summaries.latest_active_blue_score, -1),
                COALESCE(covenant_summaries.latest_active_txid, '\x'::BYTEA),
                COALESCE(covenant_summaries.latest_active_vout, -1)
            ) THEN target_vout
            ELSE covenant_summaries.latest_active_vout
        END,
        latest_active_block = CASE
            WHEN ROW(
                target_blue_score,
                target_txid,
                target_vout
            ) > ROW(
                COALESCE(covenant_summaries.latest_active_blue_score, -1),
                COALESCE(covenant_summaries.latest_active_txid, '\x'::BYTEA),
                COALESCE(covenant_summaries.latest_active_vout, -1)
            ) THEN target_created_block
            ELSE covenant_summaries.latest_active_block
        END,
        latest_active_blue_score = GREATEST(
            target_blue_score,
            COALESCE(covenant_summaries.latest_active_blue_score, -1)
        ),
        updated_at_ms = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000;
END;
$$;

CREATE OR REPLACE FUNCTION remove_covenant_summary_active_utxo(
    target_covenant_id BYTEA,
    target_txid BYTEA,
    target_vout INT,
    target_amount_sompi BIGINT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    summary_active_utxos BIGINT;
    removed_latest BOOLEAN;
    defer_repair BOOLEAN;
BEGIN
    SELECT
        active_utxos,
        latest_active_txid = target_txid AND latest_active_vout = target_vout
      INTO summary_active_utxos, removed_latest
      FROM covenant_summaries
     WHERE covenant_id = target_covenant_id
     FOR UPDATE;

    IF NOT FOUND OR summary_active_utxos <= 0 THEN
        PERFORM refresh_covenant_summary(target_covenant_id);
        RETURN;
    END IF;

    UPDATE covenant_summaries s
       SET current_address = CASE
               WHEN summary_active_utxos = 1 THEN c.address
               ELSE s.current_address
           END,
           active_utxos = summary_active_utxos - 1,
           total_amount_sompi = s.total_amount_sompi - target_amount_sompi,
           latest_active_txid = CASE
               WHEN summary_active_utxos = 1 THEN NULL
               ELSE s.latest_active_txid
           END,
           latest_active_vout = CASE
               WHEN summary_active_utxos = 1 THEN NULL
               ELSE s.latest_active_vout
           END,
           latest_active_block = CASE
               WHEN summary_active_utxos = 1 THEN NULL
               ELSE s.latest_active_block
           END,
           latest_active_blue_score = CASE
               WHEN summary_active_utxos = 1 THEN NULL
               ELSE s.latest_active_blue_score
           END,
           updated_at_ms = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
      FROM covenants c
     WHERE s.covenant_id = target_covenant_id
       AND c.covenant_id = s.covenant_id;

    defer_repair := COALESCE(
        current_setting('tn12.defer_covenant_summary_repair', TRUE),
        'off'
    ) = 'on';

    IF summary_active_utxos > 1 AND removed_latest AND NOT defer_repair THEN
        PERFORM refresh_covenant_summary(target_covenant_id);
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION finalize_deferred_covenant_summary(target_covenant_id BYTEA)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    summary_active_utxos BIGINT;
    summary_latest_txid BYTEA;
    summary_latest_vout INT;
    latest_is_active BOOLEAN;
BEGIN
    SELECT active_utxos, latest_active_txid, latest_active_vout
      INTO summary_active_utxos, summary_latest_txid, summary_latest_vout
      FROM covenant_summaries
     WHERE covenant_id = target_covenant_id;

    IF NOT FOUND THEN
        PERFORM refresh_covenant_summary(target_covenant_id);
        RETURN;
    END IF;

    IF summary_active_utxos = 0 THEN
        RETURN;
    END IF;

    SELECT EXISTS (
        SELECT 1
          FROM covenant_utxos
         WHERE txid = summary_latest_txid
           AND vout = summary_latest_vout
           AND covenant_id = target_covenant_id
           AND status = 'active'
    ) INTO latest_is_active;

    IF NOT latest_is_active THEN
        PERFORM refresh_covenant_summary(target_covenant_id);
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION refresh_covenant_summary_from_utxo_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status = 'active' THEN
            PERFORM upsert_covenant_summary_active_utxo(
                NEW.covenant_id,
                NEW.txid,
                NEW.vout,
                NEW.address,
                NEW.amount_sompi,
                NEW.created_block
            );
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        IF OLD.status = 'active' THEN
            PERFORM remove_covenant_summary_active_utxo(
                OLD.covenant_id,
                OLD.txid,
                OLD.vout,
                OLD.amount_sompi
            );
        END IF;
        RETURN OLD;
    END IF;

    IF OLD.covenant_id IS DISTINCT FROM NEW.covenant_id THEN
        PERFORM refresh_covenant_summary(OLD.covenant_id);
        PERFORM refresh_covenant_summary(NEW.covenant_id);
        RETURN NEW;
    END IF;

    IF OLD.status = 'active' AND NEW.status = 'spent' THEN
        PERFORM remove_covenant_summary_active_utxo(
            OLD.covenant_id,
            OLD.txid,
            OLD.vout,
            OLD.amount_sompi
        );
        RETURN NEW;
    END IF;

    IF OLD.status = 'spent' AND NEW.status = 'active' THEN
        PERFORM upsert_covenant_summary_active_utxo(
            NEW.covenant_id,
            NEW.txid,
            NEW.vout,
            NEW.address,
            NEW.amount_sompi,
            NEW.created_block
        );
        RETURN NEW;
    END IF;

    IF NEW.status = 'spent' OR (
        OLD.address IS NOT DISTINCT FROM NEW.address
        AND OLD.amount_sompi IS NOT DISTINCT FROM NEW.amount_sompi
        AND OLD.created_block IS NOT DISTINCT FROM NEW.created_block
    ) THEN
        RETURN NEW;
    END IF;

    PERFORM refresh_covenant_summary(NEW.covenant_id);
    RETURN NEW;
END;
$$;

CREATE TABLE covenant_summaries (
    covenant_id              BYTEA PRIMARY KEY REFERENCES covenants(covenant_id) ON UPDATE CASCADE ON DELETE CASCADE,
    current_address          TEXT NOT NULL,
    active_utxos             BIGINT NOT NULL DEFAULT 0,
    total_amount_sompi       BIGINT NOT NULL DEFAULT 0,
    latest_active_txid       BYTEA,
    latest_active_vout       INT,
    latest_active_block      BYTEA,
    latest_active_blue_score BIGINT,
    updated_at_ms            BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

CREATE INDEX covenant_summaries_active_idx
    ON covenant_summaries (active_utxos DESC, covenant_id);

CREATE INDEX covenant_summaries_amount_idx
    ON covenant_summaries (total_amount_sompi DESC, covenant_id);

CREATE OR REPLACE FUNCTION refresh_covenant_summary(target_covenant_id BYTEA)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF target_covenant_id IS NULL THEN
        RETURN;
    END IF;

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
        COALESCE(active_current.address, c.address) AS current_address,
        COALESCE(active_stats.active_utxos, 0)::BIGINT AS active_utxos,
        COALESCE(active_stats.total_amount_sompi, 0)::BIGINT AS total_amount_sompi,
        active_current.txid,
        active_current.vout,
        active_current.created_block,
        active_current.blue_score,
        EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 AS updated_at_ms
    FROM covenants c
    LEFT JOIN LATERAL (
        SELECT
            COUNT(*)::BIGINT AS active_utxos,
            COALESCE(SUM(u.amount_sompi), 0)::BIGINT AS total_amount_sompi
        FROM covenant_utxos u
        WHERE u.covenant_id = c.covenant_id
          AND u.status = 'active'
    ) active_stats ON TRUE
    LEFT JOIN LATERAL (
        SELECT
            u.txid,
            u.vout,
            u.address,
            u.created_block,
            COALESCE(b.blue_score, 0)::BIGINT AS blue_score
        FROM covenant_utxos u
        LEFT JOIN blocks b ON b.hash = u.created_block
        WHERE u.covenant_id = c.covenant_id
          AND u.status = 'active'
        ORDER BY COALESCE(b.blue_score, 0) DESC, u.txid DESC, u.vout DESC
        LIMIT 1
    ) active_current ON TRUE
    WHERE c.covenant_id = target_covenant_id
    ON CONFLICT (covenant_id) DO UPDATE SET
        current_address = EXCLUDED.current_address,
        active_utxos = EXCLUDED.active_utxos,
        total_amount_sompi = EXCLUDED.total_amount_sompi,
        latest_active_txid = EXCLUDED.latest_active_txid,
        latest_active_vout = EXCLUDED.latest_active_vout,
        latest_active_block = EXCLUDED.latest_active_block,
        latest_active_blue_score = EXCLUDED.latest_active_blue_score,
        updated_at_ms = EXCLUDED.updated_at_ms;

    IF NOT FOUND THEN
        DELETE FROM covenant_summaries WHERE covenant_id = target_covenant_id;
    END IF;
END;
$$;

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
    COALESCE(active_current.address, c.address) AS current_address,
    COALESCE(active_stats.active_utxos, 0)::BIGINT AS active_utxos,
    COALESCE(active_stats.total_amount_sompi, 0)::BIGINT AS total_amount_sompi,
    active_current.txid,
    active_current.vout,
    active_current.created_block,
    active_current.blue_score,
    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 AS updated_at_ms
FROM covenants c
LEFT JOIN (
    SELECT
        covenant_id,
        COUNT(*)::BIGINT AS active_utxos,
        COALESCE(SUM(amount_sompi), 0)::BIGINT AS total_amount_sompi
    FROM covenant_utxos
    WHERE status = 'active'
    GROUP BY covenant_id
) active_stats ON active_stats.covenant_id = c.covenant_id
LEFT JOIN (
    SELECT DISTINCT ON (u.covenant_id)
        u.covenant_id,
        u.txid,
        u.vout,
        u.address,
        u.created_block,
        COALESCE(b.blue_score, 0)::BIGINT AS blue_score
    FROM covenant_utxos u
    LEFT JOIN blocks b ON b.hash = u.created_block
    WHERE u.status = 'active'
    ORDER BY u.covenant_id, COALESCE(b.blue_score, 0) DESC, u.txid DESC, u.vout DESC
) active_current ON active_current.covenant_id = c.covenant_id;

CREATE OR REPLACE FUNCTION refresh_covenant_summary_from_utxo_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM refresh_covenant_summary(OLD.covenant_id);
        RETURN OLD;
    END IF;

    PERFORM refresh_covenant_summary(NEW.covenant_id);

    IF TG_OP = 'UPDATE' AND OLD.covenant_id IS DISTINCT FROM NEW.covenant_id THEN
        PERFORM refresh_covenant_summary(OLD.covenant_id);
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER covenant_utxos_refresh_summary
AFTER INSERT OR UPDATE OR DELETE ON covenant_utxos
FOR EACH ROW
EXECUTE FUNCTION refresh_covenant_summary_from_utxo_trigger();

CREATE OR REPLACE FUNCTION refresh_covenant_summary_from_covenant_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM refresh_covenant_summary(NEW.covenant_id);
    RETURN NEW;
END;
$$;

CREATE TRIGGER covenants_refresh_summary
AFTER INSERT OR UPDATE OF covenant_id, address ON covenants
FOR EACH ROW
EXECUTE FUNCTION refresh_covenant_summary_from_covenant_trigger();

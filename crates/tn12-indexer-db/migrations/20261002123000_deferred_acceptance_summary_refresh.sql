-- The verified acceptance transition batches summary repairs after its
-- metadata-only UTXO reassociation. Other writes keep the normal trigger path.

CREATE OR REPLACE FUNCTION refresh_covenant_summary_from_utxo_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    old_score BIGINT;
    new_score BIGINT;
    summary covenant_summaries%ROWTYPE;
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

    IF current_setting('tn12.defer_acceptance_summary_refresh', TRUE) = 'on'
       AND OLD.status = 'active' AND NEW.status = 'active'
       AND OLD.covenant_id IS NOT DISTINCT FROM NEW.covenant_id
       AND OLD.txid IS NOT DISTINCT FROM NEW.txid
       AND OLD.vout IS NOT DISTINCT FROM NEW.vout
       AND OLD.address IS NOT DISTINCT FROM NEW.address
       AND OLD.amount_sompi IS NOT DISTINCT FROM NEW.amount_sompi
       AND OLD.created_block IS DISTINCT FROM NEW.created_block THEN
        RETURN NEW;
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

    -- Metadata-only reassociation preserves counts and amounts. Only skip
    -- work when the latest-output ordering and its cached row remain valid.
    IF OLD.status = 'active' AND NEW.status = 'active'
       AND OLD.txid IS NOT DISTINCT FROM NEW.txid
       AND OLD.vout IS NOT DISTINCT FROM NEW.vout
       AND OLD.address IS NOT DISTINCT FROM NEW.address
       AND OLD.amount_sompi IS NOT DISTINCT FROM NEW.amount_sompi
       AND OLD.created_block IS DISTINCT FROM NEW.created_block THEN
        SELECT blue_score INTO old_score FROM blocks WHERE hash = OLD.created_block;
        SELECT blue_score INTO new_score FROM blocks WHERE hash = NEW.created_block;
        -- AFTER events see every row changed by the statement. Trust the
        -- cached winner only when its current row still matches every field.
        -- If another changed row can outrank it, that row's own event cannot
        -- take this branch and will refresh the final statement state.
        IF old_score IS NOT NULL AND new_score IS NOT NULL
           AND old_score <> new_score THEN
            SELECT * INTO summary FROM covenant_summaries
             WHERE covenant_id = NEW.covenant_id AND active_utxos > 0
               AND ROW(latest_active_blue_score, latest_active_txid,
                       latest_active_vout) > ROW(old_score, NEW.txid, NEW.vout)
               AND ROW(latest_active_blue_score, latest_active_txid,
                       latest_active_vout) > ROW(new_score, NEW.txid, NEW.vout)
             FOR UPDATE;
            IF FOUND AND EXISTS (
                   SELECT 1 FROM covenant_utxos u JOIN blocks b ON b.hash=u.created_block
                    WHERE u.txid=summary.latest_active_txid
                      AND u.vout=summary.latest_active_vout
                      AND u.covenant_id=NEW.covenant_id AND u.status='active'
                      AND u.created_block=summary.latest_active_block
                      AND u.address=summary.current_address
                      AND b.blue_score=summary.latest_active_blue_score
               ) THEN
                RETURN NEW;
            END IF;
        END IF;
        IF old_score IS NOT NULL AND old_score = new_score THEN
            SELECT * INTO summary FROM covenant_summaries
             WHERE covenant_id = NEW.covenant_id FOR UPDATE;
            IF FOUND AND summary.active_utxos > 0 THEN
                IF summary.latest_active_txid = NEW.txid
                   AND summary.latest_active_vout = NEW.vout
                   AND summary.latest_active_block = OLD.created_block
                   AND summary.latest_active_blue_score = old_score
                   AND summary.current_address = OLD.address THEN
                    UPDATE covenant_summaries
                       SET latest_active_block = NEW.created_block,
                           updated_at_ms = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
                     WHERE covenant_id = NEW.covenant_id;
                    RETURN NEW;
                ELSIF ROW(summary.latest_active_blue_score, summary.latest_active_txid,
                          summary.latest_active_vout) > ROW(old_score, NEW.txid, NEW.vout)
                      AND EXISTS (
                          SELECT 1 FROM covenant_utxos u JOIN blocks b ON b.hash=u.created_block
                           WHERE u.txid=summary.latest_active_txid
                             AND u.vout=summary.latest_active_vout
                             AND u.covenant_id=NEW.covenant_id AND u.status='active'
                             -- AFTER events see all rows changed by the statement;
                             -- the latest row's own event may still be pending.
                             AND (u.created_block=summary.latest_active_block
                                  OR (summary.latest_active_block=OLD.created_block
                                      AND u.created_block=NEW.created_block))
                             AND u.address=summary.current_address
                             AND b.blue_score=summary.latest_active_blue_score
                      ) THEN
                    RETURN NEW;
                END IF;
            END IF;
        END IF;
    END IF;

    PERFORM refresh_covenant_summary(NEW.covenant_id);
    RETURN NEW;
END;
$$;

-- An acceptance map is historical evidence, not a single-successor block alias.
-- Block hashes intentionally have no FK to blocks: evidence and stale-source
-- protection must survive a later canonical target reorg.
CREATE TABLE historical_acceptance_maps (
    proof_hash BYTEA PRIMARY KEY CHECK (octet_length(proof_hash) = 32),
    source_tip BIGINT NOT NULL CHECK (source_tip >= 0),
    window_start BIGINT NOT NULL CHECK (window_start >= 0),
    window_end BIGINT NOT NULL,
    cohort_digest BYTEA NOT NULL CHECK (octet_length(cohort_digest) = 32),
    window_digest BYTEA NOT NULL CHECK (octet_length(window_digest) = 32),
    -- Canonical UTF-8 JSON bytes, serialized outside the writer lock. BYTEA
    -- avoids expanding byte-array elements into PostgreSQL JSONB arrays.
    window_evidence BYTEA NOT NULL CHECK (octet_length(window_evidence) BETWEEN 1 AND 67108864),
    cohort_evidence BYTEA NOT NULL CHECK (octet_length(cohort_evidence) BETWEEN 1 AND 16777216),
    evidence JSONB NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
    status TEXT NOT NULL DEFAULT 'applied' CHECK (status IN ('applied', 'target_lost')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (window_end > window_start AND window_end - window_start <= 1000),
    CHECK (source_tip >= window_end AND source_tip - window_end >= 1000)
);

CREATE TABLE historical_acceptance_map_sources (
    old_hash BYTEA PRIMARY KEY CHECK (octet_length(old_hash) = 32),
    proof_hash BYTEA NOT NULL REFERENCES historical_acceptance_maps(proof_hash) DEFERRABLE INITIALLY DEFERRED,
    UNIQUE (proof_hash, old_hash)
);

CREATE TABLE historical_acceptance_map_entries (
    proof_hash BYTEA NOT NULL,
    old_hash BYTEA NOT NULL,
    txid BYTEA NOT NULL CHECK (octet_length(txid) = 32),
    target_hash BYTEA NOT NULL CHECK (octet_length(target_hash) = 32 AND target_hash <> old_hash),
    target_score BIGINT NOT NULL CHECK (target_score >= 0),
    target_time_ms BIGINT NOT NULL CHECK (target_time_ms >= 0),
    PRIMARY KEY (old_hash, txid),
    UNIQUE (proof_hash, txid),
    FOREIGN KEY (proof_hash, old_hash)
        REFERENCES historical_acceptance_map_sources(proof_hash, old_hash)
);
CREATE INDEX historical_acceptance_map_entries_target_idx
    ON historical_acceptance_map_entries(target_hash, proof_hash);
CREATE INDEX historical_acceptance_map_entries_txid_idx
    ON historical_acceptance_map_entries(txid, proof_hash);

CREATE FUNCTION guard_historical_acceptance_map_evidence() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Match the application writer lock. This also closes concurrent append
        -- races between a child insert and the transaction sealing its parent.
        PERFORM pg_advisory_xact_lock(6074847039450202930);
        IF TG_TABLE_NAME = 'historical_acceptance_maps' THEN
            IF NEW.status <> 'applied'
               OR NOT EXISTS (SELECT 1 FROM historical_acceptance_map_sources WHERE proof_hash=NEW.proof_hash)
               OR EXISTS (SELECT 1 FROM historical_acceptance_map_sources s
                    WHERE s.proof_hash=NEW.proof_hash AND NOT EXISTS
                      (SELECT 1 FROM historical_acceptance_map_entries e
                       WHERE e.proof_hash=s.proof_hash AND e.old_hash=s.old_hash)) THEN
                RAISE EXCEPTION 'historical acceptance map must seal a complete staged cohort'
                    USING ERRCODE = '55000';
            END IF;
        ELSIF EXISTS (SELECT 1 FROM historical_acceptance_maps WHERE proof_hash=NEW.proof_hash) THEN
            RAISE EXCEPTION 'historical acceptance map is sealed against append'
                USING ERRCODE = '55000';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'historical_acceptance_maps' THEN
        IF (to_jsonb(NEW) - 'status' - 'status_changed_at')
              IS DISTINCT FROM (to_jsonb(OLD) - 'status' - 'status_changed_at')
           OR NOT (OLD.status = 'applied' AND NEW.status = 'target_lost') THEN
            RAISE EXCEPTION 'historical acceptance map evidence is immutable'
                USING ERRCODE = '55000';
        END IF;
        NEW.status_changed_at := clock_timestamp();
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'historical acceptance map evidence cannot be rewritten or deleted'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER historical_acceptance_maps_immutable
    BEFORE INSERT OR UPDATE OR DELETE ON historical_acceptance_maps
    FOR EACH ROW EXECUTE FUNCTION guard_historical_acceptance_map_evidence();
CREATE TRIGGER historical_acceptance_map_sources_immutable
    BEFORE INSERT OR UPDATE OR DELETE ON historical_acceptance_map_sources
    FOR EACH ROW EXECUTE FUNCTION guard_historical_acceptance_map_evidence();
CREATE TRIGGER historical_acceptance_map_entries_immutable
    BEFORE INSERT OR UPDATE OR DELETE ON historical_acceptance_map_entries
    FOR EACH ROW EXECUTE FUNCTION guard_historical_acceptance_map_evidence();

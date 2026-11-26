-- Authenticated direct-sync requests survive recovery and API restarts. Only
-- identifiers are queued; bodies and canonical acceptance are fetched afresh.
CREATE TABLE tn10_direct_sync_capacity (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
    pending BIGINT NOT NULL DEFAULT 0 CHECK(pending BETWEEN 0 AND 100000)
);
INSERT INTO tn10_direct_sync_capacity(singleton) VALUES(TRUE);
CREATE TABLE tn10_direct_sync_requests (
    network TEXT NOT NULL,
    txid BYTEA NOT NULL CHECK(octet_length(txid)=32),
    force BOOLEAN NOT NULL DEFAULT FALSE,
    revision BIGINT NOT NULL DEFAULT 1,
    requested_at_ms BIGINT NOT NULL DEFAULT ((extract(epoch FROM clock_timestamp())*1000)::bigint),
    next_attempt_at_ms BIGINT NOT NULL DEFAULT 0,
    lease_token UUID,
    lease_until_ms BIGINT NOT NULL DEFAULT 0,
    attempts BIGINT NOT NULL DEFAULT 0,
    last_failure TEXT,
    PRIMARY KEY(network,txid)
);
CREATE INDEX tn10_direct_sync_due ON tn10_direct_sync_requests(network,next_attempt_at_ms,requested_at_ms);
CREATE INDEX tn10_direct_sync_oldest ON tn10_direct_sync_requests(network,requested_at_ms);
CREATE FUNCTION tn10_direct_sync_count() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE tn10_direct_sync_capacity SET pending=pending+CASE WHEN TG_OP='INSERT' THEN 1 ELSE -1 END
    WHERE singleton;
    RETURN NULL;
END $$;
CREATE TRIGGER tn10_direct_sync_insert AFTER INSERT ON tn10_direct_sync_requests
FOR EACH ROW EXECUTE FUNCTION tn10_direct_sync_count();
CREATE TRIGGER tn10_direct_sync_delete AFTER DELETE ON tn10_direct_sync_requests
FOR EACH ROW EXECUTE FUNCTION tn10_direct_sync_count();

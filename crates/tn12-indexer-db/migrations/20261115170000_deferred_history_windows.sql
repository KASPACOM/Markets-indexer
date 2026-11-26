-- Work scheduling is distinct from verified completion. Retained jobs and their
-- membership move together; reorg invalidation continues to see every job.
ALTER TABLE settled_repair_members DROP CONSTRAINT settled_repair_members_cursor_key_fkey;
ALTER TABLE settled_repair_members ADD CONSTRAINT settled_repair_members_cursor_key_fkey
    FOREIGN KEY(cursor_key) REFERENCES settled_repair_jobs(cursor_key) ON UPDATE CASCADE ON DELETE CASCADE;
CREATE TABLE settled_history_schedule (
    cursor_key TEXT PRIMARY KEY,
    next_window BIGINT NOT NULL CHECK(next_window>=0),
    last_retry_at_ms BIGINT NOT NULL DEFAULT 0,
    last_poll_at_ms BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE settled_history_unverified (
    job_key TEXT PRIMARY KEY REFERENCES settled_repair_jobs(cursor_key),
    cursor_key TEXT NOT NULL,
    window_start BIGINT NOT NULL,
    width INTEGER NOT NULL CHECK(width BETWEEN 1 AND 100),
    missing_txid TEXT NOT NULL,
    source_endpoint TEXT NOT NULL,
    source_evidence JSONB NOT NULL,
    evidence_bytes BIGINT NOT NULL CHECK(evidence_bytes BETWEEN 0 AND 16777216),
    first_missing_at_ms BIGINT NOT NULL,
    last_missing_at_ms BIGINT NOT NULL,
    next_retry_at_ms BIGINT NOT NULL,
    attempts BIGINT NOT NULL DEFAULT 1,
    last_error TEXT NOT NULL
);
CREATE INDEX settled_history_unverified_due ON settled_history_unverified(cursor_key,next_retry_at_ms,job_key);
CREATE INDEX settled_history_unverified_window ON settled_history_unverified(cursor_key,window_start);

CREATE TABLE settled_history_retry_gate (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
    last_retry_at_ms BIGINT NOT NULL DEFAULT 0
);
INSERT INTO settled_history_retry_gate(singleton) VALUES(TRUE);

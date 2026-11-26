-- Inbox metadata is separate from covenant writer serialization. Each stream
-- row serializes capacity accounting, append retries, and ordered acknowledgement.
CREATE TABLE wrpc_inbox_streams (
    stream TEXT PRIMARY KEY,
    next_sequence BIGINT NOT NULL DEFAULT 1 CHECK (next_sequence > 0),
    committed_sequence BIGINT NOT NULL DEFAULT 0 CHECK (committed_sequence >= 0),
    pending_bytes BIGINT NOT NULL DEFAULT 0 CHECK (pending_bytes >= 0),
    anchor JSONB,
    updated_at_ms BIGINT NOT NULL
);
CREATE TABLE wrpc_inbox_entries (
    stream TEXT NOT NULL REFERENCES wrpc_inbox_streams(stream),
    sequence BIGINT NOT NULL,
    received_at_ms BIGINT NOT NULL,
    payload BYTEA NOT NULL,
    PRIMARY KEY (stream, sequence)
);
CREATE TABLE wrpc_recovery_intervals (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    stream TEXT NOT NULL REFERENCES wrpc_inbox_streams(stream),
    opened_at_ms BIGINT NOT NULL,
    anchor JSONB,
    reason TEXT NOT NULL,
    verified_through JSONB,
    verified_at_ms BIGINT,
    CHECK ((verified_through IS NULL) = (verified_at_ms IS NULL))
);
CREATE INDEX wrpc_recovery_intervals_open ON wrpc_recovery_intervals(stream, id)
    WHERE verified_at_ms IS NULL;

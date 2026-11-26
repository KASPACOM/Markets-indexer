-- An unfinished effect requires canonical recovery, never blind raw replay.
ALTER TABLE wrpc_inbox_streams ADD COLUMN effect_bytes BIGINT NOT NULL DEFAULT 0 CHECK (effect_bytes >= 0);
CREATE TABLE wrpc_inbox_effects (
    stream TEXT PRIMARY KEY,
    sequence BIGINT NOT NULL,
    payload BYTEA NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 33554432),
    started_at_ms BIGINT NOT NULL,
    FOREIGN KEY (stream, sequence) REFERENCES wrpc_inbox_entries(stream, sequence)
);

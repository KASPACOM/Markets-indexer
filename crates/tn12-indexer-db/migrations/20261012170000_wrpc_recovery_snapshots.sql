-- A captured recovery prefix is immutable until canonical reconciliation and
-- proof commit. Capturing this metadata alone never advances a checkpoint.
CREATE TABLE wrpc_recovery_snapshots (
    stream TEXT PRIMARY KEY REFERENCES wrpc_inbox_streams(stream),
    snapshot JSONB NOT NULL CHECK (octet_length(snapshot::text) <= 65536),
    captured_at_ms BIGINT NOT NULL
);

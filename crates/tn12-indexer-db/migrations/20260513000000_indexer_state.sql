-- Single-row-per-key store for indexer state that doesn't fit `covenants` /
-- `covenant_actions` / `covenant_utxos`. Today's only consumer is the chain
-- scanner: it writes the latest fully-processed blue score under
-- key='chain_scan_cursor' so it can resume after a pod restart.

CREATE TABLE IF NOT EXISTS indexer_state (
    key            TEXT   PRIMARY KEY,
    value          JSONB  NOT NULL,
    updated_at_ms  BIGINT NOT NULL
);

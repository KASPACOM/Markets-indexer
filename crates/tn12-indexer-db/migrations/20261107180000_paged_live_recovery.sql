-- A retained live intent is the authority for a paged recovery plan.  The
-- plan and every page are fenced by its digest and a renewable owner token.
CREATE TABLE tn10_live_recovery_plans (
    intent_key TEXT PRIMARY KEY,
    intent_sha256 BYTEA NOT NULL CHECK (octet_length(intent_sha256) = 32),
    roots JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(roots) = 'array'),
    generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
    owner_token UUID NOT NULL,
    lease_expires_at_ms BIGINT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('discover', 'revert', 'replay', 'verify', 'complete')),
    discovered_blocks BIGINT NOT NULL DEFAULT 0 CHECK (discovered_blocks >= 0),
    reverted_blocks BIGINT NOT NULL DEFAULT 0 CHECK (reverted_blocks >= 0),
    replayed_transactions BIGINT NOT NULL DEFAULT 0 CHECK (replayed_transactions >= 0),
    last_source_change_at_ms BIGINT,
    updated_at_ms BIGINT NOT NULL
);

CREATE TABLE tn10_live_recovery_frontier (
    intent_key TEXT NOT NULL REFERENCES tn10_live_recovery_plans(intent_key) ON DELETE CASCADE,
    block_hash BYTEA NOT NULL CHECK (octet_length(block_hash) = 32),
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (intent_key, block_hash)
);

CREATE INDEX tn10_live_recovery_frontier_pending_idx
    ON tn10_live_recovery_frontier (intent_key, block_hash)
    WHERE NOT processed;

CREATE TABLE tn10_live_recovery_blocks (
    intent_key TEXT NOT NULL REFERENCES tn10_live_recovery_plans(intent_key) ON DELETE CASCADE,
    block_hash BYTEA NOT NULL CHECK (octet_length(block_hash) = 32),
    blue_score BIGINT NOT NULL CHECK (blue_score >= 0),
    transaction_ids JSONB NOT NULL CHECK (jsonb_typeof(transaction_ids) = 'array'),
    descendants JSONB NOT NULL CHECK (jsonb_typeof(descendants) = 'array'),
    source_is_chain_block BOOLEAN NOT NULL,
    reverted BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (intent_key, block_hash)
);

CREATE INDEX tn10_live_recovery_blocks_unreverted_idx
    ON tn10_live_recovery_blocks (intent_key, blue_score DESC, block_hash)
    WHERE NOT reverted;

CREATE TABLE tn10_live_recovery_transactions (
    intent_key TEXT NOT NULL REFERENCES tn10_live_recovery_plans(intent_key) ON DELETE CASCADE,
    txid BYTEA NOT NULL CHECK (octet_length(txid) = 32),
    source_body JSONB NOT NULL CHECK (jsonb_typeof(source_body) = 'object'),
    source_sha256 BYTEA NOT NULL CHECK (octet_length(source_sha256) = 32),
    replayed BOOLEAN NOT NULL DEFAULT FALSE,
    verified_rejected BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (intent_key, txid)
);

CREATE INDEX tn10_live_recovery_transactions_unreplayed_idx
    ON tn10_live_recovery_transactions (intent_key, txid)
    WHERE NOT replayed;

CREATE TABLE tn10_live_recovery_tx_frontier (
    intent_key TEXT NOT NULL REFERENCES tn10_live_recovery_plans(intent_key) ON DELETE CASCADE,
    txid BYTEA NOT NULL CHECK (octet_length(txid) = 32),
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (intent_key, txid)
);

CREATE INDEX tn10_live_recovery_tx_frontier_pending_idx
    ON tn10_live_recovery_tx_frontier (intent_key, txid)
    WHERE NOT processed;

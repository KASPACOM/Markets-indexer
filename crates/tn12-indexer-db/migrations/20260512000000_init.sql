-- TN12 covenant indexer — initial schema.
-- See /root/.claude/plans/recursive-stargazing-hamming.md for design notes.

CREATE TABLE blocks (
    hash             BYTEA PRIMARY KEY,
    blue_score       BIGINT NOT NULL,
    daa_score        BIGINT NOT NULL,
    parent_hashes    BYTEA[] NOT NULL,
    timestamp_ms     BIGINT NOT NULL,
    is_chain_block   BOOLEAN NOT NULL DEFAULT FALSE,
    indexed_at_ms    BIGINT NOT NULL
);
CREATE INDEX blocks_blue_score_idx ON blocks(blue_score);

CREATE TABLE covenants (
    covenant_id        BYTEA PRIMARY KEY,
    address            TEXT NOT NULL,
    script_version     INT NOT NULL,
    script_hash        BYTEA NOT NULL,
    template_name      TEXT,
    genesis_txid       BYTEA NOT NULL,
    genesis_vout       INT NOT NULL,
    genesis_block      BYTEA NOT NULL REFERENCES blocks(hash) ON DELETE CASCADE,
    created_at_ms      BIGINT NOT NULL,
    constructor_args   JSONB
);
CREATE INDEX covenants_address_idx ON covenants(address);
CREATE INDEX covenants_template_idx ON covenants(template_name);

CREATE TABLE covenant_utxos (
    txid             BYTEA NOT NULL,
    vout             INT NOT NULL,
    covenant_id      BYTEA REFERENCES covenants(covenant_id) ON DELETE CASCADE,
    address          TEXT NOT NULL,
    amount_sompi     BIGINT NOT NULL,
    script_pubkey    BYTEA NOT NULL,
    state            JSONB,
    created_block    BYTEA NOT NULL REFERENCES blocks(hash) ON DELETE CASCADE,
    spent_block      BYTEA REFERENCES blocks(hash) ON DELETE CASCADE,
    spent_by_txid    BYTEA,
    status           TEXT NOT NULL CHECK (status IN ('active','spent')),
    PRIMARY KEY (txid, vout)
);
CREATE INDEX cov_utxos_covenant_idx ON covenant_utxos(covenant_id);
CREATE INDEX cov_utxos_status_idx  ON covenant_utxos(covenant_id, status);

CREATE TABLE covenant_actions (
    id               BIGSERIAL PRIMARY KEY,
    covenant_id      BYTEA NOT NULL REFERENCES covenants(covenant_id) ON DELETE CASCADE,
    txid             BYTEA NOT NULL,
    block_hash       BYTEA NOT NULL REFERENCES blocks(hash) ON DELETE CASCADE,
    block_time_ms    BIGINT NOT NULL,
    action           TEXT NOT NULL CHECK (action IN ('deploy','spend','continuation')),
    entrypoint       TEXT,
    inputs           JSONB,
    outputs          JSONB,
    decoded_args     JSONB
);
CREATE INDEX actions_covenant_time_idx ON covenant_actions(covenant_id, block_time_ms DESC);
CREATE INDEX actions_txid_idx          ON covenant_actions(txid);

CREATE TABLE kcc20_holders (
    covenant_id        BYTEA NOT NULL,
    owner_identifier   BYTEA NOT NULL,
    identifier_type    SMALLINT NOT NULL,
    amount_total       NUMERIC(78,0) NOT NULL,
    utxo_count         INT NOT NULL,
    is_minter          BOOLEAN NOT NULL,
    last_change_ms     BIGINT NOT NULL,
    PRIMARY KEY (covenant_id, owner_identifier, identifier_type)
);
CREATE INDEX kcc20_holders_covenant_idx ON kcc20_holders(covenant_id);

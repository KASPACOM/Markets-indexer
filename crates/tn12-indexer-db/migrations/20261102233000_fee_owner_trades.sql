-- A leader can settle several makers. Preserve source identity without
-- inventing covenant action IDs or changing the legacy history primary key.
CREATE TABLE kcc20_fee_owner_trades (
    source_action_id BIGINT NOT NULL REFERENCES covenant_actions(id) ON DELETE CASCADE,
    fill_index BIGINT NOT NULL,
    party TEXT NOT NULL CHECK (party IN ('maker','taker')),
    owner TEXT NOT NULL,
    owner_scheme SMALLINT NOT NULL,
    address TEXT NOT NULL,
    txid_hex TEXT NOT NULL,
    block_time_ms BIGINT NOT NULL,
    canonical_token_id TEXT NOT NULL,
    market_id TEXT NOT NULL,
    amount TEXT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('in','out')),
    entrypoint TEXT NOT NULL,
    input_outpoints JSONB NOT NULL,
    output_outpoints JSONB NOT NULL,
    PRIMARY KEY(source_action_id,fill_index,party)
);
CREATE INDEX kcc20_fee_owner_trades_owner_time_idx
    ON kcc20_fee_owner_trades(owner,block_time_ms DESC,txid_hex DESC,source_action_id DESC,fill_index DESC,party DESC);
CREATE INDEX kcc20_fee_owner_trades_address_time_idx
    ON kcc20_fee_owner_trades(address,block_time_ms DESC,txid_hex DESC,source_action_id DESC,fill_index DESC,party DESC);

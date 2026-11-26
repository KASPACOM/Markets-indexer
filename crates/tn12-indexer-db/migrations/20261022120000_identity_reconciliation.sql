-- Additive, empty on install. Evidence is retained even when canonical state changes.
CREATE TABLE covenant_identity_corrections (
  id BIGSERIAL PRIMARY KEY,
  old_covenant_id BYTEA NOT NULL,
  new_covenant_id BYTEA NOT NULL,
  txid BYTEA NOT NULL,
  vout INTEGER NOT NULL CHECK (vout >= 0),
  accepting_block BYTEA NOT NULL,
  old_action JSONB NOT NULL,
  old_family JSONB NOT NULL,
  retired_family BOOLEAN NOT NULL DEFAULT FALSE,
  corrected_at_ms BIGINT NOT NULL,
  UNIQUE(old_covenant_id,txid,vout,accepting_block),
  CHECK(old_covenant_id <> new_covenant_id)
);
CREATE INDEX covenant_identity_corrections_alias_idx
  ON covenant_identity_corrections(old_covenant_id) WHERE retired_family;
ALTER TABLE settled_repair_jobs ADD COLUMN blocker JSONB;
ALTER TABLE covenant_genesis_progress ADD COLUMN retry_at_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE covenant_genesis_progress ADD COLUMN blocker JSONB;

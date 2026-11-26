-- TN12 covenant indexer — claimed constructor params.
--
-- Wallets that emit a `{"tn12":{"v":1,"tmpl":"...","args":[...]}}` envelope
-- in tx.payload at deploy let the indexer expose constructor metadata BEFORE
-- the covenant's first spend (when the redeem-script reveal would normally
-- be the only source). The on-chain reveal stays the source of truth: at
-- first spend we cross-check claim vs decoded and set `claim_verified`.
--
-- See feat/claimed-constructor-params for the rationale + envelope schema.

ALTER TABLE covenants ADD COLUMN claimed_template     TEXT;
ALTER TABLE covenants ADD COLUMN claimed_args         JSONB;
ALTER TABLE covenants ADD COLUMN claim_source         TEXT;
ALTER TABLE covenants ADD COLUMN claim_verified       BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE covenants ADD COLUMN claim_verified_at_ms BIGINT;

-- Partial index so the API's `?template=X` filter can fast-match either the
-- verified template OR the claimed one without a sequential scan.
CREATE INDEX covenants_claimed_template_idx ON covenants(claimed_template)
    WHERE claimed_template IS NOT NULL;

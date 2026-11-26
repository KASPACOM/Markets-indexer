-- Store the provider-held unsigned settlement transaction template alongside
-- the payer authorization metadata. The template is the missing material a
-- broadcaster needs to reconstruct and submit the provider-signed close tx.

ALTER TABLE api_payment_settlement_authorizations
    ADD COLUMN IF NOT EXISTS settlement_artifact_schema TEXT,
    ADD COLUMN IF NOT EXISTS unsigned_settlement_template TEXT;

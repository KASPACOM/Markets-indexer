-- Preserve the full wallet-lab settlement artifact so a broadcaster can write it
-- back to disk and submit the provider-signed close transaction.

ALTER TABLE api_payment_settlement_authorizations
    ADD COLUMN IF NOT EXISTS settlement_artifact_json JSONB;

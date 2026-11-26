ALTER TABLE api_payment_channels
    ADD COLUMN IF NOT EXISTS close_after_ms BIGINT NOT NULL DEFAULT 0;


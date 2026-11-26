CREATE INDEX IF NOT EXISTS api_payment_channels_opening_activation_idx
    ON api_payment_channels (created_at_ms ASC, channel_id ASC)
    WHERE status = 'opening';

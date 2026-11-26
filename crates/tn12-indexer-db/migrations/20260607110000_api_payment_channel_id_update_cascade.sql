-- Keep backend payment lifecycle rows attached when a fallback script-hash
-- channel id is repaired to the canonical KIP-20 covenant id.

ALTER TABLE api_payment_vouchers
    DROP CONSTRAINT IF EXISTS api_payment_vouchers_channel_id_fkey,
    ADD CONSTRAINT api_payment_vouchers_channel_id_fkey
        FOREIGN KEY (channel_id)
        REFERENCES api_payment_channels(channel_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE;

ALTER TABLE api_payment_usage_events
    DROP CONSTRAINT IF EXISTS api_payment_usage_events_channel_id_fkey,
    ADD CONSTRAINT api_payment_usage_events_channel_id_fkey
        FOREIGN KEY (channel_id)
        REFERENCES api_payment_channels(channel_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL;

ALTER TABLE api_payment_settlements
    DROP CONSTRAINT IF EXISTS api_payment_settlements_channel_id_fkey,
    ADD CONSTRAINT api_payment_settlements_channel_id_fkey
        FOREIGN KEY (channel_id)
        REFERENCES api_payment_channels(channel_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE;

ALTER TABLE api_payment_settlement_authorizations
    DROP CONSTRAINT IF EXISTS api_payment_settlement_authorizations_channel_id_fkey,
    ADD CONSTRAINT api_payment_settlement_authorizations_channel_id_fkey
        FOREIGN KEY (channel_id)
        REFERENCES api_payment_channels(channel_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE;

ALTER TABLE api_payment_channel_close_requests
    DROP CONSTRAINT IF EXISTS api_payment_channel_close_requests_channel_id_fkey,
    ADD CONSTRAINT api_payment_channel_close_requests_channel_id_fkey
        FOREIGN KEY (channel_id)
        REFERENCES api_payment_channels(channel_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE;

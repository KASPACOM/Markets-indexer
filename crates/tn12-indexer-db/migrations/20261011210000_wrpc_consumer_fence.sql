ALTER TABLE wrpc_inbox_streams
    ADD COLUMN consumer_generation BIGINT NOT NULL DEFAULT 0 CHECK (consumer_generation >= 0);

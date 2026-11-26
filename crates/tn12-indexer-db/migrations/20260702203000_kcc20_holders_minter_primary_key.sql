ALTER TABLE kcc20_holders
    DROP CONSTRAINT IF EXISTS kcc20_holders_pkey;

ALTER TABLE kcc20_holders
    ADD PRIMARY KEY (covenant_id, owner_identifier, identifier_type, is_minter);

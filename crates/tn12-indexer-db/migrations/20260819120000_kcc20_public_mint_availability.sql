ALTER TABLE kcc20_token_summaries
    ADD COLUMN active_minter_mode_value SMALLINT,
    ADD COLUMN public_mint_active BOOLEAN;

ALTER TABLE kcc20_token_summaries
    ADD CONSTRAINT kcc20_token_summaries_minter_mode_check
        CHECK (active_minter_mode_value IS NULL OR active_minter_mode_value BETWEEN 0 AND 3),
    ADD CONSTRAINT kcc20_token_summaries_public_mint_active_check
        CHECK (
            (active_minter_mode_value IN (2, 3) AND public_mint_active IS NOT NULL)
            OR (active_minter_mode_value IS DISTINCT FROM 2
                AND active_minter_mode_value IS DISTINCT FROM 3
                AND public_mint_active IS NULL)
        );

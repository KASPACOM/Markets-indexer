-- KCC20 standard-native is a state/projection cutover, not an old-artifact
-- compatibility migration. Raw covenant history stays in the generic tables.

UPDATE covenant_utxos
SET state = NULL
WHERE covenant_id IN (
    SELECT covenant_id
    FROM covenants
    WHERE COALESCE(template_name, claimed_template) IN (
        'KCC20',
        'KCC20V2',
        'KCC20V3',
        'KCC20V2V3Wrapper',
        'KCC20V3Wrapped',
        'KCC20V2Vesting',
        'KCC20Sale',
        'KCC20SaleV2',
        'KCC20BuyOrder'
    )
);

UPDATE covenants
SET template_name = NULL,
    constructor_args = NULL,
    claimed_template = NULL,
    claimed_args = NULL,
    claim_source = NULL,
    claim_verified = FALSE,
    claim_verified_at_ms = NULL,
    classification_kind = 'unknown',
    classification_status = 'unmatched'
WHERE COALESCE(template_name, claimed_template) IN (
        'KCC20',
        'KCC20V2',
        'KCC20V3',
        'KCC20V2V3Wrapper',
        'KCC20V3Wrapped',
        'KCC20V2Vesting',
        'KCC20Sale',
        'KCC20SaleV2',
        'KCC20BuyOrder'
    );

TRUNCATE TABLE
    kcc20_owner_portfolio_assets,
    kcc20_activity_feed,
    kcc20_market_summaries,
    kcc20_wrapper_summaries,
    kcc20_token_summaries,
    kcc20_holders,
    kcc20_projection_dirty,
    kcc20_projection_state;

ALTER TABLE kcc20_token_summaries
    DROP CONSTRAINT IF EXISTS kcc20_token_summaries_minter_mode_check,
    DROP CONSTRAINT IF EXISTS kcc20_token_summaries_public_mint_active_check;

ALTER TABLE kcc20_token_summaries
    RENAME COLUMN minter_supply TO remaining_supply;

ALTER TABLE kcc20_token_summaries
    RENAME COLUMN active_minter_mode_value TO active_mint_policy_value;

ALTER TABLE kcc20_token_summaries
    ADD CONSTRAINT kcc20_token_summaries_mint_policy_check
        CHECK (active_mint_policy_value IS NULL OR active_mint_policy_value BETWEEN 1 AND 2),
    ADD CONSTRAINT kcc20_token_summaries_public_mint_active_check
        CHECK (
            (active_mint_policy_value = 2 AND public_mint_active IS NOT NULL)
            OR (active_mint_policy_value IS DISTINCT FROM 2 AND public_mint_active IS NULL)
        );

INSERT INTO kcc20_projection_dirty (reason, created_at_ms)
VALUES (
    'kcc20_standard_native_cutover',
    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
);

ALTER TABLE kcc20_token_summaries
    RENAME COLUMN v3_tradeable_supply TO orderbook_tradeable_supply;

ALTER TABLE kcc20_owner_portfolio_assets
    RENAME COLUMN v2_balance TO native_balance;

ALTER TABLE kcc20_owner_portfolio_assets
    RENAME COLUMN v3_balance TO orderbook_balance;

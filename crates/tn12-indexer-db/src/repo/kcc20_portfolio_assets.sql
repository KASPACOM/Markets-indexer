-- Reuse identity discovery across all holdings before sorting/paging.
        -- Inlining the view into each lateral lookup rescans fee UTXOs per asset.
        WITH market_identities AS MATERIALIZED (
            SELECT * FROM kcc20_portfolio_market_identities
        )
        SELECT
            encode(a.canonical_token_id, 'hex') AS canonical_token_id_hex,
            encode(a.wrapper_id, 'hex') AS wrapper_id_hex,
            encode(a.wrapped_market_id, 'hex') AS wrapped_market_id_hex,
            a.native_balance::TEXT AS native_balance,
            a.orderbook_balance::TEXT AS orderbook_balance,
            a.total_balance::TEXT AS total_balance,
            a.asset_utxo_count,
            a.open_ask_amount::TEXT AS open_ask_amount,
            a.open_bid_amount::TEXT AS open_bid_amount,
            a.open_order_count,
            market.best_ask_unit_price_sompi::TEXT AS best_ask_unit_price_sompi,
            market.best_bid_unit_price_sompi::TEXT AS best_bid_unit_price_sompi,
            valuation.value_sompi::TEXT AS value_sompi,
            a.fee_ticket_supported,
            a.last_change_ms,
            a.ticker,
            a.token_name,
            a.decimals
        FROM kcc20_owner_portfolio_assets a
        LEFT JOIN LATERAL (
            SELECT MIN(m.best_ask_unit_price_sompi) AS best_ask_unit_price_sompi,
                   MAX(m.best_bid_unit_price_sompi) AS best_bid_unit_price_sompi
            FROM (
                SELECT a.canonical_token_id AS token_id
                UNION
                SELECT a.wrapped_market_id AS token_id
                WHERE a.wrapped_market_id IS NOT NULL
                UNION
                -- The displayed wrapper can differ from the wrapper with the
                -- best price. Match the same active sibling set as refresh.
                SELECT w.wrapper_id AS token_id
                FROM market_identities w
                WHERE w.canonical_token_id = a.canonical_token_id
                  AND (w.active_utxos > 0 OR NOT EXISTS (
                      SELECT 1 FROM market_identities active
                      WHERE active.canonical_token_id = a.canonical_token_id
                        AND active.active_utxos > 0
                  ))
            ) ids
            JOIN kcc20_market_summaries m ON m.token_id = ids.token_id
        ) market ON TRUE
        CROSS JOIN LATERAL (
            SELECT CASE WHEN market.best_ask_unit_price_sompi IS NULL THEN NULL
                        ELSE trunc(a.total_balance * market.best_ask_unit_price_sompi
                                   / power(10::NUMERIC, a.decimals))
                   END AS value_sompi
        ) valuation
        WHERE a.owner_identifier = $1
          AND ($2::BYTEA IS NULL OR a.canonical_token_id = $2)
          AND (
              $3::TEXT IS NULL
              OR encode(a.canonical_token_id, 'hex') LIKE '%' || lower($3) || '%' ESCAPE E'\\'
              OR lower(COALESCE(a.ticker, '')) LIKE '%' || lower($3) || '%' ESCAPE E'\\'
              OR lower(COALESCE(a.token_name, '')) LIKE '%' || lower($3) || '%' ESCAPE E'\\'
          )
          AND (NOT $4::BOOLEAN OR a.native_balance > 0)
          AND (NOT $5::BOOLEAN OR a.orderbook_balance > 0)
          AND (NOT $6::BOOLEAN OR a.open_order_count > 0)
        ORDER BY {order_by}
        LIMIT $7 OFFSET $8

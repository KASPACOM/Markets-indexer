CREATE INDEX IF NOT EXISTS covenant_utxos_kcc20_owner_order_state_idx
ON covenant_utxos ((state->>'ownerIdentifier'), (state->>'mode'), covenant_id)
WHERE status = 'active'
  AND state ? 'ownerIdentifier'
  AND state ? 'mode';

CREATE INDEX IF NOT EXISTS covenants_kcc20_sale_owner_idx
ON covenants ((COALESCE(constructor_args->>'seller', constructor_args->>'listingSeller')), created_at_ms DESC)
WHERE COALESCE(template_name, claimed_template) IN ('KCC20Sale', 'KCC20SaleV2');

CREATE INDEX IF NOT EXISTS covenants_kcc20_bid_owner_idx
ON covenants ((COALESCE(constructor_args->>'buyer', constructor_args->>'orderBuyer')), created_at_ms DESC)
WHERE COALESCE(template_name, claimed_template) IN ('KCC20BuyOrder');

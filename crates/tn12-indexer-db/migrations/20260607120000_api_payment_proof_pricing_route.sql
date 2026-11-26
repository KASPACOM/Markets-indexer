UPDATE api_payment_pricing
SET enabled = FALSE,
    effective_to_ms = 0
WHERE pricing_id = 'kcc20.discovery.v1'
  AND method = 'GET'
  AND path_pattern = '/kcc20/discovery';

INSERT INTO api_payment_pricing (
    pricing_id,
    method,
    path_pattern,
    base_sompi,
    per_row_sompi,
    max_limit,
    enabled,
    effective_from_ms,
    effective_to_ms
)
VALUES (
    'api-payment.proof.kcc20-discovery.v1',
    'GET',
    '/payments/proof/kcc20-discovery',
    777,
    0,
    100,
    TRUE,
    0,
    NULL
)
ON CONFLICT (pricing_id) DO UPDATE
SET method = EXCLUDED.method,
    path_pattern = EXCLUDED.path_pattern,
    base_sompi = EXCLUDED.base_sompi,
    per_row_sompi = EXCLUDED.per_row_sompi,
    max_limit = EXCLUDED.max_limit,
    enabled = EXCLUDED.enabled,
    effective_from_ms = EXCLUDED.effective_from_ms,
    effective_to_ms = EXCLUDED.effective_to_ms;

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
    'kcc20.discovery.v1',
    'GET',
    '/kcc20/discovery',
    777,
    0,
    100,
    TRUE,
    0,
    NULL
)
ON CONFLICT (pricing_id) DO NOTHING;

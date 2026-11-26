UPDATE api_payment_pricing
SET base_sompi = 50000000,
    per_row_sompi = 0,
    max_limit = 100,
    enabled = TRUE,
    effective_from_ms = 0,
    effective_to_ms = NULL
WHERE pricing_id = 'api-payment.proof.kcc20-discovery.v1'
  AND method = 'GET'
  AND path_pattern = '/payments/proof/kcc20-discovery';

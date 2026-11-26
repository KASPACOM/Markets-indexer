use serde_json::{json, Value};

use crate::api_payments::{
    API_PAYMENT_PROOF_BODY_ECHO_PRICING_ID, API_PAYMENT_PROOF_BODY_ECHO_ROUTE,
    API_PAYMENT_PROOF_DISCOVERY_PRICING_ID, API_PAYMENT_PROOF_DISCOVERY_ROUTE,
};

pub fn spec() -> Value {
    let mut spec = json!({
        "openapi": "3.1.0",
        "info": {
            "title": "KaspaCom Covenant Tools API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Public read API for indexed covenant, inscription, KCC20, orderbook, and transaction activity."
        },
        "servers": [
            { "url": "https://tn10-indexer.kaspa.com", "description": "TN10 covenant tools API" },
            { "url": "http://127.0.0.1:8081", "description": "Local covenant tools API" }
        ],
        "tags": [
            { "name": "System" },
            { "name": "Covenants" },
            { "name": "Covenant UTXOs" },
            { "name": "KCC20" },
            { "name": "FOMO" },
            { "name": "Addresses" },
            { "name": "Transactions" },
            { "name": "Events" },
            { "name": "Payments" }
        ],
        "paths": {
            "/health": {
                "get": {
                    "tags": ["System"],
                    "summary": "Return complete indexer health after historical coverage is verified",
                    "responses": ok_response("Health response", ref_schema("HealthResponse"))
                }
            },
            "/health/live": {
                "get": {
                    "tags": ["System"],
                    "summary": "Return live ingestion health with near-tip repair lag details",
                    "responses": ok_response("Live health response", object_schema())
                }
            },
            "/health/history": {
                "get": {
                    "tags": ["System"],
                    "summary": "Return historical gap, replay rate, and ETA",
                    "responses": ok_response("Historical coverage response", object_schema())
                }
            },
            "/explorer/summary": {
                "get": {
                    "tags": ["System"],
                    "summary": "Return the fast dashboard summary used by the covenant explorer",
                    "description": "Serves scanner freshness, global counts, classification buckets, unknown counts, and template buckets from read-model tables so explorer dashboards do not scan full action history.",
                    "responses": ok_response("Explorer summary", ref_schema("ExplorerSummary"))
                }
            },
            "/explorer/search": {
                "get": {
                    "tags": ["System"],
                    "summary": "Resolve explorer search text into typed navigation targets",
                    "parameters": [
                        query_string("q", "Covenant id, script hash, transaction id, address, template, or KCC20 token id"),
                        query_string("limit", "Maximum results to return; defaults to 10")
                    ],
                    "responses": ok_response("Explorer search results", array_schema(ref_schema("ExplorerSearchResult")))
                }
            },
            "/livez": {
                "get": {
                    "tags": ["System"],
                    "summary": "Return process liveness without database reads",
                    "responses": ok_response("Liveness response", object_schema())
                }
            },
            "/readyz": {
                "get": {
                    "tags": ["System"],
                    "summary": "Return readiness using only a cheap database ping",
                    "responses": ok_response("Readiness response", object_schema())
                }
            },
            "/metrics": {
                "get": {
                    "tags": ["System"],
                    "summary": "Return Prometheus text metrics for indexer health, readiness, and scanner freshness",
                    "responses": {
                        "200": {
                            "description": "Prometheus text exposition",
                            "content": {
                                "text/plain": {
                                    "schema": { "type": "string" }
                                }
                            }
                        }
                    }
                }
            },
            "/openapi.json": {
                "get": {
                    "tags": ["System"],
                    "summary": "Return this OpenAPI document",
                    "responses": ok_response("OpenAPI document", object_schema())
                }
            },
            "/swagger-ui": {
                "get": {
                    "tags": ["System"],
                    "summary": "Redirect to the interactive Swagger UI",
                    "responses": swagger_redirect_response()
                }
            },
            "/swagger-ui/": {
                "get": {
                    "tags": ["System"],
                    "summary": "Interactive Swagger UI for this API",
                    "responses": {
                        "200": {
                            "description": "Swagger UI HTML",
                            "content": { "text/html": { "schema": { "type": "string" } } }
                        }
                    }
                }
            },
            "/swagger": {
                "get": {
                    "tags": ["System"],
                    "summary": "Redirect to the interactive Swagger UI",
                    "responses": swagger_redirect_response()
                }
            },
            "/docs": {
                "get": {
                    "tags": ["System"],
                    "summary": "Redirect to the interactive Swagger UI",
                    "responses": swagger_redirect_response()
                }
            },
            "/payments/pricing": {
                "get": {
                    "tags": ["Payments"],
                    "summary": "Return API payment methods, free routes, and current priced route catalog",
                    "responses": ok_response("API payment pricing catalog", ref_schema("ApiPaymentPricing"))
                }
            },
            "/payments/metrics": {
                "get": {
                    "tags": ["Payments"],
                    "summary": "Return per-process API payment runtime counters",
                    "responses": ok_response("API payment runtime metrics", ref_schema("ApiPaymentRuntimeMetrics"))
                }
            },
            "/payments/debug": {
                "get": {
                    "tags": ["Payments"],
                    "summary": "Read-only API payment support/debug page",
                    "description": "Static operator page that fetches the existing redacted receipt, channel, settlement/refund, and direct-proof status endpoints by id. It does not collect private keys, raw credentials, or authorization headers.",
                    "responses": {
                        "200": {
                            "description": "API payment support/debug HTML",
                            "content": { "text/html": { "schema": { "type": "string" } } }
                        }
                    }
                }
            },
            "/payments/challenges": {
                "post": {
                    "tags": ["Payments"],
                    "summary": "Create a preflight payment challenge for a priced API request",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": ref_schema("ApiPaymentChallengeRequest"),
                                "examples": {
                                    "kcc20Discovery": {
                                        "value": {
                                            "method": "GET",
                                            "path": "/payments/proof/kcc20-discovery",
                                            "rawQuery": "limit=5&sortBy=totalVolumeSompi"
                                        }
                                    },
                                    "kcc20DiscoveryDirect": {
                                        "value": {
                                            "method": "GET",
                                            "path": "/payments/proof/kcc20-discovery",
                                            "rawQuery": "limit=5&sortBy=totalVolumeSompi",
                                            "paymentMethod": "kaspa-direct"
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": json_response("Payment challenge", ref_schema("ApiPaymentChallengeResponse")),
                        "400": error_response("Invalid request binding"),
                        "404": error_response("Route is not supported by the payment catalog"),
                        "409": error_response("Route is not currently priced")
                    }
                }
            },
            "/payments/direct-proofs": {
                "post": {
                    "tags": ["Payments"],
                    "summary": "Submit a client-broadcast direct Kaspa payment proof",
                    "description": "Support/debug endpoint for storing a txid-bound proof as submitted. Normal paid-route redemption can skip this endpoint: retry the paid route with Authorization: Payment <base64url JSON { method: \"kaspa-direct\", txidHex: \"...\" }> and the route guard verifies the tx through REST before serving.",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": ref_schema("ApiDirectPaymentProofRequest")
                            }
                        }
                    },
                    "responses": {
                        "202": json_response("Direct payment proof accepted for verification", ref_schema("ApiDirectPaymentProofResponse")),
                        "400": error_response("Invalid direct payment proof"),
                        "409": error_response("Direct payment route is not configured or the proof was already submitted"),
                        "503": error_response("Payment persistence is unavailable")
                    }
                }
            },
            "/payments/direct-proofs/{txid}": {
                "get": {
                    "tags": ["Payments"],
                    "summary": "Return direct payment proof submission status by txid",
                    "parameters": [
                        path_string("txid", "32-byte transaction id hex")
                    ],
                    "responses": {
                        "200": json_response("Direct payment proof status", ref_schema("ApiDirectPaymentProofResponse")),
                        "400": error_response("Invalid txid"),
                        "404": error_response("Direct payment proof was not submitted"),
                        "503": error_response("Payment persistence is unavailable")
                    }
                }
            },
            "/payments/direct-proofs/{txid}/verify": {
                "post": {
                    "tags": ["Payments"],
                    "summary": "Verify a submitted direct payment proof against the configured REST node",
                    "description": "Fetches the transaction from API_PAYMENT_REST_URL and checks txid, recipient, amount, challenge payload, and accepted status before updating the stored proof.",
                    "parameters": [
                        path_string("txid", "32-byte transaction id hex")
                    ],
                    "responses": {
                        "200": json_response("Updated direct payment proof status", ref_schema("ApiDirectPaymentProofResponse")),
                        "400": error_response("Invalid txid"),
                        "404": error_response("Direct payment proof was not submitted"),
                        "503": error_response("Payment persistence or REST verifier is unavailable")
                    }
                }
            },
            "/payments/receipts/{receiptId}": {
                "get": {
                    "tags": ["Payments"],
                    "summary": "Return durable payment receipt status",
                    "description": "Looks up either a channel voucher receipt emitted in the Payment-Receipt response header or a direct-payment proof receipt. Channel receipts tie served API usage to the accepted voucher and current channel state; direct receipts expose the indexed txid proof status.",
                    "parameters": [
                        path_string("receiptId", "Receipt id: apr_ plus 32-byte credential hash hex, or apd_ plus 32-byte txid hex")
                    ],
                    "responses": {
                        "200": json_response(
                            "API payment receipt status",
                            json!({
                                "oneOf": [
                                    ref_schema("ApiPaymentReceiptStatusResponse"),
                                    ref_schema("ApiDirectPaymentProofResponse")
                                ]
                            })
                        ),
                        "400": error_response("Invalid receipt id"),
                        "404": error_response("Receipt was not recorded"),
                        "503": error_response("Payment persistence is unavailable")
                    }
                }
            },
            "/payments/channels/{channelId}": {
                "get": {
                    "tags": ["Payments"],
                    "summary": "Return indexed API payment channel lifecycle status",
                    "description": "Reads the projected ApiPaymentChannel lifecycle rows populated by the indexer. This endpoint is for audit, support, and reconciliation; it is not used in the hot request authorization path.",
                    "parameters": [
                        path_string("channelId", "32-byte API payment channel id hex")
                    ],
                    "responses": {
                        "200": json_response("API payment channel lifecycle status", ref_schema("ApiPaymentChannelStatusResponse")),
                        "400": error_response("Invalid channel id"),
                        "404": error_response("Channel was not indexed"),
                        "503": error_response("Payment persistence is unavailable")
                    }
                }
            },
            "/payments/channels/{channelId}/sync": {
                "post": {
                    "tags": ["Payments"],
                    "summary": "Fetch and ingest one API payment channel transaction",
                    "description": "Fast-paths an accepted channel open, settlement, or refund transaction through the same REST hydration and Postgres projection path used by the scanner. This is for provider/API reconciliation after wallet submission; it is idempotent and returns success only when the projected channel row references the supplied txid. Deployments can require a provider bearer token with API_PAYMENT_CHANNEL_SYNC_BEARER_TOKEN and always apply the process-local API_PAYMENT_CHANNEL_SYNC_MAX_PER_MINUTE throttle.",
                    "parameters": [
                        path_string("channelId", "32-byte API payment channel id hex")
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": ref_schema("ApiPaymentChannelSyncRequest")
                            }
                        }
                    },
                    "responses": {
                        "200": json_response("API payment channel lifecycle status", ref_schema("ApiPaymentChannelStatusResponse")),
                        "400": error_response("Invalid channel id or txid"),
                        "401": error_response("Missing or invalid sync bearer token"),
                        "409": error_response("Synced tx did not project onto the requested channel"),
                        "429": error_response("Too many channel sync requests"),
                        "422": error_response("Synced tx did not decode as an API payment channel event"),
                        "503": error_response("Payment persistence or REST lookup is unavailable")
                    }
                }
            },
            "/payments/channels/{channelId}/close": {
                "post": {
                    "tags": ["Payments"],
                    "summary": "Request provider finalization for an API payment channel",
                    "description": "Accepts a payer-signed close request, marks the channel close_requested, and lets the provider settlement broadcaster claim the latest settlement authorization. This is not a payer refund endpoint.",
                    "parameters": [
                        path_string("channelId", "32-byte API payment channel id hex")
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": ref_schema("ApiPaymentChannelCloseRequest")
                            }
                        }
                    },
                    "responses": {
                        "202": json_response("Channel close requested", ref_schema("ApiPaymentChannelStatusResponse")),
                        "400": error_response("Invalid channel id, request shape, or payer signature"),
                        "404": error_response("Channel was not indexed"),
                        "409": error_response("Channel cannot be finalized by provider settlement"),
                        "503": error_response("Payment persistence is unavailable")
                    }
                }
            },
            "/payments/settlements/{txid}": {
                "get": {
                    "tags": ["Payments"],
                    "summary": "Return indexed API payment channel settlement or refund status",
                    "description": "Looks up a channel settlement or refund transaction from projected lifecycle rows and includes scanner freshness metadata. Unknown txids return indexed=false.",
                    "parameters": [
                        path_string("txid", "32-byte settlement or refund transaction id hex")
                    ],
                    "responses": {
                        "200": json_response("API payment channel tx status", ref_schema("ApiPaymentSettlementStatusResponse")),
                        "400": error_response("Invalid txid"),
                        "503": error_response("Payment persistence is unavailable")
                    }
                }
            },
            "/snapshot": {
                "get": {
                    "tags": ["System"],
                    "summary": "Return the in-memory engine snapshot for fixture-backed local runs",
                    "responses": ok_response("Engine snapshot", object_schema())
                }
            },
            "/utxos": {
                "get": {
                    "tags": ["Covenant UTXOs"],
                    "summary": "List active covenant UTXOs across every indexed covenant",
                    "parameters": [
                        query_integer("limit", "Maximum rows to return, capped at 1000"),
                        query_integer("offset", "Pagination offset")
                    ],
                    "responses": ok_response("Active covenant UTXOs", array_schema(ref_schema("CovenantUtxo")))
                }
            },
            "/covenant-templates": {
                "get": {
                    "tags": ["Covenants"],
                    "summary": "Summarize indexed templates with counts, active balances, and action totals",
                    "responses": ok_response("Template summaries", array_schema(ref_schema("CovenantTemplateSummary")))
                }
            },
            "/covenants": {
                "get": {
                    "tags": ["Covenants"],
                    "summary": "List indexed covenant, inscription, and unknown P2SH rows",
                    "parameters": [
                        query_string("template", "Filter by verified template name or wallet-declared template"),
                        query_bool("verified_only", "Only match verified-on-chain templates"),
                        query_string("classification", "Filter by classification kind: covenant, inscription, or unknown"),
                        query_string("classificationStatus", "Filter by classification status: unrevealed, matched, or unmatched"),
                        query_string("claimArg", "Wallet-declared constructor arg name inside claimedArgs.args"),
                        query_string("claimArgValue", "Optional value match for claimArg"),
                        query_string("wallet", "Wallet address or x-only pubkey to match against covenant address, participant claimedArgs, or decoded constructor args; P2PK address/pubkey forms are cross-matched"),
                        query_string("walletArg", "Optional arg name to narrow wallet matching, such as owner, signer, recoveryKey, heir, seller, buyer, arbiter, ownerIdentifier, or stateOwner"),
                        query_string("covenantId", "Exact canonical covenant id or legacy script hash hex"),
                        query_string("q", "Free-text search across covenant id, script hash, genesis txid, covenant and indexed UTXO addresses, template, classification, claim source, and claimed/decoded arg names and values"),
                        query_bool("active", "true = only covenants with active UTXOs; false = fully spent only"),
                        query_string("sort", "Sort key: recent, active, amount, or template"),
                        query_integer("limit", "Page size; defaults to 50, is capped at 200, and accepts 0 for a count-only response"),
                        query_integer("offset", "Pagination offset")
                    ],
                    "responses": covenant_list_response()
                }
            },
            "/covenants/by-id/{covenant_id}": {
                "get": {
                    "tags": ["Covenants"],
                    "summary": "Return one covenant by canonical covenant id plus a bounded action page",
                    "parameters": covenant_detail_parameters("covenant_id", "Canonical covenant id hex"),
                    "responses": {
                        "200": paginated_json_response("Covenant detail; X-Total-Count is the full matching action count", ref_schema("CovenantDetail")),
                        "404": error_response("No matching covenant row")
                    }
                }
            },
            "/covenants/by-id/{covenant_id}/actions": {
                "get": {
                    "tags": ["Covenants"],
                    "summary": "Return a bounded deploy, spend, and continuation action page",
                    "parameters": covenant_detail_parameters("covenant_id", "Canonical covenant id hex"),
                    "responses": paginated_response("Covenant actions", array_schema(ref_schema("ActionRow")))
                }
            },
            "/kcc20/snapshot/controllers/{controller_id}/claims/{token_id}": {
                "get": {
                    "tags": ["KCC20 Snapshot Migration"],
                    "summary": "Return canonical snapshot claim rows and an exact scope content commitment",
                    "parameters": [
                        path_string("controller_id", "Snapshot controller covenant id hex"),
                        path_string("token_id", "Canonical KCC20 token id hex"),
                        query_integer("limit", "Page size; defaults to 1000, is capped at 1000, and accepts 0 for a commitment-only response"),
                        query_integer("offset", "Pagination offset")
                    ],
                    "responses": paginated_response("Versioned snapshot claim page", json!({ "type": "object" }))
                }
            },
            "/covenants/by-id/{covenant_id}/utxos": {
                "get": {
                    "tags": ["Covenant UTXOs"],
                    "summary": "Return a bounded active UTXO page for one canonical covenant id",
                    "parameters": covenant_utxo_parameters("covenant_id", "Canonical covenant id hex"),
                    "responses": paginated_response("Covenant UTXOs", array_schema(ref_schema("CovenantUtxo")))
                }
            },
            "/covenants/{covenant_id_or_script_hash}": {
                "get": {
                    "tags": ["Covenants"],
                    "summary": "Return one covenant or inscription row plus a bounded action page",
                    "parameters": covenant_detail_parameters("covenant_id_or_script_hash", "Canonical covenant id or legacy script hash"),
                    "responses": {
                        "200": paginated_json_response("Covenant detail; X-Total-Count is the full matching action count", ref_schema("CovenantDetail")),
                        "404": error_response("No matching covenant row")
                    }
                }
            },
            "/covenants/{covenant_id_or_script_hash}/actions": {
                "get": {
                    "tags": ["Covenants"],
                    "summary": "Return a bounded deploy, spend, and continuation action page",
                    "parameters": covenant_detail_parameters("covenant_id_or_script_hash", "Canonical covenant id or legacy script hash"),
                    "responses": paginated_response("Covenant actions", array_schema(ref_schema("ActionRow")))
                }
            },
            "/covenants/{covenant_id_or_script_hash}/utxos": {
                "get": {
                    "tags": ["Covenant UTXOs"],
                    "summary": "Return a bounded active UTXO page for one covenant",
                    "parameters": covenant_utxo_parameters("covenant_id_or_script_hash", "Canonical covenant id or legacy script hash"),
                    "responses": paginated_response("Covenant UTXOs", array_schema(ref_schema("CovenantUtxo")))
                }
            },
            "/addresses/{address}/covenants": {
                "get": {
                    "tags": ["Addresses"],
                    "summary": "Return covenants whose covenant address or indexed wallet participant matches this address",
                    "parameters": [
                        path_string("address", "Kaspa covenant or wallet address"),
                        query_integer("limit", "Page size; defaults to 100 and is capped at 200"),
                        query_integer("offset", "Pagination offset")
                    ],
                    "responses": paginated_response("Address covenants", array_schema(ref_schema("CovenantSummary")))
                }
            },
            "/addresses/{address}/utxos": {
                "get": {
                    "tags": ["Addresses"],
                    "summary": "Return active covenant UTXOs at one covenant address",
                    "parameters": [
                        path_string("address", "Kaspa covenant address"),
                        query_integer("limit", "Page size; defaults to 100 and is capped at 200"),
                        query_integer("offset", "Pagination offset")
                    ],
                    "responses": paginated_response("Address UTXOs", array_schema(ref_schema("CovenantUtxo")))
                }
            },
            "/addresses/{address}/events": {
                "get": {
                    "tags": ["Addresses"],
                    "summary": "Return recent covenant actions for one covenant address",
                    "parameters": [
                        path_string("address", "Kaspa covenant address"),
                        query_integer("limit", "Maximum rows to return, capped by the API")
                    ],
                    "responses": ok_response("Address events", array_schema(ref_schema("ActionRow")))
                }
            },
            "/fomo/rounds": {
                "get": {
                    "tags": ["FOMO"],
                    "summary": "List indexed Kaspa FOMO time-vault rounds",
                    "parameters": [
                        query_string("active", "true to return only rounds with an active covenant UTXO"),
                        query_integer("limit", "Maximum rows to return"),
                        query_integer("offset", "Pagination offset")
                    ],
                    "responses": ok_response("FOMO rounds", array_schema(ref_schema("FomoRound")))
                }
            },
            "/fomo/rounds/{covenant_id}": {
                "get": {
                    "tags": ["FOMO"],
                    "summary": "Return one FOMO round with actions and active UTXOs",
                    "parameters": [
                        path_string("covenant_id", "FOMO round covenant id or script hash"),
                        query_integer("limit", "Action and UTXO page size; defaults to 100 and is capped at 200"),
                        query_integer("offset", "Action and UTXO pagination offset")
                    ],
                    "responses": {
                        "200": json_response("FOMO round detail", ref_schema("FomoRoundDetail")),
                        "404": error_response("FOMO round not found")
                    }
                }
            },
            "/kcom/campaigns/{graph_id}": {
                "get": {
                    "tags": ["KCOM"],
                    "summary": "Return authenticated KCOM campaign lifecycle, reserve, and liabilities",
                    "parameters": [path_string("graph_id", "KCOM campaign graph covenant ID")],
                    "responses": {
                        "200": json_response("KCOM campaign", object_schema()),
                        "400": error_response("Invalid graph ID"),
                        "404": error_response("Campaign not found"),
                        "503": error_response("Campaign history is incomplete or conflicting")
                    }
                }
            },
            "/kcom/campaigns/{graph_id}/participants/{authority}": {
                "get": {
                    "tags": ["KCOM"],
                    "summary": "Return one KCOM participant's accepted selection, entitlement, and vesting state",
                    "parameters": [
                        path_string("graph_id", "KCOM campaign graph covenant ID"),
                        path_string("authority", "Original eligible authority, not redirected beneficiary")
                    ],
                    "responses": {
                        "200": json_response("KCOM participant", object_schema()),
                        "400": error_response("Invalid graph ID or authority"),
                        "404": error_response("Campaign or participant not found"),
                        "503": error_response("Campaign or participant history is incomplete or conflicting")
                    }
                }
            },
            "/kcc20/freshness": {
                "get": {
                    "tags": ["KCC20"],
                    "summary": "Return scanner freshness and suggested polling cadence",
                    "responses": ok_response("KCC20 freshness", object_schema())
                }
            },
            "/kcc20/markets": {
                "get": {
                    "tags": ["KCC20"],
                    "summary": "List KCC20 markets with best bid/ask, spread, volume, and depth totals",
                    "parameters": [
                        query_integer("limit", "Maximum market rows to return; defaults to 500 and is capped at 1000"),
                        query_integer("offset", "Pagination offset; defaults to 0")
                    ],
                    "responses": ok_response("KCC20 markets", array_schema(object_schema()))
                }
            },
            "/kcc20/discovery": {
                "get": {
                    "tags": ["KCC20"],
                    "summary": "Return indexed KCC20 market discovery rows with database-level filter, sort, and pagination",
                    "parameters": [
                        query_string("tokenId", "Optional 32-byte token id hex. Returns that market or an empty page."),
                        query_string("sortBy", "One of tokenIdHex, bestAskUnitPriceSompi, bestBidUnitPriceSompi, spreadSompi, openAskCount, openBidCount, totalVolumeSompi, totalTrades, volume24hSompi, volume7dSompi, tradeCount24h, tradeCount7d, lastTradeTimeMs"),
                        query_string("sortDirection", "asc or desc; defaults to desc"),
                        query_integer("limit", "Maximum rows to return, capped at 500"),
                        query_integer("offset", "Pagination offset"),
                        query_bool("includeTotal", "Include an exact count from the indexed summary table")
                    ],
                    "responses": {
                        "200": json_response("KCC20 discovery envelope", object_schema()),
                        "503": error_response("Postgres or payment persistence is unavailable")
                    }
                }
            },
            "/payments/proof/kcc20-discovery": {
                "get": {
                    "tags": ["Payments"],
                    "summary": "Payment-gated proof endpoint backed by KCC20 discovery rows",
                    "parameters": [
                        query_string("tokenId", "Optional 32-byte token id hex. Returns that market or an empty page."),
                        query_string("sortBy", "One of tokenIdHex, bestAskUnitPriceSompi, bestBidUnitPriceSompi, spreadSompi, openAskCount, openBidCount, totalVolumeSompi, totalTrades, volume24hSompi, volume7dSompi, tradeCount24h, tradeCount7d, lastTradeTimeMs"),
                        query_string("sortDirection", "asc or desc; defaults to desc"),
                        query_integer("limit", "Maximum rows to return, capped at 500"),
                        query_integer("offset", "Pagination offset"),
                        query_bool("includeTotal", "Include an exact count from the indexed summary table")
                    ],
                    "responses": {
                        "200": json_response("KCC20 discovery envelope", object_schema()),
                        "402": json_response("Payment challenge when API payment enforcement is enabled", ref_schema("PaymentRequiredProblem")),
                        "503": error_response("Postgres or payment persistence is unavailable")
                    },
                    "x-payment-info": payment_info(
                        API_PAYMENT_PROOF_DISCOVERY_PRICING_ID,
                        API_PAYMENT_PROOF_DISCOVERY_ROUTE,
                        &["kaspa-channel"],
                    )
                }
            },
            "/payments/proof/body-echo": {
                "post": {
                    "tags": ["Payments"],
                    "summary": "Payment-gated proof endpoint for body-bearing routes",
                    "description": "Returns redacted request metadata including body hash and byte length. This route exists to prove selected-route monetization for POST/body-bearing APIs without charging production KCC20 endpoints.",
                    "requestBody": {
                        "required": false,
                        "content": {
                            "application/json": {
                                "schema": object_schema()
                            }
                        }
                    },
                    "responses": {
                        "200": json_response("Body-bearing payment proof metadata", object_schema()),
                        "402": json_response("Payment challenge when API payment enforcement is enabled", ref_schema("PaymentRequiredProblem")),
                        "503": error_response("Payment persistence is unavailable")
                    },
                    "x-payment-info": payment_info(
                        API_PAYMENT_PROOF_BODY_ECHO_PRICING_ID,
                        API_PAYMENT_PROOF_BODY_ECHO_ROUTE,
                        &["kaspa-channel"],
                    )
                }
            },
            "/kcc20/market-snapshots": {
                "get": {
                    "tags": ["KCC20"],
                    "summary": "Return backend-friendly market snapshot rows for one or more timeframe windows",
                    "parameters": [
                        query_string("windows", "Up to four comma-separated window sizes in milliseconds; defaults to 24h and 7d"),
                        query_integer("limit", "Maximum markets to scan; defaults to and caps at 50"),
                        query_integer("offset", "Market pagination offset")
                    ],
                    "responses": ok_response("KCC20 market snapshots", array_schema(object_schema()))
                }
            },
            "/kcc20/wrappers": {
                "get": {
                    "tags": ["KCC20"],
                    "summary": "List indexed native-to-wrapped KCC20 market summaries",
                    "parameters": wrapper_summary_query_parameters(),
                    "responses": {
                        "200": paginated_json_response("KCC20 wrapper summaries", array_schema(object_schema())),
                        "503": error_response("Postgres state is unavailable")
                    }
                }
            },
            "/kcc20/wrappers/by-canonical/{covenant_id}": {
                "get": {
                    "tags": ["KCC20"],
                    "summary": "List wrapper market summaries for one canonical KCC20 token",
                    "parameters": wrapper_summary_by_canonical_query_parameters(),
                    "responses": {
                        "200": paginated_json_response("KCC20 wrapper summaries for canonical token", array_schema(object_schema())),
                        "400": error_response("Invalid covenant id"),
                        "503": error_response("Postgres state is unavailable")
                    }
                }
            },
            "/kcc20/fee-markets/by-canonical/{covenant_id}": {
                "get": {
                    "tags": ["KCC20"],
                    "summary": "Discover active versioned fee markets for one canonical KCC20 token",
                    "parameters": [path_string("covenant_id", "Canonical KCC20 token covenant id")],
                    "responses": {
                        "200": ok_response("Versioned fee market candidates", array_schema(object_schema())),
                        "400": error_response("Invalid covenant id"),
                        "503": error_response("Postgres state is unavailable")
                    }
                }
            },
            "/kcc20/{covenant_id}/summary": {
                "get": {
                    "tags": ["KCC20"],
                    "summary": "Return indexed supply and holder summary for one KCC20 token",
                    "parameters": [
                        path_string("covenant_id", "KCC20 token covenant id")
                    ],
                    "responses": {
                        "200": json_response("KCC20 token summary", object_schema()),
                        "400": error_response("Invalid covenant id"),
                        "404": error_response("KCC20 token summary was not indexed"),
                        "503": error_response("Postgres state is unavailable")
                    }
                }
            },
            "/kcc20/{covenant_id}/holders": paged_token_get("List holder balances for one KCC20 token"),
            "/kcc20/{covenant_id}/utxos": paged_token_utxos_get(),
            "/kcc20/{covenant_id}/orderbook": {
                "get": {
                    "tags": ["KCC20"],
                    "summary": "Return ask and bid depth for one KCC20 token",
                    "parameters": [
                        path_string("covenant_id", "KCC20 token covenant id"),
                        query_string("status", "Order status filter; defaults to open when omitted"),
                        market_row_sort_query(),
                        query_integer("limit", "Maximum ask and bid rows to return after filtering"),
                        query_integer("offset", "Pagination offset applied independently to asks and bids"),
                        query_integer(
                            "depthLimit",
                            "Maximum aggregated price levels per side; defaults to 100 and is capped at 1000"
                        )
                    ],
                    "responses": ok_response("KCC20 orderbook", object_schema())
                }
            },
            "/kcc20/{covenant_id}/stats": {
                "get": {
                    "tags": ["KCC20"],
                    "summary": "Return windowed market stats for one KCC20 token",
                    "parameters": [
                        path_string("covenant_id", "KCC20 token covenant id"),
                        query_integer("windowMs", "Stats window in milliseconds")
                    ],
                    "responses": ok_response("KCC20 stats", object_schema())
                }
            },
            "/kcc20/{covenant_id}/candles": {
                "get": {
                    "tags": ["KCC20"],
                    "summary": "Return OHLCV candles for indexed fills",
                    "parameters": [
                        path_string("covenant_id", "KCC20 token covenant id"),
                        query_integer("intervalMs", "Candle interval in milliseconds"),
                        query_integer("limit", "Maximum candles to return"),
                        query_integer("from", "Inclusive lower bound on bucketTimeMs (epoch ms); bounded on the bucket boundary so a bucket is never partially included"),
                        query_integer("to", "Exclusive upper bound on bucketTimeMs (epoch ms); same bucket-boundary semantics as from")
                    ],
                    "responses": ok_response("KCC20 candles", array_schema(object_schema()))
                }
            },
            "/kcc20/{covenant_id}/activity": activity_get("Return recent order creates, cancels, fills, and token actions"),
            "/kcc20/{covenant_id}/quote": {
                "get": {
                    "tags": ["KCC20"],
                    "summary": "Validate and quote a proposed buy or sell fill",
                    "parameters": [
                        path_string("covenant_id", "KCC20 token covenant id"),
                        query_required_string("side", "buy or sell"),
                        query_required_string("amount", "Requested token amount"),
                        query_string("orderId", "Optional specific order id to quote")
                    ],
                    "responses": ok_response("KCC20 quote", object_schema())
                }
            },
            "/kcc20/{covenant_id}/orders/{order_id}": {
                "get": {
                    "tags": ["KCC20"],
                    "summary": "Return one order with current row, lineage, and related fills",
                    "parameters": [
                        path_string("covenant_id", "KCC20 token covenant id"),
                        path_string("order_id", "Stable order id")
                    ],
                    "responses": {
                        "200": json_response("KCC20 order detail", object_schema()),
                        "404": error_response("No matching order")
                    }
                }
            },
            "/kcc20/{covenant_id}/listings": token_market_rows_get("List sell-side fixed listings for one KCC20 token"),
            "/kcc20/{covenant_id}/bids": token_market_rows_get("List buy-side fixed bids for one KCC20 token"),
            "/kcc20/listings": market_rows_get("List sell-side fixed listings across all KCC20 tokens"),
            "/kcc20/bids": market_rows_get("List buy-side fixed bids across all KCC20 tokens"),
            "/kcc20/{covenant_id}/trades": {
                "get": {
                    "tags": ["KCC20"],
                    "summary": "Return indexed trade tape for one token",
                    "parameters": trade_parameters(Some(path_string("covenant_id", "KCC20 token covenant id"))),
                    "responses": ok_response("KCC20 trades", array_schema(object_schema()))
                }
            },
            "/addresses/{address}/kcc20/orders": {
                "get": {
                    "tags": ["Addresses"],
                    "summary": "Return ask and bid order history for one owner identifier",
                    "parameters": [
                        path_string("address", "Owner identifier or address"),
                        query_string("status", "Order status filter"),
                        query_string("tokenId", "Optional token covenant id"),
                        query_integer("from", "Inclusive lower bound on createdAtMs in epoch milliseconds for historical orders; ignored for open orders"),
                        query_integer("to", "Exclusive upper bound on createdAtMs in epoch milliseconds for historical orders; ignored for open orders"),
                        query_integer("limit", "Maximum rows to return"),
                        query_integer("offset", "Pagination offset")
                    ],
                    "responses": ok_response("Address KCC20 orders", array_schema(object_schema()))
                }
            },
            "/addresses/{address}/kcc20/balances": {
                "get": {
                    "tags": ["Addresses"],
                    "summary": "Return KCC20 balances for one owner identifier across tokens",
                    "parameters": [
                        path_string("address", "Owner identifier or address"),
                        query_integer("limit", "Maximum balance rows to return; defaults to 200 and caps at 1000"),
                        query_integer("offset", "Balance pagination offset"),
                        query_bool("includeCoverage", "Return an items and coverage envelope instead of a plain array")
                    ],
                    "responses": {
                        "200": paginated_json_response("Address KCC20 balances", array_schema(object_schema())),
                        "400": error_response("Invalid owner identifier"),
                        "503": error_response("Postgres state is unavailable")
                    }
                }
            },
            "/addresses/{address}/kcc20/portfolio": {
                "get": {
                    "tags": ["Addresses"],
                    "summary": "Return a paginated canonical KCC20 portfolio for one owner identifier",
                    "parameters": [
                        path_string("address", "Owner identifier or address"),
                        query_integer("limit", "Maximum canonical token rows to return"),
                        query_integer("offset", "Pagination offset"),
                        query_bool("includeWrapped", "Include wrapped balances grouped under native KCC20 tokens"),
                        query_bool("includeReserves", "Include wrapper-owned native reserve rows for each canonical token"),
                        query_bool("includeTotals", "Include totalBalance fields"),
                        query_bool("includeEmpty", "Include zero-balance rows"),
                        query_bool("includeCoverage", "Return an items and coverage envelope instead of a plain array")
                    ],
                    "responses": ok_response("Address KCC20 portfolio", array_schema(object_schema()))
                }
            },
            "/addresses/{address}/kcc20/portfolio-assets": {
                "get": {
                    "tags": ["Addresses"],
                    "summary": "Return indexed, globally sorted KCC20 portfolio assets for one owner identifier",
                    "description": "Balances, orders, and market prices are refreshed by the KCC20 projector and may lag the chain by one projector cycle.",
                    "parameters": [
                        path_string("address", "Owner identifier or address"),
                        query_integer("limit", "Maximum asset rows to return; defaults to 10 and caps at 1000"),
                        query_integer("offset", "Asset pagination offset"),
                        query_string("sortBy", "One of canonicalTokenIdHex, nativeBalance, orderbookBalance, totalBalance, assetUtxoCount, openAskAmount, openBidAmount, openOrderCount, lastChangeMs, bestAskUnitPriceSompi, valueSompi"),
                        query_string("sortDirection", "asc or desc"),
                        query_string("tokenId", "Exact canonical token covenant id"),
                        query_string("search", "Case-insensitive token id, ticker, or token-name fragment"),
                        query_bool("hasNativeBalance", "Require a positive native KCC20 balance; accepts true/false or 1/0"),
                        query_bool("hasOrderbookBalance", "Require a positive orderbook balance; accepts true/false or 1/0"),
                        query_bool("hasOpenOrders", "Require at least one open order; accepts true/false or 1/0")
                    ],
                    "responses": {
                        "200": json_response("Address KCC20 portfolio asset envelope", json!({
                            "type": "object",
                            "required": ["items", "total", "limit", "offset", "sortBy", "sortDirection"],
                            "properties": {
                                "items": array_schema(portfolio_asset_schema()),
                                "total": { "type": "integer", "format": "int64", "minimum": 0 },
                                "limit": { "type": "integer", "format": "int64", "minimum": 1 },
                                "offset": { "type": "integer", "format": "int64", "minimum": 0 },
                                "sortBy": { "type": "string" },
                                "sortDirection": { "type": "string", "enum": ["asc", "desc"] },
                                "coverage": { "type": "object", "additionalProperties": true }
                            }
                        })),
                        "400": error_response("Invalid owner identifier, pagination, sorting, filtering, token id, or search"),
                        "500": error_response("Portfolio projection query failed"),
                        "503": error_response("Postgres state is unavailable or the owner portfolio projection has not completed its initial refresh")
                    }
                }
            },
            "/addresses/{address}/kcc20/trades": {
                "get": {
                    "tags": ["Addresses"],
                    "summary": "Return indexed fills where the owner was maker or taker",
                    "parameters": trade_parameters(Some(path_string("address", "Owner identifier or address"))),
                    "responses": ok_response("Address KCC20 trades", array_schema(object_schema()))
                }
            },
            "/addresses/{address}/kcc20/actions": {
                "get": {
                    "tags": ["Addresses"],
                    "summary": "Return address-wide KCC20 lifecycle actions for portfolio history",
                    "parameters": [
                        path_string("address", "Owner identifier hex or indexed Kaspa address"),
                        query_string("tokenId", "Optional canonical or wrapped token id"),
                        query_string("action", "Optional normalized action filter such as deploy, mint, wrap, unwrap, feeTicketCreate, feeTicketUse, feeTicketBurn, orderCreate, orderCancel, trade, transfer, or burn"),
                        query_integer("limit", "Maximum rows to return"),
                        query_integer("offset", "Pagination offset")
                    ],
                    "responses": ok_response("Address KCC20 actions", array_schema(object_schema()))
                }
            },
            "/tx/{txid}/settlement-status": {
                "get": {
                    "tags": ["Transactions"],
                    "summary": "Return whether a submitted tx is indexed, decoded, and current with scanner lag",
                    "parameters": [path_string("txid", "Transaction id")],
                    "responses": ok_response("Settlement status", object_schema())
                }
            },
            "/events": {
                "get": {
                    "tags": ["Events"],
                    "summary": "Return recent indexed actions across all covenants",
                    "parameters": [
                        query_integer("limit", "Maximum rows to return, capped by the API"),
                        query_string("classification", "Filter by classification kind"),
                        query_string("classificationStatus", "Filter by classification status")
                    ],
                    "responses": ok_response("Action rows", array_schema(ref_schema("ActionRow")))
                }
            },
            "/tx/{txid}": {
                "get": {
                    "tags": ["Transactions"],
                    "summary": "Return indexed actions for one transaction",
                    "parameters": [path_string("txid", "Transaction id")],
                    "responses": ok_response("Action rows", array_schema(ref_schema("ActionRow")))
                }
            },
            "/tx/{txid}/sync": {
                "post": {
                    "tags": ["Transactions"],
                    "summary": "Fetch and ingest one accepted transaction",
                    "description": "Fast-paths an accepted transaction through the same REST hydration and Postgres projection path used by the scanner. This is intended for backend reconciliation immediately after wallet broadcast; it is idempotent and returns the decoded action rows currently projected for the supplied txid. A transaction that has not propagated to any configured REST source returns 202 Accepted with pending=true and Retry-After: 2. During canonical recovery, authenticated requests are durably queued and return 202 with queued=true, indexed=false and ingested=false. Queued requests survive API restarts and retry after recovery, using fresh acceptance evidence. Queue receipt does not make balances or orders queryable. Use force=true to re-fetch and reproject an already-indexed transaction after decoder/projection fixes.",
                    "parameters": [
                        path_string("txid", "32-byte transaction id hex"),
                        query_bool("force", "Re-fetch and reproject even when action rows already exist")
                    ],
                    "responses": {
                        "200": json_response("Transaction sync result", ref_schema("TransactionSyncResponse")),
                        "202": json_response("Transaction is pending propagation, decoding, or durable queue processing; indexed=false is not a completed sync", ref_schema("TransactionSyncResponse")),
                        "400": error_response("Invalid txid"),
                        "401": error_response("Missing or invalid sync bearer token"),
                        "429": error_response("Too many sync requests"),
                        "503": error_response("Persistence or REST lookup is unavailable")
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "HealthResponse": {
                    "type": "object",
                    "additionalProperties": true,
                    "required": ["ok", "source"],
                    "properties": {
                        "ok": { "type": "boolean" },
                        "source": { "type": "string", "enum": ["postgres", "memory"] },
                        "covenants": { "type": "integer" },
                        "activeUtxos": { "type": "integer" },
                        "actions": { "type": "integer" },
                        "scanner": { "type": ["object", "null"], "additionalProperties": true },
                        "coverage": { "type": "object", "additionalProperties": true },
                        "classifications": { "type": "array", "items": object_schema() },
                        "unknown": { "type": ["object", "array", "null"] }
                    }
                },
                "ExplorerSummary": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["ok", "source", "counts", "scanner", "classifications", "unknown", "templates"],
                    "properties": {
                        "ok": { "type": "boolean" },
                        "source": { "type": "string" },
                        "counts": object_schema(),
                        "scanner": { "type": ["object", "null"], "additionalProperties": true },
                        "classifications": { "type": "array", "items": object_schema() },
                        "unknown": object_schema(),
                        "templates": { "type": "array", "items": object_schema() }
                    }
                },
                "ExplorerSearchResult": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["kind", "label", "path", "score"],
                    "properties": {
                        "kind": { "type": "string", "enum": ["covenant", "transaction", "address", "kcc20"] },
                        "label": { "type": "string" },
                        "description": { "type": ["string", "null"] },
                        "id": { "type": ["string", "null"] },
                        "path": { "type": "string" },
                        "status": { "type": ["string", "null"] },
                        "score": { "type": "integer" }
                    }
                },
                "ApiPaymentPricing": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["enabled", "networkId", "methods", "freeRoutes", "paidRoutes"],
                    "properties": {
                        "enabled": { "type": "boolean" },
                        "networkId": { "type": "string" },
                        "methods": { "type": "array", "items": { "type": "string", "enum": ["kaspa-channel", "kaspa-direct"] } },
                        "freeRoutes": { "type": "array", "items": { "type": "string" } },
                        "paidRoutes": { "type": "array", "items": { "$ref": "#/components/schemas/ApiPaymentPricingRoute" } }
                    }
                },
                "ApiPaymentPricingRoute": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["pricingId", "method", "path", "route", "amountSompi", "methodName", "enabled"],
                    "properties": {
                        "pricingId": { "type": "string" },
                        "method": { "type": "string" },
                        "path": { "type": "string" },
                        "route": { "type": "string" },
                        "amountSompi": { "type": "string" },
                        "methodName": { "type": "string", "enum": ["kaspa-channel", "kaspa-direct"] },
                        "enabled": { "type": "boolean" }
                    }
                },
                "ApiPaymentRuntimeMetrics": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["paidRequestsServed", "authorizationFailures", "receiptRecordFailures", "receiptEncodeFailures"],
                    "properties": {
                        "paidRequestsServed": { "type": "integer", "minimum": 0 },
                        "authorizationFailures": { "type": "integer", "minimum": 0 },
                        "receiptRecordFailures": { "type": "integer", "minimum": 0 },
                        "receiptEncodeFailures": { "type": "integer", "minimum": 0 }
                    }
                },
                "ApiPaymentChallengeRequest": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["method", "path"],
                    "properties": {
                        "method": { "type": "string", "example": "GET" },
                        "path": { "type": "string", "example": "/payments/proof/kcc20-discovery" },
                        "rawQuery": {
                            "type": ["string", "null"],
                            "description": "Raw query string without leading ?, using the same byte-level parameter names and values the client will request."
                        },
                        "bodyHashHex": {
                            "type": ["string", "null"],
                            "description": "Optional 32-byte hex body hash. GET requests default to the empty-body hash."
                        },
                        "paymentMethod": {
                            "type": ["string", "null"],
                            "enum": ["kaspa-channel", "kaspa-direct", null],
                            "description": "Optional payment method. Defaults to kaspa-channel."
                        }
                    }
                },
                "ApiPaymentChallengeResponse": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["challenge", "pricingId", "route", "amountSompi", "requestHash", "enabled"],
                    "properties": {
                        "challenge": { "$ref": "#/components/schemas/ApiPaymentChallenge" },
                        "pricingId": { "type": "string" },
                        "route": { "type": "string" },
                        "amountSompi": { "type": "string" },
                        "requestHash": { "type": "string" },
                        "enabled": { "type": "boolean" }
                    }
                },
                "ApiPaymentChallenge": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["id", "method", "intent", "request"],
                    "properties": {
                        "id": { "type": "string" },
                        "method": { "type": "string", "enum": ["kaspa-channel", "kaspa-direct"] },
                        "intent": { "type": "string", "enum": ["charge", "session"] },
                        "request": {
                            "type": "object",
                            "additionalProperties": true,
                            "description": "For kaspa-direct, request includes payloadHex. Clients must put this payload on the payment transaction so the verifier can bind the tx to the challenge, then retry the paid route with Authorization: Payment <base64url JSON { method: \"kaspa-direct\", txidHex: \"...\" }>."
                        }
                    }
                },
                "ApiDirectPaymentProofRequest": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "challengeId", "networkId", "txidHex", "recipientAddress",
                        "amountSompi", "pricingId", "route", "requestHash"
                    ],
                    "properties": {
                        "challengeId": { "type": "string" },
                        "networkId": { "type": "string" },
                        "txidHex": { "type": "string", "description": "32-byte transaction id hex" },
                        "payerIdentifier": { "type": ["string", "null"] },
                        "recipientAddress": { "type": "string" },
                        "amountSompi": { "type": "string" },
                        "pricingId": { "type": "string" },
                        "route": { "type": "string" },
                        "requestHash": { "type": "string", "description": "32-byte canonical request hash hex" }
                    }
                },
                "ApiPaymentChannelCloseRequest": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "schema", "method", "networkId", "channelId",
                        "payerPubkey", "providerPubkey", "requestedAtMs",
                        "expiresAtMs", "nonce", "signature"
                    ],
                    "properties": {
                        "schema": { "type": "string", "const": "kaspa-api-payment-channel-close-request/v1" },
                        "method": { "type": "string", "enum": ["kaspa-channel"] },
                        "networkId": { "type": "string" },
                        "channelId": { "type": "string", "description": "32-byte channel id hex" },
                        "payerPubkey": { "type": "string", "description": "32-byte x-only payer pubkey hex" },
                        "providerPubkey": { "type": "string", "description": "32-byte x-only provider pubkey hex" },
                        "requestedAtMs": { "type": "integer" },
                        "expiresAtMs": { "type": "integer" },
                        "nonce": { "type": "string" },
                        "reason": { "type": ["string", "null"] },
                        "signature": { "type": "string", "description": "64-byte Schnorr signature over the close request digest" }
                    }
                },
                "ApiPaymentChannelSyncRequest": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["txidHex"],
                    "properties": {
                        "txidHex": { "type": "string", "description": "32-byte accepted channel open, settlement, or refund transaction id hex" }
                    }
                },
                "ApiDirectPaymentProofResponse": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "receiptId", "challengeId", "txidHex", "status",
                        "amountSompi", "pricingId", "route", "requestHash"
                    ],
                    "properties": {
                        "receiptId": { "type": "string" },
                        "challengeId": { "type": "string" },
                        "txidHex": { "type": "string" },
                        "status": { "type": "string", "enum": ["submitted", "verified", "accepted", "rejected"] },
                        "failureReason": { "type": ["string", "null"] },
                        "amountSompi": { "type": "string" },
                        "pricingId": { "type": "string" },
                        "route": { "type": "string" },
                        "requestHash": { "type": "string" },
                        "verifiedAtMs": { "type": ["string", "null"] },
                        "indexedAtMs": { "type": ["string", "null"] }
                    }
                },
                "ApiPaymentReceiptStatusResponse": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "receiptId", "requestId", "route", "pricingId",
                        "amountSompi", "createdAtMs"
                    ],
                    "properties": {
                        "receiptId": { "type": "string" },
                        "requestId": { "type": "string" },
                        "channelId": { "type": ["string", "null"] },
                        "route": { "type": "string" },
                        "pricingId": { "type": "string" },
                        "amountSompi": { "type": "string" },
                        "voucherSequence": { "type": ["string", "null"] },
                        "responseStatus": { "type": ["integer", "null"] },
                        "durationMs": { "type": ["string", "null"] },
                        "createdAtMs": { "type": "string" },
                        "requestHash": { "type": ["string", "null"] },
                        "voucherTotalSpentSompi": { "type": ["string", "null"] },
                        "voucherAcceptedAtMs": { "type": ["string", "null"] },
                        "channelStatus": { "type": ["string", "null"] },
                        "channelSpentSompi": { "type": ["string", "null"] },
                        "channelLatestSequence": { "type": ["string", "null"] }
                    }
                },
                "ApiPaymentChannelStatusResponse": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "channelId", "networkId", "status", "payerIdentifier",
                        "payerPubkey", "providerPubkey", "depositSompi",
                        "reserveSompi", "spentSompi", "remainingSompi",
                        "latestSequence", "closeAfterMs", "updatedAtMs", "scanner"
                    ],
                    "properties": {
                        "channelId": { "type": "string", "description": "32-byte channel id hex" },
                        "networkId": { "type": "string" },
                        "status": { "type": "string", "enum": ["opening", "usable", "close_requested", "settlement_pending", "settled", "refund_pending", "refunded", "failed", "disabled"] },
                        "payerIdentifier": { "type": "string" },
                        "payerPubkey": { "type": "string" },
                        "providerPubkey": { "type": "string" },
                        "providerPayoutPubkey": { "type": ["string", "null"] },
                        "voucherDomainHash": { "type": ["string", "null"] },
                        "depositSompi": { "type": "string" },
                        "reserveSompi": { "type": "string" },
                        "spentSompi": { "type": "string" },
                        "remainingSompi": { "type": "string" },
                        "latestSequence": { "type": "string" },
                        "maxSpendSompi": { "type": ["string", "null"] },
                        "refundAfterMs": { "type": ["string", "null"] },
                        "closeAfterMs": { "type": "string", "description": "0 for active channels; final refund unlock time after on-chain requestRefundClose." },
                        "openTxid": { "type": ["string", "null"] },
                        "currentTxid": { "type": ["string", "null"], "description": "Current live channel UTXO txid; changes on continuation/top-up." },
                        "currentVout": { "type": ["integer", "null"], "description": "Current live channel UTXO output index; changes on continuation/top-up." },
                        "settlementTxid": { "type": ["string", "null"] },
                        "refundTxid": { "type": ["string", "null"] },
                        "indexedAtMs": { "type": ["string", "null"] },
                        "updatedAtMs": { "type": "string" },
                        "scanner": { "type": "object", "additionalProperties": true }
                    }
                },
                "ApiPaymentSettlementStatusResponse": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["txidHex", "indexed", "scanner"],
                    "properties": {
                        "txidHex": { "type": "string", "description": "32-byte transaction id hex" },
                        "indexed": { "type": "boolean" },
                        "kind": { "type": ["string", "null"], "enum": ["settlement", "refund", null] },
                        "channelId": { "type": ["string", "null"] },
                        "networkId": { "type": ["string", "null"] },
                        "channelStatus": { "type": ["string", "null"] },
                        "settledSequence": { "type": ["string", "null"] },
                        "settledTotalSompi": { "type": ["string", "null"] },
                        "providerAmountSompi": { "type": ["string", "null"] },
                        "payerRefundSompi": { "type": ["string", "null"] },
                        "indexerStatus": { "type": ["string", "null"] },
                        "createdAtMs": { "type": ["string", "null"] },
                        "indexedAtMs": { "type": ["string", "null"] },
                        "updatedAtMs": { "type": ["string", "null"] },
                        "scanner": { "type": "object", "additionalProperties": true }
                    }
                },
                "TransactionSyncResponse": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["txidHex", "indexed", "pending", "actionCount", "persistStats", "scanner", "actions"],
                    "properties": {
                        "txidHex": { "type": "string", "description": "32-byte transaction id hex" },
                        "indexed": { "type": "boolean" },
                        "pending": { "type": "boolean", "description": "True while propagation or queued indexing remains incomplete" },
                        "queued": { "type": "boolean", "description": "Durably saved for later processing, not yet indexed" },
                        "ingested": { "type": "boolean" },
                        "coverage": { "type": "object", "additionalProperties": true },
                        "reason": { "type": "string", "enum": ["transaction_not_found_yet", "canonical_recovery_in_progress"] },
                        "retryAfterMs": { "type": "integer", "description": "Recommended client retry delay when pending is true" },
                        "actionCount": { "type": "integer" },
                        "persistStats": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["blocksInserted", "covenantsInserted", "utxosInserted", "utxosSpent", "actionsInserted"],
                            "properties": {
                                "blocksInserted": { "type": "integer" },
                                "covenantsInserted": { "type": "integer" },
                                "utxosInserted": { "type": "integer" },
                                "utxosSpent": { "type": "integer" },
                                "actionsInserted": { "type": "integer" }
                            }
                        },
                        "scanner": { "type": ["object", "null"], "additionalProperties": true },
                        "actions": { "type": "array", "items": { "$ref": "#/components/schemas/ActionRow" } }
                    }
                },
                "PaymentRequiredProblem": {
                    "type": "object",
                    "additionalProperties": true,
                    "required": ["type", "title", "status", "payment"],
                    "properties": {
                        "type": { "type": "string" },
                        "title": { "type": "string" },
                        "status": { "type": "integer", "const": 402 },
                        "failureCode": { "type": "string" },
                        "detail": { "type": "string" },
                        "payment": { "type": "object", "additionalProperties": true }
                    }
                },
                "CovenantSummary": {
                    "type": "object",
                    "additionalProperties": true,
                    "properties": {
                        "covenantIdHex": { "type": ["string", "null"] },
                        "scriptHashHex": { "type": "string" },
                        "canonicalCovenantIdKnown": { "type": "boolean" },
                        "identitySource": { "type": "string", "enum": ["canonical", "scriptHashFallback"] },
                        "address": { "type": ["string", "null"] },
                        "template": { "type": ["string", "null"] },
                        "classificationKind": { "type": ["string", "null"], "enum": ["covenant", "inscription", "unknown", null] },
                        "classificationStatus": { "type": ["string", "null"], "enum": ["unrevealed", "matched", "unmatched", null] },
                        "inscriptionProtocol": { "type": ["string", "null"] },
                        "decodedArgs": { "type": ["object", "null"], "additionalProperties": true },
                        "activeUtxos": { "type": "integer" },
                        "totalAmountSompi": { "type": ["integer", "string", "null"] },
                        "genesisTxidHex": { "type": ["string", "null"] },
                        "createdAtMs": { "type": ["integer", "null"] }
                    }
                },
                "CovenantTemplateSummary": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "template": { "type": "string" },
                        "covenantCount": { "type": "integer" },
                        "verifiedCount": { "type": "integer" },
                        "claimedOnlyCount": { "type": "integer" },
                        "activeCovenants": { "type": "integer" },
                        "activeUtxos": { "type": "integer" },
                        "totalAmountSompi": { "type": "string" },
                        "actionCount": { "type": "integer" },
                        "matchedCount": { "type": "integer" },
                        "unrevealedCount": { "type": "integer" },
                        "unmatchedCount": { "type": "integer" },
                        "latestCreatedAtMs": { "type": ["integer", "null"] },
                        "latestActionTimeMs": { "type": ["integer", "null"] }
                    }
                },
                "CovenantUtxo": {
                    "type": "object",
                    "additionalProperties": true,
                    "properties": {
                        "covenantIdHex": { "type": "string" },
                        "scriptHashHex": { "type": "string" },
                        "address": { "type": "string" },
                        "txidHex": { "type": "string" },
                        "vout": { "type": "integer" },
                        "amountSompi": { "type": "integer" },
                        "amountSompiExact": { "type": "string" },
                        "state": { "type": ["object", "null"], "additionalProperties": true },
                        "status": { "type": "string" },
                        "spentByTxidHex": { "type": ["string", "null"] }
                    }
                },
                "CovenantDetail": {
                    "type": "object",
                    "additionalProperties": true,
                    "properties": {
                        "covenant": { "$ref": "#/components/schemas/CovenantSummary" },
                        "actions": { "type": "array", "items": { "$ref": "#/components/schemas/ActionRow" } },
                        "events": { "type": "array", "items": object_schema() }
                    }
                },
                "FomoRound": {
                    "type": "object",
                    "additionalProperties": true,
                    "properties": {
                        "covenantIdHex": { "type": "string" },
                        "scriptHashHex": { "type": "string" },
                        "address": { "type": "string" },
                        "status": { "type": "string", "enum": ["active", "settled", "spent"] },
                        "potSompi": { "type": ["string", "null"] },
                        "activeTxidHex": { "type": ["string", "null"] },
                        "activeVout": { "type": ["integer", "null"] },
                        "state": { "type": ["object", "null"], "additionalProperties": true },
                        "lastBuyer": { "type": ["string", "null"] },
                        "endTimeMs": { "type": ["string", "null"] },
                        "ticketCount": { "type": ["string", "null"] },
                        "buyCount": { "type": "integer" },
                        "settledTxidHex": { "type": ["string", "null"] },
                        "createdAtMs": { "type": "integer" },
                        "lastActionTimeMs": { "type": ["integer", "null"] }
                    }
                },
                "FomoRoundDetail": {
                    "type": "object",
                    "additionalProperties": true,
                    "properties": {
                        "round": { "$ref": "#/components/schemas/FomoRound" },
                        "actions": { "type": "array", "items": { "$ref": "#/components/schemas/ActionRow" } },
                        "utxos": { "type": "array", "items": { "$ref": "#/components/schemas/CovenantUtxo" } }
                    }
                },
                "ActionRow": {
                    "type": "object",
                    "additionalProperties": true,
                    "properties": {
                        "txidHex": { "type": "string" },
                        "covenantIdHex": { "type": ["string", "null"] },
                        "scriptHashHex": { "type": ["string", "null"] },
                        "action": { "type": ["string", "null"] },
                        "entrypoint": { "type": ["string", "null"] },
                        "classificationKind": { "type": ["string", "null"] },
                        "classificationStatus": { "type": ["string", "null"] },
                        "inscriptionProtocol": { "type": ["string", "null"] },
                        "decodedArgs": { "type": ["object", "null"], "additionalProperties": true },
                        "inputs": { "type": ["object", "null"], "additionalProperties": true },
                        "outputs": { "type": ["object", "null"], "additionalProperties": true },
                        "blockTimeMs": { "type": ["integer", "null"] }
                    }
                }
            }
        }
    });
    add_operation_ids(&mut spec);
    spec
}

fn paged_token_get(summary: &str) -> Value {
    json!({
        "get": {
            "tags": ["KCC20"],
            "summary": summary,
            "parameters": [
                path_string("covenant_id", "KCC20 token covenant id"),
                query_integer("limit", "Page size; defaults to 100 and is capped at 200"),
                query_integer("offset", "Pagination offset")
            ],
            "responses": paginated_response(summary, array_schema(object_schema()))
        }
    })
}

fn paged_token_utxos_get() -> Value {
    json!({
        "get": {
            "tags": ["KCC20"],
            "summary": "List active token UTXOs for one KCC20 token",
            "parameters": covenant_utxo_parameters("covenant_id", "KCC20 token covenant id"),
            "responses": paginated_response(
                "Active KCC20 token UTXOs",
                array_schema(ref_schema("CovenantUtxo"))
            )
        }
    })
}

fn activity_get(summary: &str) -> Value {
    json!({
        "get": {
            "tags": ["KCC20"],
            "summary": summary,
            "parameters": [
                path_string("covenant_id", "KCC20 token covenant id"),
                query_integer("limit", "Maximum rows to return"),
                query_integer("offset", "Pagination offset"),
                query_integer("from", "Inclusive lower bound on blockTimeMs in epoch milliseconds"),
                query_integer("to", "Exclusive upper bound on blockTimeMs in epoch milliseconds"),
                query_string("kind", "Activity kind: deploy, mint, mintConfig, transfer, burn, wrap, unwrap, orderCreated, orderCancelled, trade, feeTicketCreate, feeTicketBurn, feeTicketConfig, or action"),
                query_string("scope", "Activity scope: all, token, or trading"),
                query_string("side", "Orderbook side: ask or bid"),
                query_string("entrypoint", "Raw contract entrypoint name"),
                query_string("owner", "Owner identifier hex"),
                query_string("txid", "Transaction id hex"),
                query_string("orderId", "Projected order id")
            ],
            "responses": ok_response(summary, array_schema(object_schema()))
        }
    })
}

fn token_market_rows_get(summary: &str) -> Value {
    let mut params = vec![path_string("covenant_id", "KCC20 token covenant id")];
    params.extend(market_row_query_parameters());
    json!({
        "get": {
            "tags": ["KCC20"],
            "summary": summary,
            "parameters": params,
            "responses": ok_response(summary, array_schema(object_schema()))
        }
    })
}

fn market_rows_get(summary: &str) -> Value {
    json!({
        "get": {
            "tags": ["KCC20"],
            "summary": summary,
            "parameters": market_row_query_parameters(),
            "responses": ok_response(summary, array_schema(object_schema()))
        }
    })
}

fn market_row_query_parameters() -> Vec<Value> {
    vec![
        query_string("status", "Order status filter"),
        market_row_sort_query(),
        query_integer(
            "limit",
            "Maximum rows to return after filtering; defaults to 100 and caps at 500",
        ),
        query_integer("offset", "Pagination offset"),
    ]
}

fn wrapper_summary_query_parameters() -> Vec<Value> {
    vec![
        query_bool(
            "include_pending",
            "Include pending wrapper reveals; snake_case form",
        ),
        query_bool(
            "includePending",
            "Include pending wrapper reveals; camelCase alias",
        ),
        query_integer(
            "limit",
            "Maximum wrapper summaries to return; defaults to 100 and caps at 200",
        ),
        query_integer("offset", "Wrapper summary pagination offset"),
    ]
}

fn wrapper_summary_by_canonical_query_parameters() -> Vec<Value> {
    let mut params = vec![path_string(
        "covenant_id",
        "Canonical KCC20 token covenant id",
    )];
    params.extend(wrapper_summary_query_parameters());
    params
}

fn market_row_sort_query() -> Value {
    query_param(
        "sort",
        "Sort mode: price_asc, price_desc, created_asc, or created_desc. Listings default to created_desc and unknown values fall back to price_asc; bids default to created_desc and unknown values fall back to price_desc.",
        false,
        json!({
            "type": "string",
            "enum": ["price_asc", "price_desc", "created_asc", "created_desc"]
        }),
    )
}

fn trade_parameters(first: Option<Value>) -> Vec<Value> {
    let mut params = Vec::new();
    if let Some(first) = first {
        params.push(first);
    }
    params.extend([
        query_integer("limit", "Maximum rows to return"),
        query_integer("offset", "Pagination offset"),
        query_integer(
            "from",
            "Inclusive lower bound on blockTimeMs in epoch milliseconds",
        ),
        query_integer(
            "to",
            "Exclusive upper bound on blockTimeMs in epoch milliseconds",
        ),
        query_string("side", "buy, sell, cross, or trade"),
        query_string("address", "Filter by maker or taker owner identifier"),
    ]);
    params
}

fn ok_response(description: &str, schema: Value) -> Value {
    json!({ "200": json_response(description, schema) })
}

fn covenant_list_response() -> Value {
    let mut response = json_response(
        "Covenant summaries",
        array_schema(ref_schema("CovenantSummary")),
    );
    response["headers"] = json!({
        "X-Total-Count": {
            "description": "Full number of rows matching the filters before limit and offset",
            "required": true,
            "schema": { "type": "integer", "format": "int64", "minimum": 0 }
        }
    });
    json!({ "200": response })
}

fn paginated_response(description: &str, schema: Value) -> Value {
    json!({ "200": paginated_json_response(description, schema) })
}

fn paginated_json_response(description: &str, schema: Value) -> Value {
    let mut response = json_response(description, schema);
    response["headers"] = json!({
        "X-Total-Count": {
            "description": "Full number of rows matching the filters before limit and offset",
            "required": true,
            "schema": { "type": "integer", "format": "int64", "minimum": 0 }
        }
    });
    response
}

fn covenant_detail_parameters(path_name: &str, path_description: &str) -> Vec<Value> {
    vec![
        path_string(path_name, path_description),
        query_integer("limit", "Action page size; defaults to 100, is capped at 200, and accepts 0 for summary-only detail"),
        query_integer("offset", "Action pagination offset"),
        query_string("sort", "Action order: asc (default) or desc"),
        query_string("action", "Exact action filter, such as deploy, spend, or continuation"),
        query_string("entrypoint", "Comma-separated exact entrypoint filters"),
    ]
}

fn covenant_utxo_parameters(path_name: &str, path_description: &str) -> Vec<Value> {
    vec![
        path_string(path_name, path_description),
        query_integer("limit", "Page size; defaults to 100 and is capped at 200"),
        query_integer("offset", "Pagination offset"),
        query_string("address", "Exact covenant output address"),
        query_string("ownerIdentifier", "Exact state ownerIdentifier or owner"),
        query_integer("stateMode", "Exact numeric state mode"),
        query_bool("stateNull", "Only return UTXOs whose decoded state is null"),
    ]
}

fn json_response(description: &str, schema: Value) -> Value {
    json!({
        "description": description,
        "content": {
            "application/json": { "schema": schema }
        }
    })
}

fn error_response(description: &str) -> Value {
    json!({
        "description": description,
        "content": {
            "text/plain": { "schema": { "type": "string" } }
        }
    })
}

fn swagger_redirect_response() -> Value {
    json!({
        "303": {
            "description": "Redirects to /swagger-ui/",
            "headers": {
                "Location": {
                    "description": "Swagger UI location",
                    "schema": { "type": "string", "example": "/swagger-ui/" }
                }
            }
        }
    })
}

fn path_string(name: &str, description: &str) -> Value {
    json!({
        "name": name,
        "in": "path",
        "required": true,
        "description": description,
        "schema": { "type": "string" }
    })
}

fn query_string(name: &str, description: &str) -> Value {
    query_param(name, description, false, json!({ "type": "string" }))
}

fn query_required_string(name: &str, description: &str) -> Value {
    query_param(name, description, true, json!({ "type": "string" }))
}

fn query_bool(name: &str, description: &str) -> Value {
    query_param(name, description, false, json!({ "type": "boolean" }))
}

fn query_integer(name: &str, description: &str) -> Value {
    query_param(name, description, false, json!({ "type": "integer" }))
}

fn query_param(name: &str, description: &str, required: bool, schema: Value) -> Value {
    json!({
        "name": name,
        "in": "query",
        "required": required,
        "description": description,
        "schema": schema
    })
}

fn array_schema(item_schema: Value) -> Value {
    json!({ "type": "array", "items": item_schema })
}

fn ref_schema(name: &str) -> Value {
    json!({ "$ref": format!("#/components/schemas/{name}") })
}

fn object_schema() -> Value {
    json!({ "type": "object", "additionalProperties": true })
}

fn portfolio_asset_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "canonicalTokenIdHex", "wrapperIdHex", "wrappedMarketIdHex",
            "nativeBalance", "orderbookBalance", "totalBalance",
            "assetUtxoCount", "openAskAmount", "openBidAmount", "openOrderCount",
            "bestAskUnitPriceSompi", "bestBidUnitPriceSompi", "valueSompi",
            "feeTicketSupported", "lastChangeMs", "ticker", "tokenName",
            "decimals", "actions"
        ],
        "properties": {
            "canonicalTokenIdHex": { "type": "string" },
            "wrapperIdHex": { "type": ["string", "null"] },
            "wrappedMarketIdHex": { "type": ["string", "null"] },
            "nativeBalance": { "type": "string", "pattern": "^[0-9]+$" },
            "orderbookBalance": { "type": "string", "pattern": "^[0-9]+$" },
            "totalBalance": { "type": "string", "pattern": "^[0-9]+$" },
            "assetUtxoCount": { "type": "integer", "format": "int64" },
            "openAskAmount": { "type": "string", "pattern": "^[0-9]+$" },
            "openBidAmount": { "type": "string", "pattern": "^[0-9]+$" },
            "openOrderCount": { "type": "integer", "format": "int64" },
            "bestAskUnitPriceSompi": { "type": ["string", "null"], "pattern": "^[0-9]+$" },
            "bestBidUnitPriceSompi": { "type": ["string", "null"], "pattern": "^[0-9]+$" },
            "valueSompi": { "type": ["string", "null"], "pattern": "^[0-9]+$" },
            "feeTicketSupported": { "type": "boolean" },
            "lastChangeMs": { "type": "integer", "format": "int64" },
            "ticker": { "type": ["string", "null"] },
            "tokenName": { "type": ["string", "null"] },
            "decimals": { "type": "integer", "minimum": 0, "maximum": 8 },
            "actions": {
                "type": "object",
                "required": ["wrap", "unwrap", "trade"],
                "properties": {
                    "wrap": portfolio_asset_action_schema(),
                    "unwrap": portfolio_asset_action_schema(),
                    "trade": portfolio_asset_action_schema()
                }
            }
        }
    })
}

fn portfolio_asset_action_schema() -> Value {
    json!({
        "type": "object",
        "required": ["enabled", "reason"],
        "properties": {
            "enabled": { "type": "boolean" },
            "reason": { "type": ["string", "null"] }
        }
    })
}

fn payment_info(pricing_id: &str, route: &str, methods: &[&str]) -> Value {
    json!({
        "required": true,
        "pricingId": pricing_id,
        "route": route,
        "methods": methods,
        "authorizationScheme": "Payment",
        "challengeEndpoint": "/payments/challenges",
        "pricingEndpoint": "/payments/pricing",
        "receiptHeader": "Payment-Receipt",
        "runtimeChallengeAuthoritative": true,
        "notes": [
            "Runtime 402 challenges are authoritative over static discovery metadata.",
            "The listed methods are accepted credentials for the protected API route; direct-payment proof submission is exposed separately."
        ]
    })
}

fn add_operation_ids(spec: &mut Value) {
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    for (path, methods) in paths {
        let Some(methods) = methods.as_object_mut() else {
            continue;
        };
        for (method, operation) in methods {
            let Some(operation) = operation.as_object_mut() else {
                continue;
            };
            operation
                .entry("operationId")
                .or_insert_with(|| Value::String(operation_id(method, path)));
        }
    }
}

fn operation_id(method: &str, path: &str) -> String {
    let mut id = method.to_ascii_lowercase();
    for segment in path.trim_matches('/').split('/') {
        if segment.is_empty() {
            continue;
        }
        for part in segment
            .trim_matches(|ch| ch == '{' || ch == '}')
            .split(|ch: char| !ch.is_ascii_alphanumeric())
        {
            if part.is_empty() {
                continue;
            }
            let mut chars = part.chars();
            if let Some(first) = chars.next() {
                id.push(first.to_ascii_uppercase());
                id.push_str(chars.as_str());
            }
        }
    }
    if path.ends_with('/') && path != "/" {
        id.push_str("Index");
    }
    id
}

#[cfg(test)]
mod tests {
    use super::spec;
    use crate::api_payments::{
        API_PAYMENT_PROOF_BODY_ECHO_PRICING_ID, API_PAYMENT_PROOF_BODY_ECHO_ROUTE,
        API_PAYMENT_PROOF_DISCOVERY_PRICING_ID, API_PAYMENT_PROOF_DISCOVERY_ROUTE,
    };

    #[test]
    fn openapi_spec_exposes_public_routes() {
        let spec = spec();
        assert_eq!(spec["openapi"], "3.1.0");
        let paths = spec["paths"].as_object().expect("paths object");
        for path in [
            "/openapi.json",
            "/swagger-ui",
            "/swagger-ui/",
            "/swagger",
            "/docs",
            "/livez",
            "/readyz",
            "/health",
            "/health/live",
            "/health/history",
            "/metrics",
            "/explorer/summary",
            "/explorer/search",
            "/payments/pricing",
            "/payments/metrics",
            "/payments/debug",
            "/payments/challenges",
            "/payments/direct-proofs",
            "/payments/direct-proofs/{txid}",
            "/payments/direct-proofs/{txid}/verify",
            "/payments/receipts/{receiptId}",
            "/payments/channels/{channelId}",
            "/payments/channels/{channelId}/sync",
            "/payments/channels/{channelId}/close",
            "/payments/settlements/{txid}",
            "/snapshot",
            "/utxos",
            "/covenant-templates",
            "/covenants",
            "/covenants/by-id/{covenant_id}",
            "/covenants/by-id/{covenant_id}/actions",
            "/covenants/by-id/{covenant_id}/utxos",
            "/covenants/{covenant_id_or_script_hash}",
            "/covenants/{covenant_id_or_script_hash}/actions",
            "/covenants/{covenant_id_or_script_hash}/utxos",
            "/addresses/{address}/covenants",
            "/addresses/{address}/utxos",
            "/addresses/{address}/events",
            "/fomo/rounds",
            "/fomo/rounds/{covenant_id}",
            "/kcom/campaigns/{graph_id}",
            "/kcom/campaigns/{graph_id}/participants/{authority}",
            "/kcc20/wrappers",
            "/kcc20/wrappers/by-canonical/{covenant_id}",
            "/kcc20/fee-markets/by-canonical/{covenant_id}",
            "/kcc20/snapshot/controllers/{controller_id}/claims/{token_id}",
            "/kcc20/{covenant_id}/summary",
            "/kcc20/{covenant_id}/holders",
            "/kcc20/{covenant_id}/utxos",
            "/kcc20/{covenant_id}/orderbook",
            "/kcc20/discovery",
            "/kcc20/freshness",
            "/kcc20/markets",
            "/kcc20/market-snapshots",
            "/payments/proof/kcc20-discovery",
            "/payments/proof/body-echo",
            "/kcc20/{covenant_id}/activity",
            "/kcc20/{covenant_id}/quote",
            "/kcc20/{covenant_id}/stats",
            "/kcc20/{covenant_id}/candles",
            "/kcc20/{covenant_id}/listings",
            "/kcc20/{covenant_id}/bids",
            "/kcc20/{covenant_id}/orders/{order_id}",
            "/kcc20/listings",
            "/kcc20/bids",
            "/kcc20/{covenant_id}/trades",
            "/addresses/{address}/kcc20/orders",
            "/addresses/{address}/kcc20/balances",
            "/addresses/{address}/kcc20/portfolio",
            "/addresses/{address}/kcc20/portfolio-assets",
            "/addresses/{address}/kcc20/trades",
            "/addresses/{address}/kcc20/actions",
            "/tx/{txid}/settlement-status",
            "/events",
            "/tx/{txid}",
            "/tx/{txid}/sync",
        ] {
            assert!(paths.contains_key(path), "missing {path}");
        }
    }

    #[test]
    fn openapi_spec_assigns_unique_operation_ids() {
        let spec = spec();
        let paths = spec["paths"].as_object().expect("paths object");
        let mut seen = std::collections::HashSet::new();
        for (path, methods) in paths {
            let methods = methods.as_object().expect("path item object");
            for (method, operation) in methods {
                let operation_id = operation["operationId"]
                    .as_str()
                    .unwrap_or_else(|| panic!("missing operationId for {method} {path}"));
                assert!(
                    seen.insert(operation_id.to_string()),
                    "duplicate operationId {operation_id}"
                );
            }
        }
    }

    #[test]
    fn openapi_spec_documents_covenant_total_count_header() {
        let spec = spec();
        for path in [
            "/covenants",
            "/covenants/{covenant_id_or_script_hash}",
            "/covenants/{covenant_id_or_script_hash}/actions",
            "/covenants/{covenant_id_or_script_hash}/utxos",
            "/addresses/{address}/covenants",
            "/addresses/{address}/utxos",
            "/kcc20/{covenant_id}/holders",
            "/kcc20/{covenant_id}/utxos",
            "/kcc20/wrappers",
            "/kcc20/wrappers/by-canonical/{covenant_id}",
            "/addresses/{address}/kcc20/balances",
        ] {
            let header =
                &spec["paths"][path]["get"]["responses"]["200"]["headers"]["X-Total-Count"];
            assert_eq!(
                header["required"], true,
                "missing required header on {path}"
            );
            assert_eq!(header["schema"]["type"], "integer");
            assert_eq!(header["schema"]["format"], "int64");
        }
    }

    #[test]
    fn openapi_spec_documents_kcc20_query_parameters() {
        let spec = spec();
        let paths = spec["paths"].as_object().expect("paths object");
        assert_query_params(
            paths,
            "/kcc20/wrappers",
            &["include_pending", "includePending", "limit", "offset"],
        );
        assert_query_params(
            paths,
            "/kcc20/wrappers/by-canonical/{covenant_id}",
            &["include_pending", "includePending", "limit", "offset"],
        );
        assert_query_params(paths, "/kcc20/markets", &["limit", "offset"]);
        assert_query_params(paths, "/kcc20/{covenant_id}/holders", &["limit", "offset"]);
        assert_query_params(
            paths,
            "/kcc20/{covenant_id}/utxos",
            &[
                "limit",
                "offset",
                "address",
                "ownerIdentifier",
                "stateMode",
                "stateNull",
            ],
        );
        assert_query_params(
            paths,
            "/kcc20/{covenant_id}/orderbook",
            &["status", "sort", "limit", "offset", "depthLimit"],
        );
        assert_query_params(
            paths,
            "/kcc20/{covenant_id}/listings",
            &["status", "sort", "limit", "offset"],
        );
        assert_query_params(
            paths,
            "/kcc20/{covenant_id}/bids",
            &["status", "sort", "limit", "offset"],
        );
        assert_query_params(
            paths,
            "/kcc20/discovery",
            &[
                "tokenId",
                "sortBy",
                "sortDirection",
                "limit",
                "offset",
                "includeTotal",
            ],
        );
        assert_query_params(
            paths,
            "/addresses/{address}/kcc20/balances",
            &["limit", "offset"],
        );
        assert_query_params(
            paths,
            "/addresses/{address}/kcc20/portfolio-assets",
            &[
                "limit",
                "offset",
                "sortBy",
                "sortDirection",
                "tokenId",
                "search",
                "hasNativeBalance",
                "hasOrderbookBalance",
                "hasOpenOrders",
            ],
        );
    }

    fn assert_query_params(
        paths: &serde_json::Map<String, serde_json::Value>,
        path: &str,
        expected: &[&str],
    ) {
        let params = paths[path]["get"]["parameters"]
            .as_array()
            .unwrap_or_else(|| panic!("{path} should expose parameters"));
        let names: std::collections::HashSet<_> = params
            .iter()
            .filter(|param| param["in"] == "query")
            .filter_map(|param| param["name"].as_str())
            .collect();
        for expected in expected {
            assert!(
                names.contains(expected),
                "missing {path} query param {expected}"
            );
        }
    }

    #[test]
    fn openapi_spec_exposes_payment_info_for_paid_discovery_route() {
        let spec = spec();
        assert!(spec["paths"]["/kcc20/discovery"]["get"]
            .get("x-payment-info")
            .is_none());
        let payment = &spec["paths"]["/payments/proof/kcc20-discovery"]["get"]["x-payment-info"];
        assert_eq!(payment["required"], true);
        assert_eq!(payment["pricingId"], API_PAYMENT_PROOF_DISCOVERY_PRICING_ID);
        assert_eq!(payment["route"], API_PAYMENT_PROOF_DISCOVERY_ROUTE);
        assert_eq!(payment["methods"], serde_json::json!(["kaspa-channel"]));
        assert_eq!(payment["authorizationScheme"], "Payment");
        assert_eq!(payment["challengeEndpoint"], "/payments/challenges");
        assert_eq!(payment["pricingEndpoint"], "/payments/pricing");
        assert_eq!(payment["receiptHeader"], "Payment-Receipt");
        assert_eq!(payment["runtimeChallengeAuthoritative"], true);

        let body_echo_payment =
            &spec["paths"]["/payments/proof/body-echo"]["post"]["x-payment-info"];
        assert_eq!(
            body_echo_payment["pricingId"],
            API_PAYMENT_PROOF_BODY_ECHO_PRICING_ID
        );
        assert_eq!(
            body_echo_payment["route"],
            API_PAYMENT_PROOF_BODY_ECHO_ROUTE
        );
        assert_eq!(
            body_echo_payment["methods"],
            serde_json::json!(["kaspa-channel"])
        );
    }
}

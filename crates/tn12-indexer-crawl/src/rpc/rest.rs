use anyhow::{Context, Result};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::time::Duration;

use tn12_indexer_core::{p2sh_script_hash, RestCovenantBinding, RestTransaction};
mod acceptance;
mod acceptance_map;

#[derive(Debug, Clone, thiserror::Error)]
#[error("transaction {txid} unavailable from {endpoint}")]
pub(crate) struct MissingTransaction {
    pub txid: String,
    pub endpoint: String,
}

#[derive(Debug, thiserror::Error)]
#[error("REST {url} returned {status}")]
pub(crate) struct RestStatusError {
    pub status: StatusCode,
    url: String,
}

pub(crate) fn retryable_status(status: StatusCode) -> bool {
    status.is_server_error() || matches!(status, StatusCode::TOO_MANY_REQUESTS | StatusCode::REQUEST_TIMEOUT)
}

fn require_success(status: StatusCode, url: &str) -> Result<()> {
    if !status.is_success() {
        return Err(RestStatusError { status, url: url.to_owned() }.into());
    }
    Ok(())
}

// Dense DAG scores can exceed 4 MiB. Keep full-block hydration bounded while
// avoiding thousands of individual transaction lookups for ordinary history.
const MAX_FULL_BLOCK_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const METADATA_SEARCH_BATCH_SIZE: usize = 1_000;

fn append_full_block_chunk(body: &mut Vec<u8>, chunk: &[u8], blue_score: u64) -> Result<()> {
    if body.len().saturating_add(chunk.len()) > MAX_FULL_BLOCK_RESPONSE_BYTES {
        anyhow::bail!(
            "full block response at blue score {blue_score} exceeds {} bytes",
            MAX_FULL_BLOCK_RESPONSE_BYTES
        );
    }
    body.extend_from_slice(chunk);
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct BlockOutputMetadata {
    pub amount: u64,
    pub script_public_key: String,
    pub covenant: Option<RestCovenantBinding>,
}

#[derive(Debug, Clone)]
pub(crate) struct BlockTxMetadata {
    pub transaction_id: String,
    pub payload: Option<String>,
    pub version: u32,
    pub outputs: Vec<BlockOutputMetadata>,
}

#[derive(Deserialize)]
struct FullBlock {
    #[serde(default)]
    transactions: Vec<FullBlockTx>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullBlockTx {
    verbose_data: Option<FullBlockTxVerbose>,
    payload: Option<String>,
    version: u32,
    #[serde(default)]
    outputs: Vec<FullBlockOutput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullBlockTxVerbose {
    transaction_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullBlockOutput {
    amount: u64,
    script_public_key: FullBlockScriptPublicKey,
    covenant: Option<RestCovenantBinding>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullBlockScriptPublicKey {
    script_public_key: String,
}

#[derive(Deserialize)]
struct SearchTxMetadata {
    transaction_id: String,
    version: u32,
    // An omitted field is incomplete metadata; an explicit null is an empty payload.
    #[serde(deserialize_with = "Option::<String>::deserialize")]
    payload: Option<String>,
    outputs: Vec<SearchOutputMetadata>,
}

#[derive(Deserialize)]
struct SearchOutputMetadata {
    index: u64,
    #[serde(flatten)]
    output: tn12_indexer_core::RestTxOutput,
}

fn parse_search_metadata(body: &[u8], wanted_txids: &[String]) -> Result<Vec<BlockTxMetadata>> {
    let rows: Vec<SearchTxMetadata> =
        serde_json::from_slice(body).context("parsing transaction search metadata")?;
    let wanted: BTreeSet<_> = wanted_txids.iter().map(String::as_str).collect();
    let mut seen = BTreeSet::new();
    let mut metadata = Vec::new();
    for mut row in rows {
        if !wanted.contains(row.transaction_id.as_str()) {
            continue;
        }
        anyhow::ensure!(
            seen.insert(row.transaction_id.clone()),
            "duplicate transaction search result"
        );
        row.outputs.sort_by_key(|output| output.index);
        for (index, output) in row.outputs.iter().enumerate() {
            anyhow::ensure!(
                output.index == index as u64
                    && (output.output.transaction_id.is_empty()
                        || output.output.transaction_id == row.transaction_id),
                "invalid transaction search output position or owner"
            );
        }
        metadata.push(BlockTxMetadata {
            transaction_id: row.transaction_id,
            payload: row.payload,
            version: row.version,
            outputs: row
                .outputs
                .into_iter()
                .map(|output| BlockOutputMetadata {
                    amount: output.output.amount,
                    script_public_key: output.output.script_public_key,
                    covenant: output.output.covenant,
                })
                .collect(),
        });
    }
    Ok(metadata)
}

#[derive(Debug, thiserror::Error)]
enum TransactionFetchError {
    #[error("REST {url} returned 404 Not Found: {body}")]
    NotFound { url: String, body: String },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Shared across every parent body in one dependency-resolution attempt.
#[derive(Default)]
pub(crate) struct ParentResponseBudget(std::sync::atomic::AtomicUsize);
impl ParentResponseBudget {
    pub(crate) fn charge(&self, bytes: usize) -> Result<()> {
        use std::sync::atomic::Ordering;
        self.0.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
            used.checked_add(bytes).filter(|total| *total <= MAX_FULL_BLOCK_RESPONSE_BYTES)
         }).map_err(|used| crate::recovery_policy::RecoveryCapacity {
            dimension: "dependency_response_bytes",
            observed: used.saturating_add(bytes),
            limit: MAX_FULL_BLOCK_RESPONSE_BYTES,
        })?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RestClient {
    base_url: String,
    fallback_base_urls: Vec<String>,
    http: Client,
    allow_degraded_snapshot: bool,
    pub(crate) canonical_verifier: Option<std::sync::Arc<dyn crate::rest_replay_fence::CanonicalVerifier>>,
}

impl RestClient {
    /// Orphan headers may never reach REST. Only recovery may use the owned
    /// synced node for this immutable identity/canonicality evidence; REST
    /// transaction windows and acceptance-set completeness remain mandatory.
    pub(crate) async fn recovery_block_evidence(&self,hash:&str) -> Result<tn12_indexer_db::persist::AcceptingBlockEvidence> {
        match self.accepting_block_evidence(hash).await {
            Ok(block)=>Ok(block),
            Err(error) if error.downcast_ref::<RestStatusError>().is_some_and(|e|e.status==reqwest::StatusCode::NOT_FOUND)=>{
                let verifier=self.canonical_verifier.as_ref().ok_or_else(||
                    crate::live_supervisor::RecoveryPending("orphan block requires node evidence"))?;
                let expected=hex::decode(hash)?;
                let block=verifier.block_evidence(&expected).await.map_err(|error|
                    anyhow::Error::new(crate::live_supervisor::RecoveryPending("orphan node evidence unavailable"))
                        .context(format!("node orphan evidence: {error:#}")))?;
                anyhow::ensure!(block.hash==expected,"orphan node block identity mismatch");
                Ok(block)
            }
            Err(error)=>Err(error),
        }
    }
    pub(crate) async fn event_block_coordinates(&self, hashes:&[String]) -> Result<Vec<(Vec<u8>,u64)>> {
        let verifier=self.canonical_verifier.as_ref().ok_or_else(||
            crate::live_supervisor::RecoveryPending("event metadata requires the configured node"))?;
        let encoded=hashes.iter().map(hex::decode).collect::<std::result::Result<Vec<_>,_>>()?;
        verifier.coordinates(&encoded).await.map_err(|error|
            anyhow::Error::new(crate::live_supervisor::RecoveryPending("node event metadata unavailable"))
                .context(format!("immutable node coordinates: {error:#}")))
    }
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let timeout_secs = std::env::var("KASPA_REST_HTTP_TIMEOUT_SECS")
            .ok()
            .map(|raw| {
                let seconds = raw
                    .parse::<u64>()
                    .context("KASPA_REST_HTTP_TIMEOUT_SECS must be an integer")?;
                anyhow::ensure!(
                    (20..=120).contains(&seconds),
                    "KASPA_REST_HTTP_TIMEOUT_SECS must be between 20 and 120"
                );
                Ok::<_, anyhow::Error>(seconds)
            })
            .transpose()?
            .unwrap_or(20);
        let http = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent("tn12-indexer/0.1")
            .build()
            .context("building reqwest client")?;
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let fallback_base_urls = std::env::var("KASPA_REST_FALLBACK_URLS")
            .ok()
            .map(parse_fallback_urls)
            .unwrap_or_default()
            .into_iter()
            .filter(|url| url != &base_url)
            .collect();
        Ok(Self {
            base_url,
            fallback_base_urls,
            http,
            allow_degraded_snapshot: false,
            canonical_verifier: crate::rest_replay_fence::configured_verifier()?,
        })
    }

    /// Only for a frozen historical source with a separately verified score
    /// boundary. Current REST sources must report a synced database.
    pub fn allow_degraded_snapshot(mut self) -> Self {
        self.allow_degraded_snapshot = true;
        self
    }

    pub(crate) async fn ensure_current_database_synced(&self) -> Result<()> {
        if !self.allow_degraded_snapshot {
            self.get_rest_database_blue_score().await?;
        }
        Ok(())
    }

    pub fn with_fallback_urls(mut self, fallback_urls: impl IntoIterator<Item = String>) -> Self {
        self.fallback_base_urls = fallback_urls
            .into_iter()
            .map(|url| url.trim().trim_end_matches('/').to_string())
            .filter(|url| !url.is_empty() && url != &self.base_url)
            .collect();
        self
    }

    /// Full block bodies contain payloads and native covenant bindings. A
    /// single blue score can contain several DAG blocks, so keep all of them.
    pub(crate) async fn get_block_transaction_metadata(
        &self,
        blue_score: u64,
        wanted_txids: &BTreeSet<String>,
    ) -> Result<Vec<BlockTxMetadata>> {
        let url = format!(
            "{}/blocks-from-bluescore?blueScore={blue_score}&includeTransactions=true",
            self.base_url
        );
        let mut response = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = response.status();
        require_success(status, &url)?;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("reading full block response")?
        {
            append_full_block_chunk(&mut body, &chunk, blue_score)?;
        }
        let blocks: Vec<FullBlock> = serde_json::from_slice(&body)
            .with_context(|| format!("parsing full blocks at blue score {blue_score}"))?;
        Ok(blocks
            .into_iter()
            .flat_map(|block| block.transactions)
            .filter_map(|tx| {
                let transaction_id = tx.verbose_data?.transaction_id;
                if !wanted_txids.contains(&transaction_id) {
                    return None;
                }
                Some(BlockTxMetadata {
                    transaction_id,
                    payload: tx.payload,
                    version: tx.version,
                    outputs: tx
                        .outputs
                        .into_iter()
                        .map(|output| BlockOutputMetadata {
                            amount: output.amount,
                            script_public_key: output.script_public_key.script_public_key,
                            covenant: output.covenant,
                        })
                        .collect(),
                })
            })
            .collect())
    }

    /// Read-only search returns metadata for exactly the requested transaction
    /// IDs, without downloading unrelated DAG transactions or input scripts.
    pub(crate) async fn search_transaction_metadata(
        &self,
        txids: &[String],
    ) -> Result<Vec<BlockTxMetadata>> {
        anyhow::ensure!(
            txids.len() <= METADATA_SEARCH_BATCH_SIZE,
            "transaction metadata batch exceeds limit"
        );
        if txids.is_empty() {
            return Ok(Vec::new());
        }
        let url = format!("{}/transactions/search", self.base_url);
        let mut response = self
            .http
            .post(&url)
            .query(&[("fields", "transaction_id,version,payload,outputs")])
            .json(&serde_json::json!({"transactionIds": txids}))
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        require_success(response.status(), &url)?;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("reading transaction search metadata")?
        {
            anyhow::ensure!(
                body.len().saturating_add(chunk.len()) <= MAX_FULL_BLOCK_RESPONSE_BYTES,
                "transaction search response exceeds {} bytes",
                MAX_FULL_BLOCK_RESPONSE_BYTES
            );
            body.extend_from_slice(&chunk);
        }
        parse_search_metadata(&body, txids)
    }

    /// Recovery must distinguish explicit rejection from omitted acceptance fields.
    pub async fn get_transaction_with_explicit_acceptance(
        &self,
        txid: &str,
    ) -> Result<RestTransaction> {
        // Acceptance is mutable across reorgs, even though transaction bytes
        // are immutable. A cached response cannot revalidate a recovery step.
        self.get_fresh_acceptance_transaction(txid).await
    }

    pub(crate) async fn get_transaction_with_budget(
        &self, txid: &str, budget: &ParentResponseBudget,
    ) -> Result<RestTransaction> {
        self.get_acceptance_transaction(txid, budget, false).await
    }

    async fn get_fresh_acceptance_transaction(&self, txid: &str) -> Result<RestTransaction> {
        self.get_acceptance_transaction(txid, &ParentResponseBudget::default(), true).await
    }

    async fn get_acceptance_transaction(
        &self, txid: &str, budget: &ParentResponseBudget, fresh: bool,
    ) -> Result<RestTransaction> {
        let url = format!(
            "{}/transactions/{txid}?inputs=true&outputs=true&resolve_previous_outpoints=light",
            self.base_url
        );
        let mut request = self.http.get(&url).timeout(Duration::from_secs(30));
        if fresh {
            request = request.header(reqwest::header::CACHE_CONTROL, "no-cache, no-store, max-age=0")
                .header(reqwest::header::PRAGMA, "no-cache")
                .query(&[("source_observation", chrono::Utc::now().timestamp_millis().to_string())]);
        }
        let mut response = request.send().await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(anyhow::Error::new(crate::live_supervisor::RecoveryPending("required transaction is not published yet"))
                .context(MissingTransaction { txid:txid.to_owned(), endpoint:self.base_url.clone() }));
        }
        require_success(response.status(), &url)?;
        if fresh {
            crate::source_observation::validate_health_headers(
                response.headers(), chrono::Utc::now().timestamp_millis(),
            ).context("stale deferred transaction acceptance evidence")?;
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            budget.charge(chunk.len())?;
            body.extend_from_slice(&chunk);
        }
        let value: serde_json::Value = serde_json::from_slice(&body)?;
        let accepted = value
            .get("is_accepted")
            .and_then(serde_json::Value::as_bool)
            .ok_or(crate::live_supervisor::RecoveryPending("repair source omitted explicit acceptance state"))?;
        if accepted {
            anyhow::ensure!(
                value
                    .get("accepting_block_hash")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|hash| hash.len() == 64 && hex::decode(hash).is_ok())
                    && value
                        .get("accepting_block_blue_score")
                        .and_then(serde_json::Value::as_u64)
                        .is_some(),
                crate::live_supervisor::RecoveryPending("repair source omitted canonical acceptance coordinates")
            );
        }
        let tx: RestTransaction = serde_json::from_value(value)?;
        anyhow::ensure!(
            tx.transaction_id == txid,
            crate::recovery_policy::RecoveryBlocked("source_identity_mismatch")
        );
        Ok(tx)
    }

    /// GET /transactions/{txid}?inputs=true&outputs=true&resolve_previous_outpoints=light
    pub async fn get_transaction(&self, txid: &str) -> Result<RestTransaction> {
        self.find_transaction(txid).await?.ok_or_else(|| {
            anyhow::anyhow!(
                "REST transaction lookup returned 404 for {txid} across all configured endpoints"
            )
        })
    }

    /// Returns `Ok(None)` only when every configured REST endpoint reports 404.
    /// Transport failures and mixed 404/upstream failures remain errors.
    pub async fn find_transaction(&self, txid: &str) -> Result<Option<RestTransaction>> {
        let mut errors = Vec::new();
        let mut all_not_found = true;
        let mut best_incomplete: Option<(RestTransaction, NativeBindingStats, String)> = None;
        for (attempt, base_url) in std::iter::once(&self.base_url)
            .chain(self.fallback_base_urls.iter())
            .enumerate()
        {
            match self.get_transaction_from(base_url, txid).await {
                Ok(tx) => {
                    let stats = native_binding_stats(&tx);
                    if attempt > 0 {
                        tracing::info!(
                            txid,
                            rest_url = %base_url,
                            "REST fallback transaction lookup succeeded"
                        );
                    }
                    if !stats.needs_better_source() {
                        return Ok(Some(tx));
                    }
                    if has_more_native_bindings(&stats, best_incomplete.as_ref().map(|(_, s, _)| s))
                    {
                        best_incomplete = Some((tx, stats, base_url.clone()));
                    }
                    if attempt == 0 && !self.fallback_base_urls.is_empty() {
                        tracing::warn!(
                            txid,
                            primary_rest_url = %self.base_url,
                            fallback_count = self.fallback_base_urls.len(),
                            p2sh_outputs = stats.p2sh_outputs,
                            complete_native_bindings = stats.complete_native_bindings,
                            incomplete_native_bindings = stats.incomplete_native_bindings,
                            "primary REST transaction response lacks native covenant bindings; trying fallback REST endpoints"
                        );
                    }
                }
                Err(error) => {
                    if !matches!(&error, TransactionFetchError::NotFound { .. }) {
                        all_not_found = false;
                    }
                    if attempt == 0 && !self.fallback_base_urls.is_empty() {
                        tracing::warn!(
                            txid,
                            primary_rest_url = %self.base_url,
                            fallback_count = self.fallback_base_urls.len(),
                            error = %error,
                            "primary REST transaction lookup failed; trying fallback REST endpoints"
                        );
                    }
                    errors.push(error.to_string());
                }
            }
        }
        if let Some((tx, stats, rest_url)) = best_incomplete {
            tracing::warn!(
                txid,
                rest_url = %rest_url,
                p2sh_outputs = stats.p2sh_outputs,
                complete_native_bindings = stats.complete_native_bindings,
                incomplete_native_bindings = stats.incomplete_native_bindings,
                "returning best REST transaction response despite incomplete native covenant bindings"
            );
            return Ok(Some(tx));
        }
        if all_not_found {
            return Ok(None);
        }
        anyhow::bail!(
            "REST transaction lookup failed for {txid} across {} endpoint(s): {}",
            1 + self.fallback_base_urls.len(),
            errors.join(" | ")
        )
    }

    async fn get_transaction_from(
        &self,
        base_url: &str,
        txid: &str,
    ) -> std::result::Result<RestTransaction, TransactionFetchError> {
        let url = format!(
            "{base_url}/transactions/{txid}?inputs=true&outputs=true&resolve_previous_outpoints=light",
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))
            .map_err(TransactionFetchError::Other)?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .context("reading body")
            .map_err(TransactionFetchError::Other)?;
        if status == StatusCode::NOT_FOUND {
            return Err(TransactionFetchError::NotFound { url, body });
        }
        require_success(status, &url).map_err(TransactionFetchError::Other)?;
        serde_json::from_str(&body)
            .with_context(|| format!("parsing REST tx {txid}"))
            .map_err(TransactionFetchError::Other)
    }

    /// GET /addresses/{address}/full-transactions?limit=N&offset=O
    /// Returns the full `RestTransaction` shape (`transaction_id`, `is_accepted`,
    /// `inputs`, `outputs`, `accepting_block_hash`, …) for every accepted tx
    /// that touched this address, ordered newest first by `accepting_block_time`.
    pub async fn get_address_full_transactions(
        &self,
        address: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<RestTransaction>> {
        let mut errors = Vec::new();
        let mut best_incomplete: Option<(Vec<RestTransaction>, NativeBindingStats, String)> = None;
        for (attempt, base_url) in std::iter::once(&self.base_url)
            .chain(self.fallback_base_urls.iter())
            .enumerate()
        {
            match self
                .get_address_full_transactions_from(base_url, address, limit, offset)
                .await
            {
                Ok(txs) => {
                    let stats = native_binding_stats_for_transactions(&txs);
                    if !stats.needs_better_source() {
                        return Ok(txs);
                    }
                    if has_more_native_bindings(&stats, best_incomplete.as_ref().map(|(_, s, _)| s))
                    {
                        best_incomplete = Some((txs, stats, base_url.clone()));
                    }
                    if attempt == 0 && !self.fallback_base_urls.is_empty() {
                        tracing::warn!(
                            address,
                            primary_rest_url = %self.base_url,
                            fallback_count = self.fallback_base_urls.len(),
                            p2sh_outputs = stats.p2sh_outputs,
                            complete_native_bindings = stats.complete_native_bindings,
                            incomplete_native_bindings = stats.incomplete_native_bindings,
                            "primary REST address response lacks native covenant bindings; trying fallback REST endpoints"
                        );
                    }
                }
                Err(error) => {
                    if attempt == 0 && !self.fallback_base_urls.is_empty() {
                        tracing::warn!(
                            address,
                            primary_rest_url = %self.base_url,
                            fallback_count = self.fallback_base_urls.len(),
                            error = %error,
                            "primary REST address lookup failed; trying fallback REST endpoints"
                        );
                    }
                    errors.push(error.to_string());
                }
            }
        }
        if let Some((txs, stats, rest_url)) = best_incomplete {
            tracing::warn!(
                address,
                rest_url = %rest_url,
                p2sh_outputs = stats.p2sh_outputs,
                complete_native_bindings = stats.complete_native_bindings,
                incomplete_native_bindings = stats.incomplete_native_bindings,
                "returning best REST address response despite incomplete native covenant bindings"
            );
            return Ok(txs);
        }
        anyhow::bail!(
            "REST address lookup failed for {address} across {} endpoint(s): {}",
            1 + self.fallback_base_urls.len(),
            errors.join(" | ")
        )
    }

    async fn get_address_full_transactions_from(
        &self,
        base_url: &str,
        address: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<RestTransaction>> {
        let url = format!(
            "{base_url}/addresses/{address}/full-transactions?limit={limit}&offset={offset}&resolve_previous_outpoints=light",
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        let body = resp.text().await.context("reading body")?;
        require_success(status, &url)?;
        serde_json::from_str(&body).with_context(|| format!("parsing address txs {address}"))
    }

    /// GET /virtual-chain?blueScoreGte=N&limit=L&resolveInputs=true
    ///
    /// Returns up to `limit` *chain* blocks with blue score ≥ N, each carrying
    /// its full accepted-tx list (inputs + outputs inline). Way more efficient
    /// than /blocks-from-bluescore for a backlog sweep: 100 chain blocks per
    /// HTTP call instead of one per discrete blue-score value.
    ///
    /// `resolveInputs=true` populates each input's `previous_outpoint_script`
    /// so the scanner can detect spends of P2SH covenants (txs that consume a
    /// covenant UTXO but produce no new P2SH output, e.g. final-withdraw
    /// spends). Without it the scanner only sees deploys and the decoder
    /// pipeline never runs on the spend that reveals the redeem script.
    ///
    /// Caveat: `blue_score_gte` must be divisible by `limit` per the API's
    /// contract. Callers should round down.
    pub async fn get_virtual_chain(
        &self,
        blue_score_gte: u64,
        limit: u32,
    ) -> Result<Vec<tn12_indexer_core::VirtualChainBlock>> {
        let url = format!(
            "{}/virtual-chain?blueScoreGte={blue_score_gte}&limit={limit}&resolveInputs=true",
            self.base_url
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        let body = resp.text().await.context("reading body")?;
        require_success(status, &url)?;
        serde_json::from_str(&body)
            .with_context(|| format!("parsing /virtual-chain?blueScoreGte={blue_score_gte}"))
    }

    /// Reject an oversized wider page before retaining its body in memory.
    pub async fn get_virtual_chain_bounded(
        &self,
        blue_score_gte: u64,
        limit: u32,
        max_bytes: usize,
    ) -> Result<Vec<tn12_indexer_core::VirtualChainBlock>> {
        let url = format!(
            "{}/virtual-chain?blueScoreGte={blue_score_gte}&limit={limit}&resolveInputs=true",
            self.base_url
        );
        let mut response = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = response.status();
        require_success(status, &url)?;
        if response
            .content_length()
            .is_some_and(|size| size > max_bytes as u64)
        {
            anyhow::bail!("REST virtual-chain page at {blue_score_gte} exceeds {max_bytes} bytes");
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("reading virtual-chain page")?
        {
            if body.len().saturating_add(chunk.len()) > max_bytes {
                anyhow::bail!(
                    "REST virtual-chain page at {blue_score_gte} exceeds {max_bytes} bytes"
                );
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).with_context(|| {
            format!("parsing bounded /virtual-chain?blueScoreGte={blue_score_gte}")
        })
    }

    /// GET /info/virtual-chain-blue-score
    pub async fn get_virtual_chain_blue_score(&self) -> Result<u64> {
        let url = format!("{}/info/virtual-chain-blue-score", self.base_url);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        let body = resp.text().await.context("reading body")?;
        require_success(status, &url)?;
        let value: serde_json::Value =
            serde_json::from_str(&body).with_context(|| format!("parsing {url}"))?;
        value
            .get("blueScore")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("missing blueScore in {body}"))
    }

    /// GET /info/health
    ///
    /// This returns the REST index database progress, which can lag the
    /// connected kaspad node. The chain scanner must use this as its effective
    /// tip because `/virtual-chain` cannot serve windows beyond the REST DB
    /// cursor even when `/info/virtual-chain-blue-score` is already higher.
    pub(super) fn source_health_request(&self) -> reqwest::RequestBuilder {
        self.http
            .get(format!("{}/info/health", self.base_url))
            .header(
                reqwest::header::CACHE_CONTROL,
                "no-cache, no-store, max-age=0",
            )
            .header(reqwest::header::PRAGMA, "no-cache")
            .query(&[(
                "source_observation",
                chrono::Utc::now().timestamp_millis().to_string(),
            )])
    }

    async fn fetch_source_health(&self) -> Result<(StatusCode, String)> {
        let url = format!("{}/info/health", self.base_url);
        let resp = self
            .source_health_request()
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        crate::source_observation::validate_health_headers(
            resp.headers(),
            chrono::Utc::now().timestamp_millis(),
        )?;
        let status = resp.status();
        let body = read_observation_body(resp).await?;
        Ok((status, body))
    }

    pub async fn get_rest_database_blue_score(&self) -> Result<u64> {
        let (status, body) = self.fetch_source_health().await?;
        parse_rest_database_blue_score(status, &body, self.allow_degraded_snapshot)
    }

    /// Observe both publication watermarks, including a degraded database.
    /// Network identity is fetched from the same endpoint without cached evidence.
    pub async fn observe_publication(
        &self,
        expected_network: &str,
    ) -> Result<crate::source_observation::RestPublicationObservation> {
        let observed_at_ms = chrono::Utc::now().timestamp_millis();
        let (status, body) = self.fetch_source_health().await?;
        anyhow::ensure!(
            status.is_success() || status == StatusCode::SERVICE_UNAVAILABLE,
            "REST publication observation returned {status}"
        );
        let health: RestHealth = serde_json::from_str(&body)?;
        let network = self
            .http
            .get(format!("{}/info/network", self.base_url))
            .header(
                reqwest::header::CACHE_CONTROL,
                "no-cache, no-store, max-age=0",
            )
            .query(&[("source_observation", observed_at_ms.to_string())])
            .send()
            .await?;
        crate::source_observation::validate_health_headers(
            network.headers(),
            chrono::Utc::now().timestamp_millis(),
        )?;
        let identity: serde_json::Value =
            serde_json::from_str(&read_observation_body(network.error_for_status()?).await?)?;
        let network = identity
            .get("networkName")
            .and_then(|v| v.as_str())
            .context("REST network identity missing")?;
        let network = network.strip_prefix("kaspa-").unwrap_or(network);
        anyhow::ensure!(network == expected_network, "REST source network mismatch");
        Ok(crate::source_observation::RestPublicationObservation {
            endpoint: crate::source_observation::endpoint_identity(&self.base_url)?,
            network: network.to_owned(),
            observed_at_ms,
            database: health.database,
        })
    }
}

const MAX_OBSERVATION_BYTES: usize = 64 * 1024;

async fn read_observation_body(mut response: reqwest::Response) -> Result<String> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        anyhow::ensure!(
            chunk.len() <= MAX_OBSERVATION_BYTES.saturating_sub(bytes.len()),
            "source observation body exceeds 64 KiB"
        );
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).context("source observation is not UTF-8")
}

fn parse_rest_database_blue_score(
    status: StatusCode,
    body: &str,
    allow_degraded_snapshot: bool,
) -> Result<u64> {
    if !status.is_success()
        && !(allow_degraded_snapshot && status == StatusCode::SERVICE_UNAVAILABLE)
    {
        require_success(status, "/info/health")?;
    }
    let value: RestHealth = serde_json::from_str(body)
        .with_context(|| format!("parsing REST health response body: {body}"))?;
    if !allow_degraded_snapshot {
        if value.database.require_current_transactions(chrono::Utc::now().timestamp_millis()).is_err() {
            return Err(crate::live_supervisor::RecoveryPending("REST transaction publication is unavailable or stale").into());
        }
    }
    if status == StatusCode::SERVICE_UNAVAILABLE {
        tracing::warn!(
            blue_score = value.database.blue_score,
            "REST /info/health returned 503 but included database blue score; continuing scanner at REST DB cursor"
        );
    }
    Ok(value.database.blue_score)
}

#[derive(Debug, Default, Clone, Copy)]
struct NativeBindingStats {
    p2sh_outputs: u32,
    complete_native_bindings: u32,
    incomplete_native_bindings: u32,
}

impl NativeBindingStats {
    fn needs_better_source(self) -> bool {
        self.incomplete_native_bindings > 0
    }

    fn merge(&mut self, other: Self) {
        self.p2sh_outputs += other.p2sh_outputs;
        self.complete_native_bindings += other.complete_native_bindings;
        self.incomplete_native_bindings += other.incomplete_native_bindings;
    }
}

fn native_binding_stats_for_transactions(txs: &[RestTransaction]) -> NativeBindingStats {
    txs.iter()
        .fold(NativeBindingStats::default(), |mut acc, tx| {
            acc.merge(native_binding_stats(tx));
            acc
        })
}

/// Version 1 permits unbound P2SH outputs. Accept that absence only when the
/// consensus transaction ID commits to the exact supplied output bindings.
/// REST omits sequence, lock time and gas; zero is a conservative candidate,
/// never an assumption: a mismatch leaves the normal fallback/warning intact.
fn output_bindings_match_transaction_id(tx: &RestTransaction) -> bool {
    use kaspa_consensus_core::tx::{
        CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput,
    };
    (|| -> Option<bool> {
        let version = u16::try_from(tx.version).ok()?;
        if version != 1 {
            return None;
        }
        let inputs = tx
            .inputs
            .iter()
            .map(|input| {
                Some(TransactionInput::new(
                    TransactionOutpoint::new(
                        input.previous_outpoint_hash.parse().ok()?,
                        input.previous_outpoint_index.parse().ok()?,
                    ),
                    vec![],
                    0,
                    0,
                ))
            })
            .collect::<Option<Vec<_>>>()?;
        let outputs = tx
            .outputs
            .iter()
            .enumerate()
            .map(|(index, output)| {
                if output.index != index as u64 {
                    return None;
                }
                let binding = match (
                    output.canonical_covenant_id(),
                    output.covenant_authorizing_input(),
                ) {
                    (None, None) => None,
                    (Some(id), Some(input)) => Some(CovenantBinding::new(input, id.parse().ok()?)),
                    _ => return None,
                };
                Some(TransactionOutput::with_covenant(
                    output.amount,
                    ScriptPublicKey::from_vec(0, hex::decode(&output.script_public_key).ok()?),
                    binding,
                ))
            })
            .collect::<Option<Vec<_>>>()?;
        let reconstructed = Transaction::new(
            version,
            inputs,
            outputs,
            0,
            tx.subnetwork_id.parse().ok()?,
            0,
            hex::decode(tx.payload.as_deref().unwrap_or("")).ok()?,
        );
        Some(
            reconstructed
                .id()
                .to_string()
                .eq_ignore_ascii_case(&tx.transaction_id),
        )
    })()
    .unwrap_or(false)
}

fn native_binding_stats(tx: &RestTransaction) -> NativeBindingStats {
    let mut stats = NativeBindingStats::default();
    if tx.version == 0 {
        return stats;
    }
    for out in &tx.outputs {
        let Ok(spk) = hex::decode(&out.script_public_key) else {
            continue;
        };
        if p2sh_script_hash(&spk).is_none() {
            continue;
        }
        stats.p2sh_outputs += 1;
        if out.canonical_covenant_id().is_some() && out.covenant_authorizing_input().is_some() {
            stats.complete_native_bindings += 1;
        } else {
            stats.incomplete_native_bindings += 1;
        }
    }
    if stats.incomplete_native_bindings > 0 && output_bindings_match_transaction_id(tx) {
        stats.incomplete_native_bindings = 0;
    }
    stats
}

fn has_more_native_bindings(stats: &NativeBindingStats, best: Option<&NativeBindingStats>) -> bool {
    best.is_none_or(|best| {
        stats.complete_native_bindings > best.complete_native_bindings
            || (stats.complete_native_bindings == best.complete_native_bindings
                && stats.incomplete_native_bindings < best.incomplete_native_bindings)
    })
}

fn parse_fallback_urls(raw: String) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .map(|url| url.trim_end_matches('/'))
        .filter(|url| !url.is_empty())
        .map(str::to_string)
        .collect()
}

#[derive(Debug, Deserialize)]
struct RestHealth {
    database: RestHealthDatabase,
}

type RestHealthDatabase = crate::source_observation::RestDatabasePublication;

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn recovery_fetches_retry_temporary_statuses_but_reject_invalid_data() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (status, retry) in [(503,true),(429,true),(408,true),(401,false),(404,false),(200,false)] {
            for route in 0..4 {
                let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address=listener.local_addr().unwrap();
                let server=tokio::spawn(async move {
                    let (mut stream,_)=listener.accept().await.unwrap();
                    let mut request=[0u8;4096];
                    stream.read(&mut request).await.unwrap();
                    // A 200 with malformed JSON is a fatal source contract error.
                    let response=format!("HTTP/1.1 {status} fixture\r\nContent-Length: 7\r\nConnection: close\r\n\r\ninvalid");
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
                let client=RestClient::new(format!("http://{address}")).unwrap();
                let error=match route {
                    0 => client.get_virtual_chain(100,100).await.unwrap_err(),
                    1 => client.get_virtual_chain_bounded(100,100,1024).await.unwrap_err(),
                    2 => client.get_transaction_with_explicit_acceptance(&"11".repeat(32)).await.unwrap_err(),
                    _ => client.accepting_block_evidence(&"11".repeat(32)).await.unwrap_err(),
                };
                assert_eq!(crate::live_supervisor::retry_recovery(&error),retry || (route == 2 && status == 404),"route={route} status={status}: {error:#}");
                assert_eq!(error.downcast_ref::<MissingTransaction>().is_some(), route == 2 && status == 404);
                if let Some(missing) = error.downcast_ref::<MissingTransaction>() {
                    assert_eq!(missing.txid, "11".repeat(32));
                    assert_eq!(missing.endpoint, format!("http://{address}"));
                }
                server.await.unwrap();
            }
        }
    }

    use super::*;

    fn search_row(id: &str) -> serde_json::Value {
        serde_json::json!({
            "transaction_id": id, "version": 0, "payload": null,
            "outputs": [{"index": 0, "amount": 12, "script_public_key": "aa"}]
        })
    }

    #[tokio::test]
    async fn metadata_search_enforces_request_limit_before_network_access() {
        let client = RestClient::new("http://127.0.0.1:1").unwrap();
        assert!(client
            .search_transaction_metadata(&[])
            .await
            .unwrap()
            .is_empty());
        let ids = vec!["a".into(); METADATA_SEARCH_BATCH_SIZE + 1];
        assert!(client
            .search_transaction_metadata(&ids)
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeds limit"));
    }

    #[test]
    fn search_metadata_accepts_empty_payload_and_partial_results() {
        let body = serde_json::to_vec(&vec![search_row("a"), search_row("unrequested")]).unwrap();
        let rows = parse_search_metadata(&body, &["a".into(), "missing".into()]).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].transaction_id, "a");
        assert_eq!(rows[0].version, 0);
        assert!(rows[0].payload.is_none());
    }

    #[test]
    fn search_metadata_requires_explicit_version_payload_and_output_indexes() {
        for field in ["version", "payload", "outputs"] {
            let mut row = search_row("a");
            row.as_object_mut().unwrap().remove(field);
            let body = serde_json::to_vec(&vec![row]).unwrap();
            assert!(
                parse_search_metadata(&body, &["a".into()]).is_err(),
                "{field}"
            );
        }
        let mut row = search_row("a");
        row["outputs"][0].as_object_mut().unwrap().remove("index");
        assert!(
            parse_search_metadata(&serde_json::to_vec(&vec![row]).unwrap(), &["a".into()]).is_err()
        );
    }

    #[test]
    fn search_metadata_sorts_outputs_and_preserves_native_bindings() {
        let mut row = search_row("a");
        row["version"] = serde_json::json!(1);
        row["outputs"] = serde_json::json!([
            {"index": 1, "amount": 24, "script_public_key": "bb"},
            {"index": 0, "amount": 12, "script_public_key": "aa", "covenant_id": "native", "covenant_authorizing_input": 0}
        ]);
        let rows =
            parse_search_metadata(&serde_json::to_vec(&vec![row]).unwrap(), &["a".into()]).unwrap();
        assert_eq!(rows[0].outputs[0].amount, 12);
        assert_eq!(rows[0].outputs[1].amount, 24);
        let binding = rows[0].outputs[0].covenant.as_ref().unwrap();
        assert_eq!(binding.covenant_id.as_deref(), Some("native"));
        assert_eq!(binding.authorizing_input, Some(0));
    }

    #[test]
    fn search_metadata_rejects_duplicate_transactions_and_invalid_output_positions() {
        let body = serde_json::to_vec(&vec![search_row("a"), search_row("a")]).unwrap();
        assert!(parse_search_metadata(&body, &["a".into()]).is_err());
        for outputs in [
            serde_json::json!([{"index": 1, "amount": 12, "script_public_key": "aa"}]),
            serde_json::json!([{"index": 0, "amount": 12, "script_public_key": "aa"}, {"index": 0, "amount": 12, "script_public_key": "aa"}]),
            serde_json::json!([{"index": 0, "transaction_id": "wrong", "amount": 12, "script_public_key": "aa"}]),
        ] {
            let mut row = search_row("a");
            row["outputs"] = outputs;
            assert!(
                parse_search_metadata(&serde_json::to_vec(&vec![row]).unwrap(), &["a".into()])
                    .is_err()
            );
        }
    }

    #[test]
    fn dense_full_block_response_stays_bounded_without_premature_fallback() {
        let mut body = Vec::new();
        let first_chunk = vec![0; 4 * 1024 * 1024];
        let second_chunk = vec![0; 1024 * 1024];

        append_full_block_chunk(&mut body, &first_chunk, 568_816_996).unwrap();
        append_full_block_chunk(&mut body, &second_chunk, 568_816_996).unwrap();
        assert_eq!(body.len(), 5 * 1024 * 1024);

        let oversized_chunk = vec![0; MAX_FULL_BLOCK_RESPONSE_BYTES - body.len() + 1];
        let error = append_full_block_chunk(&mut body, &oversized_chunk, 568_816_996).unwrap_err();
        assert!(error
            .to_string()
            .contains(&format!("exceeds {MAX_FULL_BLOCK_RESPONSE_BYTES} bytes")));
        assert_eq!(body.len(), 5 * 1024 * 1024);
    }

    #[test]
    fn parses_rest_database_blue_score_from_healthy_response() {
        let body = serde_json::json!({"database":{"blueScore":492387040,"isSynced":true,"acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),"acceptedTxBlockTimeDiff":0}}).to_string();

        let score = parse_rest_database_blue_score(StatusCode::OK, &body, false).unwrap();

        assert_eq!(score, 492387040);
    }

    #[test]
    fn permits_lagging_503_only_for_archived_snapshot() {
        let body = r#"{"kaspadServers":[{"isSynced":true}],"database":{"blueScore":492369428,"blueScoreDiff":3055,"isSynced":false}}"#;

        assert!(
            parse_rest_database_blue_score(StatusCode::SERVICE_UNAVAILABLE, body, false).is_err()
        );
        assert!(parse_rest_database_blue_score(StatusCode::OK, body, false).is_err());
        let score =
            parse_rest_database_blue_score(StatusCode::SERVICE_UNAVAILABLE, body, true).unwrap();

        assert_eq!(score, 492369428);
    }

    #[test]
    fn rejects_missing_sync_state_for_current_source() {
        let body = r#"{"database":{"blueScore":492369428}}"#;
        assert!(parse_rest_database_blue_score(StatusCode::OK, body, false).is_err());
    }

    #[test]
    fn rejects_non_health_error_response() {
        let body = r#"{"database":{"blueScore":492369428}}"#;

        let error =
            parse_rest_database_blue_score(StatusCode::BAD_GATEWAY, body, false).unwrap_err();

        assert!(error.to_string().contains("502"));
    }

    #[test]
    fn detects_degraded_v1_p2sh_response_without_native_binding() {
        let tx: RestTransaction = serde_json::from_value(serde_json::json!({
            "transaction_id": "0037c890235fa1a04d4a6d7449c15408a6828e328dc009ed0207cf23323f0ada",
            "version": 1,
            "outputs": [
                {
                    "index": 1,
                    "amount": 100,
                    "script_public_key": "aa201a118a6b40584432a1ff2971c093aa9268f886ae64483ddc4e1c79b45144c66887"
                }
            ]
        }))
        .unwrap();

        let stats = native_binding_stats(&tx);

        assert_eq!(stats.p2sh_outputs, 1);
        assert_eq!(stats.complete_native_bindings, 0);
        assert_eq!(stats.incomplete_native_bindings, 1);
        assert!(stats.needs_better_source());
    }

    #[test]
    fn accepts_v1_unbound_outputs_only_when_the_transaction_id_proves_them() {
        let tx: RestTransaction =
            serde_json::from_str(include_str!("../../fixtures/tn10-v1-unbound-output.json"))
                .unwrap();
        let stats = native_binding_stats(&tx);
        assert_eq!(stats.p2sh_outputs, 1);
        assert_eq!(stats.complete_native_bindings, 0);
        assert!(
            !stats.needs_better_source(),
            "the recorded ID commits to an unbound P2SH output"
        );
        let mut changed = tx.clone();
        changed.outputs[0].amount += 1;
        assert!(native_binding_stats(&changed).needs_better_source());
        let mut changed_payload = tx.clone();
        changed_payload.payload = Some("00".into());
        assert!(native_binding_stats(&changed_payload).needs_better_source());
        let mut changed_index = tx.clone();
        changed_index.outputs[0].index = 1;
        assert!(native_binding_stats(&changed_index).needs_better_source());
        let mut missing = tx.clone();
        missing.subnetwork_id.clear();
        assert!(native_binding_stats(&missing).needs_better_source());
        let mut partial = tx;
        partial.outputs[0].covenant = Some(RestCovenantBinding {
            covenant_id: None,
            authorizing_input: Some(0),
        });
        assert!(native_binding_stats(&partial).needs_better_source());
    }

    #[test]
    fn accepts_v1_p2sh_response_with_native_binding() {
        let tx: RestTransaction = serde_json::from_value(serde_json::json!({
            "transaction_id": "0037c890235fa1a04d4a6d7449c15408a6828e328dc009ed0207cf23323f0ada",
            "version": 1,
            "outputs": [
                {
                    "index": 1,
                    "amount": 100,
                    "script_public_key": "aa201a118a6b40584432a1ff2971c093aa9268f886ae64483ddc4e1c79b45144c66887",
                    "covenant_id": "472d4aa57d51eb93ac84e20a7198d65dfb1396d66d5b421538fa3d5a73ba3a12",
                    "covenant_authorizing_input": 0
                }
            ]
        }))
        .unwrap();

        let stats = native_binding_stats(&tx);

        assert_eq!(stats.p2sh_outputs, 1);
        assert_eq!(stats.complete_native_bindings, 1);
        assert_eq!(stats.incomplete_native_bindings, 0);
        assert!(!stats.needs_better_source());
    }

    #[test]
    fn ignores_legacy_v0_p2sh_without_native_binding() {
        let tx: RestTransaction = serde_json::from_value(serde_json::json!({
            "transaction_id": "28202613b2486195c2640d7c12c05b87881d8986af8436e4d65d5288b904435d",
            "version": 0,
            "outputs": [
                {
                    "index": 0,
                    "amount": 100,
                    "script_public_key": "aa201a118a6b40584432a1ff2971c093aa9268f886ae64483ddc4e1c79b45144c66887"
                }
            ]
        }))
        .unwrap();

        let stats = native_binding_stats(&tx);

        assert_eq!(stats.p2sh_outputs, 0);
        assert!(!stats.needs_better_source());
    }

    #[test]
    fn parses_comma_separated_fallback_urls() {
        assert_eq!(
            parse_fallback_urls(" https://a.example/ ,https://b.example ,, ".into()),
            vec!["https://a.example", "https://b.example"]
        );
    }
}

#[cfg(test)]
mod parent_budget_tests {
    use super::*;
    #[test]
    fn dependency_response_budget_is_shared_and_cannot_overflow() {
        let budget = ParentResponseBudget::default();
        budget.charge(8 * 1024 * 1024).unwrap();
        budget.charge(8 * 1024 * 1024).unwrap();
        let error = budget.charge(1).unwrap_err();
        let capacity = error.downcast_ref::<crate::recovery_policy::RecoveryCapacity>().unwrap();
        assert_eq!(capacity.dimension, "dependency_response_bytes");
        assert_eq!(capacity.observed, MAX_FULL_BLOCK_RESPONSE_BYTES + 1);
        assert_eq!(capacity.limit, MAX_FULL_BLOCK_RESPONSE_BYTES);
        assert_eq!(crate::recovery_policy::classify(&error),
            crate::recovery_policy::Decision::Reassess("dependency_response_bytes"));
        let overflow = budget.charge(usize::MAX).unwrap_err();
        assert_eq!(overflow.downcast_ref::<crate::recovery_policy::RecoveryCapacity>().unwrap().observed, usize::MAX);
        // Refused charges cannot overflow or reset the shared budget.
        budget.charge(0).unwrap();
        assert!(budget.charge(1).is_err());
    }
}

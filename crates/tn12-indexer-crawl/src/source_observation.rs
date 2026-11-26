//! Source freshness is independent of ingestion and REST publication progress.
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{ensure, Result};
use kaspa_wrpc_client::prelude::{ConnectOptions, KaspaRpcClient, NetworkId, RpcApi, WrpcEncoding};
use serde::{Deserialize, Serialize};

pub const MAX_OBSERVATION_AGE_MS: i64 = 15_000;
pub type SharedNodeObservation = Arc<Mutex<Option<NodeObservation>>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeObservation {
    pub endpoint: String,
    pub network: String,
    pub blue_score: u64,
    pub observed_at_ms: i64,
    pub synced: bool,
}

impl NodeObservation {
    pub fn fresh_score(&self, network: &str, now_ms: i64) -> Option<i64> {
        let age = now_ms.checked_sub(self.observed_at_ms)?;
        (self.synced && self.network == network && (0..=MAX_OBSERVATION_AGE_MS).contains(&age))
            .then(|| i64::try_from(self.blue_score).ok())
            .flatten()
    }
}

/// A persistent connection polls independently from notification processing.
/// Callers retain the handle and abort it when their runtime shuts down.
pub fn spawn_node_observer(
    endpoint: &str,
    network: &str,
    observation: SharedNodeObservation,
) -> Result<tokio::task::JoinHandle<()>> {
    let id = NetworkId::from_str(network)?;
    let rpc =
        KaspaRpcClient::new_with_args(WrpcEncoding::Borsh, Some(endpoint), None, Some(id), None)?;
    let endpoint = endpoint_identity(endpoint)?;
    let expected_network = network.to_owned();
    Ok(tokio::spawn(async move {
        if let Err(error) = rpc
            .connect(Some(ConnectOptions {
                block_async_connect: false,
                ..Default::default()
            }))
            .await
        {
            tracing::warn!(%error, "source observer connection failed");
            return;
        }
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let observed_at_ms = chrono::Utc::now().timestamp_millis();
            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let info = rpc.get_server_info().await?;
                ensure!(
                    info.network_id.to_string() == expected_network,
                    "source network mismatch"
                );
                let blue_score = rpc.get_sink_blue_score().await?;
                Ok::<_, anyhow::Error>(NodeObservation {
                    endpoint: endpoint.clone(),
                    network: info.network_id.to_string(),
                    blue_score,
                    observed_at_ms,
                    synced: info.is_synced,
                })
            })
            .await;
            match result {
                Ok(Ok(sample)) => {
                    *observation.lock().expect("source observation lock") = Some(sample)
                }
                _ => {
                    // An unsuccessful request must never refresh an older observation.
                    *observation.lock().expect("source observation lock") = None;
                    tracing::warn!(source = %endpoint, "source observation unavailable");
                }
            }
        }
    }))
}

pub fn endpoint_identity(endpoint: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(endpoint)?;
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

/// Never let HTTP cache residence time become a new source observation.
pub fn validate_health_headers(headers: &reqwest::header::HeaderMap, now_ms: i64) -> Result<()> {
    if let Some(age) = headers.get(reqwest::header::AGE) {
        let age = age.to_str()?.parse::<u64>()?;
        ensure!(age == 0, "cached source health response (Age={age})");
    }
    if let Some(status) = headers.get("cf-cache-status") {
        let status = status.to_str()?.to_ascii_uppercase();
        ensure!(
            !matches!(
                status.as_str(),
                "STALE" | "UPDATING" | "HIT" | "REVALIDATED"
            ),
            "cached source health response ({status})"
        );
    }
    for name in ["cache-status", "x-cache", "x-cache-status"] {
        if let Some(value) = headers.get(name) {
            let cached = value.to_str()?.to_ascii_lowercase();
            ensure!(
                !cached
                    .split(|c: char| !c.is_ascii_alphanumeric())
                    .any(|part| matches!(part, "hit" | "stale" | "updating")),
                "cached source health response ({name})"
            );
        }
    }
    let date = headers
        .get(reqwest::header::DATE)
        .ok_or_else(|| anyhow::anyhow!("source health has no Date freshness evidence"))?;
    {
        let at = chrono::DateTime::parse_from_rfc2822(date.to_str()?)?.timestamp_millis();
        let age = now_ms.saturating_sub(at);
        ensure!(
            (-5_000..=MAX_OBSERVATION_AGE_MS).contains(&age),
            "stale or future source health Date"
        );
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn fresh_test_response(response: String) -> String {
    let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT");
    response.replacen("\r\n", &format!("\r\nDate: {date}\r\n"), 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "read-only live smoke; requires TN10_WRPC_TEST_URL"]
    async fn live_node_progress_is_independent_of_rest() {
        let endpoint = std::env::var("TN10_WRPC_TEST_URL").unwrap();
        let observed = Arc::new(Mutex::new(None));
        let task = spawn_node_observer(&endpoint, "testnet-10", observed.clone()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let snapshot = observed.lock().unwrap().clone();
                if let Some(score) = snapshot.and_then(|sample| {
                    sample.fresh_score("testnet-10", chrono::Utc::now().timestamp_millis())
                }) {
                    break score;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        task.abort();
        assert!(result.unwrap() > 0);
    }
    #[test]
    fn node_progress_requires_fresh_synced_matching_network() {
        let mut sample = NodeObservation {
            endpoint: "wss://node/".into(),
            network: "testnet-10".into(),
            blue_score: 100,
            observed_at_ms: 100_000,
            synced: true,
        };
        assert_eq!(sample.fresh_score("testnet-10", 105_000), Some(100));
        assert_eq!(sample.fresh_score("testnet-10", 116_000), None);
        assert_eq!(sample.fresh_score("testnet-10", 99_999), None);
        assert_eq!(sample.fresh_score("testnet-12", 105_000), None);
        sample.synced = false;
        assert_eq!(sample.fresh_score("testnet-10", 105_000), None);
    }
    #[test]
    fn cached_health_cannot_refresh_source_progress() {
        for status in ["STALE", "UPDATING", "HIT"] {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert("cf-cache-status", status.parse().unwrap());
            assert!(validate_health_headers(&headers, 0).is_err());
        }
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("age", "1".parse().unwrap());
        assert!(validate_health_headers(&headers, 0).is_err());
        headers.insert("age", "0".parse().unwrap());
        headers.insert("cf-cache-status", "DYNAMIC".parse().unwrap());
        assert!(validate_health_headers(&headers, 0).is_err());
        headers.insert("date", "Sun, 11 Oct 2026 16:00:00 GMT".parse().unwrap());
        let at = chrono::DateTime::parse_from_rfc2822("Sun, 11 Oct 2026 16:00:00 GMT")
            .unwrap()
            .timestamp_millis();
        assert!(validate_health_headers(&headers, at + 1_000).is_ok());
        assert!(validate_health_headers(&headers, at + 16_000).is_err());
    }
    #[test]
    fn standard_cache_hits_and_missing_dates_are_rejected() {
        let mut headers = reqwest::header::HeaderMap::new();
        assert!(validate_health_headers(&headers, 0).is_err());
        headers.insert("date", "Thu, 01 Jan 1970 00:00:00 GMT".parse().unwrap());
        assert!(validate_health_headers(&headers, 0).is_ok());
        for name in ["cache-status", "x-cache", "x-cache-status"] {
            headers.insert(name, "ExampleCache; hit; ttl=376".parse().unwrap());
            assert!(validate_health_headers(&headers, 0).is_err());
            headers.remove(name);
        }
    }
    #[test]
    fn source_identity_does_not_expose_credentials() {
        assert_eq!(
            endpoint_identity("wss://user:secret@node/path?key=secret#secret").unwrap(),
            "wss://node/path"
        );
    }
}

/// Block publication and transaction publication are separate watermarks.
/// A block score alone cannot qualify a source for acceptance reconciliation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestPublicationObservation {
    pub endpoint: String,
    pub network: String,
    pub observed_at_ms: i64,
    pub database: RestDatabasePublication,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestDatabasePublication {
    pub blue_score: u64,
    pub is_synced: Option<bool>,
    pub accepted_tx_block_time: Option<i64>,
    pub accepted_tx_block_time_diff: Option<i64>,
}

impl RestDatabasePublication {
    pub fn transaction_age_ms(&self, now_ms: i64) -> Option<i64> {
        now_ms.checked_sub(self.accepted_tx_block_time?)
    }
    pub fn require_current_transactions(&self, now_ms: i64) -> Result<()> {
        ensure!(self.is_synced == Some(true), "REST database is not synced");
        let age = self.transaction_age_ms(now_ms);
        ensure!(
            age.is_some_and(|age| (-5_000..=300_000).contains(&age)),
            "REST accepted-transaction publication is missing, stale, or in the future"
        );
        ensure!(
            self.accepted_tx_block_time_diff
                .is_some_and(|seconds| (0..=300).contains(&seconds)
                    && (seconds * 1000 - age.unwrap()).abs() <= 15_000),
            "REST transaction publication age disagrees with its watermark"
        );
        Ok(())
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    #[tokio::test]
    #[ignore = "read-only source observation; requires TN10_REST_TEST_URL"]
    async fn live_publication_observation_checks_network_and_both_watermarks() {
        let endpoint = std::env::var("TN10_REST_TEST_URL").unwrap();
        let sample = crate::RestClient::new(endpoint)
            .unwrap()
            .observe_publication("testnet-10")
            .await
            .unwrap();
        assert_eq!(sample.network, "testnet-10");
        assert!(sample.database.blue_score > 0);
        sample
            .database
            .require_current_transactions(chrono::Utc::now().timestamp_millis())
            .unwrap();
    }

    #[test]
    fn current_blocks_do_not_hide_stalled_transaction_publication() {
        let mut publication = RestDatabasePublication {
            blue_score: 1000,
            is_synced: Some(true),
            accepted_tx_block_time: Some(1_000_000),
            accepted_tx_block_time_diff: Some(0),
        };
        assert!(publication.require_current_transactions(1_000_000).is_ok());
        assert!(publication.require_current_transactions(1_400_000).is_err());
        publication.accepted_tx_block_time = None;
        assert!(publication.require_current_transactions(1_000_000).is_err());
    }
    #[test]
    fn reject_future_or_inconsistent_publication_evidence() {
        let mut publication = RestDatabasePublication {
            blue_score: 1000,
            is_synced: Some(true),
            accepted_tx_block_time: Some(1_100_000),
            accepted_tx_block_time_diff: Some(0),
        };
        assert!(publication.require_current_transactions(1_000_000).is_err());
        publication.accepted_tx_block_time = Some(900_000);
        assert!(publication.require_current_transactions(1_000_000).is_err());
        publication.accepted_tx_block_time_diff = Some(100);
        assert!(publication.require_current_transactions(1_000_000).is_ok());
    }
}

pub type SharedRestObservation = Arc<Mutex<Option<RestPublicationObservation>>>;

pub fn spawn_rest_observer(
    client: crate::RestClient,
    network: String,
    cache: SharedRestObservation,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let sample =
                tokio::time::timeout(Duration::from_secs(3), client.observe_publication(&network))
                    .await;
            *cache.lock().expect("REST observation lock") = match sample {
                Ok(Ok(sample)) => Some(sample),
                _ => None,
            };
        }
    })
}

// src/threat_intel/sources/ipinfo.rs
//
// ipinfo.io geo/ASN probe — country, ASN, org, anycast flag.
// Endpoint: https://ipinfo.io/{ip}/json
// Auth:     none (free tier, ~50 k req/day)
// Bogon/private IPs: returns a minimal { "ip": "...", "bogon": true } response

use crate::threat_intel::types::{IpInfoData, SourceOutcome};
use std::time::Duration;

const SOURCE: &str = "ipinfo";

pub async fn fetch(
    ip: &str,
    client: &reqwest::Client,
    timeout: Duration,
) -> SourceOutcome<IpInfoData> {
    let url = format!("https://ipinfo.io/{ip}/json");

    let result = tokio::time::timeout(
        timeout,
        client
            .get(&url)
            .header("Accept", "application/json")
            .send(),
    )
    .await;

    let resp = match result {
        Err(_) => {
            tracing::debug!(%ip, source = SOURCE, "timeout");
            return SourceOutcome::Timeout;
        }
        Ok(Err(e)) => {
            tracing::debug!(%ip, source = SOURCE, error = %e, "request error");
            return SourceOutcome::Error(e.to_string());
        }
        Ok(Ok(r)) => r,
    };

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        tracing::debug!(%ip, source = SOURCE, %status, "non-OK status");
        return SourceOutcome::Error(format!("HTTP {status}"));
    }

    match resp.json::<IpInfoData>().await {
        Ok(data) => SourceOutcome::Ok(data),
        Err(e) => {
            tracing::debug!(%ip, source = SOURCE, error = %e, "parse error");
            SourceOutcome::Error(e.to_string())
        }
    }
}

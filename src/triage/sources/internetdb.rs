// src/triage/sources/internetdb.rs
//
// Shodan InternetDB probe — open ports, CVE IDs, tags, CPEs.
// Ported from SeekYou worker/sources/internetdb.ts.
//
// Endpoint: https://internetdb.shodan.io/{ip}
// Auth:     none
// Limits:   none documented
// 404:      IP not indexed → return empty result (not an error)

use crate::triage::types::{InternetDbData, SourceOutcome};
use std::time::Duration;

const SOURCE: &str = "internetdb";

pub async fn fetch(
    ip: &str,
    client: &reqwest::Client,
    timeout: Duration,
) -> SourceOutcome<InternetDbData> {
    let url = format!("https://internetdb.shodan.io/{ip}");

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

    // 404 = IP not in Shodan — valid empty result
    if resp.status() == 404 {
        return SourceOutcome::Ok(InternetDbData {
            ip: ip.to_string(),
            ports: vec![],
            hostnames: vec![],
            tags: vec![],
            vulns: vec![],
            cpes: vec![],
        });
    }

    if !resp.status().is_success() {
        tracing::debug!(%ip, source = SOURCE, status = resp.status().as_u16(), "non-OK status");
        return SourceOutcome::Error(format!("HTTP {}", resp.status().as_u16()));
    }

    match resp.json::<InternetDbData>().await {
        Ok(data) => SourceOutcome::Ok(data),
        Err(e) => {
            tracing::debug!(%ip, source = SOURCE, error = %e, "parse error");
            SourceOutcome::Error(e.to_string())
        }
    }
}

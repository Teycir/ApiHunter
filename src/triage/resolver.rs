// src/triage/resolver.rs
//
// Domain → IP resolution via Cloudflare DoH (1.1.1.1).
// Returns the first A record (IPv4) found, falling back to AAAA.
// No system resolver dependency — works in any network environment.

use std::time::Duration;

const DOH_URL: &str = "https://1.1.1.1/dns-query";

#[derive(Debug, serde::Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer", default)]
    answer: Vec<DohRecord>,
}

#[derive(Debug, serde::Deserialize)]
struct DohRecord {
    #[serde(rename = "type")]
    rtype: u16,
    data: String,
}

/// Resolve a domain to an IPv4 (or IPv6) address using Cloudflare DoH.
/// Returns None if resolution fails or times out.
pub async fn resolve(
    domain: &str,
    client: &reqwest::Client,
    timeout: Duration,
) -> Option<String> {
    // Try A first, fall back to AAAA
    for qtype in ["A", "AAAA"] {
        if let Some(ip) = query_doh(domain, qtype, client, timeout).await {
            return Some(ip);
        }
    }
    None
}

async fn query_doh(
    name: &str,
    qtype: &str,
    client: &reqwest::Client,
    timeout: Duration,
) -> Option<String> {
    // reqwest 0.13 async RequestBuilder does not expose .query(); build the
    // query string directly so we have no dependency on the blocking client.
    let url = format!("{DOH_URL}?name={name}&type={qtype}");

    let resp = tokio::time::timeout(
        timeout,
        client
            .get(&url)
            .header("Accept", "application/dns-json")
            .send(),
    )
    .await
    .ok()?
    .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let body: DohResponse = resp.json().await.ok()?;
    let expected_type: u16 = if qtype == "A" { 1 } else { 28 };

    body.answer
        .into_iter()
        .find(|r| r.rtype == expected_type)
        .map(|r| r.data)
}

/// True if the string looks like a raw IPv4 or IPv6 address.
pub fn is_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

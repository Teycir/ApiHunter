use async_trait::async_trait;
use dashmap::DashSet;
use rand::Rng;
use std::{collections::HashMap, sync::Arc};
use url::Url;

use crate::{
    config::Config,
    error::CapturedError,
    http_client::{HttpClient, HttpResponse},
    reports::{Finding, Severity},
};

use super::Scanner;

pub struct RateLimitScanner {
    checked_hosts: Arc<DashSet<String>>,
}

impl RateLimitScanner {
    pub fn new(_config: &Config) -> Self {
        Self {
            checked_hosts: Arc::new(DashSet::new()),
        }
    }
}

const BURST_REQUESTS: usize = 12;
const BYPASS_REQUESTS: usize = 3;

fn random_reserved_ipv4() -> String {
    let mut rng = rand::thread_rng();
    let block = match rng.gen_range(0..3) {
        0 => "203.0.113",
        1 => "198.51.100",
        _ => "192.0.2",
    };
    format!("{block}.{}", rng.gen_range(1..=254))
}

#[derive(Default)]
struct BurstStats {
    success: usize,
    too_many: usize,
    saw_rate_limit_headers: bool,
    saw_retry_after: bool,
    statuses: HashMap<u16, usize>,
}

#[async_trait]
impl Scanner for RateLimitScanner {
    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        if !config.active_checks {
            return (Vec::new(), Vec::new());
        }

        let mut findings = Vec::new();
        let mut errors = Vec::new();

        let host = match Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
        {
            Some(h) => h,
            None => return (findings, errors),
        };

        // Ensure we probe each host only once in a scan run.
        if !self.checked_hosts.insert(host.clone()) {
            return (findings, errors);
        }

        let baseline = burst_gets(client, url, None, BURST_REQUESTS, &mut errors).await;
        if baseline.success == 0 && baseline.too_many == 0 {
            return (findings, errors);
        }

        if baseline.too_many > 0 {
            if !baseline.saw_retry_after {
                findings.push(
                    Finding::new(
                        url,
                        "rate_limit/missing-retry-after",
                        "Rate limiting without Retry-After hint",
                        Severity::Low,
                        "Endpoint responded with HTTP 429 but did not include Retry-After.",
                        "rate_limit",
                    )
                    .with_evidence(format!(
                        "Host: {host}\nBurst: {BURST_REQUESTS}\n429s: {}\nStatuses: {}",
                        baseline.too_many,
                        compact_statuses(&baseline.statuses)
                    ))
                    .with_remediation(
                        "Include Retry-After with 429 responses to guide compliant client backoff.",
                    ),
                );
            }

            let spoof_ip = random_reserved_ipv4();
            let bypass_headers = vec![
                ("X-Forwarded-For".to_string(), spoof_ip.clone()),
                ("X-Real-IP".to_string(), spoof_ip.clone()),
                (
                    "Forwarded".to_string(),
                    format!("for={spoof_ip};proto=https"),
                ),
            ];
            let bypass = burst_gets(
                client,
                url,
                Some(&bypass_headers),
                BYPASS_REQUESTS,
                &mut errors,
            )
            .await;

            if bypass.success > 0 && bypass.too_many == 0 {
                findings.push(
                    Finding::new(
                        url,
                        "rate_limit/ip-header-bypass",
                        "Rate limit may be bypassed via client IP headers",
                        Severity::High,
                        "Baseline burst hit HTTP 429, but requests with spoofed IP headers succeeded.",
                        "rate_limit",
                    )
                    .with_evidence(format!(
                        "Host: {host}\nBaseline burst: {BURST_REQUESTS}, 429s: {}\nBypass burst: {BYPASS_REQUESTS}, 429s: {}, successes: {}",
                        baseline.too_many,
                        bypass.too_many,
                        bypass.success
                    ))
                    .with_remediation(
                        "Do not trust client-controlled IP headers unless set by trusted proxies; enforce limits on canonical client identity.",
                    ),
                );
            }

            return (findings, errors);
        }

        if baseline.success > 0 && !baseline.saw_rate_limit_headers {
            findings.push(
                Finding::new(
                    url,
                    "rate_limit/not-detected",
                    "No rate limiting detected in burst probe",
                    Severity::Low,
                    "A controlled burst did not trigger 429 and no rate-limit headers were observed.",
                    "rate_limit",
                )
                .with_evidence(format!(
                    "Host: {host}\nBurst: {BURST_REQUESTS}\n429s: 0\nStatuses: {}",
                    compact_statuses(&baseline.statuses)
                ))
                .with_remediation(
                    "Apply endpoint-level rate limits and emit standard rate-limit headers and 429 responses when thresholds are exceeded.",
                ),
            );
        }

        (findings, errors)
    }
}

async fn burst_gets(
    client: &HttpClient,
    url: &str,
    headers: Option<&[(String, String)]>,
    count: usize,
    errors: &mut Vec<CapturedError>,
) -> BurstStats {
    let mut stats = BurstStats::default();

    for _ in 0..count {
        let resp = match headers {
            Some(h) => client.get_with_headers(url, h).await,
            None => client.get(url).await,
        };

        match resp {
            Ok(r) => update_stats(&mut stats, &r),
            Err(e) => errors.push(e),
        }
    }

    stats
}

fn update_stats(stats: &mut BurstStats, resp: &HttpResponse) {
    *stats.statuses.entry(resp.status).or_insert(0) += 1;

    if resp.status == 429 {
        stats.too_many += 1;
    } else if resp.status < 400 {
        stats.success += 1;
    }

    if has_rate_limit_headers(&resp.headers) {
        stats.saw_rate_limit_headers = true;
    }
    if resp.header("retry-after").is_some() {
        stats.saw_retry_after = true;
    }
}

fn has_rate_limit_headers(headers: &HashMap<String, String>) -> bool {
    const KEYS: &[&str] = &[
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "ratelimit-limit",
        "ratelimit-remaining",
        "ratelimit-reset",
    ];

    KEYS.iter().any(|k| headers.contains_key(*k))
}

fn compact_statuses(statuses: &HashMap<u16, usize>) -> String {
    let mut parts = statuses
        .iter()
        .map(|(status, count)| format!("{status}:{count}"))
        .collect::<Vec<_>>();
    parts.sort();
    parts.join(", ")
}

use std::collections::HashSet;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;
use url::Url;

use crate::{
    config::Config,
    error::CapturedError,
    http_client::{HttpClient, HttpResponse},
    reports::{Confidence, Finding, Severity},
};

use super::Scanner;

pub struct ApiVersioningScanner;

impl ApiVersioningScanner {
    pub fn new(_config: &Config) -> Self {
        Self
    }
}

const VERSION_HEADER_KEYS: &[&str] = &[
    "api-version",
    "x-api-version",
    "x-version",
    "version",
    "x-service-version",
];
const DEPRECATION_HEADER_KEYS: &[&str] = &["deprecation", "sunset"];
const API_HINT_KEYWORDS: &[&str] = &["/api", "/v1", "/v2", "/v3", "graphql", "openapi", "swagger"];
const MAX_DEEP_PROBES: usize = 4;

#[derive(Debug, Clone, Copy)]
struct VersionSegment {
    index: usize,
    value: u32,
}

#[derive(Debug, Clone)]
struct DeepProbe {
    label: &'static str,
    url: String,
    headers: Option<HeaderMap>,
}

#[async_trait]
impl Scanner for ApiVersioningScanner {
    fn name(&self) -> &'static str {
        "api_versioning"
    }

    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        let mut findings = Vec::new();
        let mut errors = Vec::new();

        let baseline = match client.get(url).await {
            Ok(response) => response,
            Err(err) => {
                errors.push(err);
                return (findings, errors);
            }
        };

        if let Some(evidence) = collect_header_evidence(&baseline, VERSION_HEADER_KEYS) {
            findings.push(
                Finding::new(
                    url,
                    "api_versioning/version-header-disclosed",
                    "API version disclosed via response headers",
                    Severity::Info,
                    "Endpoint reveals explicit API version metadata in response headers.",
                    "api_versioning",
                )
                .with_evidence(evidence)
                .with_remediation(
                    "If version disclosure is unnecessary, trim verbose version headers in production.",
                ),
            );
        }

        if let Some(evidence) = collect_header_evidence(&baseline, DEPRECATION_HEADER_KEYS) {
            findings.push(
                Finding::new(
                    url,
                    "api_versioning/deprecation-signaled",
                    "API deprecation or sunset headers present",
                    Severity::Low,
                    "Endpoint advertises deprecation/sunset metadata. This often indicates active version transition risk.",
                    "api_versioning",
                )
                .with_evidence(evidence)
                .with_remediation(
                    "Track migration cutovers and ensure deprecated versions are retired on schedule.",
                ),
            );
        }

        run_query_variant_diff_probe(url, client, &baseline, &mut findings, &mut errors).await;
        run_version_variant_probes(url, client, &baseline, &mut findings, &mut errors).await;
        if config.response_diff_deep {
            run_deep_response_diff_probes(url, client, &baseline, &mut findings, &mut errors).await;
        }

        (findings, errors)
    }
}

async fn run_query_variant_diff_probe(
    url: &str,
    client: &HttpClient,
    baseline: &HttpResponse,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    if !is_api_like_url(url) {
        return;
    }

    let Some(variant_url) = add_diff_query(url) else {
        return;
    };

    let variant = match client.get(&variant_url).await {
        Ok(response) => response,
        Err(err) => {
            errors.push(err);
            return;
        }
    };

    if baseline.status < 500 && variant.status >= 500 {
        findings.push(
            Finding::new(
                &variant_url,
                "response_diff/query-variant-server-error",
                "Benign query variant triggered server error",
                Severity::Medium,
                "A harmless query-parameter variation changed the endpoint into a 5xx response.",
                "api_versioning",
            )
            .with_evidence(format!(
                "Baseline status: {} | Variant status: {}",
                baseline.status, variant.status
            ))
            .with_confidence(Confidence::High)
            .with_remediation(
                "Review request parsing and cache/gateway normalization for query-param edge cases.",
            ),
        );
        return;
    }

    if is_significant_response_drift(baseline, &variant) {
        findings.push(
            Finding::new(
                &variant_url,
                "response_diff/query-variant-drift",
                "Response drift detected for benign query variant",
                Severity::Low,
                "Baseline and benign query-variant responses diverge significantly (status/content-type/body shape).",
                "api_versioning",
            )
            .with_evidence(format!(
                "Baseline status/content-type: {}/{} | Variant: {}/{} | Body similarity: {:.2}",
                baseline.status,
                content_type(baseline),
                variant.status,
                content_type(&variant),
                token_similarity(&baseline.body, &variant.body)
            ))
            .with_confidence(Confidence::Medium)
            .with_remediation(
                "Validate edge-case query normalization and ensure consistent handler behavior across benign variants.",
            ),
        );
    }
}

async fn run_version_variant_probes(
    url: &str,
    client: &HttpClient,
    baseline: &HttpResponse,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    let Ok(parsed) = Url::parse(url) else {
        return;
    };
    let Some(segment) = detect_version_segment(parsed.path()) else {
        return;
    };

    let mut candidate_versions = Vec::new();
    if segment.value > 1 {
        candidate_versions.push(segment.value - 1);
    }
    candidate_versions.push(segment.value + 1);

    let mut accessible_variants: Vec<(u32, String, HttpResponse)> = Vec::new();
    for candidate in candidate_versions {
        let Some(variant_url) = build_version_variant_url(url, segment, candidate) else {
            continue;
        };

        let response = match client.get(&variant_url).await {
            Ok(response) => response,
            Err(err) => {
                errors.push(err);
                continue;
            }
        };

        if baseline.status < 500 && response.status >= 500 {
            findings.push(
                Finding::new(
                    &variant_url,
                    "response_diff/version-variant-server-error",
                    "Version sibling probe triggered server error",
                    Severity::Medium,
                    "Changing only the API version segment produced a 5xx response.",
                    "api_versioning",
                )
                .with_evidence(format!(
                    "Baseline status: {} | Version v{} status: {}",
                    baseline.status, candidate, response.status
                ))
                .with_confidence(Confidence::Medium)
                .with_remediation(
                    "Harden version router/middleware behavior and verify unsupported versions fail safely.",
                ),
            );
        }

        if response.status < 400 {
            accessible_variants.push((candidate, variant_url, response));
        }
    }

    if accessible_variants.is_empty() {
        return;
    }

    let mut live_versions: Vec<u32> = vec![segment.value];
    live_versions.extend(accessible_variants.iter().map(|(v, _, _)| *v));
    live_versions.sort_unstable();
    live_versions.dedup();

    if live_versions.len() > 1 {
        findings.push(
            Finding::new(
                url,
                "api_versioning/multiple-active-versions",
                "Multiple API versions appear concurrently active",
                Severity::Medium,
                "Neighbor API versions responded successfully for the same endpoint shape.",
                "api_versioning",
            )
            .with_evidence(format!("Observed active versions: {:?}", live_versions))
            .with_confidence(Confidence::Medium)
            .with_remediation(
                "Enforce explicit lifecycle controls (deprecation windows + cutoffs) and restrict stale versions.",
            ),
        );
    }

    if accessible_variants
        .iter()
        .any(|(version, _, _)| *version < segment.value)
    {
        findings.push(
            Finding::new(
                url,
                "api_versioning/legacy-version-still-accessible",
                "Legacy API version still reachable",
                Severity::Medium,
                "Older sibling API version remains reachable for this endpoint pattern.",
                "api_versioning",
            )
            .with_evidence(format!(
                "Current path version: v{} | Reachable older version(s): {}",
                segment.value,
                accessible_variants
                    .iter()
                    .filter(|(version, _, _)| *version < segment.value)
                    .map(|(version, _, _)| format!("v{version}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .with_confidence(Confidence::Medium)
            .with_remediation(
                "Retire legacy versions or gate them behind explicit allowlists and migration controls.",
            ),
        );
    }

    for (version, variant_url, variant_response) in accessible_variants {
        if is_significant_response_drift(baseline, &variant_response) {
            findings.push(
                Finding::new(
                    variant_url,
                    "response_diff/version-variant-drift",
                    "Response drift detected across API versions",
                    Severity::Low,
                    "Sibling API versions return materially different response behavior for the same endpoint shape.",
                    "api_versioning",
                )
                .with_evidence(format!(
                    "Baseline v{} status/content-type: {}/{} | Variant v{}: {}/{} | Body similarity: {:.2}",
                    segment.value,
                    baseline.status,
                    content_type(baseline),
                    version,
                    variant_response.status,
                    content_type(&variant_response),
                    token_similarity(&baseline.body, &variant_response.body)
                ))
                .with_confidence(Confidence::Low)
                .with_remediation(
                    "Review versioned handler parity and maintain backward-compatible schema/error contracts where intended.",
                ),
            );
        }
    }
}

async fn run_deep_response_diff_probes(
    url: &str,
    client: &HttpClient,
    baseline: &HttpResponse,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    if !is_api_like_url(url) {
        return;
    }

    let probes = build_deep_probes(url);
    if probes.is_empty() {
        return;
    }

    let mut drift_candidate: Option<(String, HttpResponse)> = None;
    for probe in probes.into_iter().take(MAX_DEEP_PROBES) {
        let response = match execute_deep_probe(client, &probe).await {
            Ok(value) => value,
            Err(error) => {
                errors.push(error);
                continue;
            }
        };

        if baseline.status < 500 && response.status >= 500 {
            findings.push(
                Finding::new(
                    &probe.url,
                    "response_diff/deep-variant-server-error",
                    "Deep response-diff variant triggered server error",
                    Severity::Medium,
                    "A deep response-diff variant (query/header) caused a 5xx response while baseline stayed stable.",
                    "api_versioning",
                )
                .with_evidence(format!(
                    "Variant: {} | Baseline status/content-type: {}/{} | Variant status/content-type: {}/{}",
                    probe.label,
                    baseline.status,
                    content_type(baseline),
                    response.status,
                    content_type(&response)
                ))
                .with_confidence(Confidence::High)
                .with_remediation(
                    "Harden cache/gateway normalization and request parser behavior so benign query/header permutations fail safely.",
                ),
            );
            return;
        }

        if drift_candidate.is_none() && is_significant_response_drift(baseline, &response) {
            drift_candidate = Some((probe.label.to_string(), response));
        }
    }

    if let Some((label, variant)) = drift_candidate {
        findings.push(
            Finding::new(
                url,
                "response_diff/deep-variant-drift",
                "Deep response-diff drift detected",
                Severity::Low,
                "A deeper query/header variant produced materially different API behavior compared to baseline.",
                "api_versioning",
            )
            .with_evidence(format!(
                "Variant: {} | Baseline status/content-type: {}/{} | Variant: {}/{} | Body similarity: {:.2}",
                label,
                baseline.status,
                content_type(baseline),
                variant.status,
                content_type(&variant),
                token_similarity(&baseline.body, &variant.body)
            ))
            .with_confidence(Confidence::Medium)
            .with_remediation(
                "Review edge-case parameter/header handling in API routers and gateway layers to keep behavior consistent for benign variants.",
            ),
        );
    }
}

async fn execute_deep_probe(
    client: &HttpClient,
    probe: &DeepProbe,
) -> Result<HttpResponse, CapturedError> {
    if let Some(headers) = &probe.headers {
        client
            .request(Method::GET, &probe.url, Some(headers.clone()), None)
            .await
    } else {
        client.get(&probe.url).await
    }
}

fn build_deep_probes(url: &str) -> Vec<DeepProbe> {
    let mut probes = Vec::new();
    if let Some(variant) = add_query_pair(url, "apihunter_diff_probe", "deep") {
        probes.push(DeepProbe {
            label: "query:diff=deep",
            url: variant,
            headers: None,
        });
    }
    if let Some(variant) = add_query_pair(url, "format", "json") {
        probes.push(DeepProbe {
            label: "query:format=json",
            url: variant,
            headers: None,
        });
    }
    probes.push(DeepProbe {
        label: "header:accept-json",
        url: url.to_string(),
        headers: Some(singleton_header("accept", "application/json")),
    });
    probes.push(DeepProbe {
        label: "header:cache-control-no-cache",
        url: url.to_string(),
        headers: Some(singleton_header("cache-control", "no-cache")),
    });
    probes
}

fn collect_header_evidence(response: &HttpResponse, keys: &[&str]) -> Option<String> {
    let mut lines = Vec::new();
    for key in keys {
        if let Some(value) = response.header(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                lines.push(format!("{key}: {trimmed}"));
            }
        }
    }
    if lines.is_empty() {
        None
    } else {
        Some(lines.join(" | "))
    }
}

fn detect_version_segment(path: &str) -> Option<VersionSegment> {
    for (index, segment) in path
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .enumerate()
    {
        if let Some(value) = parse_version_segment(segment) {
            return Some(VersionSegment { index, value });
        }
    }
    None
}

fn parse_version_segment(segment: &str) -> Option<u32> {
    let lower = segment.trim().to_ascii_lowercase();
    let suffix = lower.strip_prefix('v')?;
    if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    suffix.parse::<u32>().ok().filter(|v| *v > 0)
}

fn build_version_variant_url(
    url: &str,
    segment: VersionSegment,
    new_version: u32,
) -> Option<String> {
    let mut parsed = Url::parse(url).ok()?;
    let raw_segments = parsed.path().trim_start_matches('/');
    if raw_segments.is_empty() {
        return None;
    }

    let mut segments = raw_segments
        .split('/')
        .filter(|part| !part.is_empty())
        .map(|part| part.to_string())
        .collect::<Vec<_>>();
    if segment.index >= segments.len() {
        return None;
    }

    segments[segment.index] = format!("v{new_version}");
    parsed.set_path(&format!("/{}", segments.join("/")));
    Some(parsed.to_string())
}

fn add_diff_query(url: &str) -> Option<String> {
    add_query_pair(url, "apihunter_diff_probe", "1")
}

fn add_query_pair(url: &str, key: &str, value: &str) -> Option<String> {
    let mut parsed = Url::parse(url).ok()?;
    parsed.query_pairs_mut().append_pair(key, value);
    Some(parsed.to_string())
}

fn singleton_header(name: &str, value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let (Ok(key), Ok(val)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        headers.insert(key, val);
    }
    headers
}

fn is_api_like_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    API_HINT_KEYWORDS
        .iter()
        .any(|needle| lower.contains(needle))
}

fn content_type(response: &HttpResponse) -> String {
    response
        .header("content-type")
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn normalize_for_similarity(body: &str) -> String {
    body.chars()
        .map(|ch| {
            if ch.is_ascii_alphabetic() {
                ch.to_ascii_lowercase()
            } else if ch.is_ascii_digit() {
                '#'
            } else if ch.is_ascii_whitespace() {
                ' '
            } else {
                ch
            }
        })
        .collect::<String>()
}

fn token_similarity(a: &str, b: &str) -> f64 {
    let a_norm = normalize_for_similarity(a);
    let b_norm = normalize_for_similarity(b);

    let a_tokens: HashSet<String> = a_norm
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .filter(|token| token.len() >= 3)
        .map(|token| token.to_string())
        .collect();
    let b_tokens: HashSet<String> = b_norm
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .filter(|token| token.len() >= 3)
        .map(|token| token.to_string())
        .collect();

    if a_tokens.is_empty() || b_tokens.is_empty() {
        return 1.0;
    }

    let intersection = a_tokens.intersection(&b_tokens).count() as f64;
    let union = a_tokens.union(&b_tokens).count() as f64;
    if union == 0.0 {
        1.0
    } else {
        intersection / union
    }
}

fn is_significant_response_drift(baseline: &HttpResponse, variant: &HttpResponse) -> bool {
    if baseline.status >= 500 || variant.status >= 500 {
        return false;
    }

    let content_type_changed = content_type(baseline) != content_type(variant);
    let status_changed = baseline.status != variant.status;
    let similarity = token_similarity(&baseline.body, &variant.body);

    let long_enough = baseline.body.len() >= 40 && variant.body.len() >= 40;
    let low_similarity = similarity < 0.35;

    (status_changed || content_type_changed) && long_enough && low_similarity
}

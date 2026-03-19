// src/scanner/cors.rs

use async_trait::async_trait;
use rand::seq::SliceRandom;
use reqwest::header::{HeaderMap, HeaderValue};
use std::collections::HashSet;

use crate::{
    config::Config,
    error::CapturedError,
    http_client::{HttpClient, HttpResponse},
    reports::{Finding, Severity},
};

use super::Scanner;

pub struct CorsScanner;

impl CorsScanner {
    pub fn new(_config: &Config) -> Self {
        Self
    }
}

static REGEX_BYPASS_SUFFIXES: &[&str] = &[".cdn-edge.net", "%60.cdn-edge.net"];
static REGEX_BYPASS_PREFIXES: &[&str] = &["cdn", "img"];

fn extract_domain_from_url(url: &str) -> Option<String> {
    url.split("://")
        .nth(1)?
        .split('/')
        .next()
        .map(|s| s.to_string())
}

fn generate_probe_origins(url: &str) -> Vec<String> {
    let mut origins = vec!["null".to_string(), "https://cdn.example.net".to_string()];

    if let Some(domain) = extract_domain_from_url(url) {
        let scheme = if url.starts_with("https://") {
            "https"
        } else {
            "http"
        };
        origins.push(format!("{}://{}", scheme, domain));
        origins.push(format!("{}://app.{}", scheme, domain));
        origins.push(format!("{}://cdn.{}", scheme, domain));
        origins.push(format!("{}://www.{}", scheme, domain));
    }

    // Keep probe set unique and randomize order to avoid deterministic fingerprints.
    let mut seen = HashSet::new();
    origins.retain(|origin| seen.insert(origin.clone()));
    if origins.len() > 1 {
        let mut rng = rand::thread_rng();
        origins.shuffle(&mut rng);
    }

    origins
}

async fn probe_cors_response(
    client: &HttpClient,
    url: &str,
    origin: &str,
) -> Result<HttpResponse, CapturedError> {
    let mut preflight = HeaderMap::new();
    let origin_header = HeaderValue::from_str(origin).map_err(|e| {
        CapturedError::from_str(
            "cors/probe",
            Some(url.to_string()),
            format!("Invalid Origin header value '{origin}': {e}"),
        )
    })?;
    preflight.insert("Origin", origin_header);
    preflight.insert(
        "Access-Control-Request-Method",
        HeaderValue::from_static("GET"),
    );

    // Prefer OPTIONS probing (lower-impact than repeated GET requests).
    if let Ok(resp) = client.options(url, Some(preflight)).await {
        if resp.header("access-control-allow-origin").is_some() {
            return Ok(resp);
        }
    }

    let extra = [
        ("Origin".to_string(), origin.to_string()),
        (
            "Access-Control-Request-Method".to_string(),
            "GET".to_string(),
        ),
    ];
    client.get_with_headers(url, &extra).await
}

#[async_trait]
impl Scanner for CorsScanner {
    fn name(&self) -> &'static str {
        "cors"
    }

    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        let mut findings = Vec::new();
        let mut errors = Vec::new();
        let mut regex_bypass_checked = false;

        let probe_origins = generate_probe_origins(url);
        let target_origin = extract_domain_from_url(url)
            .map(|domain| {
                let scheme = if url.starts_with("https://") {
                    "https"
                } else {
                    "http"
                };
                format!("{}://{}", scheme, domain)
            })
            .unwrap_or_default();

        for origin in &probe_origins {
            let resp = match probe_cors_response(client, url, origin).await {
                Ok(r) => r,
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            };

            let acao = resp.header("access-control-allow-origin");
            let acac = resp.header("access-control-allow-credentials");

            // ── Wildcard with credentials (browser blocks, skip) ──────────────
            if acao == Some("*") && acac == Some("true") {
                continue;
            }

            // ── Wildcard without credentials (low severity) ────────────────────
            if acao == Some("*") && acac != Some("true") {
                findings.push(
                    Finding::new(
                        url,
                        "cors/wildcard-no-credentials",
                        "Wildcard CORS without credentials",
                        Severity::Low,
                        "ACAO header is '*' but credentials not allowed. Only exploitable if sensitive data exposed without auth.",
                        "cors",
                    )
                    .with_evidence(format!(
                        "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: {}",
                        acac.unwrap_or("-")
                    ))
                    .with_remediation(
                        "If endpoint handles sensitive data, restrict CORS to specific trusted origins.",
                    ),
                );
                break;
            }

            // ── Test regex bypasses if origin reflected ───────────────────────
            if let Some(reflected) = acao {
                if reflected == origin.as_str()
                    && origin != "null"
                    && (origin.starts_with("http://") || origin.starts_with("https://"))
                    && !regex_bypass_checked
                {
                    regex_bypass_checked = true;
                    for suffix in REGEX_BYPASS_SUFFIXES {
                        let bypass = format!("{}{}", reflected, suffix);
                        match probe_cors_response(client, url, &bypass).await {
                            Ok(r) => {
                                if r.header("access-control-allow-origin") == Some(&bypass)
                                    && r.header("access-control-allow-credentials") == Some("true")
                                {
                                    findings.push(
                                            Finding::new(
                                                url,
                                                "cors/regex-bypass-suffix",
                                                "CORS regex bypass (suffix)",
                                                Severity::High,
                                                format!("Origin validation uses weak regex — attacker can bypass by appending: {}", bypass),
                                                "cors",
                                            )
                                            .with_evidence(format!(
                                                "Origin: {}\nAccess-Control-Allow-Origin: {}\nAccess-Control-Allow-Credentials: true",
                                                bypass, bypass
                                            ))
                                            .with_remediation(
                                                "Use exact domain matching or strict regex anchors (^https://trusted\\.com$).",
                                            ),
                                        );
                                    break;
                                }
                            }
                            Err(e) => errors.push(e),
                        }
                    }

                    let (scheme, rest) = match reflected.split_once("://") {
                        Some((s, r)) => (s, r),
                        None => continue,
                    };
                    for prefix in REGEX_BYPASS_PREFIXES {
                        let bypass = format!("{}://{}{}", scheme, prefix, rest);
                        match probe_cors_response(client, url, &bypass).await {
                            Ok(r) => {
                                if r.header("access-control-allow-origin") == Some(&bypass)
                                    && r.header("access-control-allow-credentials") == Some("true")
                                {
                                    findings.push(
                                            Finding::new(
                                                url,
                                                "cors/regex-bypass-prefix",
                                                "CORS regex bypass (prefix)",
                                                Severity::High,
                                                format!("Origin validation uses weak regex — attacker can bypass by prepending: {}", bypass),
                                                "cors",
                                            )
                                            .with_evidence(format!(
                                                "Origin: {}\nAccess-Control-Allow-Origin: {}\nAccess-Control-Allow-Credentials: true",
                                                bypass, bypass
                                            ))
                                            .with_remediation(
                                                "Use exact domain matching or strict regex anchors (^https://trusted\\.com$).",
                                            ),
                                        );
                                    break;
                                }
                            }
                            Err(e) => errors.push(e),
                        }
                    }
                }
            }

            // ── Origin reflected ──────────────────────────────────────────────
            if acao == Some(origin.as_str()) {
                // Skip same-origin echoes; they are not exploitable via CORS.
                if !target_origin.is_empty() && origin.as_str() == target_origin.as_str() {
                    continue;
                }
                if *origin == "null" {
                    findings.push(
                        Finding::new(
                            url,
                            "cors/null-origin",
                            "Null origin accepted",
                            Severity::Medium,
                            "Server accepts 'null' origin, exploitable from sandboxed iframes \
                             or local file:// contexts.",
                            "cors",
                        )
                        .with_evidence(format!(
                            "Origin: null\nAccess-Control-Allow-Origin: null\n\
                             Access-Control-Allow-Credentials: {}",
                            acac.unwrap_or("-"),
                        ))
                        .with_remediation(
                            "Explicitly disallow the 'null' origin and restrict CORS to known origins.",
                        ),
                    );
                } else {
                    let creds = acac == Some("true");
                    findings.push(
                        Finding::new(
                            url,
                            "cors/reflected-origin",
                            "Reflected CORS origin",
                            if creds { Severity::High } else { Severity::Low },
                            if creds {
                                format!(
                                    "Origin '{origin}' reflected with credentials allowed — \
                                     potential credential theft via cross-origin request."
                                )
                            } else {
                                format!("Origin '{origin}' reflected (credentials not allowed).")
                            },
                            "cors",
                        )
                        .with_evidence(format!(
                            "Origin: {origin}\n\
                             Access-Control-Allow-Origin: {}\n\
                             Access-Control-Allow-Credentials: {}",
                            acao.unwrap_or("-"),
                            acac.unwrap_or("-"),
                        ))
                        .with_remediation(
                            "Validate origins against an allowlist and only enable credentials for trusted origins.",
                        ),
                    );
                }

                // Missing Vary: Origin when reflecting origin can create cache leaks.
                let vary = resp.header("vary").unwrap_or("");
                if !vary.to_ascii_lowercase().contains("origin") {
                    findings.push(
                        Finding::new(
                            url,
                            "cors/missing-vary-origin",
                            "CORS reflection without Vary: Origin",
                            Severity::Low,
                            "Origin is reflected but the response lacks Vary: Origin, which can cause cache poisoning and cross-tenant leaks.",
                            "cors",
                        )
                        .with_evidence(format!(
                            "Origin: {origin}\nVary: {}",
                            if vary.is_empty() { "-" } else { vary }
                        ))
                        .with_remediation(
                            "Add `Vary: Origin` to responses that reflect the Origin header.",
                        ),
                    );
                }
            }
        }

        // Active preflight method exposure check (opt-in).
        if config.active_checks {
            let origin = "https://cdn.example.net";
            let mut extra = reqwest::header::HeaderMap::new();
            extra.insert("Origin", HeaderValue::from_static(origin));
            extra.insert(
                "Access-Control-Request-Method",
                HeaderValue::from_static("DELETE"),
            );
            extra.insert(
                "Access-Control-Request-Headers",
                HeaderValue::from_static("authorization"),
            );

            match client.options(url, Some(extra)).await {
                Ok(resp) => {
                    let acao = resp.header("access-control-allow-origin");
                    let acam = resp
                        .header("access-control-allow-methods")
                        .unwrap_or("")
                        .to_ascii_uppercase();
                    let allowed = acam.contains("DELETE") || acam.contains("*");

                    if allowed && (acao == Some("*") || acao == Some(origin)) {
                        findings.push(
                            Finding::new(
                                url,
                                "cors/preflight-unsafe-methods",
                                "CORS preflight allows unsafe methods",
                                Severity::Medium,
                                "Preflight response allows unsafe methods for a hostile origin.",
                                "cors",
                            )
                            .with_evidence(format!(
                                "Origin: {origin}\nAccess-Control-Allow-Origin: {}\nAccess-Control-Allow-Methods: {}",
                                acao.unwrap_or("-"),
                                if acam.is_empty() { "-" } else { &acam }
                            ))
                            .with_remediation(
                                "Restrict allowed methods in CORS responses and require authentication for dangerous verbs.",
                            ),
                        );
                    }
                }
                Err(e) => errors.push(e),
            }
        }

        (findings, errors)
    }
}

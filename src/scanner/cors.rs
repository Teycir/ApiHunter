// src/scanner/cors.rs

use async_trait::async_trait;
use reqwest::header::HeaderValue;

use crate::{config::Config, error::CapturedError, http_client::HttpClient, reports::{Finding, Severity}};

use super::Scanner;

pub struct CorsScanner;

impl CorsScanner {
    pub fn new(_config: &Config) -> Self {
        Self
    }
}

static PROBE_ORIGINS: &[&str] = &[
    "https://evil.com",
    "null",
    "https://attacker.example.com",
];

#[async_trait]
impl Scanner for CorsScanner {
    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        let mut findings = Vec::new();
        let mut errors = Vec::new();

        for origin in PROBE_ORIGINS {
            let extra = [
                ("Origin".to_string(), origin.to_string()),
                (
                    "Access-Control-Request-Method".to_string(),
                    "GET".to_string(),
                ),
            ];

            let resp = match client.get_with_headers(url, &extra).await {
                Ok(r) => r,
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            };

            let acao = resp.header("access-control-allow-origin");
            let acac = resp.header("access-control-allow-credentials");

            // ── Wildcard ──────────────────────────────────────────────────────
            if acao == Some("*") {
                findings.push(
                    Finding::new(
                        url,
                        "cors/wildcard",
                        "Wildcard CORS",
                        Severity::Medium,
                        "ACAO header is '*', allowing any origin.",
                        "cors",
                    )
                    .with_evidence("Access-Control-Allow-Origin: *")
                    .with_remediation(
                        "Set Access-Control-Allow-Origin to specific trusted origins; avoid '*' on sensitive endpoints.",
                    ),
                );
                break;
            }

            // ── Origin reflected ──────────────────────────────────────────────
            if acao == Some(origin) {
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
            let origin = "https://evil.com";
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
                    let acam = resp.header("access-control-allow-methods").unwrap_or("").to_ascii_uppercase();
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

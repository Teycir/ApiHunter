// src/scanner/cors.rs

use async_trait::async_trait;

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
        _config: &Config,
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
                findings.push(Finding::new(
                    url,
                    "cors/wildcard",
                    "Wildcard CORS",
                    Severity::Medium,
                    "ACAO header is '*', allowing any origin.",
                    "cors",
                ).with_evidence("Access-Control-Allow-Origin: *"));
                break;
            }

            // ── Origin reflected ──────────────────────────────────────────────
            if acao == Some(origin) {
                let creds = acac == Some("true");
                findings.push(Finding::new(
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
                ).with_evidence(format!(
                    "Origin: {origin}\n\
                     Access-Control-Allow-Origin: {}\n\
                     Access-Control-Allow-Credentials: {}",
                    acao.unwrap_or("-"),
                    acac.unwrap_or("-"),
                )));
            }

            // ── null origin ───────────────────────────────────────────────────
            if *origin == "null" && acao == Some("null") {
                findings.push(Finding::new(
                    url,
                    "cors/null-origin",
                    "Null origin accepted",
                    Severity::Medium,
                    "Server accepts 'null' origin, exploitable from sandboxed iframes \
                     or local file:// contexts.",
                    "cors",
                ).with_evidence(format!(
                    "Origin: null\nAccess-Control-Allow-Origin: null\n\
                     Access-Control-Allow-Credentials: {}",
                    acac.unwrap_or("-"),
                )));
            }
        }

        (findings, errors)
    }
}

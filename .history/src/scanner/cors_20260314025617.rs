use async_trait::async_trait;

use crate::{config::Config, error::CapturedError, http_client::HttpClient};

use super::{Finding, Scanner, Severity};

pub struct CorsScanner;

/// Origins to inject for CORS probing
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
                ("Access-Control-Request-Method".to_string(), "GET".to_string()),
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

            // ── Wildcard CORS ─────────────────────────────────────────────────
            if acao.as_deref() == Some("*") {
                findings.push(Finding {
                    url: url.to_string(),
                    check: "cors/wildcard".to_string(),
                    severity: Severity::Medium,
                    detail: "ACAO header is set to '*', allowing any origin.".to_string(),
                    evidence: Some(format!("Access-Control-Allow-Origin: *")),
                });
                break; // No need to probe further with wildcard
            }

            // ── Origin reflected ──────────────────────────────────────────────
            if acao.as_deref() == Some(origin) {
                let creds_allowed = acac.as_deref() == Some("true");
                let (severity, detail) = if creds_allowed {
                    (
                        Severity::High,
                        format!(
                            "Origin '{origin}' is reflected with credentials allowed. \
                             Potential CORS misconfiguration leading to credential theft."
                        ),
                    )
                } else {
                    (
                        Severity::Low,
                        format!("Origin '{origin}' is reflected (no credentials)."),
                    )
                };

                findings.push(Finding {
                    url: url.to_string(),
                    check: "cors/reflected-origin".to_string(),
                    severity,
                    detail,
                    evidence: Some(format!(
                        "Origin: {origin}\nAccess-Control-Allow-Origin: {}\nAccess-Control-Allow-Credentials: {}",
                        acao.as_deref().unwrap_or("-"),
                        acac.as_deref().unwrap_or("-"),
                    )),
                });
            }

            // ── null origin accepted ──────────────────────────────────────────
            if *origin == "null" && acao.as_deref() == Some("null") {
                findings.push(Finding {
                    url: url.to_string(),
                    check: "cors/null-origin".to_string(),
                    severity

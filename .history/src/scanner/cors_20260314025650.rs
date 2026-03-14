use async_trait::async_trait;

use crate::{config::Config, error::CapturedError, http_client::HttpClient};

use super::{Finding, Scanner, Severity};

pub struct CorsScanner;

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
            if acao.as_deref() == Some("*") {
                findings.push(Finding {
                    url: url.to_string(),
                    check: "cors/wildcard".to_string(),
                    severity: Severity::Medium,
                    detail: "ACAO header is '*', allowing any origin.".to_string(),
                    evidence: Some("Access-Control-Allow-Origin: *".to_string()),
                });
                break;
            }

            // ── Origin reflected ──────────────────────────────────────────────
            if acao.as_deref() == Some(origin) {
                let creds = acac.as_deref() == Some("true");
                findings.push(Finding {
                    url: url.to_string(),
                    check: "cors/reflected-origin".to_string(),
                    severity: if creds { Severity::High } else { Severity::Low },
                    detail: if creds {
                        format!(
                            "Origin '{origin}' reflected with credentials allowed — \
                             potential credential theft via cross-origin request."
                        )
                    } else {
                        format!("Origin '{origin}' reflected (credentials not allowed).")
                    },
                    evidence: Some(format!(
                        "Origin: {origin}\n\
                         Access-Control-Allow-Origin: {}\n\
                         Access-Control-Allow-Credentials: {}",
                        acao.as_deref().unwrap_or("-"),
                        acac.as_deref().unwrap_or("-"),
                    )),
                });
            }

            // ── null origin ───────────────────────────────────────────────────
            if *origin == "null" && acao.as_deref() == Some("null") {
                findings.push(Finding {
                    url: url.to_string(),
                    check: "cors/null-origin".to_string(),
                    severity: Severity::Medium,
                    detail: "Server accepts 'null' origin, exploitable from sandboxed iframes \
                             or local file:// contexts."
                        .to_string(),
                    evidence: Some(format!(
                        "Origin: null\nAccess-Control-Allow-Origin: null\n\
                         Access-Control-Allow-Credentials: {}",
                        acac.as_deref().unwrap_or("-"),
                    )),
                });
            }
        }

        (findings, errors)
    }
}

use async_trait::async_trait;
use serde_json::json;

use crate::{
    config::Config,
    error::CapturedError,
    http_client::HttpClient,
    reports::{Finding, Severity},
};

use super::Scanner;

pub struct MassAssignmentScanner;

impl MassAssignmentScanner {
    pub fn new(_config: &Config) -> Self {
        Self
    }
}

static MUTATION_HINTS: &[&str] = &[
    "/users",
    "/user",
    "/account",
    "/profile",
    "/admin",
    "/settings",
    "/roles",
    "/permissions",
];

#[async_trait]
impl Scanner for MassAssignmentScanner {
    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        if !config.active_checks || !is_likely_mutation_target(url) {
            return (Vec::new(), Vec::new());
        }

        let mut findings = Vec::new();
        let mut errors = Vec::new();

        let payload = json!({
            "__ah_probe": "1",
            "is_admin": true,
            "role": "admin",
            "permissions": ["*"]
        });

        let resp = match client.post_json(url, &payload).await {
            Ok(r) => r,
            Err(e) => {
                errors.push(e);
                return (findings, errors);
            }
        };

        if resp.status >= 400 {
            return (findings, errors);
        }

        let ct = resp
            .headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let json_like =
            ct.contains("json") || serde_json::from_str::<serde_json::Value>(&resp.body).is_ok();
        if !json_like {
            return (findings, errors);
        }

        let reflected = reflected_probe_fields(&resp.body);
        if !reflected.is_empty() {
            findings.push(
                Finding::new(
                    url,
                    "mass_assignment/reflected-fields",
                    "Potential mass-assignment via reflected fields",
                    Severity::Medium,
                    "Response reflected crafted sensitive fields from request payload.",
                    "mass_assignment",
                )
                .with_evidence(format!(
                    "POST {url}\nStatus: {}\nReflected fields: {}",
                    resp.status,
                    reflected.join(", ")
                ))
                .with_remediation(
                    "Use explicit allowlists for writeable fields and reject unexpected attributes server-side.",
                ),
            );
        }

        (findings, errors)
    }
}

fn is_likely_mutation_target(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    MUTATION_HINTS.iter().any(|k| lower.contains(k))
}

fn reflected_probe_fields(body: &str) -> Vec<&'static str> {
    let mut out = Vec::new();
    for key in ["__ah_probe", "is_admin", "role", "permissions"] {
        let needle = format!("\"{key}\"");
        if body.contains(&needle) {
            out.push(key);
        }
    }
    out
}

pub mod cors;
pub mod csp;
pub mod graphql;
pub mod api_security;

use crate::{error::CapturedError, http_client::HttpClient, config::Config};

/// A single scanner finding.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub url: String,
    pub check: String,
    pub severity: Severity,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Every scanner module implements this trait.
#[async_trait::async_trait]
pub trait Scanner: Send + Sync {
    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>);
}


// src/scanner/mod.rs  (trait definition, already in your codebase)
#[async_trait::async_trait]
pub trait Scanner: Send + Sync + 'static {
    /// Run this scanner against a single URL.
    /// Returns `(findings, errors)` — never propagates.
    async fn scan(
        &self,
        url:    &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>);
}

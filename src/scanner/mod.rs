// src/scanner/mod.rs
//
// Scanner trait definition and shared types.

pub mod api_security;
pub mod cors;
pub mod csp;
pub mod graphql;
pub mod jwt;
pub mod openapi;
pub mod websocket;

use crate::{config::Config, error::CapturedError, http_client::HttpClient, reports::Finding};

/// Every scanner module implements this trait.
///
/// `scan()` returns `(findings, errors)` and must never panic; all internal
/// errors should be captured and returned in the error vector.
#[async_trait::async_trait]
pub trait Scanner: Send + Sync + 'static {
    /// Run this scanner against a single URL.
    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>);
}

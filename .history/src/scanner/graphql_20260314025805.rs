use async_trait::async_trait;
use serde_json::{json, Value};
use tracing::debug;

use crate::{config::Config, error::CapturedError, http_client::HttpClient};

use super::{Finding, Scanner, Severity};

pub struct GraphqlScanner;

/// Common GraphQL endpoint suffixes to probe when a base URL is given.
static GQL_PATHS: &[&str] = &[
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/gql",
];

/// Standard introspection query (full schema).
const INTROSPECTION_QUERY: &str = r#"
{
  "__schema": {
    "queryType": { "name": null },
    "types": [
      {
        "kind": null,
        "name": null,
        "fields": [
          { "name": null }
        ]
      }
    ]
  }
}
"#;

fn introspection_payload() -> Value {
    json!({
        "query": "{ __schema { queryType { name } types { kind name fields { name } } } }"
    })
}

fn field_suggestion_payload() -> Value {
    json!({ "query": "{ __typ }" })
}

#[async_trait]
impl Scanner for GraphqlScanner {
    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        _config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        let mut findings = Vec::new();
        let mut errors = Vec::new();

        // Build candidate URLs: if the URL already ends with a known GQL path
        // just use it; otherwise also probe common suffixes.
        let mut candidates: Vec<String> = Vec::new();
        let lower = url.to_ascii_lowercase();
        let already_gql = GQL_PATHS.iter().any(|p| lower.ends_with(p));

        if already_gql {
            candidates.push(url.to_string());
        } else {
            candidates.push(url.to_string()); // original
            let base = url.trim_end_matches('/');
            for path in GQL_PATHS {
                candidates.push(format!("{base}{path}"));
            }
        }

        for candidate in &candidates {
            probe_endpoint(candidate, client, &mut findings, &mut errors).await;
        }

        (findings, errors)
    }
}

async fn probe_endpoint(
    url: &str,
    client: &HttpClient,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    // ── 1. Introspection ──────────────────────────────────────────────────────
    let payload = introspection_payload();
    let resp = match client.post_json(url, &payload).await {
        Ok(r) => r,
        Err(e) => {
            errors.push(e);
            return;
        }
    };

    // Not a GraphQL endpoint at all
    if resp.status >= 400 && resp.status != 400 {
        return;
    }

    let body: Value = match serde_json::from_str(&resp.body) {
        Ok(v) => v,
        Err(_) => return,
    };

    // ── Introspection enabled? ────────────────────────────────────────────────
    if body.pointer("/__schema/types").is_some()
        || body.pointer("/data/__schema/types").is_some()
    {
        debug!("[graphql] introspection enabled at {url


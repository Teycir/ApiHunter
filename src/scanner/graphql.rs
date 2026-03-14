// src/scanner/graphql.rs

use async_trait::async_trait;
use serde_json::{json, Value};
use tracing::debug;

use crate::{config::Config, error::CapturedError, http_client::HttpClient, reports::{Finding, Severity}};

use super::Scanner;

pub struct GraphqlScanner;

impl GraphqlScanner {
    pub fn new(_config: &Config) -> Self {
        Self
    }
}

static GQL_PATHS: &[&str] = &[
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/gql",
];

// ── Payloads ──────────────────────────────────────────────────────────────────

fn introspection_payload() -> Value {
    json!({
        "query": "{ __schema { queryType { name } types { kind name \
                   fields { name args { name type { name kind } } } } } }"
    })
}

fn field_suggestion_payload() -> Value {
    json!({ "query": "{ __typ }" })
}

fn batch_payload() -> Value {
    json!([
        { "query": "{ __typename }" },
        { "query": "{ __typename }" }
    ])
}

fn alias_dos_payload() -> Value {
    let aliases: String = (0..10)
        .map(|i| format!("a{i}: __typename "))
        .collect();
    json!({ "query": format!("{{ {aliases} }}") })
}

// ── Sensitive type / field names that warrant a finding ───────────────────────
static SENSITIVE_TYPES: &[&str] = &[
    "user", "users", "admin", "password", "secret", "token",
    "apikey", "api_key", "credential", "auth", "session", "privatekey",
    "ssn", "creditcard", "payment", "billing",
];

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

        // Build candidate endpoint list
        let lower = url.to_ascii_lowercase();
        let already_gql = GQL_PATHS.iter().any(|p| lower.ends_with(p));

        let mut candidates: Vec<String> = Vec::new();
        candidates.push(url.to_string());
        if !already_gql {
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

// ── Per-endpoint probing ──────────────────────────────────────────────────────

async fn probe_endpoint(
    url: &str,
    client: &HttpClient,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    // ── Step 1: Introspection ─────────────────────────────────────────────────
    let payload = introspection_payload();
    let resp = match client.post_json(url, &payload).await {
        Ok(r) => r,
        Err(e) => {
            errors.push(e);
            return;
        }
    };

    // Non-GraphQL or hard error — skip remaining checks for this candidate.
    // Status >= 500 is a server error; 401-499 (except 400) are auth/not-found.
    if resp.status >= 500 || (resp.status >= 401) {
        return;
    }

    let body: Value = match serde_json::from_str(&resp.body) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Locate the `types` array regardless of whether it sits under `data`
    let types_ptr = body
        .pointer("/data/__schema/types")
        .or_else(|| body.pointer("/__schema/types"));

    if let Some(types_val) = types_ptr {
        // ── 1a. Introspection enabled ─────────────────────────────────────────
        findings.push(Finding::new(
            url,
            "graphql/introspection-enabled",
            "GraphQL introspection enabled",
            Severity::Medium,
            "GraphQL introspection is enabled. Full schema is publicly discoverable.",
            "graphql",
        ).with_evidence(format!(
            "POST {url}\nPayload: {payload}\nStatus: {}",
            resp.status
        )));

        // ── 1b. Sensitive type / field names in schema ────────────────────────
        if let Some(types) = types_val.as_array() {
            let mut matched: Vec<String> = Vec::new();

            for t in types {
                let type_name = t["name"]
                    .as_str()
                    .unwrap_or("")
                    .to_ascii_lowercase();

                if is_sensitive(&type_name) && !type_name.starts_with("__") {
                    matched.push(format!("type:{type_name}"));
                }

                if let Some(fields) = t["fields"].as_array() {
                    for field in fields {
                        let fname = field["name"]
                            .as_str()
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        if is_sensitive(&fname) {
                            matched.push(format!(
                                "{}::{}",
                                t["name"].as_str().unwrap_or("?"),
                                fname
                            ));
                        }
                    }
                }
            }

            if !matched.is_empty() {
                findings.push(Finding::new(
                    url,
                    "graphql/sensitive-schema-fields",
                    "Sensitive GraphQL schema fields",
                    Severity::High,
                    format!(
                        "Schema exposes potentially sensitive types/fields: {}",
                        matched.join(", ")
                    ),
                    "graphql",
                ).with_evidence(format!("Matched names: {}", matched.join(", "))));
            }
        }
    } else if let Some(errors_val) = body.get("errors") {
        debug!("[graphql] introspection disabled at {url}: {errors_val}");
        findings.push(Finding::new(
            url,
            "graphql/endpoint-detected",
            "GraphQL endpoint detected",
            Severity::Info,
            "GraphQL endpoint detected; introspection is disabled (good).",
            "graphql",
        ).with_evidence(format!("Errors: {errors_val}")));
    }

    // ── Step 2: Field suggestions (information leakage) ──────────────────────
    let sugg_payload = field_suggestion_payload();
    if let Ok(sr) = client.post_json(url, &sugg_payload).await {
        if let Ok(sb) = serde_json::from_str::<Value>(&sr.body) {
            let has_suggestion = sb["errors"]
                .as_array()
                .map(|errs| {
                    errs.iter().any(|e| {
                        e["message"]
                            .as_str()
                            .map(|m| {
                                m.contains("Did you mean") || m.contains("did you mean")
                            })
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);

            if has_suggestion {
                findings.push(Finding::new(
                    url,
                    "graphql/field-suggestions",
                    "GraphQL field suggestions enabled",
                    Severity::Low,
                    "Server returns field-name suggestions in errors, leaking schema \
                     information even with introspection disabled.",
                    "graphql",
                ).with_evidence(sr.body.chars().take(512).collect::<String>()));
            }
        }
    }

    // ── Step 3: Query batching ────────────────────────────────────────────────
    let batch = batch_payload();
    if let Ok(br) = client.post_json(url, &batch).await {
        if let Ok(bv) = serde_json::from_str::<Value>(&br.body) {
            if bv.as_array().map(|a| a.len() >= 2).unwrap_or(false) {
                findings.push(Finding::new(
                    url,
                    "graphql/batching-enabled",
                    "GraphQL query batching enabled",
                    Severity::Low,
                    "GraphQL query batching is enabled. This can amplify DoS impact \
                     and may bypass rate limiting applied per-request.",
                    "graphql",
                ).with_evidence(br.body.chars().take(256).collect::<String>()));
            }
        }
    }

    // ── Step 4: Alias amplification probe ────────────────────────────────────
    let alias = alias_dos_payload();
    if let Ok(ar) = client.post_json(url, &alias).await {
        if let Ok(av) = serde_json::from_str::<Value>(&ar.body) {
            let resolved = (0..10)
                .filter(|i| av.pointer(&format!("/data/a{i}")).is_some())
                .count();
            if resolved >= 10 {
                findings.push(Finding::new(
                    url,
                    "graphql/alias-amplification",
                    "GraphQL alias amplification possible",
                    Severity::Low,
                    "Server resolves all query aliases without restriction. \
                     Malicious clients can craft deeply aliased queries to amplify \
                     server-side work (alias-based DoS).",
                    "graphql",
                ).with_evidence(format!("{resolved}/10 aliases resolved")));
            }
        }
    }

    // ── Step 5: GraphiQL / playground UI exposed ──────────────────────────────
    if let Ok(gr) = client.get(url).await {
        let body_lower = gr.body.to_ascii_lowercase();
        if body_lower.contains("graphiql") || body_lower.contains("graphql playground") {
            findings.push(Finding::new(
                url,
                "graphql/playground-exposed",
                "GraphQL IDE exposed",
                Severity::Low,
                "GraphQL IDE (GraphiQL / Playground) is exposed. Attackers can \
                 interactively explore and query the API.",
                "graphql",
            ).with_evidence(format!("GET {url} → HTML contains IDE marker")));
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn is_sensitive(name: &str) -> bool {
    SENSITIVE_TYPES
        .iter()
        .any(|&s| name == s || name.contains(s))
}

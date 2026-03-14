// src/auth.rs
//
// Authentication flow: load a JSON flow descriptor, execute the login
// sequence, extract credentials, and optionally refresh them mid-scan.

use std::{path::Path, sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use jsonpath_rust::JsonPathFinder;
use reqwest::{
    cookie::Jar,
    header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE},
};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// ── Flow descriptor ───────────────────────────────────────────────────────────

/// How the extracted credential is injected into every request.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectAs {
    /// Sets `Authorization: Bearer <value>`
    Bearer,
    /// Sets `Authorization: Basic <base64(value)>`  (value must be "user:pass")
    Basic,
    /// Sets a named header: `header_name: <value>`
    Header(String),
    /// Adds the value as a cookie: `cookie_name=<value>`
    Cookie(String),
}

/// One HTTP step in the auth flow.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthStep {
    /// Full URL to hit.
    pub url: String,
    /// HTTP method (GET, POST, PUT…). Default: POST.
    #[serde(default = "default_post")]
    pub method: String,
    /// Optional JSON request body. Supports `{{ENV_VAR}}` substitution.
    pub body: Option<Value>,
    /// Optional extra headers for this step only.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    /// JSONPath expression to extract the credential value from the response.
    /// e.g. `"$.data.access_token"` or `"$.access_token"`
    pub extract: Option<String>,
    /// Where to extract the refresh token (optional).
    pub extract_refresh: Option<String>,
    /// Where to extract expiry in seconds from now (optional).
    /// e.g. `"$.expires_in"` — if absent, refresh_interval_secs is used.
    pub extract_expires_in: Option<String>,
    /// How to inject the extracted value into all subsequent requests.
    pub inject_as: Option<InjectAs>,
}

/// Top-level auth flow descriptor — loaded from `--auth-flow <file>`.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthFlow {
    /// Ordered list of HTTP steps. Usually 1 step (POST /login).
    pub steps: Vec<AuthStep>,
    /// How often (seconds) to refresh the token proactively.
    /// If `extract_expires_in` is set, that value overrides this.
    #[serde(default = "default_refresh_secs")]
    pub refresh_interval_secs: u64,
}

fn default_post() -> String {
    "POST".to_string()
}
fn default_refresh_secs() -> u64 {
    840
} // 14 minutes — safe for most 15-min tokens

// ── Loaded / live credential ──────────────────────────────────────────────────

/// The resolved, live credential produced by executing the flow.
#[derive(Debug, Clone)]
pub struct LiveCredential {
    /// The primary credential value (token, cookie value…).
    pub value: Arc<RwLock<String>>,
    /// Optional refresh token.
    pub refresh_value: Option<Arc<RwLock<String>>>,
    /// How to apply it.
    pub inject_as: InjectAs,
    /// For token refresh: seconds before expiry to trigger refresh.
    pub refresh_lead_secs: u64,
}

impl LiveCredential {
    /// Read the current token value.
    pub async fn current(&self) -> String {
        self.value.read().await.clone()
    }

    /// Apply this credential to a HeaderMap (called per-request in HttpClient).
    pub async fn apply_to(&self, map: &mut HeaderMap) {
        let val = self.current().await;
        match &self.inject_as {
            InjectAs::Bearer => {
                if let Ok(v) = HeaderValue::from_str(&format!("Bearer {val}")) {
                    map.insert(reqwest::header::AUTHORIZATION, v);
                }
            }
            InjectAs::Basic => {
                use base64::engine::general_purpose::STANDARD;
                use base64::Engine;
                let encoded = STANDARD.encode(val.as_bytes());
                if let Ok(v) = HeaderValue::from_str(&format!("Basic {encoded}")) {
                    map.insert(reqwest::header::AUTHORIZATION, v);
                }
            }
            InjectAs::Header(name) => {
                if let (Ok(k), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(&val),
                ) {
                    map.insert(k, v);
                }
            }
            InjectAs::Cookie(name) => {
                let cookie = format!("{name}={val}");
                // Merge with existing Cookie header if present
                let key = reqwest::header::COOKIE;
                let merged = if let Some(existing) = map.get(&key) {
                    let existing = existing.to_str().unwrap_or("");
                    format!("{existing}; {cookie}")
                } else {
                    cookie
                };
                if let Ok(v) = HeaderValue::from_str(&merged) {
                    map.insert(key, v);
                }
            }
        }
    }
}

// ── Auth flow loader ──────────────────────────────────────────────────────────

pub fn load_flow(path: &Path) -> Result<AuthFlow> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read auth flow file: {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| "Auth flow file is not valid JSON")
}

// ── Flow executor ─────────────────────────────────────────────────────────────

/// Execute all steps in the auth flow using a plain reqwest client
/// (not the scanner's HttpClient, to avoid circular dependency).
/// Returns the live credential ready for injection.
pub async fn execute_flow(flow: &AuthFlow) -> Result<LiveCredential> {
    let jar = Arc::new(Jar::default());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .cookie_provider(Arc::clone(&jar))
        .build()
        .context("Failed to build auth client")?;

    let mut last_credential: Option<LiveCredential> = None;

    for (i, step) in flow.steps.iter().enumerate() {
        info!(
            "Auth flow step {}/{}: {} {}",
            i + 1,
            flow.steps.len(),
            step.method,
            step.url
        );

        let url = substitute_env_vars(&step.url);

        let mut req = client.request(
            step.method.parse().context("Invalid HTTP method in auth flow")?,
            &url,
        );

        // Apply step-level headers
        for (k, v) in &step.headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(&substitute_env_vars(v)),
            ) {
                req = req.header(name, value);
            }
        }

        // Apply the previous step's credential to subsequent steps
        if let Some(ref cred) = last_credential {
            let mut map = HeaderMap::new();
            cred.apply_to(&mut map).await;
            req = req.headers(map);
        }

        if let Some(ref body) = step.body {
            let substituted = substitute_env_vars_in_value(body);
            req = req
                .header(CONTENT_TYPE, "application/json")
                .json(&substituted);
        }

        let resp = req.send().await.context("Auth flow request failed")?;
        let status = resp.status().as_u16();

        if status >= 400 {
            bail!("Auth flow step {} returned HTTP {status}", i + 1);
        }

        let body: Value = resp
            .json()
            .await
            .context("Auth flow response is not JSON")?;
        debug!("Auth flow step {} response: {}", i + 1, body);

        if let (Some(extract), Some(inject_as)) = (&step.extract, &step.inject_as) {
            let token = extract_jsonpath(&body, extract)
                .with_context(|| format!("JSONPath '{extract}' matched nothing in auth response"))?;

            let expires_in = step
                .extract_expires_in
                .as_ref()
                .and_then(|p| extract_jsonpath(&body, p).ok())
                .and_then(|v| v.parse::<u64>().ok());

            let refresh_value = step
                .extract_refresh
                .as_ref()
                .and_then(|p| extract_jsonpath(&body, p).ok())
                .map(|v| Arc::new(RwLock::new(v)));

            let refresh_interval = expires_in
                .map(|e| e.saturating_sub(60)) // refresh 60s before expiry
                .filter(|v| *v > 0)
                .unwrap_or(flow.refresh_interval_secs);

            info!("Auth flow: credential obtained (refresh in {refresh_interval}s)");

            last_credential = Some(LiveCredential {
                value: Arc::new(RwLock::new(token)),
                refresh_value,
                inject_as: inject_as.clone(),
                refresh_lead_secs: refresh_interval,
            });
        }
    }

    last_credential.context("Auth flow completed but no credential was extracted")
}

// ── Token refresh background task ─────────────────────────────────────────────

/// Spawn a background task that re-executes the auth flow before the token
/// expires. Writes the new token into `cred.value` so all in-flight requests
/// automatically pick it up on the next read.
pub fn spawn_refresh_task(flow: AuthFlow, cred: Arc<LiveCredential>) {
    tokio::spawn(async move {
        loop {
            let sleep_secs = cred.refresh_lead_secs.max(1);
            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;

            info!("Auth flow: refreshing credential…");
            match execute_flow(&flow).await {
                Ok(new_cred) => {
                    let new_val = new_cred.current().await;
                    *cred.value.write().await = new_val.clone();
                    info!("Auth flow: credential refreshed successfully");
                }
                Err(e) => {
                    warn!("Auth flow: refresh failed — {e}. Continuing with existing token.");
                }
            }
        }
    });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract a value from a JSON document using a JSONPath expression.
/// Supports both `$.foo.bar` (dot notation) and `/foo/bar` (JSON Pointer).
fn extract_jsonpath(doc: &Value, path: &str) -> Result<String> {
    // Fast path: JSON Pointer (RFC 6901)
    if path.starts_with('/') {
        return doc
            .pointer(path)
            .and_then(|v| {
                v.as_str()
                    .map(|s| s.to_string())
                    .or_else(|| v.as_i64().map(|n| n.to_string()))
            })
            .context("JSON Pointer matched nothing");
    }

    // JSONPath: $.foo.bar style
    let finder = JsonPathFinder::from_str(&doc.to_string(), path)
        .map_err(|e| anyhow::anyhow!("JSONPath error: {e}"))?;
    let first = finder.find();
    if let Value::Array(arr) = &first {
        if let Some(v) = arr.first() {
            return v
                .as_str()
                .map(|s| s.to_string())
                .or_else(|| v.as_i64().map(|n| n.to_string()))
                .context("JSONPath result is not a string or integer");
        }
    }
    bail!("JSONPath '{path}' matched nothing in response")
}

/// Replace `{{ENV_VAR}}` placeholders with environment variable values.
fn substitute_env_vars(s: &str) -> String {
    let mut out = s.to_string();
    let re = once_cell::sync::Lazy::force(&ENV_RE);
    for cap in re.captures_iter(s) {
        let var_name = &cap[1];
        let replacement = std::env::var(var_name).unwrap_or_default();
        out = out.replace(&cap[0], &replacement);
    }
    out
}

fn substitute_env_vars_in_value(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(substitute_env_vars(s)),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), substitute_env_vars_in_value(v)))
                .collect(),
        ),
        Value::Array(arr) => Value::Array(arr.iter().map(substitute_env_vars_in_value).collect()),
        other => other.clone(),
    }
}

static ENV_RE: once_cell::sync::Lazy<regex::Regex> =
    once_cell::sync::Lazy::new(|| regex::Regex::new(r"\{\{([A-Z0-9_]+)\}\}").unwrap());

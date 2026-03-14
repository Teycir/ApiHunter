use std::collections::HashSet;

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;
use tracing::{debug, warn};
use url::Url;

use crate::{error::CapturedError, http_client::HttpClient};

use super::normalize_path;

static PATH_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"["'](/[a-zA-Z0-9_/\-\.\{\}]{2,120})["']"#).unwrap());

// ── Minimal OpenAPI v3 ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
struct OpenApiV3 {
    paths: Option<std::collections::HashMap<String, serde_json::Value>>,
    servers: Option<Vec<ServerObject>>,
}

#[derive(Debug, Deserialize)]
struct ServerObject {
    url: String,
}

// ── Minimal Swagger v2 ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
struct SwaggerV2 {
    paths: Option<std::collections::HashMap<String, serde_json::Value>>,
    #[serde(rename = "basePath")]
    base_path: Option<String>,
    host: Option<String>,
    schemes: Option<Vec<String>>,
}

// ── Discovery struct ─────────────────────────────────────────────────────────

pub struct SwaggerDiscovery<'a> {
    client: &'a HttpClient,
    base_url: &'a str,
    host: &'a str,
}

/// Well-known OpenAPI / Swagger spec locations to probe.
static SPEC_PATHS: &[&str] = &[
    "/swagger.json",
    "/swagger.yaml",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs.json",
    "/api-docs.yaml",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/api-docs", // Spring Boot default
    "/v3/api-docs.yaml",
];

impl<'a> SwaggerDiscovery<'a> {
    pub fn new(client: &'a HttpClient, base_url: &'a str, host: &'a str) -> Self {
        Self {
            client,
            base_url,
            host,
        }
    }

    pub async fn run(&self) -> (HashSet<String>, Vec<CapturedError>) {
        let mut paths = HashSet::new();
        let mut errors = Vec::new();

        let base = self.base_url.trim_end_matches('/');

        for spec_path in SPEC_PATHS {
            let url = format!("{base}{spec_path}");

            let resp = match self.client.get(&url).await {
                Ok(r) if r.status < 400 => r,
                Ok(_) => continue,
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            };

            debug!("[swagger] found spec at {url}");
            self.client.cache_spec(&url, &resp.body);
            self.parse_spec(&resp.body, &mut paths, &mut errors);
        }

        debug!("[swagger] total paths extracted: {}", paths.len());
        (paths, errors)
    }

    // ── Parse dispatch ────────────────────────────────────────────────────────

    fn parse_spec(&self, body: &str, paths: &mut HashSet<String>, errors: &mut Vec<CapturedError>) {
        // Try JSON first (most common), then YAML
        if body.trim_start().starts_with('{') || body.trim_start().starts_with('[') {
            self.parse_json(body, paths, errors);
        } else {
            self.parse_yaml(body, paths, errors);
        }
    }

    // ── JSON parsing ──────────────────────────────────────────────────────────

    fn parse_json(&self, body: &str, paths: &mut HashSet<String>, errors: &mut Vec<CapturedError>) {
        // Detect spec version from raw JSON before full deserialisation
        let version_hint = body.contains("\"openapi\"");

        if version_hint {
            match serde_json::from_str::<OpenApiV3>(body) {
                Ok(spec) => self.harvest_v3(spec, paths),
                Err(e) => {
                    warn!("[swagger] OpenAPI v3 parse failed: {e}");
                    errors.push(CapturedError::parse("swagger/openapi-v3", e.to_string()));
                    self.fallback_regex(body, paths);
                }
            }
        } else {
            match serde_json::from_str::<SwaggerV2>(body) {
                Ok(spec) => self.harvest_v2(spec, paths),
                Err(e) => {
                    warn!("[swagger] Swagger v2 parse failed: {e}");
                    errors.push(CapturedError::parse("swagger/swagger-v2", e.to_string()));
                    self.fallback_regex(body, paths);
                }
            }
        }
    }

    // ── YAML parsing ──────────────────────────────────────────────────────────

    fn parse_yaml(&self, body: &str, paths: &mut HashSet<String>, errors: &mut Vec<CapturedError>) {
        // Try OpenAPI v3 YAML
        if body.contains("openapi:") {
            match serde_yaml::from_str::<OpenApiV3>(body) {
                Ok(spec) => {
                    self.harvest_v3(spec, paths);
                    return;
                }
                Err(e) => {
                    warn!("[swagger] YAML OpenAPI v3 parse failed: {e}");
                    errors.push(CapturedError::parse("swagger/yaml-v3", e.to_string()));
                }
            }
        }

        // Try Swagger v2 YAML
        match serde_yaml::from_str::<SwaggerV2>(body) {
            Ok(spec) => self.harvest_v2(spec, paths),
            Err(e) => {
                warn!("[swagger] YAML Swagger v2 parse failed: {e}");
                errors.push(CapturedError::parse("swagger/yaml-v2", e.to_string()));
                self.fallback_regex(body, paths);
            }
        }
    }

    // ── Harvesters ────────────────────────────────────────────────────────────

    /// Extract paths from an OpenAPI v3 spec.
    /// Respects `servers[].url` to build absolute endpoints when possible.
    fn harvest_v3(&self, spec: OpenApiV3, paths: &mut HashSet<String>) {
        // Collect server base URLs that belong to this host
        let server_bases: Vec<String> = spec
            .servers
            .unwrap_or_default()
            .into_iter()
            .filter_map(|s| {
                let url = s.url;
                // Relative server URL (e.g. "/api/v1") — prefix with base
                if url.starts_with('/') {
                    return Some(format!("{}{}", self.base_url.trim_end_matches('/'), url));
                }
                // Absolute URL — only keep same-host
                Url::parse(&url)
                    .ok()
                    .filter(|u| u.host_str() == Some(self.host))
                    .map(|u| u.to_string())
            })
            .collect();

        for raw_path in spec.paths.unwrap_or_default().into_keys() {
            // Strip OpenAPI path-templating: /users/{id} → /users/{id} kept as-is
            // but we still emit it for endpoint enumeration
            if server_bases.is_empty() {
                if let Some(p) = normalize_path(&raw_path, self.host) {
                    paths.insert(p);
                }
            } else {
                for base in &server_bases {
                    let full = format!(
                        "{}/{}",
                        base.trim_end_matches('/'),
                        raw_path.trim_start_matches('/')
                    );
                    if let Some(p) = normalize_path(&full, self.host) {
                        paths.insert(p);
                    }
                }
            }
        }
    }

    /// Extract paths from a Swagger v2 spec.
    /// Builds the base from `schemes + host + basePath` when available.
    fn harvest_v2(&self, spec: SwaggerV2, paths: &mut HashSet<String>) {
        // Try to construct the v2 server base
        let server_base: Option<String> = spec.host.as_ref().and_then(|h| {
            // Only use if same host
            let canonical = h.split(':').next().unwrap_or(h);
            if canonical != self.host {
                return None;
            }
            let scheme = spec
                .schemes
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .find(|s| s.as_str() == "https" || s.as_str() == "http")
                .map(|s| s.as_str())
                .unwrap_or("https");

            let bp = spec
                .base_path
                .as_deref()
                .unwrap_or("")
                .trim_end_matches('/');

            Some(format!("{scheme}://{h}{bp}"))
        });

        for raw_path in spec.paths.unwrap_or_default().into_keys() {
            let candidate = if let Some(ref base) = server_base {
                format!(
                    "{}/{}",
                    base.trim_end_matches('/'),
                    raw_path.trim_start_matches('/')
                )
            } else {
                // Prepend basePath only if it's a relative path
                let bp = spec
                    .base_path
                    .as_deref()
                    .unwrap_or("")
                    .trim_end_matches('/');
                format!("{bp}{raw_path}")
            };

            if let Some(p) = normalize_path(&candidate, self.host) {
                paths.insert(p);
            }
        }
    }

    // ── Regex fallback ────────────────────────────────────────────────────────

    /// When structured parsing fails, scrape any path-like strings from the raw body.
    fn fallback_regex(&self, body: &str, paths: &mut HashSet<String>) {
        for cap in PATH_RE.captures_iter(body) {
            let raw = &cap[1];
            if let Some(p) = normalize_path(raw, self.host) {
                paths.insert(p);
            }
        }
    }
}

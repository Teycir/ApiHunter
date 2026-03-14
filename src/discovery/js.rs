use std::collections::HashSet;

use once_cell::sync::Lazy;
use regex::Regex;
use tracing::{debug, warn};
use url::Url;

use crate::{error::CapturedError, http_client::HttpClient};

use super::normalize_path;

// Pre-compiled patterns for extracting API paths from JS
static API_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // fetch("/api/...") / axios.get("/v1/...")
        Regex::new(
            r#"(?:fetch|axios|\.request|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*['"](/[^'"]{2,150})['"]"#,
        )
        .unwrap(),
        // Explicit API prefixes
        Regex::new(r#"['"](?:/api|/v\d|/graphql|/rest|/internal|/private|/admin)([^'"]{0,120})['"]"#)
            .unwrap(),
        // url: "/something"
        Regex::new(r#"(?:url|endpoint|path|baseURL|base_url)\s*[=:]\s*['"](/[^'"]{2,120})['"]"#)
            .unwrap(),
    ]
});

// <script src="...">
static SCRIPT_SRC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"<script[^>]+src=['"]([^'"]+)['"]"#).unwrap());

// Inline <script>...</script>
static INLINE_SCRIPT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)<script[^>]*>(.*?)</script>").unwrap());

// sourceMappingURL
static SOURCEMAP: Lazy<Regex> = Lazy::new(|| Regex::new(r"sourceMappingURL=([^\s*]+)").unwrap());

pub struct JsDiscovery<'a> {
    client: &'a HttpClient,
    target_url: &'a str,
    host: &'a str,
    max_scripts: usize,
}

impl<'a> JsDiscovery<'a> {
    pub fn new(
        client: &'a HttpClient,
        target_url: &'a str,
        host: &'a str,
        max_scripts: usize,
    ) -> Self {
        Self {
            client,
            target_url,
            host,
            max_scripts,
        }
    }

    /// Main entry: parse the target page, extract + analyse JS files
    pub async fn run(&self) -> (HashSet<String>, Vec<CapturedError>) {
        let mut endpoints = HashSet::new();
        let mut errors: Vec<CapturedError> = Vec::new();

        let resp = match self.client.get(self.target_url).await {
            Ok(r) => r,
            Err(e) => {
                errors.push(e);
                return (endpoints, errors);
            }
        };

        let page = &resp.body;

        // 1. Collect external script URLs
        let script_urls: Vec<String> = SCRIPT_SRC
            .captures_iter(page)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .take(self.max_scripts)
            .collect();

        // 2. Analyse external scripts (+ sourcemaps)
        for src in &script_urls {
            let full_url = match self.resolve(src) {
                Some(u) => u,
                None => continue,
            };

            match self.client.get(&full_url).await {
                Ok(sr) => {
                    self.extract_from_text(&sr.body, &mut endpoints);
                    // Try sourcemap
                    if let Some(sm_path) = SOURCEMAP
                        .captures(&sr.body)
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str().to_string())
                    {
                        if let Some(sm_url) = self.resolve_from(&full_url, &sm_path) {
                            let (mut ep, mut er) = self.fetch_sourcemap(&sm_url).await;
                            endpoints.extend(ep.drain());
                            errors.extend(er.drain(..));
                        }
                    }
                }
                Err(e) => errors.push(e),
            }
        }

        // 3. Analyse inline scripts
        for cap in INLINE_SCRIPT.captures_iter(page) {
            if let Some(content) = cap.get(1) {
                self.extract_from_text(content.as_str(), &mut endpoints);
            }
        }

        debug!("[js] found {} endpoints", endpoints.len());
        (endpoints, errors)
    }

    fn extract_from_text(&self, text: &str, out: &mut HashSet<String>) {
        for re in API_PATTERNS.iter() {
            for cap in re.captures_iter(text) {
                // Group 1 or group 0 depending on pattern
                let raw = cap
                    .get(1)
                    .or_else(|| cap.get(0))
                    .map(|m| m.as_str())
                    .unwrap_or("");
                if let Some(p) = normalize_path(raw, self.host) {
                    out.insert(p);
                }
            }
        }
    }

    async fn fetch_sourcemap(&self, sm_url: &str) -> (HashSet<String>, Vec<CapturedError>) {
        let mut out = HashSet::new();
        let mut errors = Vec::new();

        match self.client.get(sm_url).await {
            Ok(r) => match serde_json::from_str::<serde_json::Value>(&r.body) {
                Ok(map) => {
                    let sources = map
                        .get("sourcesContent")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    for src in sources {
                        if let Some(text) = src.as_str() {
                            self.extract_from_text(text, &mut out);
                        }
                    }
                }
                Err(e) => {
                    warn!("[js] sourcemap parse error at {sm_url}: {e}");
                }
            },
            Err(e) => errors.push(e),
        }

        (out, errors)
    }

    fn resolve(&self, raw: &str) -> Option<String> {
        self.resolve_from(self.target_url, raw)
    }

    fn resolve_from(&self, base: &str, raw: &str) -> Option<String> {
        let base_url = Url::parse(base).ok()?;
        let resolved = base_url.join(raw).ok()?;
        // Only follow same-host scripts
        if resolved.host_str()? != self.host {
            return None;
        }
        Some(resolved.to_string())
    }
}

use std::collections::HashSet;

use futures::stream::{self, StreamExt};
use rand::seq::SliceRandom;
use tracing::{debug, warn};

use crate::{error::CapturedError, http_client::HttpClient};

/// Built-in wordlist of high-value API / admin paths.
/// Extend this list or load an external wordlist via `Config::wordlist`.
static COMMON_PATHS: &[&str] = &[
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/graphql",
    "/graphiql",
    "/playground",
    "/swagger",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger-ui",
    "/swagger-ui.html",
    "/openapi",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs.json",
    "/docs",
    "/redoc",
    "/admin",
    "/admin/api",
    "/internal",
    "/internal/api",
    "/private",
    "/debug",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/metrics",
    "/metrics",
    "/health",
    "/healthz",
    "/readyz",
    "/livez",
    "/status",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/token",
    "/oauth/authorize",
    "/auth/token",
    "/auth/login",
    "/auth/refresh",
    "/login",
    "/logout",
    "/register",
    "/users",
    "/user",
    "/account",
    "/accounts",
    "/profile",
    "/me",
    "/config",
    "/configuration",
    "/settings",
    "/env",
    "/environment",
    "/version",
    "/info",
    "/ping",
    "/trace",
    "/log",
    "/logs",
    "/debug/vars",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/.env",
    "/.git/config",
    "/wp-json/wp/v2",
    "/wp-json",
    "/jsonapi",
    "/rest/v1",
    "/rest/v2",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/graphql",
];

pub struct CommonPathDiscovery<'a> {
    client: &'a HttpClient,
    base_url: &'a str,
    concurrency: usize,
    /// Optional external wordlist to merge with the built-in list
    extra: Vec<String>,
}

impl<'a> CommonPathDiscovery<'a> {
    pub fn new(
        client: &'a HttpClient,
        base_url: &'a str,
        concurrency: usize,
        extra: Vec<String>,
    ) -> Self {
        Self {
            client,
            base_url,
            concurrency,
            extra,
        }
    }

    /// Returns only paths that responded with < 404 (i.e. exist or auth-gated)
    pub async fn run(&self) -> (HashSet<String>, Vec<CapturedError>) {
        let base = self.base_url.trim_end_matches('/');

        // Merge built-in + external wordlist, deduplicate, and shuffle to
        // avoid deterministic probing fingerprints.
        let mut all_paths: Vec<String> = COMMON_PATHS.iter().map(|p| (*p).to_string()).collect();
        all_paths.extend(self.extra.iter().cloned());
        all_paths.sort_unstable();
        all_paths.dedup();
        if all_paths.len() > 1 {
            let mut rng = rand::thread_rng();
            all_paths.shuffle(&mut rng);
        }

        let results = stream::iter(all_paths)
            .map(|path| {
                let url = format!("{base}{path}");
                async move {
                    let result = self.client.head(&url).await;
                    (path, url, result)
                }
            })
            .buffer_unordered(self.concurrency)
            .collect::<Vec<_>>()
            .await;

        let mut found = HashSet::new();
        let mut errors = Vec::new();

        for (path, url, result) in results {
            match result {
                Ok(resp) => {
                    // Treat anything except 404/410 as "exists"
                    if resp.status != 404 && resp.status != 410 {
                        debug!("[common_paths] {} => {}", url, resp.status);
                        found.insert(path);
                    }
                }
                Err(e) => {
                    warn!("[common_paths] probe error: {}", e);
                    errors.push(e);
                }
            }
        }

        debug!("[common_paths] {} live paths found", found.len());
        (found, errors)
    }
}

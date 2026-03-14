use std::collections::HashSet;

use tracing::debug;

use crate::{error::CapturedError, http_client::HttpClient};

use super::normalize_path;

pub struct RobotsDiscovery<'a> {
    client: &'a HttpClient,
    base_url: &'a str,
    host: &'a str,
}

impl<'a> RobotsDiscovery<'a> {
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

        let robots_url = format!("{}/robots.txt", self.base_url.trim_end_matches('/'));

        match self.client.get(&robots_url).await {
            Ok(resp) if resp.status < 400 => {
                for line in resp.body.lines() {
                    let line = line.trim();

                    // Disallow: /path  or  Allow: /path
                    if let Some(rest) = line
                        .strip_prefix("Disallow:")
                        .or_else(|| line.strip_prefix("Allow:"))
                    {
                        let raw = rest.trim().split('#').next().unwrap_or("").trim();
                        // Skip wildcards / empty / root-only lines
                        if raw.is_empty() || raw == "/" || raw.contains('*') {
                            continue;
                        }
                        if let Some(p) = normalize_path(raw, self.host) {
                            paths.insert(p);
                        }
                    }

                    // Sitemap: https://... — forward to sitemap discovery
                    if let Some(rest) = line.strip_prefix("Sitemap:") {
                        let raw = rest.trim();
                        if let Some(p) = normalize_path(raw, self.host) {
                            paths.insert(p);
                        }
                    }
                }
                debug!("[robots] found {} paths", paths.len());
            }
            Ok(_) => {
                debug!("[robots] non-2xx response, skipping");
            }
            Err(e) => errors.push(e),
        }

        (paths, errors)
    }
}

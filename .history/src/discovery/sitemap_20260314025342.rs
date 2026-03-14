use std::collections::HashSet;

use once_cell::sync::Lazy;
use regex::Regex;
use tracing::debug;

use crate::{error::CapturedError, http_client::HttpClient};

use super::normalize_path;

// Match <loc>...</loc> entries (XML sitemaps)
static LOC_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)<loc>\s*(https?://[^<]+)\s*</loc>").unwrap());

// Sitemap index: <sitemap><loc>…</loc></sitemap>
static SITEMAP_INDEX_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)<sitemap>\s*<loc>\s*(https?://[^<]+)\s*</loc>").unwrap());

pub struct SitemapDiscovery<'a> {
    client: &'a HttpClient,
    base_url: &'a str,
    host: &'a str,
    /// Limit recursion into sitemap indexes
    max_sitemaps: usize,
}

impl<'a> SitemapDiscovery<'a> {
    pub fn new(
        client: &'a HttpClient,
        base_url: &'a str,
        host: &'a str,
        max_sitemaps: usize,
    ) -> Self {
        Self { client, base_url, host, max_sitemaps }
    }

    pub async fn run(&self) -> (HashSet<String>, Vec<CapturedError>) {
        let mut paths = HashSet::new();
        let mut errors = Vec::new();

        let root = format!("{}/sitemap.xml", self.base_url.trim_end_matches('/'));
        self.fetch_sitemap(&root, 0, &mut paths, &mut errors).await;

        debug!("[sitemap] found {} paths", paths.len());
        (paths, errors)
    }

    async fn fetch_sitemap(
        &self,
        url: &str,
        depth: usize,
        paths: &mut HashSet<String>,
        errors: &mut Vec<CapturedError>,
    ) {
        if depth >= self.max_sitemaps {
            return;
        }

        let resp = match self.client.get(url).await {
            Ok(r) if r.status < 400 => r,
            Ok(_) => return,
            Err(e) => {
                errors.push(e);
                return;
            }
        };

        let body = &resp.body;

        // Is this a sitemap index?
        let sub_sitemaps: Vec<String> = SITEMAP_INDEX_RE
            .captures_iter(body)
            .filter_map(|c| c.get(1).map(|m| m.as_str().trim().to_string()))
            .collect();

        if !sub_sitemaps.is_empty() {
            // Recurse into sub-sitemaps (depth-limited, sequential to stay polite)
            for sub in sub_sitemaps.iter().take(self.max_sitemaps.saturating_sub(depth)) {
                // Only follow same-host sitemaps
                if url::Url::parse(sub)
                    .ok()
                    .and_then(|u| u.host_str().map(|h| h.to_string()))
                    .as_deref()
                    != Some(self.host)
                {
                    continue;
                }
                Box::pin(self.fetch_sitemap(sub, depth + 1, paths, errors)).await;
            }
            return;
        }

        // Regular sitemap: harvest <loc> URLs
        for cap in LOC_RE.captures_iter(body) {
            let raw = cap[1].trim();
            if let Some(p) = normalize_path(raw, self.host) {
                paths.insert(p);
            }
        }
    }
}

use std::collections::HashSet;

use tracing::debug;

use crate::{error::CapturedError, http_client::HttpClient};

use super::normalize_path;

/// Interesting response headers that may reveal internal API paths / links
const LINK_HEADERS: &[&str] = &["link", "location", "x-redirect-to", "content-location"];

pub struct HeaderDiscovery<'a> {
    client: &'a HttpClient,
    base_url: &'a str,
    host: &'a str,
}

impl<'a> HeaderDiscovery<'a> {
    pub fn new(client: &'a HttpClient, base_url: &'a str, host: &'a str) -> Self {
        Self {
            client,
            base_url,
            host,
        }
    }

    /// Probe the root URL (GET + HEAD) and extract navigational paths from headers.
    pub async fn run(&self) -> (HashSet<String>, Vec<CapturedError>) {
        let mut paths = HashSet::new();
        let mut errors = Vec::new();

        for probe in &[
            self.client.get(self.base_url).await,
            self.client.head(self.base_url).await,
        ] {
            match probe {
                Ok(resp) => {
                    for key in LINK_HEADERS {
                        if let Some(val) = resp.header(key) {
                            for raw in self.extract_link_targets(val) {
                                if let Some(p) = normalize_path(&raw, self.host) {
                                    paths.insert(p);
                                }
                            }
                        }
                    }
                }
                Err(e) => errors.push(e.clone()),
            }
        }

        debug!("[headers] found {} paths", paths.len());
        (paths, errors)
    }

    /// Parse RFC 5988 Link header values like:
    /// `</api/v2>; rel="next", </docs>; rel="help"`
    fn extract_link_targets(&self, header_val: &str) -> Vec<String> {
        header_val
            .split(',')
            .filter_map(|part| {
                // Extract the <...> URI reference from each link item
                let start = part.find('<')?;
                let end = part.find('>')?;
                if end > start {
                    Some(part[start + 1..end].trim().to_string())
                } else {
                    None
                }
            })
            .collect()
    }
}

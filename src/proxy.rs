use crate::error::{ScannerError, ScannerResult};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use url::Url;

/// Strategy object that resolves which proxy (if any) should be used.
///
/// Behavior is additive and backward-compatible:
/// - If `single` is set, it always wins.
/// - If `single` is unset and a pool exists, selection is deterministic per host.
/// - If both are unset, direct connections are used.
#[derive(Debug, Clone, Default)]
pub struct ProxyStrategy {
    single: Option<String>,
    pool: Vec<String>,
}

impl ProxyStrategy {
    pub fn new(single: Option<String>, pool: Vec<String>) -> Self {
        let single = single
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        if single.is_some() {
            // Preserve legacy behavior: explicit --proxy takes precedence.
            return Self {
                single,
                pool: Vec::new(),
            };
        }

        let pool = pool
            .into_iter()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();

        Self { single, pool }
    }

    pub fn is_pool_enabled(&self) -> bool {
        !self.pool.is_empty()
    }

    pub fn pool_size(&self) -> usize {
        self.pool.len()
    }

    pub fn resolve_for_host(&self, host: &str) -> Option<String> {
        if let Some(proxy) = &self.single {
            return Some(proxy.clone());
        }

        if self.pool.is_empty() {
            return None;
        }

        let mut hasher = DefaultHasher::new();
        host.hash(&mut hasher);
        let idx = (hasher.finish() as usize) % self.pool.len();
        self.pool.get(idx).cloned()
    }

    pub fn resolve_for_url(&self, url: &str) -> Option<String> {
        let host = Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_default();
        self.resolve_for_host(&host)
    }
}

/// Parse a single proxy line.
///
/// Accepted formats:
/// - Full URL (e.g. http://user:pass@host:port, socks5://host:1080)
/// - host:port
/// - host:port:user:pass
pub fn parse_proxy_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    if trimmed.contains("://") {
        return Some(trimmed.to_string());
    }

    let parts: Vec<&str> = trimmed.splitn(4, ':').collect();
    match parts.len() {
        2 => Some(format!("http://{}:{}", parts[0], parts[1])),
        4 => Some(format!(
            "http://{}:{}@{}:{}",
            parts[2], parts[3], parts[0], parts[1]
        )),
        _ => None,
    }
}

/// Load and parse proxy URLs from a file.
///
/// Blank lines and `#` comments are ignored.
pub fn parse_proxy_file(path: &Path) -> ScannerResult<Vec<String>> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        ScannerError::Config(format!(
            "Failed to read proxy file '{}': {e}",
            path.display()
        ))
    })?;

    let proxies: Vec<String> = content.lines().filter_map(parse_proxy_line).collect();

    if proxies.is_empty() {
        return Err(ScannerError::Config(format!(
            "Proxy file '{}' is empty or has no valid entries",
            path.display()
        )));
    }

    Ok(proxies)
}

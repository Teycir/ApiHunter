pub mod common_paths;
pub mod headers;
pub mod js;
pub mod robots;
pub mod sitemap;
pub mod swagger;

use std::collections::HashSet;

/// Normalise a raw path candidate into a clean `/foo/bar` string.
/// Returns `None` if the path is empty, crosses origins, or is unusable.
pub fn normalize_path(raw: &str, target_host: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    // If it looks like a full URL, validate the host then extract path
    if raw.starts_with("http://") || raw.starts_with("https://") {
        if let Ok(parsed) = url::Url::parse(raw) {
            if parsed.host_str().unwrap_or("") != target_host {
                return None; // cross-origin
            }
            return normalize_path(parsed.path(), target_host);
        }
        return None;
    }

    let mut path = raw.to_string();
    if !path.starts_with('/') {
        path = format!("/{path}");
    }

    // Strip trailing slash (except root)
    if path.len() > 1 && path.ends_with('/') {
        path.pop();
    }

    Some(path)
}

/// Keywords that flag a path as interesting for API discovery
pub fn is_interesting(path: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "api", "graphql", "swagger", "openapi", "admin", "internal", "private", "debug",
        "actuator", "metrics", "health", "config", "oauth", "auth", "token", "session", "keys",
        "secret", "rest", "v1", "v2", "v3", "webhook", "upload", "download",
    ];
    let lower = path.to_lowercase();
    KEYWORDS.iter().any(|k| lower.contains(k))
}

/// Merge a batch of raw path strings into a set, normalising each one
pub fn collect_paths(
    raws: impl IntoIterator<Item = String>,
    host: &str,
    out: &mut HashSet<String>,
) {
    for raw in raws {
        if let Some(p) = normalize_path(&raw, host) {
            out.insert(p);
        }
    }
}

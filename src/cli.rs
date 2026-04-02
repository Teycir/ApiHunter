// src/cli.rs
//
// CLI argument definitions and helpers shared by main and tests.

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, BufRead},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::{ArgGroup, Parser, ValueEnum};
use serde_json::Value;
use url::Url;

use crate::reports::{ReportFormat, Severity};

// ── CLI definition ────────────────────────────────────────────────────────────

/// A fast, async web security scanner.
///
/// Reads a list of URLs from a file or stdin, runs the enabled checks
/// concurrently, and writes findings in JSON or NDJSON format.
#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about,
    long_about = None,
    // Require exactly one of --urls, --stdin, or --har
    group(
        ArgGroup::new("input")
            .required(true)
            .args(["urls", "stdin", "har", "collection"])
    )
)]
pub struct Cli {
    // ── Input ────────────────────────────────────────────────────────────────
    /// Path to a newline-delimited file of URLs to scan.
    #[arg(short = 'u', long, value_name = "FILE", group = "input")]
    pub urls: Option<PathBuf>,

    /// Read newline-delimited URLs from stdin instead of a file.
    #[arg(long, group = "input")]
    pub stdin: bool,

    /// Path to a HAR file; imports `log.entries[].request.url` as scan seeds.
    #[arg(long, value_name = "FILE", group = "input")]
    pub har: Option<PathBuf>,

    /// Path to a Postman/Insomnia collection export (JSON).
    #[arg(long, value_name = "FILE", group = "input")]
    pub collection: Option<PathBuf>,

    /// Skip pre-filtering of inaccessible URLs (enabled by default).
    #[arg(long)]
    pub no_filter: bool,

    /// Timeout for accessibility pre-check (seconds).
    #[arg(long, default_value_t = 3, value_name = "SECS")]
    pub filter_timeout: u64,

    /// Skip endpoint discovery and scan only the provided seed URLs.
    #[arg(long)]
    pub no_discovery: bool,

    // ── Output ───────────────────────────────────────────────────────────────
    /// Write findings to this file path (default: stdout).
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Output format.
    #[arg(short = 'f', long, default_value = "pretty", value_name = "FORMAT")]
    pub format: CliFormat,

    /// Emit NDJSON findings as they arrive (NDJSON only).
    #[arg(long)]
    pub stream: bool,

    /// Baseline NDJSON file; suppress findings already present in baseline.
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// Suppress all stdout output except findings (no summary box).
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Print the summary box even in quiet mode.
    #[arg(long)]
    pub summary: bool,

    /// Disable automatic local report persistence under ~/Documents/ApiHunterReports.
    #[arg(long)]
    pub no_auto_report: bool,

    // ── Concurrency & limits ─────────────────────────────────────────────────
    /// Maximum number of concurrent in-flight requests.
    #[arg(short = 'c', long, default_value_t = 20, value_name = "N")]
    pub concurrency: usize,

    /// Maximum number of endpoints to scan per site (0 = unlimited).
    #[arg(short = 'n', long, default_value_t = 50, value_name = "N")]
    pub max_endpoints: usize,

    // ── Politeness ───────────────────────────────────────────────────────────
    /// Per-domain minimum delay between requests (milliseconds).
    #[arg(long, default_value_t = 150, value_name = "MS")]
    pub delay_ms: u64,

    /// Maximum number of retry attempts on transient errors.
    #[arg(long, default_value_t = 1, value_name = "N")]
    pub retries: u32,

    /// Per-request timeout (seconds).
    #[arg(long, default_value_t = 8, value_name = "SECS")]
    pub timeout_secs: u64,

    // ── WAF evasion ──────────────────────────────────────────────────────────
    /// Enable WAF-evasion heuristics (randomised UA, header shuffling, jitter).
    #[arg(long)]
    pub waf_evasion: bool,

    /// Rotate through these User-Agent strings (comma-separated).
    /// Implies --waf-evasion.
    #[arg(long, value_name = "UA,...", value_delimiter = ',')]
    pub user_agents: Vec<String>,

    // ── Proxy / TLS ──────────────────────────────────────────────────────────
    /// Extra request headers applied to every request (e.g. "Authorization: Bearer xxx").
    #[arg(long, value_name = "NAME:VALUE", value_delimiter = ',')]
    pub headers: Vec<String>,

    /// Cookies applied to every request (e.g. "session=abc123,theme=dark").
    #[arg(long, value_name = "NAME=VALUE", value_delimiter = ',')]
    pub cookies: Vec<String>,

    /// HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080).
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Accept invalid / self-signed TLS certificates (dangerous).
    #[arg(long)]
    pub danger_accept_invalid_certs: bool,

    /// Enable active (potentially invasive) checks.
    #[arg(long)]
    pub active_checks: bool,

    /// Dry-run active checks: do not send mutation probes, emit informational "would test" findings.
    #[arg(long)]
    pub dry_run: bool,

    /// Use per-host HTTP client pools.
    #[arg(long)]
    pub per_host_clients: bool,

    /// Enable adaptive concurrency (AIMD).
    #[arg(long)]
    pub adaptive_concurrency: bool,

    /// Convenience: add `Authorization: Bearer <token>`.
    #[arg(long, value_name = "TOKEN")]
    pub auth_bearer: Option<String>,

    /// Convenience: add `Authorization: Basic <base64(user:pass)>`.
    #[arg(long, value_name = "USER:PASS")]
    pub auth_basic: Option<String>,

    /// Path to a JSON auth flow descriptor for pre-scan login.
    /// See docs/auth-flow.md for the format.
    #[arg(long, value_name = "FILE")]
    pub auth_flow: Option<PathBuf>,

    /// Second auth flow for cross-user IDOR checks (--active-checks required).
    #[arg(long, value_name = "FILE")]
    pub auth_flow_b: Option<PathBuf>,

    /// Extra auth-like headers to strip for unauthenticated probes (comma-separated).
    #[arg(long, value_name = "NAME", value_delimiter = ',')]
    pub unauth_strip_headers: Option<Vec<String>>,

    /// Load/save cookies from a JSON session file.
    #[arg(long, value_name = "FILE")]
    pub session_file: Option<PathBuf>,

    // ── Scanner toggles ──────────────────────────────────────────────────────
    /// Disable the CORS scanner.
    #[arg(long)]
    pub no_cors: bool,

    /// Disable the CSP scanner.
    #[arg(long)]
    pub no_csp: bool,

    /// Disable the GraphQL scanner.
    #[arg(long)]
    pub no_graphql: bool,

    /// Disable the API-security scanner.
    #[arg(long)]
    pub no_api_security: bool,

    /// Disable the JWT scanner.
    #[arg(long)]
    pub no_jwt: bool,

    /// Disable the OpenAPI scanner.
    #[arg(long)]
    pub no_openapi: bool,

    /// Disable the API versioning scanner.
    #[arg(long)]
    pub no_api_versioning: bool,

    /// Disable the Mass Assignment scanner (active checks).
    #[arg(long)]
    pub no_mass_assignment: bool,

    /// Disable the OAuth/OIDC scanner (active checks).
    #[arg(long)]
    pub no_oauth_oidc: bool,

    /// Disable the Rate Limit scanner (active checks).
    #[arg(long)]
    pub no_rate_limit: bool,

    /// Disable the CVE Template scanner (active checks).
    #[arg(long)]
    pub no_cve_templates: bool,

    /// Disable the WebSocket scanner (active checks).
    #[arg(long)]
    pub no_websocket: bool,

    // ── Reporting threshold ───────────────────────────────────────────────────
    /// Minimum severity to include in findings output.
    #[arg(long, value_name = "LEVEL")]
    pub min_severity: Option<CliSeverity>,

    /// Exit with code 1 when findings at or above this severity are found.
    #[arg(long, default_value = "medium", value_name = "LEVEL")]
    pub fail_on: CliSeverity,
}

// ── Clap value enums ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliFormat {
    Pretty,
    Ndjson,
    Sarif,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<CliSeverity> for Severity {
    fn from(c: CliSeverity) -> Self {
        match c {
            CliSeverity::Critical => Severity::Critical,
            CliSeverity::High => Severity::High,
            CliSeverity::Medium => Severity::Medium,
            CliSeverity::Low => Severity::Low,
            CliSeverity::Info => Severity::Info,
        }
    }
}

impl From<CliFormat> for ReportFormat {
    fn from(c: CliFormat) -> Self {
        match c {
            CliFormat::Pretty => ReportFormat::Pretty,
            CliFormat::Ndjson => ReportFormat::Ndjson,
            CliFormat::Sarif => ReportFormat::Sarif,
        }
    }
}

// ── URL loader ────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct HarFile {
    log: HarLog,
}

#[derive(Debug, serde::Deserialize)]
struct HarLog {
    entries: Vec<HarEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct HarEntry {
    request: HarRequest,
}

#[derive(Debug, serde::Deserialize)]
struct HarRequest {
    url: String,
    #[serde(default)]
    method: String,
}

/// Read URLs from a file, stdin, or HAR input.
/// Blank lines and lines starting with `#` are ignored.
pub fn load_urls(cli: &Cli) -> Result<Vec<String>> {
    let lines: Vec<String> = if let Some(ref path) = cli.urls {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Cannot read URL file: {}", path.display()))?;
        content.lines().map(str::to_owned).collect()
    } else if let Some(ref path) = cli.har {
        load_urls_from_har(path)?
    } else if let Some(ref path) = cli.collection {
        load_urls_from_collection(path)?
    } else {
        // --stdin
        let stdin = io::stdin();
        stdin
            .lock()
            .lines()
            .collect::<Result<_, _>>()
            .context("Failed to read URLs from stdin")?
    };

    let urls = lines
        .into_iter()
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    Ok(urls)
}

fn load_urls_from_har(path: &PathBuf) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Cannot read HAR file: {}", path.display()))?;
    let har: HarFile = serde_json::from_str(&content)
        .with_context(|| format!("Cannot parse HAR file: {}", path.display()))?;

    Ok(har
        .log
        .entries
        .into_iter()
        .filter_map(|entry| {
            let url = entry.request.url.trim().to_string();
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return None;
            }
            if !is_likely_api_url(&url, &entry.request.method) {
                return None;
            }
            Some(url)
        })
        .collect())
}

fn load_urls_from_collection(path: &PathBuf) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Cannot read collection file: {}", path.display()))?;
    let root: Value = serde_json::from_str(&content)
        .with_context(|| format!("Cannot parse collection JSON: {}", path.display()))?;

    let postman_vars = collect_postman_variables(&root);
    let mut out = Vec::new();

    extract_postman_requests(&root, &postman_vars, &mut out);
    extract_insomnia_requests(&root, &mut out);

    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for url in out {
        if seen.insert(url.clone()) {
            deduped.push(url);
        }
    }

    Ok(deduped)
}

fn collect_postman_variables(root: &Value) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    if let Some(entries) = root.get("variable").and_then(|v| v.as_array()) {
        for entry in entries {
            let key = entry
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let value = entry
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if !key.is_empty() && !value.is_empty() {
                vars.insert(key.to_string(), value.to_string());
            }
        }
    }
    vars
}

fn extract_postman_requests(node: &Value, vars: &HashMap<String, String>, out: &mut Vec<String>) {
    if let Some(request) = node.get("request") {
        let method = request
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET");
        if let Some(raw_url) = postman_request_url(request) {
            let resolved = resolve_postman_variables(&raw_url, vars);
            push_collection_candidate(&resolved, method, out);
        }
    }

    if let Some(items) = node.get("item").and_then(|v| v.as_array()) {
        for item in items {
            extract_postman_requests(item, vars, out);
        }
    }
}

fn postman_request_url(request: &Value) -> Option<String> {
    let url = request.get("url")?;
    if let Some(raw) = url.as_str() {
        return Some(raw.trim().to_string());
    }

    let raw = url.get("raw").and_then(|v| v.as_str()).map(|v| v.trim());
    if let Some(raw) = raw {
        if !raw.is_empty() {
            return Some(raw.to_string());
        }
    }

    let protocol = url
        .get("protocol")
        .and_then(|v| v.as_str())
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("https")
        .trim();

    let host = json_string_or_joined(url.get("host"), ".")?;
    if host.trim().is_empty() {
        return None;
    }

    let path = json_string_or_joined(url.get("path"), "/").unwrap_or_default();
    let mut built = if host.starts_with("http://") || host.starts_with("https://") {
        host
    } else {
        format!("{protocol}://{host}")
    };

    if !path.is_empty() {
        if !built.ends_with('/') {
            built.push('/');
        }
        built.push_str(path.trim_start_matches('/'));
    }

    if let Some(query) = url.get("query").and_then(|v| v.as_array()) {
        let mut first = true;
        for entry in query {
            let disabled = entry
                .get("disabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if disabled {
                continue;
            }
            let key = entry
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let value = entry
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if key.is_empty() {
                continue;
            }
            if first {
                built.push('?');
                first = false;
            } else {
                built.push('&');
            }
            built.push_str(key);
            if !value.is_empty() {
                built.push('=');
                built.push_str(value);
            }
        }
    }

    Some(built)
}

fn json_string_or_joined(value: Option<&Value>, delimiter: &str) -> Option<String> {
    let value = value?;
    if let Some(s) = value.as_str() {
        return Some(s.trim().to_string());
    }
    let arr = value.as_array()?;
    let joined = arr
        .iter()
        .filter_map(|part| part.as_str().map(|s| s.trim().to_string()))
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(delimiter);
    if joined.is_empty() {
        None
    } else {
        Some(joined)
    }
}

fn resolve_postman_variables(raw: &str, vars: &HashMap<String, String>) -> String {
    let mut out = raw.trim().to_string();
    for (k, v) in vars {
        let token = format!("{{{{{k}}}}}");
        out = out.replace(&token, v);
    }
    out
}

fn extract_insomnia_requests(node: &Value, out: &mut Vec<String>) {
    match node {
        Value::Array(items) => {
            for item in items {
                extract_insomnia_requests(item, out);
            }
        }
        Value::Object(map) => {
            let ty = map.get("_type").and_then(|v| v.as_str()).unwrap_or("");
            if ty == "request" {
                let method = map.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
                let url = map.get("url").and_then(|v| v.as_str()).unwrap_or("").trim();
                push_collection_candidate(url, method, out);
            }
            for value in map.values() {
                extract_insomnia_requests(value, out);
            }
        }
        _ => {}
    }
}

fn push_collection_candidate(raw_url: &str, method: &str, out: &mut Vec<String>) {
    let candidate = raw_url.trim();
    if !(candidate.starts_with("http://") || candidate.starts_with("https://")) {
        return;
    }
    if is_likely_api_url(candidate, method) {
        out.push(candidate.to_string());
    }
}

fn is_likely_api_url(raw_url: &str, method: &str) -> bool {
    let parsed = match Url::parse(raw_url) {
        Ok(u) => u,
        Err(_) => return false,
    };

    let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
    let path = parsed.path().to_ascii_lowercase();
    let query = parsed.query().unwrap_or("").to_ascii_lowercase();
    let method = method.to_ascii_uppercase();

    if is_likely_static_host(&host) || is_static_asset_path(&path) {
        return false;
    }

    // Non-read methods in HAR are usually API/business operations.
    if !matches!(method.as_str(), "" | "GET" | "HEAD" | "OPTIONS") {
        return true;
    }

    if host.starts_with("api.") || host.contains(".api.") {
        return true;
    }

    let needle_haystack = format!("{path}?{query}");
    const KEYWORDS: &[&str] = &[
        "/api", "graphql", "openapi", "swagger", "oauth", "oidc", "auth", "token", "session",
        "login", "logout", "signin", "identity", "/v1", "/v2", "/v3", "/rpc",
    ];

    KEYWORDS.iter().any(|k| needle_haystack.contains(k))
}

fn is_likely_static_host(host: &str) -> bool {
    if host.ends_with("awsstatic.com")
        || host.ends_with("cloudfront.net")
        || host.contains("fonts.")
        || host.contains("analytics")
    {
        return true;
    }

    host.starts_with("cdn.")
        || host.contains(".cdn.")
        || host.starts_with("static.")
        || host.contains(".static.")
        || host.starts_with("assets.")
        || host.contains(".assets.")
}

fn is_static_asset_path(path: &str) -> bool {
    const EXTENSIONS: &[&str] = &[
        ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
        ".ttf", ".eot", ".webp", ".avif", ".mp4", ".webm", ".mp3", ".wav", ".pdf", ".zip",
    ];
    EXTENSIONS.iter().any(|ext| path.ends_with(ext))
}

// ── Default user-agents ───────────────────────────────────────────────────────

pub fn default_user_agents() -> Vec<String> {
    crate::waf::WafEvasion::user_agent_pool()
}

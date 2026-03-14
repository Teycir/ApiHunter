// src/cli.rs
//
// CLI argument definitions and helpers shared by main and tests.

use std::{
    fs,
    io::{self, BufRead},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::{ArgGroup, Parser, ValueEnum};

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
    // Require exactly one of --urls or --stdin
    group(
        ArgGroup::new("input")
            .required(true)
            .args(["urls", "stdin"])
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

    // ── Concurrency & limits ─────────────────────────────────────────────────
    /// Maximum number of concurrent in-flight requests.
    #[arg(short = 'c', long, default_value_t = 20, value_name = "N")]
    pub concurrency: usize,

    /// Maximum number of endpoints to scan (0 = unlimited).
    #[arg(short = 'n', long, default_value_t = 0, value_name = "N")]
    pub max_endpoints: usize,

    // ── Politeness ───────────────────────────────────────────────────────────
    /// Per-domain minimum delay between requests (milliseconds).
    #[arg(long, default_value_t = 100, value_name = "MS")]
    pub delay_ms: u64,

    /// Maximum number of retry attempts on transient errors.
    #[arg(long, default_value_t = 3, value_name = "N")]
    pub retries: u32,

    /// Per-request timeout (seconds).
    #[arg(long, default_value_t = 30, value_name = "SECS")]
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

    // ── Reporting threshold ───────────────────────────────────────────────────
    /// Minimum severity to include in findings output.
    #[arg(long, default_value = "info", value_name = "LEVEL")]
    pub min_severity: CliSeverity,

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

/// Read newline-delimited URLs from a file or stdin.
/// Blank lines and lines starting with `#` are ignored.
pub fn load_urls(cli: &Cli) -> Result<Vec<String>> {
    let lines: Vec<String> = if let Some(ref path) = cli.urls {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Cannot read URL file: {}", path.display()))?;
        content.lines().map(str::to_owned).collect()
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

// ── Default user-agents ───────────────────────────────────────────────────────

pub fn default_user_agents() -> Vec<String> {
    [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
         AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) \
         AppleWebKit/605.1.15 (KHTML, like Gecko) \
         Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) \
         Gecko/20100101 Firefox/125.0",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

// src/config.rs
//
// Unified configuration types consumed by every module in the scanner.

/// Top-level configuration produced by CLI arg parsing in `main.rs`.
#[derive(Debug, Clone)]
pub struct Config {
    /// Maximum number of URLs to scan.  `usize::MAX` means unlimited.
    pub max_endpoints: usize,

    /// Number of URLs scanned concurrently (semaphore width).
    pub concurrency: usize,

    /// Per-scanner enable / disable switches.
    pub toggles: ScannerToggles,

    /// Rate-limiting / retry knobs.
    pub politeness: PolitenessConfig,

    /// WAF-evasion settings.
    pub waf_evasion: WafEvasionConfig,

    /// Default headers applied to every request.
    pub default_headers: Vec<(String, String)>,

    /// Cookies applied to every request.
    pub cookies: Vec<(String, String)>,

    /// Optional HTTP/HTTPS proxy URL.
    pub proxy: Option<String>,

    /// Accept invalid TLS certificates (dangerous).
    pub danger_accept_invalid_certs: bool,

    /// Enable active (potentially invasive) checks.
    pub active_checks: bool,

    /// Enable streaming NDJSON findings (reports while scan is running).
    pub stream_findings: bool,

    /// Optional baseline NDJSON file for diffing (suppress known findings).
    pub baseline_path: Option<std::path::PathBuf>,

    /// Optional session cookie file (JSON) to load/save.
    pub session_file: Option<std::path::PathBuf>,

    /// Optional auth helpers.
    pub auth_bearer: Option<String>,
    pub auth_basic: Option<String>,

    /// Enable per-host HTTP client pools.
    pub per_host_clients: bool,

    /// Enable adaptive concurrency.
    pub adaptive_concurrency: bool,
}

/// Individual scanner toggle flags.
#[derive(Debug, Clone)]
pub struct ScannerToggles {
    pub cors: bool,
    pub csp: bool,
    pub graphql: bool,
    pub api_security: bool,
    pub jwt: bool,
    pub openapi: bool,
}

/// Network politeness knobs.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PolitenessConfig {
    /// Minimum delay between requests per host (ms).
    pub delay_ms: u64,
    /// Maximum retry attempts on transient errors.
    pub retries: u32,
    /// Per-request timeout (seconds).
    pub timeout_secs: u64,
}

/// WAF evasion configuration.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WafEvasionConfig {
    /// Master switch for WAF evasion heuristics.
    pub enabled: bool,
    /// User-Agent rotation pool.
    pub user_agents: Vec<String>,
}

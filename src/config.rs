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

    /// Optional pool of proxy URLs (used when `proxy` is not set).
    pub proxy_pool: Vec<String>,

    /// Optional TLS profile for outbound transport.
    pub tls_profile: crate::transport_tls::TlsProfile,

    /// Optional transport backend for HTTP client construction.
    pub transport_backend: crate::transport_adapter::TransportBackend,

    /// Accept invalid TLS certificates (dangerous).
    pub danger_accept_invalid_certs: bool,

    /// Enable active (potentially invasive) checks.
    pub active_checks: bool,

    /// Do not send active-check mutation requests; emit informational "would test" findings.
    pub dry_run: bool,

    /// Enable deeper response-diff probe variants in versioning checks.
    pub response_diff_deep: bool,

    /// Enable streaming NDJSON findings (reports while scan is running).
    pub stream_findings: bool,

    /// Optional baseline NDJSON file for diffing (suppress known findings).
    pub baseline_path: Option<std::path::PathBuf>,

    /// Optional session cookie file (JSON) to load/save.
    pub session_file: Option<std::path::PathBuf>,

    /// Optional auth helpers.
    pub auth_bearer: Option<String>,
    pub auth_basic: Option<String>,

    /// Optional auth flow descriptor (loaded from --auth-flow file).
    pub auth_flow: Option<std::path::PathBuf>,

    /// Second credential set for cross-user IDOR checks (--auth-flow-b).
    pub auth_flow_b: Option<std::path::PathBuf>,

    /// Additional auth-like headers to strip for unauthenticated probes.
    pub unauth_strip_headers: Vec<String>,

    /// Enable per-host HTTP client pools.
    pub per_host_clients: bool,

    /// Enable adaptive concurrency.
    pub adaptive_concurrency: bool,

    /// Skip endpoint discovery and scan only provided seed URLs.
    pub no_discovery: bool,

    /// Fine-grained discovery controls (depth, breadth, timeouts per step).
    pub discovery: DiscoveryConfig,

    /// Suppress verbose progress output.
    pub quiet: bool,
}

/// Controls how deep and wide each discovery sub-step is allowed to go.
///
/// These knobs let operators tune the discovery phase without disabling it
/// entirely.  Lowering them is the primary fix when a target's sitemap tree
/// or JS bundle count causes the scanner to stall for hours.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Maximum number of sitemap files to fetch per site (index + sub-sitemaps).
    /// Default: 5.  Set to 1 to disable sitemap-index recursion.
    pub max_sitemaps: usize,

    /// Maximum number of external `<script src>` files to fetch per page.
    /// Default: 10.
    pub max_scripts: usize,

    /// Per-step wall-clock timeout (seconds).  Each discovery sub-step
    /// (robots, sitemap, swagger, js, headers, common-paths) is independently
    /// wrapped in this timeout, so the worst-case discovery wall time is
    /// roughly `6 × timeout_secs`.
    /// Default: 2 × politeness.timeout_secs (matches previous behaviour).
    /// Set explicitly to override without changing the scan timeout.
    pub timeout_secs: Option<u64>,
}

impl DiscoveryConfig {
    /// Resolve the effective per-step timeout.
    /// Falls back to `2 × politeness_timeout_secs` when not explicitly set,
    /// matching the behaviour that existed before this field was introduced.
    pub fn effective_timeout_secs(&self, politeness_timeout_secs: u64) -> u64 {
        self.timeout_secs
            .unwrap_or_else(|| politeness_timeout_secs.saturating_mul(2).max(1))
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            max_sitemaps: 5,
            max_scripts: 10,
            timeout_secs: None,
        }
    }
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
    pub api_versioning: bool,
    pub grpc_protobuf: bool,
    pub mass_assignment: bool,
    pub oauth_oidc: bool,
    pub rate_limit: bool,
    pub cve_templates: bool,
    pub websocket: bool,
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
    /// Keep a deterministic browser-like persona per host.
    pub sticky_persona: bool,
}

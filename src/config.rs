use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "api-scanner",
    about = "API Discovery & Vulnerability Scanner with WAF evasion",
    version
)]
pub struct Config {
    /// Target URL(s) — space-separated or a file path (one URL per line)
    #[arg(required = true)]
    pub targets: Vec<String>,

    /// Output directory for reports
    #[arg(short, long, default_value = "./api-reports")]
    pub output: PathBuf,

    /// Number of parallel worker threads (1–16)
    #[arg(short = 'j', long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(1..=16))]
    pub threads: u8,

    /// Request timeout in seconds
    #[arg(short, long, default_value_t = 10)]
    pub timeout: u64,

    /// Minimum delay between requests per worker (seconds)
    #[arg(long, default_value_t = 0.2)]
    pub min_delay: f64,

    /// Maximum delay between requests per worker (seconds)
    #[arg(long, default_value_t = 1.5)]
    pub max_delay: f64,

    /// HTTP/HTTPS proxy (e.g., http://127.0.0.1:8080)
    #[arg(short, long)]
    pub proxy: Option<String>,

    /// Disable WAF evasion headers & delays
    #[arg(long)]
    pub disable_waf_evasion: bool,

    /// Skip TLS certificate verification
    #[arg(long)]
    pub insecure: bool,

    /// Maximum endpoints to test for vulnerabilities (0 = unlimited)
    #[arg(long, default_value_t = 50)]
    pub max_endpoints: usize,

    /// Maximum JavaScript files to analyze per target
    #[arg(long, default_value_t = 15)]
    pub max_scripts: usize,

    /// Maximum response body size to read in KB
    #[arg(long, default_value_t = 512)]
    pub max_response_kb: usize,

    /// Log verbosity: error, warn, info, debug, trace
    #[arg(short, long, default_value = "info")]
    pub log_level: String,

    /// Write logs to file instead of only stdout
    #[arg(long)]
    pub log_file: Option<PathBuf>,

    /// Read targets from a file (one URL per line) instead of CLI args
    #[arg(short = 'f', long)]
    pub target_file: Option<PathBuf>,

    // src/config.rs  (additions needed by runner)
#[derive(Clone, Debug, serde::Deserialize)]
pub struct Config {
    /// Maximum number of URLs to scan in one run.  0 = unlimited.
    pub max_endpoints: usize,

    /// Number of URLs scanned concurrently.
    pub concurrency: usize,

    /// Per-scanner enable/disable toggles.
    pub scanners: ScannerToggles,

    // ... rest of your existing fields
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct ScannerToggles {
    pub cors:         bool,
    pub csp:          bool,
    pub graphql:      bool,
    pub api_security: bool,
}

}

impl Config {
    /// Resolve final target list — merging CLI args and optional file input
    pub fn resolve_targets(&self) -> anyhow::Result<Vec<String>> {
        let mut targets = self.targets.clone();

        if let Some(file) = &self.target_file {
            let content = std::fs::read_to_string(file)?;
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    targets.push(line.to_string());
                }
            }
        }

        // Deduplicate
        targets.sort();
        targets.dedup();

        Ok(targets)
    }

    pub fn max_response_bytes(&self) -> usize {
        self.max_response_kb * 1024
    }

    pub fn waf_evasion_enabled(&self) -> bool {
        !self.disable_waf_evasion
    }
}
